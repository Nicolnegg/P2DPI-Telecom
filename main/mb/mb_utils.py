# middlebox/mb/utils.py
#
# Purpose:
#   - Hold small, reusable, side-effect-free helpers for mb_main.py
#   - Keep imports minimal and avoid Flask/server state here.
#

from ctypes import cast, CDLL, c_char_p, c_int, create_string_buffer, c_ubyte, POINTER
import hashlib
import json
import os
import struct
import copy
import re

from typing import Dict, Tuple, List, Any


# Traffic block size in bytes
BLOCK_BYTES = int(os.environ.get("MB_BLOCK_BYTES", "8"))

# -------------------------
# PRF loader and signatures
# -------------------------


def load_prf(shared_dir: str = None) -> CDLL:
    """
    Load the C shared library 'prf.so' and set arg/return types.
    Search order:
      1) env PRF_SO_PATH
      2) <this_dir>/shared/prf.so
      3) <this_dir>/prf.so
      4) <this_dir>/../shared/prf.so
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = []

    # 1) Environment override
    env_path = os.environ.get("PRF_SO_PATH")
    if env_path:
        candidates.append(env_path)

    # 2) mb/shared/prf.so
    shared_dir = shared_dir or os.path.join(base_dir, 'shared')
    candidates.append(os.path.join(shared_dir, 'prf.so'))

    # 3) mb/prf.so
    candidates.append(os.path.join(base_dir, 'prf.so'))

    # 4) main/shared/prf.so
    candidates.append(os.path.abspath(os.path.join(base_dir, '..', 'shared', 'prf.so')))

    prf_path = next((p for p in candidates if os.path.isfile(p)), None)
    if not prf_path:
        raise FileNotFoundError(
            "prf.so not found. Tried: " + ", ".join(candidates) +
            ". Set PRF_SO_PATH or place prf.so under mb/shared/."
        )

    prf = CDLL(prf_path)

    # int FKH_inv_hex(const char* kmb_hex, const char* h_hex, const char* ri_hex, char* out_hex_len);
    prf.FKH_inv_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
    prf.FKH_inv_hex.restype = c_int

    # int H2(const uint8_t* y, int y_len, const uint8_t* key16, uint8_t* out16);
    prf.H2.argtypes = [
        POINTER(c_ubyte),
        c_int,
        POINTER(c_ubyte),
        POINTER(c_ubyte),
    ]
    prf.H2.restype = c_int

    return prf


def load_h_fixed(shared_dir: str = None) -> str:
    """
    Load the fixed EC point h from 'shared/h_fixed.txt'.
    Returns the hex string (or None if not found).
    """
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        shared_dir = shared_dir or os.path.join(base_dir, 'shared')
        h_path = os.path.join(shared_dir, 'h_fixed.txt')
        with open(h_path, "r") as f:
            return f.read().strip()
    except Exception:
        return None


def load_kmb_from_file(keys_dir: str = None) -> Tuple[c_char_p, create_string_buffer]:
    """
    Load kMB key material from 'keys/kmb.key'.
    Returns (kmb_c_char_p, keepalive_buffer) ready for C calls.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    keys_dir = keys_dir or os.path.join(base_dir, "keys")
    kmb_path = os.path.join(keys_dir, "kmb.key")

    with open(kmb_path, "rb") as f:
        kmb_bytes = f.read()
    kmb_hex_str = kmb_bytes.hex().upper()
    kmb_buf = create_string_buffer(kmb_hex_str.encode())  # keep a Python ref alive
    kmb = c_char_p(kmb_buf.value)
    return kmb, kmb_buf


# -------------------------
# Crypto helpers
# -------------------------

def h2_compute(prf: CDLL, counter_i: int, session_key_hex: str) -> str:
    """
    Compute H2((c+i), Sj) using the C function and AES-ECB under key derived from Sj.
    counter_i: integer c+i (32-bit int).
    session_key_hex: EC point Sj (hex string).
    Returns: 16-byte output as hex string.
    """
    # Build y = 16 bytes: 8 zero + 8 bytes big-endian counter
    y_bytes = struct.pack(">QQ", 0, counter_i)
    y_buf = create_string_buffer(y_bytes, 16)

    # Derive 16-byte AES key from SHA-256(Sj)[:16]
    sj_bytes = bytes.fromhex(session_key_hex)
    h_key_bytes = hashlib.sha256(sj_bytes).digest()[:16]
    h_key_buf = create_string_buffer(h_key_bytes, 16)

    # Output buffer
    out = create_string_buffer(16)
    ok = prf.H2(
        cast(y_buf, POINTER(c_ubyte)),
        16,
        cast(h_key_buf, POINTER(c_ubyte)),
        cast(out, POINTER(c_ubyte))
    )
    if not ok:
        raise RuntimeError("H2 encryption failed")

    return out.raw.hex()


# -------------------------
# Rule-set shaping helpers
# -------------------------

def rebuild_session_ruleset(ruleset_in: Dict[str, Any],
                            rev_map: Dict[int, Tuple],
                            seq_to_sj: Dict[int, str]) -> Dict[str, Any]:
    """
    Rebuild a ruleset by inserting session tokens (Sj) in the correct containers
    (either directly in the outer item or in a normalized child string).
    """
    out = copy.deepcopy(ruleset_in)
    rules = out.get("rules", [])

    # 1) Place each Sj into its correct container (direct or child)
    for seq, sj_hex in (seq_to_sj or {}).items():
        if seq not in rev_map:
            continue
        addr = rev_map[seq]
        # Accept 4 or 5 fields
        if isinstance(addr, (list, tuple)) and len(addr) == 5:
            r_idx, g_key, s_outer_idx, s_inner_idx, pos_idx = addr
        elif isinstance(addr, (list, tuple)) and len(addr) == 4:
            r_idx, g_key, s_outer_idx, pos_idx = addr
            s_inner_idx = -1
        else:
            continue

        group = rules[r_idx]["groups"][g_key]
        outer_list = group.setdefault("strings", [])
        if s_outer_idx >= len(outer_list):
            continue

        if s_inner_idx is None or s_inner_idx < 0:
            container = outer_list[s_outer_idx]
        else:
            # Always create the "strings" array to host normalized children
            container = outer_list[s_outer_idx]
            inner_list = container.setdefault("strings", [])
            while len(inner_list) <= s_inner_idx:
                inner_list.append({})
            container = inner_list[s_inner_idx]

        sess_list = container.setdefault("session_tokens", [])
        while len(sess_list) <= pos_idx:
            sess_list.append(None)
        # If you need alternatives later, convert to a list and append
        sess_list[pos_idx] = {"sj": sj_hex}

    # 2) Recursive cleanup: remove enc_tokens and empty wrappers
    def _strip_enc_tokens_deep(obj):
        if isinstance(obj, dict):
            obj.pop("enc_tokens", None)
            for k in list(obj.keys()):
                v = obj[k]
                _strip_enc_tokens_deep(v)
                if isinstance(v, list):
                    # filter out {}
                    v2 = [x for x in v if not (isinstance(x, dict) and len(x) == 0)]
                    if v2:
                        obj[k] = v2
                    else:
                        obj.pop(k, None)
        elif isinstance(obj, list):
            for i in range(len(obj)):
                _strip_enc_tokens_deep(obj[i])

    _strip_enc_tokens_deep(out)
    return out


def pretty_print_ruleset(ruleset: Dict[str, Any]) -> str:
    """
    Return a pretty-printed JSON string (sorted keys) for logging.
    """
    try:
        return json.dumps(ruleset, indent=2, sort_keys=True, ensure_ascii=False)
    except Exception as e:
        return f"<pretty_print_ruleset error: {e}>"


# =========================
# Runtime matching helpers
# =========================

def flatten_ruleset_from_rg(ruleset: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[int, Tuple[int, str, int, int, int]]]:
    """
    Flatten tokens considering:
      - enc_tokens directly on the outer string -> s_inner_idx = -1
      - enc_tokens inside wrappers under any LIST key (except 'id')
        => those wrappers are treated as child-strings -> s_inner_idx = 0,1,2,...

    Returns:
      flat_tokens = [{seq, obfuscated, signature}, ...]
      rev_map[seq] = (r_idx, g_key, s_outer_idx, s_inner_idx, pos_idx)
    """
    flat_tokens: List[Dict[str, Any]] = []
    rev_map: Dict[int, Tuple[int, str, int, int, int]] = {}
    seq = 0

    rules = (ruleset or {}).get("rules", [])

    for r_idx, rule in enumerate(rules):
        for g_key, g_val in (rule.get("groups") or {}).items():
            outer_list = g_val.get("strings", []) or []
            for s_outer_idx, outer in enumerate(outer_list):
                # --- Case A: enc_tokens directly on the outer item
                if isinstance(outer, dict) and isinstance(outer.get("enc_tokens"), list):
                    enc_list = outer["enc_tokens"]
                    for pos_idx, entry in enumerate(enc_list):
                        if isinstance(entry, dict):
                            ri, sig = entry.get("ri"), entry.get("sig")
                            if ri and sig:
                                flat_tokens.append({"seq": seq, "obfuscated": ri, "signature": sig})
                                rev_map[seq] = (r_idx, g_key, s_outer_idx, -1, pos_idx)
                                seq += 1
                        elif isinstance(entry, list):
                            # Alternatives share the same pos_idx
                            for alt in entry:
                                if isinstance(alt, dict):
                                    ri, sig = alt.get("ri"), alt.get("sig")
                                    if ri and sig:
                                        flat_tokens.append({"seq": seq, "obfuscated": ri, "signature": sig})
                                        rev_map[seq] = (r_idx, g_key, s_outer_idx, -1, pos_idx)
                                        seq += 1

                # --- Case B: wrappers under any list key (e.g., "value", "segments", ...)
                inner_wrappers = []
                if isinstance(outer, dict):
                    for k, v in outer.items():
                        if k == "id":
                            continue
                        if isinstance(v, list):
                            for w in v:
                                if isinstance(w, dict) and isinstance(w.get("enc_tokens"), list):
                                    inner_wrappers.append(w)

                for s_inner_idx, inner in enumerate(inner_wrappers):
                    enc_list = inner.get("enc_tokens") or []
                    for pos_idx, entry in enumerate(enc_list):
                        if isinstance(entry, dict):
                            ri, sig = entry.get("ri"), entry.get("sig")
                            if ri and sig:
                                flat_tokens.append({"seq": seq, "obfuscated": ri, "signature": sig})
                                rev_map[seq] = (r_idx, g_key, s_outer_idx, s_inner_idx, pos_idx)
                                seq += 1
                        elif isinstance(entry, list):
                            for alt in entry:
                                if isinstance(alt, dict):
                                    ri, sig = alt.get("ri"), alt.get("sig")
                                    if ri and sig:
                                        flat_tokens.append({"seq": seq, "obfuscated": ri, "signature": sig})
                                        rev_map[seq] = (r_idx, g_key, s_outer_idx, s_inner_idx, pos_idx)
                                        seq += 1

    return flat_tokens, rev_map


def reset_runtime_state(runtime):
    """Reset per-string run state (useful if you reuse the runtime across requests/batches)."""
    if not runtime:
        return
    for r in runtime.get("rules", []):
        # reset strings
        for g in r.get("groups", {}).values():
            for s in g.get("strings", []):
                s["run_len"] = 0
                s["last_hit_i"] = None
                s["cur_start_i"] = None
                s["bound_edge"] = None
                s["just_done_at"] = None
                s["done"] = False
        # reset edges
        for e in r.get("seq_edges", []):
            e["pending"] = None
            e["satisfied"] = False


def _update_string_run_state(s_state, token_pos: int, traffic_i: int):
    """
    Update the state of a *string* when its token at 'token_pos' matches at index 'traffic_i'.
    Requires consecutive matches (i, i+1, ...).
    Tracks:
      - cur_start_i: where this run started
      - just_done_at: the index where the whole string finished
    """
    if s_state["done"]:
        return

    expected = s_state.get("run_len", 0)

    # Start (pos 0)
    if token_pos == 0:
        s_state["run_len"] = 1
        s_state["last_hit_i"] = traffic_i
        s_state["cur_start_i"] = traffic_i
        s_state["bound_edge"] = None
        if len(s_state["sj_list"]) == 1:
            s_state["done"] = True
            s_state["just_done_at"] = traffic_i
        else:
            s_state["just_done_at"] = None
        return

    # Next expected in order
    if token_pos == expected:
        contiguous = (s_state["last_hit_i"] is None) or (traffic_i == s_state["last_hit_i"] + 1)
        if (not s_state["need_consecutive"]) or contiguous:
            s_state["run_len"] += 1
            s_state["last_hit_i"] = traffic_i

            if s_state["run_len"] == len(s_state["sj_list"]):
                s_state["done"] = True
                s_state["just_done_at"] = traffic_i
            else:
                s_state["just_done_at"] = None
        else:
            # Hole detected: restart from here
            s_state["run_len"] = 1
            s_state["last_hit_i"] = traffic_i
            s_state["cur_start_i"] = traffic_i
            s_state["bound_edge"] = None
            s_state["done"] = (len(s_state["sj_list"]) == 1)
            s_state["just_done_at"] = (traffic_i if s_state["done"] else None)
        return

    # Any other case (out-of-order)
    if token_pos == 0:
        s_state["run_len"] = 1
        s_state["last_hit_i"] = traffic_i
        s_state["cur_start_i"] = traffic_i
        s_state["bound_edge"] = None
        s_state["done"] = (len(s_state["sj_list"]) == 1)
        s_state["just_done_at"] = (traffic_i if s_state["done"] else None)
    else:
        s_state["run_len"] = 0
        s_state["last_hit_i"] = None
        s_state["cur_start_i"] = None
        s_state["bound_edge"] = None
        s_state["just_done_at"] = None
        s_state["done"] = False



def _extract_enc_positions_from_string_item(s_item):
    """
    Return POSITIONS with alternatives, without collapsing wrappers:
      positions = [
        [ {ri,sig}, {ri,sig}, ... ],   # pos 0 (N alternatives)
        [ {ri,sig}, ... ],             # pos 1
        ...
      ]

    Supports:
      a) {"enc_tokens":[ {...},{...}, ... ]}                       -> 1 position with N alternatives
         NEW: if "split_positions": true  or  "enc_tokens_mode":"positions"
              then EACH {ri,sig} becomes ITS OWN POSITION.

      b) {"id":"...", ANY_LIST : [ {"enc_tokens":[...]}, ... ]}    -> EACH wrapper is ONE POSITION
      c) [ {"enc_tokens":[...]}, {"enc_tokens":[...]} ]            -> EACH wrapper is ONE POSITION
      d) direct lists of {ri,sig}                                  -> 1 position with N alternatives
    """
    def _norm_list(lst):
        return [t for t in (lst or []) if isinstance(t, dict) and t.get("ri") and t.get("sig")]

    positions = []

    if isinstance(s_item, dict) and isinstance(s_item.get("enc_tokens"), list):
        toks = _norm_list(s_item["enc_tokens"])
        if not toks:
            return positions
        split_flag = bool(s_item.get("split_positions"))
        mode = str(s_item.get("enc_tokens_mode", "") or "").strip().lower()
        if split_flag or mode == "positions":
            for t in toks:
                positions.append([t])          # 1 alternative per position
        else:
            positions.append(toks)             # 1 position with N alternatives
        return positions

    if isinstance(s_item, dict):
        for k, v in s_item.items():
            if k == "id" or not isinstance(v, list):
                continue
            wrappers = [w for w in v if isinstance(w, dict) and isinstance(w.get("enc_tokens"), list)]
            if wrappers:
                for w in wrappers:
                    toks = _norm_list(w.get("enc_tokens"))
                    if toks:
                        positions.append(toks)
                continue
            direct = _norm_list(v)
            if direct:
                positions.append(direct)
        return positions

    if isinstance(s_item, list):
        wrappers = [w for w in s_item if isinstance(w, dict) and isinstance(w.get("enc_tokens"), list)]
        if wrappers:
            for w in wrappers:
                toks = _norm_list(w.get("enc_tokens"))
                if toks:
                    positions.append(toks)
            return positions
        direct = _norm_list(s_item)
        if direct:
            positions.append(direct)
        return positions

    return positions


# ---------------------------
# Condition evaluation
# ---------------------------
def _eval_condition_node(node: dict, g_truth: dict, r_entry: dict) -> tuple[bool, dict | None]:
    """
    Evaluate a condition subtree against the group truth map and sequence state.
    Supports:
      - {"not": <subtree>}
      - {"groups": [...], "operator": "and"|"or"|"not"|"none"}
      - {"and": [ ... ]} / {"or": [ ... ]}
      - {"sequence": {"group": "...", "from": "...", "to": "...", "op": "RANGE_A_B" | "ONE_WILDCARD"}}
    """
    if not isinstance(node, dict):
        return False, None

    # --- Unary NOT on any subtree ---
    if "not" in node:
        sub = node["not"]
        ok, _ = _eval_condition_node(sub, g_truth, r_entry)
        return (not ok), ({"not": sub} if not ok else None)

    # --- SEQUENCE ---
    if "sequence" in node and isinstance(node["sequence"], dict):
        s = node["sequence"]
        gid = str(s.get("group", ""))
        fid = str(s.get("from", "")); tid = str(s.get("to", ""))

        # Candidate edges by (group, from, to)
        candidates = [e for e in r_entry.get("seq_edges", [])
                      if e.get("group") == gid and e.get("from_id") == fid and e.get("to_id") == tid]

        if not candidates:
            return False, None

        # If an 'op' is recognizable, translate to TOKENS like in build_runtime_index:
        # build_runtime_index: lo_tokens = BASE + lo_bytes, hi_tokens = BASE + hi_bytes
        # here lo/hi are "abstract bytes", so we add BASE.
        op = s.get("op", "")
        lo_tok = hi_tok = None
        if isinstance(op, str):
            lo_parsed, hi_parsed = _parse_sequence_op(op)
            if lo_parsed or hi_parsed:
                BASE = BLOCK_BYTES - 1
                lo_tok = BASE + lo_parsed
                hi_tok = BASE + hi_parsed
                filtered = [e for e in candidates if e.get("lo") == lo_tok and e.get("hi") == hi_tok]
                if filtered:
                    candidates = filtered

        sat = any(bool(e.get("satisfied")) for e in candidates)
        return sat, (node if sat else None)

    # --- GROUPS (and/or/not/none over group truth values) ---
    if "groups" in node and isinstance(node["groups"], list):
        op = str(node.get("operator", "and")).lower()
        vals = [bool(g_truth.get(g, False)) for g in node["groups"]]

        if op in ("and", "all"):
            ok = all(vals)
        elif op in ("or", "any"):
            ok = any(vals)
        elif op in ("not", "none"):
            ok = not any(vals)
        else:
            ok = all(vals)

        return ok, (node if ok else None)

    # --- AND ---
    if "and" in node and isinstance(node["and"], list):
        matched = []
        for sub in node["and"]:
            ok, m = _eval_condition_node(sub, g_truth, r_entry)
            if not ok:
                return False, None
            matched.append(m or sub)
        return True, {"and": matched}

    # --- OR ---
    if "or" in node and isinstance(node["or"], list):
        for sub in node["or"]:
            ok, m = _eval_condition_node(sub, g_truth, r_entry)
            if ok:
                return True, (m or sub)
        return False, None

    return False, None


def _rule_sequences_ok(r_entry, needed_groups: set | None = None) -> bool:
    """
    Return True only if ALL relevant sequence edges are satisfied.
    If needed_groups is None -> check all edges in the rule.
    If a set is provided -> only check edges whose 'group' ∈ needed_groups.
    """
    for e in r_entry.get("seq_edges", []):
        if needed_groups and e.get("group") not in needed_groups:
            continue
        if not e.get("satisfied"):
            return False
    return True


def process_encrypted_tokens_with_conditions(
    prf,
    tokens: List[str],
    counter: int,
    runtime,
    sj_to_targets: Dict[str, list],
    h2_func
) -> tuple[bool, dict | None]:
    """
    Scan Ti against all Sj with 'sequence' gating:
      - A 'to' segment can only start (pos 0) if there is a pending edge with ready_i<=i<=deadline_i.
      - When 'from' finishes, create a pending window [ready_i, deadline_i].
      - When 'to' finishes (and was bound to that edge), mark satisfied=True.

    Notes:
      - Assumes build_runtime_index already converted lo/hi from BYTES -> TOKENS.
    """
    if not runtime or not sj_to_targets:
        return False, None

    for i, Ti in enumerate(tokens):
        ti_low = (Ti or "").lower()
        if not ti_low:
            continue

        # ---- Phase 0: expire pendings whose deadline has passed ----
        for r_entry in runtime.get("rules", []):
            for e_idx, e in enumerate(r_entry.get("seq_edges", [])):
                p = e.get("pending")
                if not p or e.get("satisfied"):
                    continue

                # If the 'to' already started and hasn't finished, do NOT expire the pending.
                to_in_progress = any(
                    s.get("bound_edge") == e_idx and not s.get("done")
                    for g in r_entry.get("groups", {}).values()
                    for s in g.get("strings", [])
                )

                if (i > p["deadline_i"]) and (not to_in_progress):
                    e["pending"] = None

        # ---- Phase A: collect hits per string at this i ----
        per_string_hits: Dict[tuple, set] = {}
        for sj_low, targets in sj_to_targets.items():
            h2_val = h2_func(prf, counter + i, sj_low)
            if h2_val.lower() != ti_low:
                continue
            for (r_idx, g_key, s_idx, pos) in targets:
                key = (r_idx, g_key, s_idx)
                per_string_hits.setdefault(key, set()).add(pos)

        # ---- Phase B: apply at most ONE update per string, with pos0 gating ----
        for (r_idx, g_key, s_idx), poses in per_string_hits.items():
            s_state = runtime["rules"][r_idx]["groups"][g_key]["strings"][s_idx]
            if s_state.get("done"):
                continue

            expected = s_state.get("run_len", 0)

            # 1) START case: expected==0 and pos 0 present -> must pass sequence gating
            if expected == 0 and 0 in poses:
                r_entry = runtime["rules"][r_idx]
                by_to    = r_entry.get("seq_by_to", {}).get(g_key, {})
                to_edges = by_to.get(s_idx, [])

                allow_start = True
                chosen_edge = None
                if to_edges:
                    allow_start = False
                    for edge_idx in to_edges:
                        e = r_entry["seq_edges"][edge_idx]
                        p = e.get("pending")
                        if p and (p["ready_i"] <= i <= p["deadline_i"]) and (not e.get("satisfied")):
                            allow_start = True
                            chosen_edge = edge_idx
                            break

                if not allow_start:
                    continue

                _update_string_run_state(s_state, token_pos=0, traffic_i=i)
                if chosen_edge is not None and s_state["run_len"] == 1:
                    s_state["bound_edge"] = chosen_edge
                continue

            # 2) NORMAL PROGRESS: has started (expected>0) and next expected is present
            if expected > 0 and expected in poses:
                _update_string_run_state(s_state, token_pos=expected, traffic_i=i)
                continue

            # 3) Other cases: ignore to avoid self-sabotage (repeats/out-of-order)

        # ---- Phase C: triggers for strings that FINISH exactly at this i ----
        # a) When 'from' finishes, activate pending(ready_i, deadline_i)
        # b) When 'to' finishes while bound to an edge, mark satisfied=True
        for r_entry in runtime.get("rules", []):
            for g_key2, g2 in r_entry.get("groups", {}).items():
                # a) from -> pending
                by_from = r_entry.get("seq_by_from", {}).get(g_key2, {})
                for s_idx2, s2 in enumerate(g2.get("strings", [])):
                    if s2.get("just_done_at") == i:
                        for edge_idx in by_from.get(s_idx2, []):
                            e = r_entry["seq_edges"][edge_idx]
                            # 'i' is the index of the LAST token of 'from' (finished at i)
                            ready = i + 1 + e["lo"]     # lo/hi are already in TOKENS
                            deadl = i + 1 + e["hi"]
                            e["pending"] = {
                                "ready_i": ready,
                                "deadline_i": deadl,
                                "from_end_i": i,   # for logging gap with 'to' if needed
                            }

                # b) to -> satisfied
                for s_idx2, s2 in enumerate(g2.get("strings", [])):
                    if s2.get("just_done_at") == i and s2.get("bound_edge") is not None:
                        edge_idx = s2["bound_edge"]
                        e = r_entry["seq_edges"][edge_idx]
                        e["satisfied"] = True
                        e["pending"] = None
                        s2["bound_edge"] = None

        # ---- Phase D: evaluate rules/conditions (groups + sequences) ----
        hit, det = _eval_groups_and_conditions_with_details(runtime)
        if hit:
            det = det or {}
            det["matched_at"] = i
            det["snapshot"] = snapshot_rule_status(runtime)
            return True, det

    # Nothing fired
    return False, {"snapshot": snapshot_rule_status(runtime)}


def _group_truth_map(rule_entry):
    """
    Return {group_key: bool}. For 'cadena' mode (chain), require >=1 string done for each seg_id
    that participates in the chain (according to seq_edges). For other modes, honor 'any/all/K'.
    """
    out = {}
    for g_key, g in (rule_entry.get("groups") or {}).items():
        strs = g.get("strings", [])
        mt = _coerce_match_type(g.get("match_type", "any"))

        # ---- Special 'cadena' mode ----
        if isinstance(mt, str) and mt == "cadena":
            # Segments participating in the chain (from/to in edges of this group)
            segs_in_chain = set()
            for e in rule_entry.get("seq_edges", []):
                if e.get("group") == g_key:
                    if e.get("from_id"): segs_in_chain.add(e["from_id"])
                    if e.get("to_id"):   segs_in_chain.add(e["to_id"])

            if not segs_in_chain:
                # If no edges, fall back to 'any'
                out[g_key] = any(s.get("done") for s in strs)
                continue

            # Do we have >=1 string done per segment?
            done_by_seg = {seg: False for seg in segs_in_chain}
            for idx, s in enumerate(strs):
                if not s.get("done"):
                    continue
                seg_id = s.get("seg_id")
                if seg_id in done_by_seg:
                    done_by_seg[seg_id] = True

            out[g_key] = all(done_by_seg.values())
            continue

        # ---- Normal modes ----
        if not strs:
            out[g_key] = False
            continue
        done_flags = [s.get("done") for s in strs]
        done_count = sum(1 for s in strs if s.get("done"))

        if isinstance(mt, int):
            out[g_key] = (done_count >= mt)
        elif isinstance(mt, str) and mt == "all":
            out[g_key] = all(done_flags) and len(strs) > 0
        else:
            out[g_key] = any(done_flags)

    return out


def _eval_groups_and_conditions(runtime) -> bool:
    if not runtime:
        return False
    for r in runtime.get("rules", []):
        # 1) sequence gate: ALL must be satisfied
        if not _rule_sequences_ok(r):
            continue

        # 2) groups
        g_truth = _group_truth_map(r)
        conds = r.get("conditions", [])
        if not conds:
            if g_truth and all(g_truth.values()):
                return True
            continue

        # 3) respect the explicit condition tree
        ok, _ = _eval_condition_node(conds[0] if len(conds) == 1 else {"and": conds}, g_truth, r)
        if ok:
            return True
    return False


def _eval_groups_and_conditions_with_details(runtime):
    if not runtime:
        return False, None
    for r_idx, r in enumerate(runtime.get("rules", [])):
        # 1) sequence gate
        if not _rule_sequences_ok(r):
            continue

        # 2) groups
        g_truth = _group_truth_map(r)
        conds = r.get("conditions", [])
        if not conds:
            if g_truth and all(g_truth.values()):
                return True, {"rule_idx": r_idx, "clause_idx": None, "g_truth": g_truth, "cond": None}
            continue

        root = conds[0] if len(conds) == 1 else {"and": conds}
        ok, matched = _eval_condition_node(root, g_truth, r)
        if ok:
            return True, {
                "rule_idx": r_idx,
                "clause_idx": None,
                "g_truth": g_truth,
                "cond": matched
            }
    return False, None


# --- Match-type normalization ----------------------------------------------
def _coerce_match_type(mt):
    """
    Accepts:
      - int                         -> return that int (threshold ≥N)
      - 'all' | 'any' | 'cadena'   -> return that string
      - numeric strings ('1', '2', ...)
      - variants '>=N' or 'N+'     -> interpret as integer N (threshold ≥N)
    Fallback: 'any'
    """
    if isinstance(mt, int):
        return mt

    if isinstance(mt, str):
        s = mt.strip().lower()

        # 'all' / 'any' / 'cadena'
        if s in ("all", "any", "cadena"):
            return s

        # '>=N'  (e.g., '>=1')
        if s.startswith(">="):
            num = s[2:].strip()
            if num.isdigit():
                return int(num)

        # 'N+'   (e.g., '1+')
        if s.endswith("+"):
            num = s[:-1].strip()
            if num.isdigit():
                return int(num)

        # Bare 'N'
        if s.isdigit():
            return int(s)

        # Fallback: keep 'any'
        return "any"

    return "any"


def _normalize_match_type(mt_raw, total_strings: int) -> tuple[str, int]:
    """
    Normalize group-level match_type into a single policy:
      ('atleast', K)

    Accepted inputs:
      - "all"  -> ('atleast', total_strings)
      - "any"  -> ('atleast', 1)
      - int N  -> ('atleast', N)   # numeric threshold: require >= N strings done
      - unknown/None -> default to ('atleast', 1)

    Note: we clamp K to be >= 1; we do NOT force it <= total_strings.
    If K > total_strings, the group will simply never evaluate to True.
    """
    # Numeric threshold directly
    if isinstance(mt_raw, int):
        return ("atleast", max(1, mt_raw))

    # String policy
    if isinstance(mt_raw, str):
        m = mt_raw.strip().lower()
        if m == "all":
            return ("atleast", max(1, total_strings))
        if m == "any":
            return ("atleast", 1)

    # Fallback (behave like 'any')
    return ("atleast", 1)


def snapshot_rule_status(runtime):
    """
    Produce a snapshot of rule/group status for debugging or inspection (no printing).
    """
    snap = []
    for r_idx, r in enumerate(runtime.get("rules", [])):
        gstat = {}
        for g_key, g in (r.get("groups") or {}).items():
            strs = g.get("strings", [])
            done_idx = [i for i, s in enumerate(strs) if s.get("done")]
            mt = _coerce_match_type(g.get("match_type", "any"))
            done_count = len(done_idx)

            if isinstance(mt, int):
                is_true = (done_count >= mt)
            elif isinstance(mt, str) and mt == "all":
                is_true = (done_count == len(strs) and len(strs) > 0)
            elif isinstance(mt, str) and mt == "cadena":
                # Segments that participate in the chain (from/to within the same group)
                segs_in_chain = set()
                for e in r.get("seq_edges", []):
                    if e.get("group") == g_key:
                        if e.get("from_id"): segs_in_chain.add(e["from_id"])
                        if e.get("to_id"):   segs_in_chain.add(e["to_id"])
                if not segs_in_chain:
                    is_true = (done_count > 0)  # friendly fallback
                else:
                    seg_index = g.get("seg_index", {})
                    def seg_done(seg_id):
                        for s_idx in seg_index.get(seg_id, []):
                            if s_idx < len(strs) and strs[s_idx].get("done"):
                                return True
                        return False
                    is_true = all(seg_done(seg) for seg in segs_in_chain)
            else:
                is_true = (done_count > 0)

            gstat[g_key] = {
                "match_type": mt,
                "total_strings": len(strs),
                "done_count": done_count,
                "done_indices": done_idx,
                "is_true": is_true
            }
        snap.append({"rule_idx": r_idx, "groups": gstat, "conditions": r.get("conditions", [])})
    return snap

#--------------------------------------

# --- Minimal helpers for sequences (if you already have them elsewhere, omit these) ---
_SEQ_OP_RX = re.compile(r"^RANGE_(\d+)_(\d+)$")
def _parse_sequence_op(op: str) -> Tuple[int, int]:
    if not isinstance(op, str):
        return (0, 0)
    s = op.strip().upper()
    if s == "ONE_WILDCARD":
        return (1, 1)
    m = _SEQ_OP_RX.fullmatch(s)
    if m:
        return (int(m.group(1)), int(m.group(2)))
    return (0, 0)

def _gather_sequence_edges(conditions: List[dict]) -> List[dict]:
    """
    Extract 'sequence' edges into a canonical form:
      [{"group","from_id","to_id","lo","hi"}, ...]
    """
    out = []
    def walk(n):
        if not isinstance(n, dict):
            return
        if "sequence" in n and isinstance(n["sequence"], dict):
            s = n["sequence"]
            lo, hi = _parse_sequence_op(s.get("op", ""))
            out.append({
                "group":   str(s.get("group", "")),
                "from_id": str(s.get("from", "")),
                "to_id":   str(s.get("to", "")),
                "lo": lo, "hi": hi
            })
        for k in ("and", "or"):
            if k in n:
                for sub in n[k]:
                    walk(sub)
    for c in (conditions or []):
        walk(c)
    return out
# -------------------------------------------------------------------------------

def build_runtime_index(final_ruleset: Dict[str, Any]):
    """
    Build a runtime index with group/string structures and sequence edges,
    and a map from Sj hex -> target string positions.
    """
    runtime = {"rules": []}
    sj_to_targets: Dict[str, List[Tuple[int, str, int, int]]] = {}

    rules = (final_ruleset or {}).get("rules", [])
    for r_idx, rule in enumerate(rules):
        r_entry = {
            "groups": {},
            "conditions": rule.get("conditions", []),
            "seq_edges": [],
            "seq_by_to": {},     # { g_key: { s_idx: [edge_idx,...] } }
            "seq_by_from": {}    # { g_key: { s_idx: [edge_idx,...] } }
        }

        for g_key, g_val in (rule.get("groups") or {}).items():
            mt_norm = _coerce_match_type(g_val.get("match_type", "any"))

            g_entry = {
                "match_type": mt_norm,
                "threshold": None,
                "strings": [],
                "seg_index": {}     # { seg_id: [s_idx, ...] }
            }

            for s_idx, s_item in enumerate(g_val.get("strings", [])):
                parent_seg_id = s_item.get("id")

                # Case with children: { "id": "g1_segX", "strings": [ {...}, {...} ] }
                child_strings = s_item.get("strings")
                if isinstance(child_strings, list) and child_strings:
                    for child in child_strings:
                        sess_list = child.get("session_tokens", [])
                        pos_count = len(sess_list)

                        # Index ALL alternatives (per position)
                        for pos, token in enumerate(sess_list):
                            if not token:
                                continue
                            alts = token if isinstance(token, list) else [token]
                            for alt in alts:
                                sj_hex = (alt.get("sj") or "").strip()
                                if not sj_hex:
                                    continue
                                sj_to_targets.setdefault(sj_hex.lower(), []).append(
                                    (r_idx, g_key, len(g_entry["strings"]), pos)
                                )

                        # Runtime placeholder per child string
                        sj_placeholder = [None] * pos_count
                        byte_len = max(8, pos_count + 7)
                        new_s_idx = len(g_entry["strings"])

                        g_entry["strings"].append({
                            "seg_id": parent_seg_id,
                            "sj_list": sj_placeholder,
                            "pos_count": pos_count,
                            "need_consecutive": True,
                            "byte_len": byte_len,
                            "run_len": 0,
                            "last_hit_i": None,
                            "cur_start_i": None,
                            "bound_edge": None,
                            "just_done_at": None,
                            "done": False
                        })

                        if parent_seg_id:
                            g_entry["seg_index"].setdefault(parent_seg_id, []).append(new_s_idx)
                    continue

                # Direct case: session_tokens on the item itself
                sess_list = s_item.get("session_tokens", [])
                pos_count = len(sess_list)
                for pos, token in enumerate(sess_list):
                    if not token:
                        continue
                    alts = token if isinstance(token, list) else [token]
                    for alt in alts:
                        sj_hex = (alt.get("sj") or "").strip()
                        if not sj_hex:
                            continue
                        sj_to_targets.setdefault(sj_hex.lower(), []).append(
                            (r_idx, g_key, len(g_entry["strings"]), pos)
                        )

                sj_placeholder = [None] * pos_count
                byte_len = max(8, pos_count + 7)
                new_s_idx = len(g_entry["strings"])

                g_entry["strings"].append({
                    "seg_id": parent_seg_id,
                    "sj_list": sj_placeholder,
                    "pos_count": pos_count,
                    "need_consecutive": True,
                    "byte_len": byte_len,
                    "run_len": 0,
                    "last_hit_i": None,
                    "cur_start_i": None,
                    "bound_edge": None,
                    "just_done_at": None,
                    "done": False
                })

                if parent_seg_id:
                    g_entry["seg_index"].setdefault(parent_seg_id, []).append(new_s_idx)

            # For non-chain, keep a standard threshold
            _mode, k = _normalize_match_type(mt_norm, len(g_entry["strings"]))
            g_entry["threshold"] = k
            r_entry["groups"][g_key] = g_entry

        # === Attach sequence edges for this rule ===
        edges = _gather_sequence_edges(r_entry["conditions"])
        for e in edges:
            # e["lo"], e["hi"] are in abstract BYTES -> convert to TOKENS with BASE=BLOCK_BYTES-1
            BASE = BLOCK_BYTES - 1
            lo_tokens = BASE + e["lo"]
            hi_tokens = BASE + e["hi"]

            edge_idx = len(r_entry["seq_edges"])
            r_entry["seq_edges"].append({
                "group":   e["group"],
                "from_id": e["from_id"],
                "to_id":   e["to_id"],
                "lo":      lo_tokens,   # in TOKENS
                "hi":      hi_tokens,   # in TOKENS
                "pending": None,
                "satisfied": False
            })

            gk = e["group"]
            # Map FROM
            from_list = r_entry["groups"].get(gk, {}).get("seg_index", {}).get(e["from_id"], [])
            if from_list:
                by_from = r_entry["seq_by_from"].setdefault(gk, {})
                for s_idx in from_list:
                    by_from.setdefault(s_idx, []).append(edge_idx)
            # Map TO
            to_list = r_entry["groups"].get(gk, {}).get("seg_index", {}).get(e["to_id"], [])
            if to_list:
                by_to = r_entry["seq_by_to"].setdefault(gk, {})
                for s_idx in to_list:
                    by_to.setdefault(s_idx, []).append(edge_idx)

        runtime["rules"].append(r_entry)

    return runtime, sj_to_targets
