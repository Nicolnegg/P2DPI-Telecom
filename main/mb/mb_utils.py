# middlebox/mb/utils.py
#
# Purpose:
#   - Hold small, reusable, side‑effect‑free helpers for mb_main.py
#   - Keep imports minimal and avoid Flask/server state here.
#

from ctypes import cast, CDLL, c_char_p, c_int, create_string_buffer, c_ubyte, POINTER
import hashlib
import json
import os
import struct
import copy
from typing import Dict, Tuple, List, Any

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
      4) <this_dir>/../shared/prf.so   <-- tu caso
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

    # (opcional) log para depurar qué ruta se usó
    print(f"[MB] Using PRF at: {prf_path}")

    prf = CDLL(prf_path)

    prf.FKH_inv_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
    prf.FKH_inv_hex.restype = c_int

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

def flatten_ruleset_from_rg(ruleset: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[int, Tuple[int, str, int, int]]]:
    """
    Flatten the incoming RG ruleset (encrypted tokens by groups) into a linear list
    of {"seq", "obfuscated", "signature"} and build a reverse mapping to reconstruct.

    Returns:
      flat_tokens: [ {"seq": int, "obfuscated": "<ri-hex>", "signature": "<b64>"} , ...]
      rev_map:     { seq: (rule_idx, group_key, string_idx, enc_idx) }
    """
    flat_tokens = []
    rev_map: Dict[int, Tuple[int, str, int, int]] = {}
    seq = 0

    rules = ruleset.get("rules", [])
    for r_idx, rule in enumerate(rules):
        groups = rule.get("groups", {})
        for g_key, g_val in groups.items():
            strings = g_val.get("strings", [])
            for s_idx, s_item in enumerate(strings):
                enc_list = s_item.get("enc_tokens")
                if not enc_list:
                    continue
                for e_idx, entry in enumerate(enc_list):
                    ri = entry.get("ri")
                    sig = entry.get("sig")
                    if not ri or not sig:
                        continue
                    flat_tokens.append({
                        "seq": seq,
                        "obfuscated": ri,
                        "signature": sig
                    })
                    rev_map[seq] = (r_idx, g_key, s_idx, e_idx)
                    seq += 1

    return flat_tokens, rev_map


def rebuild_session_ruleset(ruleset_in: Dict[str, Any],
                            rev_map: Dict[int, Tuple[int, str, int, int]],
                            seq_to_sj: Dict[int, str]) -> Dict[str, Any]:
    """
    Replace each "enc_tokens" with "session_tokens" in a deep-copied ruleset.

    Args:
      ruleset_in:  original RG ruleset (dict).
      rev_map:     seq -> (rule_idx, group_key, string_idx, enc_idx).
      seq_to_sj:   seq -> Sj_hex.

    Returns:
      ruleset_out: deep-copied ruleset with "session_tokens" lists, "enc_tokens" removed.
    """
    out = copy.deepcopy(ruleset_in)
    rules = out.get("rules", [])

    for seq, sj_hex in seq_to_sj.items():
        r_idx, g_key, s_idx, e_idx = rev_map[seq]
        group = rules[r_idx]["groups"][g_key]
        strings = group.get("strings", [])
        if s_idx >= len(strings):
            continue

        item = strings[s_idx]
        sess_list = item.setdefault("session_tokens", [])
        while len(sess_list) <= e_idx:
            sess_list.append(None)
        sess_list[e_idx] = {"sj": sj_hex}

    # Drop original enc_tokens from all items
    for rule in rules:
        for g_key, g_val in rule.get("groups", {}).items():
            for item in g_val.get("strings", []):
                if "enc_tokens" in item:
                    del item["enc_tokens"]

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

def build_runtime_index(final_ruleset: Dict[str, Any]):
    """
    Build runtime structures for fast matching:
      - 'runtime': per rule -> per group -> list of strings with their ordered Sj tokens and run state.
      - 'sj_to_targets': map Sj (lower) -> list of (rule_idx, group_key, string_idx, token_pos).
    This lets us update only the affected strings when an Sj matches a Ti at position i.
    """
    runtime = {"rules": []}
    sj_to_targets = {}  # sj_hex_lower -> [(r_idx, g_key, s_idx, pos), ...]

    rules = (final_ruleset or {}).get("rules", [])
    for r_idx, rule in enumerate(rules):
        r_entry = {"groups": {}, "conditions": rule.get("conditions", [])}
        for g_key, g_val in (rule.get("groups") or {}).items():
            raw_mt = g_val.get("match_type", "any")
            mt_norm = _coerce_match_type(raw_mt)  
            g_entry = {
                "match_type": mt_norm,   # keep as-is for snapshot/debug
                "threshold": None,      # we’ll set this after we know total_strings
                "strings": []
            }
            for s_idx, s_item in enumerate(g_val.get("strings", [])):
                sess_list = s_item.get("session_tokens", [])
                sj_list = []
                for pos, token in enumerate(sess_list):
                    if not token:
                        continue
                    sj_hex = (token.get("sj") or "").strip()
                    if not sj_hex:
                        continue
                    sj_list.append(sj_hex)
                    sj_to_targets.setdefault(sj_hex.lower(), []).append((r_idx, g_key, s_idx, pos))

                g_entry["strings"].append({
                    "sj_list": sj_list,       # ordered session tokens for the string
                    "need_consecutive": True, # require contiguous i positions for long strings
                    "run_len": 0,             # how many tokens matched consecutively from start
                    "last_hit_i": None,       # last traffic index i that matched
                    "done": False             # whole string satisfied
                })
            total_strings = len(g_entry["strings"])
            _mode, k = _normalize_match_type(mt_norm, total_strings) 
            # We only need K for evaluation because the only policy we support is "at least K"
            g_entry["threshold"] = k
            r_entry["groups"][g_key] = g_entry
        runtime["rules"].append(r_entry)

    return runtime, sj_to_targets


def reset_runtime_state(runtime):
    """Reset per-string run state (useful if you reuse the runtime across requests/batches)."""
    if not runtime:
        return
    for r in runtime.get("rules", []):
        for g in r.get("groups", {}).values():
            for s in g.get("strings", []):
                s["run_len"] = 0
                s["last_hit_i"] = None
                s["done"] = False


def _update_string_run_state(s_state, token_pos: int, traffic_i: int):
    """
    Update run-state for a string when we observed a match for its token at position 'token_pos'
    at traffic index 'traffic_i'. We require ordered and consecutive matches:
      sj_list[0] at i, sj_list[1] at i+1, ..., sj_list[m] at i+m.
    """
    if s_state["done"]:
        return

    expected = s_state["run_len"]  # next expected token_pos

    # Start of the sequence?
    if token_pos == 0:
        s_state["run_len"] = 1
        s_state["last_hit_i"] = traffic_i
        if len(s_state["sj_list"]) == 1:
            s_state["done"] = True  # single-token strings (incl. short strings)
        return

    # In-order next token?
    if token_pos == expected:
        contiguous = (s_state["last_hit_i"] is None) or (traffic_i == s_state["last_hit_i"] + 1)
        if (not s_state["need_consecutive"]) or contiguous:
            s_state["run_len"] += 1
            s_state["last_hit_i"] = traffic_i
            if s_state["run_len"] == len(s_state["sj_list"]):
                s_state["done"] = True
        else:
            # Gap: reset; allow start if this token is first in sequence
            s_state["run_len"] = 1 if token_pos == 0 else 0
            s_state["last_hit_i"] = traffic_i if token_pos == 0 else None
    else:
        # Out of order: only treat as fresh start if token_pos == 0
        if token_pos == 0:
            s_state["run_len"] = 1
            s_state["last_hit_i"] = traffic_i
            if len(s_state["sj_list"]) == 1:
                s_state["done"] = True
        else:
            s_state["run_len"] = 0
            s_state["last_hit_i"] = None

def _eval_condition_node(node: dict, g_truth: dict) -> tuple[bool, dict | None]:
    """
    Recursively evaluate a condition node against the current group truth map.

    Supported shapes:
      - {"groups":[...], "operator":"and"|"or"|"not"}  # base clause
      - {"or": [ <node>, <node>, ... ]}               # wrapper OR
      - {"and":[ <node>, <node>, ... ]}               # wrapper AND

    Returns: (ok, matched_node)
      - ok: boolean result for this node
      - matched_node: the base clause (or wrapper) that evaluated True (for debugging)
    """
    if not isinstance(node, dict):
        return False, None

    # Wrapper: OR of subnodes
    if "or" in node:
        for sub in node.get("or", []):
            ok, m = _eval_condition_node(sub, g_truth)
            if ok:
                return True, (m if m is not None else sub)
        return False, None

    # Wrapper: AND of subnodes
    if "and" in node:
        ok_all = True
        last_true = None
        for sub in node.get("and", []):
            ok, m = _eval_condition_node(sub, g_truth)
            if not ok:
                ok_all = False
            else:
                last_true = m if m is not None else sub
        return ok_all, (last_true if ok_all else None)

    # Base clause: groups + operator
    op = (node.get("operator") or "and").lower()
    groups = node.get("groups", [])
    vals = [g_truth.get(k, False) for k in groups]

    if op == "and":
        ok = all(vals)
    elif op == "or":
        ok = any(vals)
    elif op == "not":
        ok = not any(vals)
    else:
        ok = False

    return ok, node



def process_encrypted_tokens_with_conditions(prf,
                                             tokens: List[str],
                                             counter: int,
                                             runtime,
                                             sj_to_targets: Dict[str, list],
                                             h2_func) -> tuple[bool, dict | None]:
    """
    Scan encrypted traffic (Ti) against all Sj, but apply at most ONE update
    per string per traffic index i to avoid out-of-order self-resets when the
    same Sj appears at multiple positions (e.g., pos=1 and pos=17) inside the
    same long string.

    Selection policy for each string at index i:
      1) If the next expected position 'expected' (run_len) is present in hits -> use that.
      2) Else, if position 0 is present -> start/restart from 0.
      3) Else, ignore other hits for this string at this i (do NOT reset).

    After applying updates for all strings at this i, evaluate groups+conditions.
    Return (True, details) if a rule is satisfied; else (False, None).
    """
    if not runtime or not sj_to_targets:
        return False, None

    for i, Ti in enumerate(tokens):
        ti_low = (Ti or "").lower()
        if not ti_low:
            continue

        # --- Phase A: collect hits PER STRING for this traffic index i ---
        # Keyed by (rule_idx, group_key, string_idx) -> set of matched positions {pos, ...}
        per_string_hits: Dict[tuple, set] = {}

        # Try every Sj we know: compute H2(c+i, Sj) and compare with Ti
        # (This can be optimized later with caching/indexing if needed.)
        for sj_low, targets in sj_to_targets.items():
            h2_val = h2_func(prf, counter + i, sj_low)
            if h2_val.lower() != ti_low:
                continue
            for (r_idx, g_key, s_idx, pos) in targets:
                key = (r_idx, g_key, s_idx)
                if key not in per_string_hits:
                    per_string_hits[key] = set()
                per_string_hits[key].add(pos)

        # --- Phase B: for each string, apply at most ONE update with priority rules ---
        for (r_idx, g_key, s_idx), poses in per_string_hits.items():
            s_state = runtime["rules"][r_idx]["groups"][g_key]["strings"][s_idx]
            if s_state.get("done"):
                continue

            expected = s_state.get("run_len", 0)

            # 1) Prefer the exact next expected position
            if expected in poses:
                _update_string_run_state(s_state, token_pos=expected, traffic_i=i)
                continue

            # 2) Otherwise, if we can (re)start from pos 0, do that
            if 0 in poses:
                _update_string_run_state(s_state, token_pos=0, traffic_i=i)
                continue

            # 3) Ignore any other out-of-order positions at this i (do NOT reset here)
            #    This prevents self-sabotage when the same 8B window repeats later in the string.
            #    No call to _update_string_run_state in this branch.

        # --- Evaluate after processing all strings for this i ---
        hit, det = _eval_groups_and_conditions_with_details(runtime)
        if hit:
            det = det or {}
            det["matched_at"] = i
            det["snapshot"] = snapshot_rule_status(runtime)
            return True, det

    # No rule satisfied across all tokens. Return a snapshot for debugging.
    return False, {"snapshot": snapshot_rule_status(runtime)}


def _group_truth_map(rule_entry):
    """Builds {group_key: bool} from current per-string 'done' and group match_type."""
    out = {}
    for g_key, g in (rule_entry.get("groups") or {}).items():
        strs = g.get("strings", [])
        if not strs:
            out[g_key] = False
            continue
        mt = _coerce_match_type(g.get("match_type", "any"))
        done_flags = [s.get("done") for s in strs]
        done_count = sum(1 for s in strs if s.get("done"))

        if isinstance(mt, int):
            out[g_key] = (done_count >= mt)
        elif isinstance(mt, str) and mt == "all":
            out[g_key] = all(done_flags)
        else:
            out[g_key] = any(done_flags)
    return out

def _eval_groups_and_conditions(runtime) -> bool:
    """
    Returns True if any rule has its conditions satisfied.
    """
    if not runtime:
        return False

    for r in runtime.get("rules", []):
        # Build per-group truth map
        g_truth = {}
        for g_key, g in r.get("groups", {}).items():
            strs = g.get("strings", [])
            if not strs:
                g_truth[g_key] = False
                continue
            done_count = sum(1 for s in strs if s.get("done"))
            k = g.get("threshold", 1)
            g_truth[g_key] = (done_count >= k)

        conds = r.get("conditions", [])
        if not conds:
            # Default: ALL groups must be True
            if g_truth and all(g_truth.values()):
                return True
            continue

        # Evaluate each top-level condition node (OR-of-clauses structure allowed)
        for cond in conds:
            ok, _ = _eval_condition_node(cond, g_truth)
            if ok:
                return True

    return False

def _eval_groups_and_conditions_with_details(runtime):
    """
    Like _eval_groups_and_conditions, but returns (hit, details) with
    the clause that matched.
    """
    if not runtime:
        return False, None

    for r_idx, r in enumerate(runtime.get("rules", [])):
        g_truth = _group_truth_map(r)
        conds = r.get("conditions", [])

        if not conds:
            if g_truth and all(g_truth.values()):
                return True, {"rule_idx": r_idx, "clause_idx": None, "g_truth": g_truth, "cond": None}
            continue

        for c_idx, cond in enumerate(conds):
            ok, matched = _eval_condition_node(cond, g_truth)
            if ok:
                return True, {
                    "rule_idx": r_idx,
                    "clause_idx": c_idx,
                    "g_truth": g_truth,
                    "cond": matched
                }

    return False, None



# --- Match-type normalization ----------------------------------------------
def _coerce_match_type(mt):
    """
    Accept ints, 'all', 'any', or numeric strings like '14'.
    Return an int for digits, or a lowercase string for others.
    Fallback to 'any' if mt is None/unknown.
    """
    if isinstance(mt, int):
        return mt
    if isinstance(mt, str):
        s = mt.strip().lower()
        if s.isdigit():
            return int(s)
        if s == "cadena":
            return "all"
        return s
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
    Snapshot por regla y por grupo:
      match_type, total_strings, done_count, done_indices, is_true (estado del grupo).
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

