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
import re

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
    Aplana tokens soportando:
      - enc_tokens con N alternativas (1 posición)
      - varias posiciones como lista de wrappers con enc_tokens
      - modo split_positions (cada {ri,sig} = 1 posición)
    Para CADA POSICIÓN e_idx se añaden N filas (una por alternativa) con el MISMO e_idx.
    """
    flat_tokens = []
    rev_map: Dict[int, Tuple[int, str, int, int]] = {}
    seq = 0

    for r_idx, rule in enumerate((ruleset or {}).get("rules", [])):
        for g_key, g_val in (rule.get("groups") or {}).items():
            for s_idx, s_item in enumerate((g_val.get("strings") or [])):
                positions = _extract_enc_positions_from_string_item(s_item)
                if not positions:
                    # compat: forma antigua {"enc_tokens":[...]} directamente
                    enc_list = s_item.get("enc_tokens") if isinstance(s_item, dict) else None
                    if isinstance(enc_list, list):
                        positions = [[t for t in enc_list if isinstance(t, dict)]]

                for e_idx, alts in enumerate(positions):
                    for alt in alts:
                        ri = alt.get("ri"); sig = alt.get("sig")
                        if not ri or not sig:
                            continue
                        flat_tokens.append({"seq": seq, "obfuscated": ri, "signature": sig})
                        # ¡OJO! TODAS las alternativas comparten el MISMO e_idx (posición)
                        rev_map[seq] = (r_idx, g_key, s_idx, e_idx)
                        seq += 1

    return flat_tokens, rev_map



def _strip_enc_tokens_deep(obj):
    if isinstance(obj, dict):
        obj.pop("enc_tokens", None)
        for k in list(obj.keys()):
            v = obj[k]
            _strip_enc_tokens_deep(v)
            if isinstance(v, list):
                obj[k] = [x for x in v if not (isinstance(x, dict) and len(x) == 0)]
                if not obj[k]:
                    obj.pop(k, None)
    elif isinstance(obj, list):
        for x in obj:
            _strip_enc_tokens_deep(x)

def rebuild_session_ruleset(ruleset_in: Dict[str, Any],
                            rev_map: Dict[int, Tuple[int, str, int, int]],
                            seq_to_sj: Dict[int, str]) -> Dict[str, Any]:
    out = copy.deepcopy(ruleset_in)
    rules = out.get("rules", [])

    # 1) agrupa por (r,g,s,posición) → lista de SJs (alternativas)
    bucket: Dict[Tuple[int, str, int, int], List[str]] = {}
    for seq, sj_hex in seq_to_sj.items():
        r_idx, g_key, s_idx, e_idx = rev_map[seq]
        bucket.setdefault((r_idx, g_key, s_idx, e_idx), []).append(sj_hex)

    # 2) vuelca en session_tokens respetando POSICIONES y ALTERNATIVAS
    for (r_idx, g_key, s_idx, e_idx), sjs in bucket.items():
        group = rules[r_idx]["groups"][g_key]
        item  = group["strings"][s_idx]
        sess_list = item.setdefault("session_tokens", [])
        while len(sess_list) <= e_idx:
            sess_list.append(None)

        if len(sjs) == 1:
            sess_list[e_idx] = {"sj": sjs[0]}
        else:
            sess_list[e_idx] = [{"sj": s} for s in sjs]

    # 3) limpia cualquier rastro de enc_tokens
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
    Actualiza el estado de un *string* cuando su token en 'token_pos' hace match en el índice i.
    Requiere matches consecutivos (i, i+1, ...). Anota:
      - cur_start_i: dónde comenzó esta corrida
      - just_done_at: i en el cual terminó el string completo
    """
    if s_state["done"]:
        return

    expected = s_state.get("run_len", 0)

    # Arranque (pos 0)
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

    # Siguiente esperado en orden
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
            # hubo hueco: reinicia desde aquí
            s_state["run_len"] = 1
            s_state["last_hit_i"] = traffic_i
            s_state["cur_start_i"] = traffic_i
            s_state["bound_edge"] = None      
            s_state["done"] = (len(s_state["sj_list"]) == 1)
            s_state["just_done_at"] = (traffic_i if s_state["done"] else None)
        return

    # Cualquier otro caso (out-of-order)
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
    Devuelve POSICIONES con alternativas, SIN colapsar wrappers:
      positions = [
        [ {ri,sig}, {ri,sig}, ... ],   # pos 0 (N alternativas)
        [ {ri,sig}, ... ],             # pos 1
        ...
      ]

    Soporta:
      a) {"enc_tokens":[ {...},{...}, ... ]}                       -> 1 posición con N alternativas
         NUEVO: si "split_positions": true  o  "enc_tokens_mode":"positions"
                entonces CADA {ri,sig} es SU PROPIA POSICIÓN.

      b) {"id":"...", ANY_LIST : [ {"enc_tokens":[...]}, ... ]}    -> CADA wrapper es UNA POSICIÓN
      c) [ {"enc_tokens":[...]}, {"enc_tokens":[...]} ]            -> CADA wrapper es UNA POSICIÓN
      d) listas de {ri,sig} directas                               -> 1 posición con N alternativas
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
                positions.append([t])          # 1 alternativa por posición
        else:
            positions.append(toks)             # 1 posición con N alternativas
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



def _eval_condition_node(node: dict, g_truth: dict, r_entry: dict) -> tuple[bool, dict | None]:
    if not isinstance(node, dict):
        return False, None

    if "or" in node:
        for sub in node.get("or", []):
            ok, m = _eval_condition_node(sub, g_truth, r_entry)
            if ok:
                return True, (m if m is not None else sub)
        return False, None

    if "and" in node:
        ok_all, last_true = True, None
        for sub in node.get("and", []):
            ok, m = _eval_condition_node(sub, g_truth, r_entry)
            if not ok:
                ok_all = False
            else:
                last_true = m if m is not None else sub
        return ok_all, (last_true if ok_all else None)

    # NUEVO: sequence (usa satisfied del edge)
    if "sequence" in node and isinstance(node["sequence"], dict):
        s = node["sequence"]
        gid = str(s.get("group",""))
        fid = str(s.get("from",""))
        tid = str(s.get("to",""))
        lo, hi = _parse_sequence_op(s.get("op",""))
        for e in r_entry.get("seq_edges", []):
            if e["group"] == gid and e["from_id"] == fid and e["to_id"] == tid and e["lo"] == lo and e["hi"] == hi:
                return (bool(e.get("satisfied")), node if e.get("satisfied") else None)
        return (False, None)

    # Base: groups
    op = (node.get("operator") or "and").lower()
    groups = node.get("groups", [])
    vals = [g_truth.get(k, False) for k in groups]
    ok = (all(vals) if op == "and" else any(vals) if op == "or" else (not any(vals) if op == "not" else False))
    return ok, node




def process_encrypted_tokens_with_conditions(prf,
                                             tokens: List[str],
                                             counter: int,
                                             runtime,
                                             sj_to_targets: Dict[str, list],
                                             h2_func) -> tuple[bool, dict | None]:
    """
    Escanea Ti vs todos los Sj, con gating de 'sequence':
      - Un 'to' sólo puede arrancar (pos 0) si existe un edge pendiente con ready_i<=i<=deadline_i.
      - Cuando 'from' termina, se crea el pending con ventana [ready_i, deadline_i].
      - Cuando 'to' termina (y estaba ligado a ese edge), se marca satisfied=True.
    """
    if not runtime or not sj_to_targets:
        return False, None

    for i, Ti in enumerate(tokens):
        ti_low = (Ti or "").lower()
        if not ti_low:
            continue

        # ---- Fase 0: expirar pendings cuyo deadline ya pasó ----
        for r_entry in runtime.get("rules", []):
            for e_idx, e in enumerate(r_entry.get("seq_edges", [])):
                p = e.get("pending")
                if p and (i > p["deadline_i"]) and (not e.get("satisfied")):
                    e["pending"] = None
                    # liberar vínculos obsoletos de 'to' ligados a este edge
                    for g in r_entry.get("groups", {}).values():
                        for s in g.get("strings", []):
                            if s.get("bound_edge") == e_idx and not s.get("done"):
                                s["bound_edge"] = None

        # ---- Fase A: recolectar hits por string en este i ----
        per_string_hits: Dict[tuple, set] = {}
        for sj_low, targets in sj_to_targets.items():
            h2_val = h2_func(prf, counter + i, sj_low)
            if h2_val.lower() != ti_low:
                continue
            for (r_idx, g_key, s_idx, pos) in targets:
                key = (r_idx, g_key, s_idx)
                per_string_hits.setdefault(key, set()).add(pos)

        # ---- Fase B: aplicar como mucho UN update por string, con gating pos0 ----
        for (r_idx, g_key, s_idx), poses in per_string_hits.items():
            s_state = runtime["rules"][r_idx]["groups"][g_key]["strings"][s_idx]
            if s_state.get("done"):
                continue

            expected = s_state.get("run_len", 0)

            # 1) preferimos el siguiente esperado
            if expected in poses:
                _update_string_run_state(s_state, token_pos=expected, traffic_i=i)
                continue

            # 2) si hay pos0, sólo permitimos arrancar si pasa el gating por sequence
            if 0 in poses:
                r_entry = runtime["rules"][r_idx]
                by_to = r_entry.get("seq_by_to", {}).get(g_key, {})
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
                    continue  # ignoramos el intento de arranque fuera de ventana

                _update_string_run_state(s_state, token_pos=0, traffic_i=i)
                if chosen_edge is not None and s_state["run_len"] == 1:
                    s_state["bound_edge"] = chosen_edge
                continue

            # 3) ignorar otros _poses_ (evita autosabotaje por repeticiones)
            # (no llamamos a _update_string_run_state)

        # ---- Fase C: disparadores por strings que ACABAN justo en este i ----
        # a) Cuando 'from' termina, activar pending(ready_i, deadline_i)
        # b) Cuando 'to' termina y estaba ligado a un edge, marcar satisfied=True
        for r_entry in runtime.get("rules", []):
            for g_key2, g2 in r_entry.get("groups", {}).items():
                # a) from -> pending
                by_from = r_entry.get("seq_by_from", {}).get(g_key2, {})
                for s_idx2, s2 in enumerate(g2.get("strings", [])):
                    if s2.get("just_done_at") == i:
                        for edge_idx in by_from.get(s_idx2, []):
                            e = r_entry["seq_edges"][edge_idx]
                            # 'i' es el índice del ÚLTIMO token de 'from' (terminó justo en i)
                            ready = i + 1 + e["lo"]
                            deadl = i + 1 + e["hi"]
                            e["pending"] = {"ready_i": ready, "deadline_i": deadl}

                # b) to -> satisfied
                for s_idx2, s2 in enumerate(g2.get("strings", [])):
                    if s2.get("just_done_at") == i and s2.get("bound_edge") is not None:
                        edge_idx = s2["bound_edge"]
                        e = r_entry["seq_edges"][edge_idx]
                        e["satisfied"] = True
                        e["pending"] = None
                        s2["bound_edge"] = None

        # ---- Fase D: evaluar reglas/condiciones (groups + sequences) ----
        hit, det = _eval_groups_and_conditions_with_details(runtime)
        if hit:
            det = det or {}
            det["matched_at"] = i
            det["snapshot"] = snapshot_rule_status(runtime)
            return True, det

    # Nada disparó
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
    if not runtime:
        return False
    for r in runtime.get("rules", []):
        # map por grupos
        g_truth = {}
        for g_key, g in r.get("groups", {}).items():
            strs = g.get("strings", [])
            k = g.get("threshold", 1)
            done_count = sum(1 for s in strs if s.get("done"))
            g_truth[g_key] = (done_count >= k)

        conds = r.get("conditions", [])
        if not conds:
            if g_truth and all(g_truth.values()):
                return True
            continue

        for cond in conds:
            ok, _ = _eval_condition_node(cond, g_truth, r)  # <-- pasa r
            if ok:
                return True
    return False

def _eval_groups_and_conditions_with_details(runtime):
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
            ok, matched = _eval_condition_node(cond, g_truth, r)  # <-- pasa r
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
#--------------------------------------

# --- helpers mínimas para sequences (si ya las tienes definidas, omite estas) ---
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
    Extrae edges de tipo sequence a forma canónica:
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
    runtime = {"rules": []}
    sj_to_targets: Dict[str, List[Tuple[int, str, int, int]]] = {}

    rules = (final_ruleset or {}).get("rules", [])
    for r_idx, rule in enumerate(rules):
        r_entry = {
            "groups": {},
            "conditions": rule.get("conditions", []),
            "seq_edges": [],
            "seq_by_to": {},
            "seq_by_from": {}
        }

        for g_key, g_val in (rule.get("groups") or {}).items():
            mt_norm = _coerce_match_type(g_val.get("match_type", "any"))
            g_entry = {
                "match_type": mt_norm,
                "threshold": None,
                "strings": [],
                "seg_index": {}
            }

            for s_idx, s_item in enumerate(g_val.get("strings", [])):
                seg_id = s_item.get("id")
                sess_list = s_item.get("session_tokens", [])

                # Longitud lógica: número de posiciones (no alternativas)
                pos_count = len(sess_list)

                # Indexa TODAS las alternativas por posición
                for pos, token in enumerate(sess_list):
                    if not token:
                        continue
                    alts = token if isinstance(token, list) else [token]
                    for alt in alts:
                        sj_hex = (alt.get("sj") or "").strip() if isinstance(alt, dict) else ""
                        if not sj_hex:
                            continue
                        sj_to_targets.setdefault(sj_hex.lower(), []).append((r_idx, g_key, s_idx, pos))

                # placeholder para compat (se usa pos_count realmente)
                sj_placeholder = [None] * pos_count
                byte_len = max(8, pos_count + 7)

                g_entry["strings"].append({
                    "seg_id": seg_id,
                    "sj_list": sj_placeholder,   # sólo marcador
                    "pos_count": pos_count,      # ← usar esta
                    "need_consecutive": True,
                    "byte_len": byte_len,
                    "run_len": 0,
                    "last_hit_i": None,
                    "cur_start_i": None,
                    "bound_edge": None,
                    "just_done_at": None,
                    "done": False
                })
                if seg_id:
                    g_entry["seg_index"][seg_id] = s_idx

            _mode, k = _normalize_match_type(mt_norm, len(g_entry["strings"]))
            g_entry["threshold"] = k
            r_entry["groups"][g_key] = g_entry

        # (si ya tienes resolución de sequences, vuelve a engancharla aquí)
        runtime["rules"].append(r_entry)

    return runtime, sj_to_targets



