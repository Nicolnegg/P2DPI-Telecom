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


# Tamaño del bloque con el que viaja el tráfico (en bytes)
BLOCK_BYTES = int(os.environ.get("MB_BLOCK_BYTES", "8"))

# --- DEBUG helpers ---
DEBUG = bool(int(os.environ.get("MB_DEBUG", "1")))  # pon 0 para silenciar

def debug(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)
# ----------------------

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

def rebuild_session_ruleset(ruleset_in: Dict[str, Any],
                            rev_map: Dict[int, Tuple],
                            seq_to_sj: Dict[int, str]) -> Dict[str, Any]:
    out = copy.deepcopy(ruleset_in)
    rules = out.get("rules", [])

    # 1) Volcar cada Sj en su contenedor correcto (directo o "hijo")
    for seq, sj_hex in (seq_to_sj or {}).items():
        if seq not in rev_map:
            continue
        addr = rev_map[seq]
        # Acepta 4 o 5 campos
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
            # creamOS SIEMPRE el array "strings" para albergar hijos normalizados
            container = outer_list[s_outer_idx]
            inner_list = container.setdefault("strings", [])
            while len(inner_list) <= s_inner_idx:
                inner_list.append({})
            container = inner_list[s_inner_idx]

        sess_list = container.setdefault("session_tokens", [])
        while len(sess_list) <= pos_idx:
            sess_list.append(None)
        # si necesitas alternativas, cambia a lista y haz append
        sess_list[pos_idx] = {"sj": sj_hex}

    # 2) Limpieza recursiva: borra enc_tokens y wrappers vacíos
    def _strip_enc_tokens_deep(obj):
        if isinstance(obj, dict):
            obj.pop("enc_tokens", None)
            for k in list(obj.keys()):
                v = obj[k]
                _strip_enc_tokens_deep(v)
                if isinstance(v, list):
                    # filtra {} de las listas
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
    Aplana tokens contemplando:
      - enc_tokens DIRECTO en el string externo  -> s_inner_idx = -1
      - enc_tokens dentro de wrappers bajo cualquier clave LISTA (excepto 'id')
        => esos wrappers se ven como strings "hijos" -> s_inner_idx = 0,1,2,...

    Devuelve:
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
                # --- Caso A: enc_tokens directo en el item externo
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
                            # alternativas: comparten pos_idx
                            for alt in entry:
                                if isinstance(alt, dict):
                                    ri, sig = alt.get("ri"), alt.get("sig")
                                    if ri and sig:
                                        flat_tokens.append({"seq": seq, "obfuscated": ri, "signature": sig})
                                        rev_map[seq] = (r_idx, g_key, s_outer_idx, -1, pos_idx)
                                        seq += 1

                # --- Caso B: wrappers en cualquier lista (p.ej. "value", "segments"...)
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
    ...
    if "sequence" in node and isinstance(node["sequence"], dict):
        s = node["sequence"]
        gid = str(s.get("group",""))
        fid = str(s.get("from","")); tid = str(s.get("to",""))
        lo, hi = _parse_sequence_op(s.get("op",""))

        # JSON viene en BYTES → conviértelo a TOKENS para alinear con build_runtime_index
        BASE = BLOCK_BYTES - 1
        lo = BASE + lo
        hi = BASE + hi

        for e in r_entry.get("seq_edges", []):
            if (e["group"] == gid and e["from_id"] == fid and e["to_id"] == tid
                and e["lo"] == lo and e["hi"] == hi):
                sat = bool(e.get("satisfied"))
                #DEBUG
                debug(f"[COND] sequence {fid}->{tid} [{lo},{hi}] satisfied={sat}")
                return sat, (node if sat else None)
        debug(f"[COND] sequence {fid}->{tid} [{lo},{hi}] edge not found in runtime")

        return False, None

def _rule_sequences_ok(r_entry, needed_groups: set | None = None) -> bool:
    """
    Devuelve True sólo si TODAS las edges de sequence relevantes están satisfechas.
    Si needed_groups es None -> chequea todas las edges de la regla.
    Si se pasa un set -> sólo chequea edges cuyo 'group' ∈ needed_groups.
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
    Escanea Ti vs todos los Sj, con gating de 'sequence':
      - Un 'to' sólo puede arrancar (pos 0) si existe un edge pendiente con ready_i<=i<=deadline_i.
      - Cuando 'from' termina, se crea el pending con ventana [ready_i, deadline_i].
      - Cuando 'to' termina (y estaba ligado a ese edge), se marca satisfied=True.

    Notas:
      - Se asume que build_runtime_index ya convirtió lo/hi de BYTES -> TOKENS.
      - Esta función usa 'debug' si existe en globals; si no, cae a 'print'.
    """
    if not runtime or not sj_to_targets:
        return False, None

    # Usa 'debug' si está definido en tu proyecto; si no, usa print
    dbg = globals().get("debug", print)

    for i, Ti in enumerate(tokens):
        if i == 0:
            dbg(f"[SCAN] tokens={len(tokens)} counter={counter} BLOCK_BYTES={BLOCK_BYTES}")

        ti_low = (Ti or "").lower()
        if not ti_low:
            continue

        # ---- Fase 0: expirar pendings cuyo deadline ya pasó ----
        for r_entry in runtime.get("rules", []):
            for e_idx, e in enumerate(r_entry.get("seq_edges", [])):
                p = e.get("pending")
                if not p or e.get("satisfied"):
                    continue

                # Si el 'to' ya arrancó y sigue sin terminar, NO expirar el pending.
                to_in_progress = any(
                    s.get("bound_edge") == e_idx and not s.get("done")
                    for g in r_entry.get("groups", {}).values()
                    for s in g.get("strings", [])
                )

                if (i > p["deadline_i"]) and (not to_in_progress):
                    dbg(
                        f"[SEQ] expire pending edge at i={i}: "
                        f"window=[{p['ready_i']},{p['deadline_i']}] "
                        f"({e['from_id']}->{e['to_id']} lo={e['lo']} hi={e['hi']})"
                    )
                    e["pending"] = None
                    # (ya no se limpia bound_edge aquí; sólo expiramos si NO había 'to' en progreso)

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

            # 1) CASO INICIO: expected==0 y hay pos 0 -> SIEMPRE pasa por el gating de sequence
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
                    dbg(f"[SEQ] deny start {g_key}[s{s_idx}] at i={i}: no pending window")
                    continue

                if chosen_edge is None:
                    # No hay edge 'to' mapeado: no hay gating real, se permite arrancar
                    dbg(f"[SEQ] allow start {g_key}[s{s_idx}] at i={i}: no-edge gating")
                else:
                    p = r_entry["seq_edges"][chosen_edge].get("pending") or {}
                    dbg(
                        f"[SEQ] allow start {g_key}[s{s_idx}] at i={i}: "
                        f"edge={chosen_edge} window=[{p.get('ready_i')},{p.get('deadline_i')}]"
                    )

                _update_string_run_state(s_state, token_pos=0, traffic_i=i)
                if chosen_edge is not None and s_state["run_len"] == 1:
                    s_state["bound_edge"] = chosen_edge
                continue

            # 2) CASO PROGRESO NORMAL: ya empezó (expected>0) y hay el siguiente esperado
            if expected > 0 and expected in poses:
                _update_string_run_state(s_state, token_pos=expected, traffic_i=i)
                continue

            # 3) Otros casos: ignorar para no autosabotear (repeticiones/out-of-order)

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
                            ready = i + 1 + e["lo"]     # lo/hi ya están en TOKENS
                            deadl = i + 1 + e["hi"]
                            e["pending"] = {
                                "ready_i": ready,
                                "deadline_i": deadl,
                                "from_end_i": i,   # <- para poder loguear gap con 'to'
                            }
                            dbg(
                                f"[SEQ] FROM done g={g_key2} s={s_idx2} at i={i} -> "
                                f"pending [{ready},{deadl}] (lo={e['lo']} hi={e['hi']})"
                            )

                # b) to -> satisfied
                for s_idx2, s2 in enumerate(g2.get("strings", [])):
                    if s2.get("just_done_at") == i and s2.get("bound_edge") is not None:
                        edge_idx = s2["bound_edge"]
                        e = r_entry["seq_edges"][edge_idx]
                        p = e.get("pending") or {}
                        from_end = p.get("from_end_i")
                        to_start = s2.get("cur_start_i")
                        gap_tokens = (
                            to_start - (from_end + 1)
                            if (from_end is not None and to_start is not None)
                            else None
                        )
                        dbg(
                            f"[SEQ] TO done g={g_key2} s={s_idx2} at i={i} -> edge {edge_idx} "
                            f"gap_tokens={gap_tokens} expected=[{e['lo']},{e['hi']}] "
                            f"({e['from_id']}->{e['to_id']})"
                        )

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
    """
    Devuelve {group_key: bool}. Para 'cadena', exige >=1 string done por cada seg_id
    que participa en la cadena (según seq_edges). Para otros modos, respeta 'any/all/K'.
    """
    out = {}
    for g_key, g in (rule_entry.get("groups") or {}).items():
        strs = g.get("strings", [])
        mt = _coerce_match_type(g.get("match_type", "any"))

        # ---- Modo especial 'cadena' ----
        if isinstance(mt, str) and mt == "cadena":
            # Segmentos que participan en la cadena (from/to en edges de este grupo)
            segs_in_chain = set()
            for e in rule_entry.get("seq_edges", []):
                if e.get("group") == g_key:
                    if e.get("from_id"): segs_in_chain.add(e["from_id"])
                    if e.get("to_id"):   segs_in_chain.add(e["to_id"])

            if not segs_in_chain:
                # Si no hay edges, caer a 'any' (o False). Elegimos 'any' para no bloquear.
                out[g_key] = any(s.get("done") for s in strs)
                continue

            # ¿Hay >=1 string done por cada segmento?
            done_by_seg = {seg: False for seg in segs_in_chain}
            for idx, s in enumerate(strs):
                if not s.get("done"):
                    continue
                seg_id = s.get("seg_id")
                if seg_id in done_by_seg:
                    done_by_seg[seg_id] = True

            out[g_key] = all(done_by_seg.values())
            continue

        # ---- Modos normales ----
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
        # 1) gate por sequence: TODAS deben estar satisfechas
        if not _rule_sequences_ok(r):    # <-- hard gate
            continue

        # 2) grupos (como ya tenías)
        g_truth = _group_truth_map(r)
        conds = r.get("conditions", [])
        if not conds:
            if g_truth and all(g_truth.values()):
                return True
            continue

        # 3) respeta OR/AND del JSON (no lo fuerces a AND implícito)
        #    Evalúa el árbol tal cual está
        ok, _ = _eval_condition_node(conds[0] if len(conds) == 1 else {"and": conds}, g_truth, r)
        if ok:
            return True
    return False


def _eval_groups_and_conditions_with_details(runtime):
    if not runtime:
        return False, None
    for r_idx, r in enumerate(runtime.get("rules", [])):
        # 1) gate por sequence
        if not _rule_sequences_ok(r):
            print(f"[EVAL] rule {r_idx} sequences NOT OK -> skip")
            for idx, e in enumerate(r.get("seq_edges", [])):
                print(f"   edge={idx} sat={e['satisfied']} pend={e['pending']} "
                    f"({e['from_id']}->{e['to_id']} lo={e['lo']} hi={e['hi']})")
            continue

        # 2) grupos
        g_truth = _group_truth_map(r)
        conds = r.get("conditions", [])
        if not conds:
            if g_truth and all(g_truth.values()):
                return True, {"rule_idx": r_idx, "clause_idx": None, "g_truth": g_truth, "cond": None}
            continue

        root = conds[0] if len(conds) == 1 else {"and": conds}
        ok, matched = _eval_condition_node(root, g_truth, r)
        debug(f"[EVAL] rule {r_idx} g_truth={g_truth} ok={ok} matched={matched}")

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
    Acepta ints, 'all', 'any' o 'cadena' (y strings numéricas).
    Devuelve el mismo string en minúsculas para 'all'/'any'/'cadena',
    o el entero para dígitos. Fallback: 'any'.
    """
    if isinstance(mt, int):
        return mt
    if isinstance(mt, str):
        s = mt.strip().lower()
        if s.isdigit():
            return int(s)
        if s in ("all", "any", "cadena"):
            return s
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
                # segmentos que participan en la cadena (from/to del mismo grupo)
                segs_in_chain = set()
                for e in r.get("seq_edges", []):
                    if e.get("group") == g_key:
                        if e.get("from_id"): segs_in_chain.add(e["from_id"])
                        if e.get("to_id"):   segs_in_chain.add(e["to_id"])
                if not segs_in_chain:
                    is_true = (done_count > 0)  # fallback amistoso
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
            "seq_by_to": {},     # { g_key: { s_idx: [edge_idx,...] } }
            "seq_by_from": {}    # { g_key: { s_idx: [edge_idx,...] } }
        }

        for g_key, g_val in (rule.get("groups") or {}).items():
            mt_norm = _coerce_match_type(g_val.get("match_type", "any"))

            g_entry = {
                "match_type": mt_norm,
                "threshold": None,
                "strings": [],
                "seg_index": {}     # { seg_id: [s_idx, ...] }  <-- lista (¡no uno solo!)
            }

            for s_idx, s_item in enumerate(g_val.get("strings", [])):
                parent_seg_id = s_item.get("id")

                # Caso con hijas: { "id": "g1_segX", "strings": [ {...}, {...} ] }
                child_strings = s_item.get("strings")
                if isinstance(child_strings, list) and child_strings:
                    for child in child_strings:
                        sess_list = child.get("session_tokens", [])
                        pos_count = len(sess_list)

                        # indexa TODAS las alternativas (por posición)
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

                        # placeholder runtime por string hijo
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

                # Caso directo: session_tokens en el propio item
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

            # Para no-cadena seguimos con umbral estándar
            _mode, k = _normalize_match_type(mt_norm, len(g_entry["strings"]))
            g_entry["threshold"] = k
            r_entry["groups"][g_key] = g_entry

        # === Engancha edges de sequence para este rule ===
        edges = _gather_sequence_edges(r_entry["conditions"])
        for e in edges:
            # e["lo"], e["hi"] vienen en BYTES -> conviértelo a TOKENS con BASE=BLOCK_BYTES-1
            BASE = BLOCK_BYTES - 1
            lo_tokens = BASE + e["lo"]
            hi_tokens = BASE + e["hi"]

            # DEBUG: ver traducción de rangos
            debug("[IDX][EDGE]",
                  f"group={e['group']} from={e['from_id']} to={e['to_id']} ",
                  f"lo_bytes={e['lo']} hi_bytes={e['hi']} -> lo_tokens={lo_tokens} hi_tokens={hi_tokens}",
                  f"(BLOCK_BYTES={BLOCK_BYTES}, BASE={BASE})")

            edge_idx = len(r_entry["seq_edges"])
            r_entry["seq_edges"].append({
                "group":   e["group"],
                "from_id": e["from_id"],
                "to_id":   e["to_id"],
                "lo":      lo_tokens,   # <-- ahora en TOKENS
                "hi":      hi_tokens,   # <-- ahora en TOKENS
                "pending": None,
                "satisfied": False
            })

            print("[IDX][EDGE] "
                f"group={e['group']} from={e['from_id']} to={e['to_id']} "
                f"lo_bytes={e['lo']} hi_bytes={e['hi']} "
                f"-> lo_tokens={lo_tokens} hi_tokens={hi_tokens}")

            gk = e["group"]
            # mapear FROM
            from_list = r_entry["groups"].get(gk, {}).get("seg_index", {}).get(e["from_id"], [])
            if from_list:
                by_from = r_entry["seq_by_from"].setdefault(gk, {})
                for s_idx in from_list:
                    by_from.setdefault(s_idx, []).append(edge_idx)
            # mapear TO
            to_list = r_entry["groups"].get(gk, {}).get("seg_index", {}).get(e["to_id"], [])
            if to_list:
                by_to = r_entry["seq_by_to"].setdefault(gk, {})
                for s_idx in to_list:
                    by_to.setdefault(s_idx, []).append(edge_idx)

        runtime["rules"].append(r_entry)

    return runtime, sj_to_targets




