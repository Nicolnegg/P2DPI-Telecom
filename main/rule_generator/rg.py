"""
rg.py — Rule Generator (RG) for P2DPI.

Pipeline:
  1) Load PRF (FKH) shared library and constants (kMB, fixed h)
  2) Load the YARA-derived dictionary JSON (no cleartext leak to MB)
  3) For each rule:
       - Map original group names -> opaque ids ("g1", "g2", ...)
       - For each string entry:
           · Build Sender-consistent 8-byte tokens (strings/hex/mixed)
           · Obfuscate each token with FKH (Ri)
           · Sign Ri with RSA-PSS
           · Emit {"enc_tokens":[{"ri":..., "sig":...}, ...]}
       - Remap conditions to use the opaque group ids
  4) Send {"rules":[{...}, ...]} to MB (no rule name, no cleartext, no data_type)
"""

from ctypes import CDLL, c_char_p, c_int, create_string_buffer
from typing import Dict, Any, List
import json
import os
import requests
import re
import copy

from collections import defaultdict
from crypto_utils import load_private_key, sign_data
from rg_utils import emit_tokens_for_pattern, emit_tokens_for_hex_literal, normalize_view_text


# --- Debug printing (ASCII preview of tokens) ---
DEBUG_TOKENS = True

_BASE_RX = re.compile(r"^([a-zA-Z0-9]+)")

MIN_SEG_BYTES = 7  # drop si len(bytes) < 7  (<=6)


def _ascii_safe(b: bytes) -> str:
    return ''.join(chr(x) if 32 <= x <= 126 else '.' for x in b)

def _dbg_dump_tokens(label: str, original: str, view: bytes, tokens) -> None:
    if not DEBUG_TOKENS:
        return
    try:
        print(f"[RG][DBG] pattern= {original!r} | normalized_len={len(view)}")
        if view:
            prev = view[:80]
            print(f"[RG][DBG] normalized(bytes)={prev!r}{' ...' if len(view) > 80 else ''}")

        # Handle both flat list of bytes and list of list of bytes
        if tokens and isinstance(tokens[0], list):
            for i, group in enumerate(tokens):
                for j, t in enumerate(group):
                    print(f"[RG][TOK] {label}[{i}-{j}] {t.hex()}  |  ASCII: '{_ascii_safe(t)}'")
        else:
            for i, t in enumerate(tokens):
                print(f"[RG][TOK] {label}[{i:02d}] {t.hex()}  |  ASCII: '{_ascii_safe(t)}'")

    except Exception as e:
        print(f"[RG][DBG] dump error: {e}")



# --- Load PRF shared library (compiled C code) ---
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
print("[DEBUG] Loading PRF library from:", prf_path)
prf = CDLL(prf_path)

# int FKH_hex(const char* key_raw, const char* k_hex, const char* h_hex, char* out_hex, int out_len);
prf.FKH_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_hex.restype = c_int

# --- Load randomization key kMB (shared with MB), as hex string ---
kmb_path = os.path.join(current_dir, 'keys', 'kmb.key')
with open(kmb_path, 'rb') as f:
    kmb = f.read()
K_MB_HEX = kmb.hex()

# --- Load fixed point h from file (hex string) ---
h_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'h_fixed.txt'))
with open(h_path, 'r') as f:
    h_fixed_hex = f.read().strip()

# --- Paths ---
DICT_PATH = os.path.join(current_dir, "dictionary.json")   # input (YARA → default dict)
MB_URL    = "http://localhost:9999/upload_rules"        # output endpoint at MB


# ---------- PRF wrapper: obfuscate a single 8-byte token ----------

def obfuscate_token_fkh(token8: bytes) -> str:
    """
    Obfuscate one 8-byte token using FKH (key-homomorphic PRF).
    Returns ASCII-hex string (Ri).
    """
    out = create_string_buffer(200)
    res = prf.FKH_hex(
        c_char_p(token8),                         # raw bytes as PRF input
        c_char_p(K_MB_HEX.encode("utf-8")),       # kMB hex
        c_char_p(h_fixed_hex.encode("utf-8")),    # h hex
        out,
        200
    )
    if res != 1:
        raise RuntimeError("FKH_hex failed for a token")
    return out.value.decode()  # ASCII hex


# ---------- Builders for enc_tokens per string item ----------

def _enc_tokens_for_string_value(text: str) -> List[Dict[str, str]]:
    """
    Build enc_tokens for a textual value:
      - Mirror Sender’s tokenization (normalization + sliding/canonical)
      - For each 8-byte token: obfuscate + sign
    Returns a list of {"ri": "<hex>", "sig": "<base64>"}.
    """
    tokens = emit_tokens_for_pattern(text)
    view = normalize_view_text(text)  
    _dbg_dump_tokens("str", text, view, tokens)

    enc_list: List[Dict[str, str]] = []

    if not tokens:
        return enc_list
    # Load private key once at module-level? Keep simple: load here via closure from outer scope.
    for t in tokens:
        ri_hex = obfuscate_token_fkh(t)
        sig_b64 = sign_data(ri_hex, _PRIVATE_KEY)
        enc_list.append({"ri": ri_hex, "sig": sig_b64})
    return enc_list

# ---------- Builders for enc_tokens per string item (REPLACEMENTS) ----------

def _enc_tokens_for_hex_value(hex_text: str) -> List[List[Dict[str, str]]]:
    """
    Build enc_tokens for a plain hex literal (no wildcards).
    Returns a list of groups: each group is a list of {"ri","sig"} dicts.

    Reason: emit_tokens_for_hex_literal() returns List[List[bytes]] where each inner list
    corresponds to a logical group/variant for that string. We preserve that grouping
    so callers can create one {"enc_tokens": ...} per group (not merge groups from
    different strings).
    """
    tokens_groups = emit_tokens_for_hex_literal(hex_text)
    _dbg_dump_tokens("hex", hex_text, b"", tokens_groups)

    groups_out: List[List[Dict[str, str]]] = []

    for group in tokens_groups:          # group is List[bytes]
        enc_list: List[Dict[str, str]] = []
        for t in group:                  # t is bytes
            ri_hex = obfuscate_token_fkh(t)
            sig_b64 = sign_data(ri_hex, _PRIVATE_KEY)
            enc_list.append({"ri": ri_hex, "sig": sig_b64})
        if enc_list:
            groups_out.append(enc_list)

    return groups_out


def _process_group_simple(group_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simple group processing:
      - Preserve the group's match_type EXACTLY AS PROVIDED:
        * can be "all", "any", "cadena", or a numeric threshold (e.g., 14)
      - Accept both shapes for items:
        * homogeneous lists (["abc", "def"]) guided by group-level data_type
        * per-item typed lists ([{"data_type":"string","value":"..."}, ...])
      - Output format (no cleartext, no data_type):
        { "match_type": <same as input>, "strings": [ { "enc_tokens":[...] }, ... ] }
    """
    # 1) Preserve match_type exactly, but if it is a digit string like "14" -> convert to int 14.
    mt_in = group_obj.get("match_type", "all")
    if isinstance(mt_in, str) and mt_in.isdigit():
        match_type = int(mt_in)   # MB can enforce "matches >= 14"
    else:
        match_type = mt_in        # keep "all"/"any"/"cadena" (or int) as-is

    # 2) Gather items (strings) and detect the shape
    items = group_obj.get("strings", [])
    strings_out: List[Dict[str, Any]] = []

    # Detect per-item typed entries:
    per_item_typed = bool(items) and isinstance(items[0], dict) and "value" in items[0]

    if per_item_typed:
        # Per-item typing — respect each item’s data_type
        for it in items:
            v = it.get("value", "")
            t = (it.get("data_type", "string") or "string").strip().lower()
            if t == "hex":
                # _enc_tokens_for_hex_value now returns List[List[dict]]
                groups = _enc_tokens_for_hex_value(v)
                for enc_group in groups:
                    if enc_group:
                        strings_out.append({"enc_tokens": enc_group})
            else:
                enc = _enc_tokens_for_string_value(v)
                if enc:
                    strings_out.append({"enc_tokens": enc})
    else:
        # Homogeneous list — use group-level data_type (default: string)
        dtype = (group_obj.get("data_type", "string") or "string").strip().lower()
        if dtype == "hex":
            for v in items:
                groups = _enc_tokens_for_hex_value(v)
                # append one entry per inner-group
                for enc_group in groups:
                    if enc_group:
                        strings_out.append({"enc_tokens": enc_group})
        else:
            for v in items:
                enc = _enc_tokens_for_string_value(v)
                if enc:
                    strings_out.append({"enc_tokens": enc})

    # IMPORTANT: return match_type exactly as we received it (could be int)
    return {"match_type": match_type, "strings": strings_out}


def _process_group_cadena(group_obj: Dict[str, Any], gid: str,
                          seq_next_op_map: Dict[str, str]) -> tuple[Dict[str, Any], Dict[str, str], set, set, Dict[str, int], List[str]]:
    """
    Devuelve:
      - grupo_listo (sin 'value' en claro, con enc_tokens)
      - sid_map: {id_original -> id_ofuscado} (solo de kept)
      - absorbed_from: set(ids 'from' que absorbieron 1 byte)
      - dropped_sids: set(ids originales de segmentos omitidos por < MIN_SEG_BYTES)
      - seg_len_map: {id_original -> len_en_bytes} (de todos, útil para componer gaps)
      - kept_order: [ids originales en orden], solo los conservados
    """
    strings_in = group_obj.get("strings", [])
    strings_out: List[Dict[str, Any]] = []
    sid_map: Dict[str, str] = {}
    absorbed_from: set = set()
    dropped_sids: set = set()
    seg_len_map: Dict[str, int] = {}
    kept_order: List[str] = []

    for idx, s in enumerate(strings_in):
        orig_sid = s.get("id")
        val = s.get("value", "")
        try:
            b = _hex_to_bytes(val)
        except Exception:
            b = b""

        seg_len_map[orig_sid] = len(b)

        # --- drop si < 7 bytes ---
        if len(b) < MIN_SEG_BYTES:
            if DEBUG_TOKENS:
                print(f"[RG][DROP] gid={gid} orig_sid={orig_sid} len={len(b)} < {MIN_SEG_BYTES} -> drop")
            dropped_sids.add(orig_sid)
            continue

        new_sid = f"{gid}_seg{idx}"
        sid_map[orig_sid] = new_sid
        kept_order.append(orig_sid)

        # ¿absorción de 7 bytes?
        do_absorb = (
            len(b) == 7 and
            orig_sid in seq_next_op_map and
            _op_allows_absorb(seq_next_op_map[orig_sid])
        )
        if DEBUG_TOKENS:
            print(f"[RG][ABSORB?] gid={gid} orig_sid={orig_sid} len={len(b)} "
                  f"op_next={seq_next_op_map.get(orig_sid)} -> {do_absorb}")

        if do_absorb:
            variants = _enc_variants_for_hex7_absorb_right_from_hex(val)  # List[List[dict]]
            absorbed_from.add(orig_sid)

            # Opción A (lo que pides): exponer las 256 opciones bajo "value"
            #   "value": [ {"enc_tokens":[...]}, {"enc_tokens":[...]}, ... x256 ]
            strings_out.append({
                "id": new_sid,
                "value": [{"enc_tokens": v} for v in variants]
            })

        else:
            groups = _enc_tokens_for_hex_value(val)  # List[List[dict]]
            enc_tokens = [tok for group in groups for tok in group]
            strings_out.append({"id": new_sid, "enc_tokens": enc_tokens})

    return (
        {"match_type": "cadena", "strings": strings_out},
        sid_map,
        absorbed_from,
        dropped_sids,
        seg_len_map,
        kept_order,
    )



# --- Helpers para absorción de 7 bytes en cadena ---

_HEX_SP_RE = re.compile(r"\s+")

def _hex_to_bytes(hex_text: str) -> bytes:
    s = hex_text.strip()
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1].strip()
    s = _HEX_SP_RE.sub(" ", s)
    s_hex = s.replace(" ", "")
    return bytes.fromhex(s_hex)


def _first_group_name_for_base(conditions: List[Dict[str, Any]], base: str) -> str | None:
    for n in conditions or []:
        if "sequence" in n and isinstance(n["sequence"], dict):
            g = str(n["sequence"].get("group", ""))
            if _base_name(g).lower() == base:
                return g
    return None


def _ascii_lower_bytes_local(b: bytes) -> bytes:
    return bytes(x + 32 if 65 <= x <= 90 else x for x in b)

def _op_allows_absorb(op: str) -> bool:
    """
    True si hay al menos 1 byte de holgura entre 'from' y 'to'.
    """
    if not isinstance(op, str):
        return False
    op = op.strip().upper()
    if op == "ONE_WILDCARD":
        return True
    m = re.fullmatch(r"RANGE_(\d+)_(\d+)", op)
    if not m:
        return False
    lo, hi = int(m.group(1)), int(m.group(2))
    return hi >= 1 and lo >= 1  # exigimos al menos 1 como mínimo (consumimos 1)

def _adjust_op_minus_one(op: str) -> str:
    """
    Resta exactamente 1 byte al hueco del salto.
    ONE_WILDCARD -> RANGE_0_0
    RANGE_m_n    -> RANGE_{max(0,m-1)}_{max(0,n-1)}
    """
    opu = str(op).strip().upper()
    if opu == "ONE_WILDCARD":
        return "RANGE_0_0"
    m = re.fullmatch(r"RANGE_(\d+)_(\d+)", opu)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        lo2 = max(0, lo - 1)
        hi2 = max(0, hi - 1)
        return f"RANGE_{lo2}_{hi2}"
    return op  # desconocido: no tocamos

def _collect_seq_nextops_by_group(conditions: List[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """
    Devuelve: { group_key : { from_id : op_str } }
    Donde group_key incluye:
      - el nombre tal cual aparece en conditions
      - y también su base en minúsculas (para empatar tras el fuse)
    """
    out: Dict[str, Dict[str, str]] = {}

    def _add(g: str, f: str, op: str):
        if not g or not f:
            return
        # clave con el nombre exacto
        out.setdefault(g, {})[f] = op
        # clave con la base en minúsculas (tras el fuse)
        base = _base_name(g).lower()
        out.setdefault(base, {})[f] = op

    def _walk(node: Dict[str, Any]):
        if "sequence" in node and isinstance(node["sequence"], dict):
            seq = node["sequence"]
            _add(str(seq.get("group", "")),
                 str(seq.get("from", "")),
                 str(seq.get("op", "")))
        for k in ("or", "and"):
            if k in node:
                for sub in node[k]:
                    _walk(sub)

    for n in conditions or []:
        _walk(n)

    return out

def _collect_edges_for_group_base(conditions: List[Dict[str, Any]], base: str) -> Dict[str, tuple[str, str]]:
    edges: Dict[str, tuple[str, str]] = {}
    for n in conditions or []:
        if "sequence" in n and isinstance(n["sequence"], dict):
            seq = n["sequence"]
            g = str(seq.get("group", ""))
            if _base_name(g).lower() == base:
                f = str(seq.get("from", ""))
                t = str(seq.get("to", ""))
                op = str(seq.get("op", "RANGE_0_0"))
                if f and t:
                    edges[f] = (t, op)
    return edges

def _rebuild_sequences_cadena_by_base(conditions: List[Dict[str, Any]],
                                      base: str,
                                      kept_order: List[str],
                                      dropped_sids: set,
                                      seg_len_map: Dict[str, int]) -> List[Dict[str, Any]]:
    # Usa el nombre original tal como aparece en conditions (para que luego remapee a gN)
    orig_group_name = _first_group_name_for_base(conditions, base) or base

    edges = _collect_edges_for_group_base(conditions, base)

    # Elimina TODAS las sequence cuyo group tenga ese base
    kept_nodes: List[Dict[str, Any]] = []
    for n in conditions or []:
        if "sequence" in n and isinstance(n["sequence"], dict):
            g = str(n["sequence"].get("group", ""))
            if _base_name(g).lower() == base:
                continue
        kept_nodes.append(n)

    # Crea las nuevas sequence entre kept consecutivos (sumando gaps + bytes de dropeados intermedios)
    new_seq_nodes: List[Dict[str, Any]] = []
    for i in range(len(kept_order) - 1):
        start = kept_order[i]
        end   = kept_order[i+1]

        cur = start
        total_lo = 0
        total_hi = 0
        ok = True

        while cur != end:
            if cur not in edges:
                ok = False
                break
            nxt, op = edges[cur]
            lo, hi = _parse_op_to_range(op)
            total_lo += lo; total_hi += hi
            if nxt in dropped_sids:
                L = seg_len_map.get(nxt, 0)
                total_lo += L; total_hi += L
            cur = nxt

        if not ok:
            if DEBUG_TOKENS:
                print(f"[RG][WARN] No path {start}->{end} for base={base}. Skip.")
            continue

        new_op = _format_range(total_lo, total_hi)
        new_seq_nodes.append({"sequence": {"group": orig_group_name, "from": start, "to": end, "op": new_op}})

    return kept_nodes + new_seq_nodes


_OP_RX = re.compile(r"^RANGE_(\d+)_(\d+)$")

def _parse_op_to_range(op: str) -> tuple[int, int]:
    if not isinstance(op, str):
        return (0, 0)
    opu = op.strip().upper()
    if opu == "ONE_WILDCARD":
        return (1, 1)
    m = _OP_RX.fullmatch(opu)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        return (lo, hi)
    # Desconocido -> conservador
    return (0, 0)

def _format_range(lo: int, hi: int) -> str:
    lo = max(0, lo); hi = max(0, hi)
    return f"RANGE_{lo}_{hi}"

def _collect_edges_for_group(conditions: List[Dict[str, Any]], group_name: str) -> Dict[str, tuple[str, str]]:
    """
    Devuelve un grafo simple de aristas 'from' -> (to, op) SOLO del grupo dado.
    Asume 1 salto por nodo 'from' (cadena típica).
    """
    edges: Dict[str, tuple[str, str]] = {}
    for n in conditions or []:
        if "sequence" in n and isinstance(n["sequence"], dict):
            seq = n["sequence"]
            if str(seq.get("group", "")) == group_name:
                f = str(seq.get("from", ""))
                t = str(seq.get("to", ""))
                op = str(seq.get("op", "RANGE_0_0"))
                if f and t:
                    edges[f] = (t, op)
    return edges

def _enc_variants_for_hex7_absorb_right_from_hex(hex_text: str) -> List[List[Dict[str, str]]]:
    """
    Devuelve 256 variantes separadas (cada variante = 1 token firmado).
    Además, si DEBUG_TOKENS, imprime los 256 tokens crudos que se usaron.
    """
    b7 = _hex_to_bytes(hex_text)
    if len(b7) != 7:
        return []

    variants: List[List[Dict[str, str]]] = []
    if DEBUG_TOKENS:
        raw_tokens_8: List[bytes] = []

    for x in range(256):
        t8 = _ascii_lower_bytes_local(b7 + bytes([x]))  # token de 8 bytes que se ofusca
        if DEBUG_TOKENS:
            raw_tokens_8.append(t8)

        ri_hex = obfuscate_token_fkh(t8)
        sig_b64 = sign_data(ri_hex, _PRIVATE_KEY)
        variants.append([{"ri": ri_hex, "sig": sig_b64}])

    if DEBUG_TOKENS:
        # Muestra los 256 tokens crudos usados para ofuscar
        _dbg_dump_tokens("hex7absorb", hex_text, b7, raw_tokens_8)

    return variants



# ---------- Conditions remapping (original group names -> "g1","g2",...) ----------
def _remap_condition_node(node: Dict[str, Any],
                          name_map: Dict[str, str],
                          sid_maps: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    def _to_gid(gname: str) -> str:
        base = _base_name(str(gname)).lower()
        return name_map.get(base, name_map.get(gname, gname))

    if "groups" in node:
        remapped = [_to_gid(g) for g in node["groups"]]
        op = str(node.get("operator", "and")).strip().lower()
        if op == "any":
            op = "or"
        return {"groups": remapped, "operator": op}

    if "or" in node:
        return {"or": [_remap_condition_node(x, name_map, sid_maps) for x in node["or"]]}

    if "and" in node:
        return {"and": [_remap_condition_node(x, name_map, sid_maps) for x in node["and"]]}

    if "sequence" in node:
        seq = dict(node["sequence"])
        orig_group = seq.get("group", "")
        gid = _to_gid(orig_group)
        seq["group"] = gid
        sid_map = sid_maps.get(gid, {})
        if "from" in seq:
            seq["from"] = sid_map.get(seq["from"], seq["from"])
        if "to" in seq:
            seq["to"] = sid_map.get(seq["to"], seq["to"])
        return {"sequence": seq}

    return dict(node)



# --- Bucket merge (merge physical groups like url_1, url_2 → url) ---

def _base_name(name: str) -> str:
    """
    Extract logical base from a group name.
    Example: 'url_1' -> 'url', 'eml_2' -> 'eml', 'greeting' -> 'greeting'.
    Rule: take the first alphanumeric run.
    """
    m = _BASE_RX.match(name)
    return m.group(1).lower() if m else name.lower()

def _gather_condition_bases(conditions: list[dict]) -> set[str]:
    """
    Collect all group names mentioned in 'conditions'.
    Used later to prioritize order of g1,g2,...
    """
    out = set()
    def walk(node: dict):
        if "groups" in node:
            for g in node["groups"]:
                out.add(str(g).lower())
        for k in ("or", "and"):
            if k in node:
                for sub in node[k]:
                    walk(sub)
        if "not" in node:
            walk(node["not"])
        if "sequence" in node:
            seq = node["sequence"]
            if isinstance(seq, dict) and "group" in seq:
                out.add(str(seq["group"]).lower())
    for c in conditions:
        walk(c)
    return out

def _fuse_groups_by_base(rule_obj: dict) -> dict:
    """
    Merge physical groups that share the same base name into one logical group.

    Policy:
      - Keep 'cadena' buckets untouched.
      - If any numeric thresholds are present across merged groups (e.g., "14"),
        preserve a numeric match_type (we pick max(k) for safety).
      - Otherwise:
          * 'all' if all are 'all'
          * 'any' if all are 'any'
          * 'any' if mixed (documented permissive default)
      - Resolve data_type: 'string' | 'hex' | 'mixed'
      - Keep per-item {"value","data_type"} entries when mixed; otherwise flatten.
    """
    groups_in: dict = rule_obj.get("groups", {})

    buckets = defaultdict(lambda: {
        "strings": [],      # normalized entries
        "types": set(),     # {'string','hex'}
        "pols_str": set(),  # textual policies: {'all','any','cadena'}
        "ks": []            # numeric thresholds collected as ints
    })

    for orig_name, gobj in groups_in.items():
        base = _base_name(orig_name)

        # --- Preserve match_type as provided (could be int or str) ---
        mt_raw = gobj.get("match_type", "all")
        if isinstance(mt_raw, int):
            buckets[base]["ks"].append(mt_raw)
            mts = None
        elif isinstance(mt_raw, str):
            s = mt_raw.strip()
            if s.isdigit():
                buckets[base]["ks"].append(int(s))
                mts = None
            else:
                mts = s.lower() if s else "all"
        else:
            mts = "all"

        if mts is not None:
            buckets[base]["pols_str"].add(mts)

        # Handle 'cadena' specially: keep raw segments and mark as hex
        if isinstance(mt_raw, str) and mt_raw.strip().lower() == "cadena":
            buckets[base]["strings"].extend(gobj.get("strings", []))  # [{'id','value'}, ...]
            buckets[base]["types"].add("hex")
            # policy already recorded above
            continue

        # Normalize items into a consistent shape for later flattening
        dt = (gobj.get("data_type", "string") or "string").strip().lower()
        if dt == "mixed":
            for it in gobj.get("strings", []):
                v = it.get("value", "")
                t = (it.get("data_type", "string") or "string").strip().lower()
                buckets[base]["strings"].append({"value": v, "data_type": t})
                buckets[base]["types"].add(t)
        elif dt in ("string", "hex"):
            for v in gobj.get("strings", []):
                buckets[base]["strings"].append({"value": v, "data_type": dt})
                buckets[base]["types"].add(dt)
        else:
            # Unknown data_type: ignore
            pass

    fused_groups: dict = {}

    for base, info in buckets.items():
        pols = info["pols_str"]
        ks   = info["ks"]

        # 1) Pure cadena bucket
        if pols == {"cadena"} and not ks:
            fused_groups[base] = {
                "match_type": "cadena",
                "data_type": "hex",
                "strings": info["strings"],  # keep [{'id','value'}, ...]
            }
            continue

        # 2) Decide match_type
        if ks:
            # Numeric k-of-n: choose a consistent policy (max is safer/stricter)
            match_type = max(ks)  # emitted as an integer
        else:
            only_all = pols == {"all"}
            only_any = pols == {"any"}
            if only_all:
                match_type = "all"
            elif only_any:
                match_type = "any"
            else:
                match_type = "any"  # mixed/empty → permissive default

        # 3) Resolve data_type and flatten strings accordingly
        if len(info["types"]) > 1:
            data_type = "mixed"
            strings = [{"value": it["value"], "data_type": it["data_type"]} for it in info["strings"]]
        else:
            data_type = next(iter(info["types"])) if info["types"] else "string"
            strings = [it["value"] for it in info["strings"] if it.get("data_type", data_type) == data_type]

        fused_groups[base] = {
            "match_type": match_type,  # 'all'/'any' or an int threshold
            "data_type": data_type,
            "strings": strings
        }

    # Return a new rule object with fused groups
    return {**rule_obj, "groups": fused_groups}


def _ordered_group_names(groups_in: dict, conditions_in: list) -> list[str]:
    """
    Order group names:
    - first the ones referenced in conditions (for determinism in debugging),
    - then any remaining ones alphabetically.
    """
    seen = []
    seen_set = set()
    for b in _gather_condition_bases(conditions_in):
        if b in groups_in and b not in seen_set:
            seen.append(b); seen_set.add(b)
    others = sorted([k for k in groups_in.keys() if k not in seen_set])
    return seen + others

# ---------- Rule conversion (one rule from input -> one anonymized rule object) ----------
def _convert_rule(rule_obj: Dict[str, Any]) -> Dict[str, Any]:
    rule_obj = _fuse_groups_by_base(rule_obj)

    groups_in: Dict[str, Any] = rule_obj.get("groups", {})
    conditions_in: List[Dict[str, Any]] = rule_obj.get("conditions", [])

    ordered_names = _ordered_group_names(groups_in, conditions_in)

    # 1) recolectar los 'op' por grupo (por nombre y por base)
    seq_nextops_by_group = _collect_seq_nextops_by_group(conditions_in)

    name_map: Dict[str, str] = {}
    groups_out: Dict[str, Any] = {}
    sid_maps: Dict[str, Dict[str, str]] = {}

    # meta por grupo base (para reconstrucción de secuencias)
    meta_by_base = {}  # base -> dict(absorbed_from, dropped_sids, seg_len_map, kept_order, orig_name)

    for idx, orig_name in enumerate(ordered_names, start=1):
        gobj = groups_in[orig_name]
        gid = f"g{idx}"
        base = _base_name(orig_name).lower()

        name_map[orig_name] = gid
        name_map[base] = gid

        mt_raw = gobj.get("match_type", "all")
        is_cadena = isinstance(mt_raw, str) and mt_raw.strip().lower() == "cadena"
        if is_cadena:
            seq_map = seq_nextops_by_group.get(orig_name, {}) or seq_nextops_by_group.get(base, {})
            grp_out, sid_map, absorbed_from, dropped_sids, seg_len_map, kept_order = _process_group_cadena(gobj, gid, seq_map)
            groups_out[gid] = grp_out
            sid_maps[gid] = sid_map

            meta_by_base[base] = {
                "absorbed_from": absorbed_from,
                "dropped_sids": dropped_sids,
                "seg_len_map": seg_len_map,
                "kept_order": kept_order,
                "orig_name": orig_name,
            }
        else:
            groups_out[gid] = _process_group_simple(gobj)

    # 2) Ajuste por absorción (-1) sobre las conditions originales
    conditions_adj = copy.deepcopy(conditions_in)

    def _adjust_inplace(node: Dict[str, Any]):
        if "sequence" in node and isinstance(node["sequence"], dict):
            seq = node["sequence"]
            g = str(seq.get("group", ""))
            f = str(seq.get("from", ""))
            base = _base_name(g).lower()
            if base in meta_by_base and f in meta_by_base[base]["absorbed_from"]:
                seq["op"] = _adjust_op_minus_one(seq.get("op", ""))
        elif "or" in node:
            for sub in node["or"]:
                _adjust_inplace(sub)
        elif "and" in node:
            for sub in node["and"]:
                _adjust_inplace(sub)

    for n in conditions_adj:
        _adjust_inplace(n)

    # 3) RECONSTRUIR secuencias para cada grupo 'cadena' con drops (<7B) sumando gaps + longitudes dropeadas
    conditions_rebuilt = conditions_adj
    for base, meta in meta_by_base.items():
        if not meta["kept_order"]:
            continue
        conditions_rebuilt = _rebuild_sequences_cadena_by_base(
            conditions_rebuilt,
            base,
            meta["kept_order"],
            meta["dropped_sids"],
            meta["seg_len_map"],
        )


    # 4) Remapear condiciones (grupo y from/to) a gN y gN_segM FINAL
    conditions_out = [_remap_condition_node(c, name_map, sid_maps) for c in conditions_rebuilt]

    return {"groups": groups_out, "conditions": conditions_out}



# ---------- Main: load dict -> build anonymized payload -> POST to MB ----------

def generate_and_send_ruleset(dict_path: str = DICT_PATH, mb_url: str = MB_URL):
    """
    Load the default dictionary JSON and send the anonymized ruleset to the MB.
    Output payload shape (no rule names, no cleartext, no data_type):
      { "rules": [ { "groups": {...}, "conditions": [...] }, ... ] }
    """
    # Load private RSA key once (for signing obfuscated tokens)
    global _PRIVATE_KEY
    _PRIVATE_KEY = load_private_key(os.path.join(current_dir, 'keys', 'rg_private_key.pem'))

    # Load input dictionary
    with open(dict_path, "r", encoding="utf-8") as f:
        input_dict = json.load(f)

    # Convert each rule entry to anonymized form (drop rule names)
    rules_out: List[Dict[str, Any]] = []
    for _rule_name, rule_obj in input_dict.items():
        anon_rule = _convert_rule(rule_obj)
        rules_out.append(anon_rule)

    payload = {"rules": rules_out}
    print(payload)
    # POST to MB
    try:
        print(f"[RG] Sending anonymized ruleset with {len(rules_out)} rules to MB: {mb_url}")
        resp = requests.post(mb_url, json=payload, timeout=10)
        print("[RG] MB response:", resp.status_code, resp.text)
    except Exception as e:
        print("[RG] Error sending ruleset to MB:", e)


if __name__ == "__main__":
    generate_and_send_ruleset()
