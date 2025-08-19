import os
import yaramod
import re
import json
from sympy import symbols
from sympy.logic.boolalg import to_dnf

# ----------------------------
# Utilities
# ----------------------------
HEX_WILDCARD_RE = re.compile(r"\?\?")
HEX_RANGE_RE = re.compile(r"\[(\d+)-(\d+)\]")

LEAF_OF_RE = re.compile(r'\b(any|all|\d+)\s+of\s*\(\s*\$([A-Za-z0-9_]+)\*\s*\)', re.I)
AT_RE      = re.compile(r'\$([A-Za-z0-9_]+)\s+at\s+(\d+)', re.I)

MAGIC_RE = re.compile(r'uint(8|16|32)\s*\(\s*0\s*\)\s*==\s*0x([0-9a-fA-F]+)')
ID_RE = re.compile(r'\$([A-Za-z0-9_]+)(?!\*)')


def clean_string_value(yara_string):
    """Extract literal text from a quoted YARA string, e.g. '"From:" nocase' -> 'From:'."""
    m = re.match(r'"([^"]*)"', yara_string)
    return m.group(1) if m else yara_string


def extract_group_name(identifier):
    """
    Extracts the prefix from a YARA string identifier for grouping.
    Examples:
      $eml_1 -> 'eml'
      $create0 -> 'create'
      $97str1 -> 97str
      $officemagic -> officemagic
    """
    m = re.match(r"\$([A-Za-z0-9_]+?)(\d*)$", identifier.strip())
    if m:
        return m.group(1)  # keep the alnum+_ prefix, drop trailing digits
    return "default_group"
    

def is_hex_with_wildcards_or_gaps(hex_text):
    """Return True if the hex pattern contains '??' or '[m-n]'."""
    return bool(HEX_WILDCARD_RE.search(hex_text) or HEX_RANGE_RE.search(hex_text))


def split_hex_into_tokens(hex_text):
    """Split { ... } body into tokens (hex bytes, ??, or [m-n])."""
    body = hex_text.strip()
    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1]
    body = re.sub(r"\s+", " ", body.strip())
    return body.split() if body else []

def contiguous_literal_runs(tokens):
    """
    From token list, extract contiguous literal runs (only hex bytes, no ?? or [m-n]).
    Returns list of strings like "AA BB CC".
    """
    runs, buf = [], []
    for t in tokens:
        if re.fullmatch(r"[0-9A-Fa-f]{2}", t):
            buf.append(t.upper())
        else:
            if buf:
                runs.append(" ".join(buf))
                buf = []
    if buf:
        runs.append(" ".join(buf))
    return runs

def derive_sequence_ops(tokens, segment_ids):
    """
    Given tokens and segment IDs for literal runs, build sequence constraints (ops).
    Mapping:
      - '??' = ONE_WILDCARD
      - '[m-n]' = RANGE_m_n
      - Multiple wildcards/ranges are combined into a single RANGE.
    """
    gaps = []
    current_gap_min = current_gap_max = None
    in_literal = False
    seen_first_run = False

    def add_gap():
        nonlocal gaps, current_gap_min, current_gap_max
        if current_gap_min is not None and current_gap_max is not None:
            gaps.append((current_gap_min, current_gap_max))
        current_gap_min = current_gap_max = None

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if re.fullmatch(r"[0-9A-Fa-f]{2}", t):
            if not in_literal:
                in_literal = True
                if seen_first_run:
                    add_gap()
                seen_first_run = True
        else:
            if in_literal:
                in_literal = False
                current_gap_min = current_gap_max = 0
            if t == "??":
                current_gap_min = (current_gap_min or 0) + 1
                current_gap_max = (current_gap_max or 0) + 1
            else:
                m = HEX_RANGE_RE.fullmatch(t)
                if m:
                    lo, hi = int(m.group(1)), int(m.group(2))
                    current_gap_min = (current_gap_min or 0) + lo
                    current_gap_max = (current_gap_max or 0) + hi
        i += 1

    seqs = []
    for idx, (gmin, gmax) in enumerate(gaps):
        if gmin == 1 and gmax == 1:
            op = "ONE_WILDCARD"
        else:
            op = f"RANGE_{gmin}_{gmax}"
        if idx + 1 < len(segment_ids):
            seqs.append({
                "from": segment_ids[idx],
                "to": segment_ids[idx+1],
                "op": op
            })
    return seqs

def is_plain_hex_without_wildcards(value):
    """True if it's pure hex bytes (no ?? or [m-n]). ex: AB CD AB.."""
    val = value.strip()
    val = val[1:-1] if val.startswith("{") and val.endswith("}") else val
    if HEX_WILDCARD_RE.search(val) or HEX_RANGE_RE.search(val):
        return False
    toks = re.split(r"\s+", val.strip()) if val.strip() else []
    return all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks) and len(toks) > 0

def is_numeric_matchtype(mt: str) -> bool:
    """Return True if match_type is a numeric string like '14'."""
    return bool(re.fullmatch(r"\d+", str(mt).strip()))


def _add_simple(groups_simple, gname, val, dt):
    g = groups_simple.setdefault(gname, {"match_type": "all", "strings": [], "_types": set()})
    # normalize hex/text spacing
    if dt == "hex":
        val = re.sub(r"\s+", " ", val.strip())
    else:
        val = val  # keep as-is for text
    g["strings"].append({"value": val, "data_type": dt})
    g["_types"].add(dt)

def _hex_le_bytes(value_hex: str, bits: int) -> str:
    """Devuelve string 'AA BB ...' en little-endian para el valor y tamaño indicado."""
    v = int(value_hex, 16)
    nbytes = {8:1, 16:2, 32:4}[bits]
    b = [(v >> (8*i)) & 0xFF for i in range(nbytes)]  # little-endian
    return " ".join(f"{x:02X}" for x in b)

def inject_magic_group(simple_groups: dict, cond_text: str):
    """
    Si hay tests de cabecera (uintX(0) == 0xNN...), añade grupo 'magic'
    con match_type='all' y data_type='hex'. Acumula varias comparaciones.
    """
    matches = list(MAGIC_RE.finditer(cond_text))
    if not matches:
        return

    # crea o reutiliza el grupo
    g = simple_groups.setdefault("magic", {"match_type":"all", "strings":[], "_types": set()})

    for m in matches:
        bits = int(m.group(1))
        hx   = m.group(2)
        val  = _hex_le_bytes(hx, bits)
        # evita duplicados exactos
        if not any(s["value"] == val and s["data_type"] == "hex" for s in g["strings"]):
            g["strings"].append({"value": val, "data_type": "hex"})
            g["_types"].add("hex")

#--------------------------------
#INTENTO 2
#-----------------------------

def _extract_leaves_for_groups(cond_text: str):
    """Devuelve lista de (span, group_name) desde hojas tipo 'any/all/N of ($pref*)' o '$id at N'."""
    leaves = []
    for m in LEAF_OF_RE.finditer(cond_text):
        pref = m.group(2)
        leaves.append((m.span(), pref))
    for m in AT_RE.finditer(cond_text):
        pref = m.group(1)
        # Si quieres preservar el anclaje, guarda también pos=m.group(2) y crea una hoja anchor_at
        leaves.append((m.span(), pref))
    leaves.sort(key=lambda x: x[0][0])
    return leaves

def _tokenize_to_bool(cond_text: str):
    leaves = _extract_leaves_for_groups(cond_text)
    mapping, out, i, k = {}, [], 0, 0
    for (s,e), g in leaves:
        out.append(cond_text[i:s])
        sym = f"X{k}"
        mapping[sym] = g  # g = group name
        out.append(sym)
        i = e; k += 1
    out.append(cond_text[i:])
    expr = "".join(out)
    # Normaliza operadores booleanos
    expr = re.sub(r'\bAND\b', ' & ', expr, flags=re.I)
    expr = re.sub(r'\bOR\b',  ' | ', expr, flags=re.I)
    expr = re.sub(r'\bNOT\b', ' ~ ', expr, flags=re.I)  # por si apareciera
    expr = re.sub(r'\s+', ' ', expr).strip()
    return expr, mapping

def condition_to_or_of_group_ands(cond_text: str):
    """
    Devuelve un dict de la forma:
    { "or": [ { "groups":[...], "operator":"and" }, ... ] }
    """
    expr, mapping = _tokenize_to_bool(cond_text)
    if not mapping:
        return None  # no se detectaron hojas compatibles
    # Prepara símbolos para sympy
    syms = {s: symbols(s) for s in mapping}
    # Eval segura: sólo símbolos Xk y &,|,~,(), espacios
    safe = expr
    for s in syms:
        safe = safe.replace(s, f"syms['{s}']")
    dnf = to_dnf(eval(safe), simplify=True)

    def clause_to_groups(cl):
        # cl puede ser un símbolo único o una conjunción And(...)
        if getattr(cl, "is_Symbol", False):
            return [mapping[str(cl)]]
        # And(...)
        seen, ordered = set(), []
        for arg in cl.args:
            g = mapping[str(arg)]
            if g not in seen:
                seen.add(g); ordered.append(g)
        # And: recopila todos los símbolos dentro
        return ordered

    # Convierte DNF a lista de bloques AND
    # Construye bloques (OR de ANDs en general)
    if dnf.func.__name__ == 'Or':
        blocks = [clause_to_groups(arg) for arg in dnf.args]
    else:
        blocks = [clause_to_groups(dnf)]

    # 🔧 FIX: si solo hay UN bloque, devuelve un AND plano (sin "or")
    if len(blocks) == 1:
        return {"groups": blocks[0], "operator": "and"}

    # Si hay varios bloques, sí usa "or"
    return {"or": [ {"groups": g, "operator": "and"} for g in blocks ]}

# ----------------------------
# Main conversion
# ----------------------------
def yara_to_default_dict(yara_path: str) -> dict:
    y = yaramod.Yaramod(yaramod.Features.AllCurrent)
    yr_file = y.parse_file(yara_path)

    result = {}

    for rule in yr_file.rules:
        rule_out = {"groups": {}, "conditions": []}

        # Containers
        simple_groups = {}   # prefix-based groups for plain strings/hex
        chain_groups = []    # list of {group_name, strings:[{id,value}], seqs:[{from,to,op}]}
        chain_counter = 0

        # Collect strings
        for s in rule.strings:
            if s.is_plain:
                # Plain text string
                dt = "string"
                val = clean_string_value(s.text)
                gname = extract_group_name(s.identifier)
                _add_simple(simple_groups, gname, val, "string")

            elif s.is_hex:
                raw = s.text  # includes braces
                tokens = split_hex_into_tokens(raw)

                if is_hex_with_wildcards_or_gaps(raw):
                    # Hex with wildcards/gaps -> build a "cadena" group with IDs and sequences in conditions
                    runs = contiguous_literal_runs(tokens)
                    if not runs:
                        # Ignore fully-wildcard patterns (rare)
                        continue
                    group_name = f"group{chain_counter}"
                    chain_counter += 1

                    id_list, strings_list = [], []
                    for idx, run in enumerate(runs):
                        sid = f"{group_name}_s{idx}"
                        id_list.append(sid)
                        strings_list.append({"id": sid, "value": run})

                    seqs = derive_sequence_ops(tokens, id_list)
                    chain_groups.append({"group_name": group_name, "strings": strings_list, "seqs": seqs})

                else:
                    # Pure hex without wildcards -> treat as a plain group by prefix
                    val = raw.strip()
                    val = val[1:-1] if val.startswith("{") and val.endswith("}") else val
                    gname = extract_group_name(s.identifier)
                    _add_simple(simple_groups, gname, val, "hex")

            else:
                # You can extend here for regex, wide, nocase, etc.
                continue

        # Deduce match_type for simple groups from the YARA rule condition
        cond_text = rule.condition.text.lower() if rule.condition else ""
        inject_magic_group(simple_groups, cond_text)
        for gname in list(simple_groups.keys()):
            all_pat = re.compile(rf"\ball of\s*\(\s*\${gname}\*", re.IGNORECASE)
            any_pat = re.compile(rf"\bany of\s*\(\s*\${gname}\*", re.IGNORECASE)
            n_of_them_pat = re.compile(r"\b(\d+)\s+of\s+them\b", re.IGNORECASE)

            if all_pat.search(cond_text):
                simple_groups[gname]["match_type"] = "all"
            elif any_pat.search(cond_text):
                simple_groups[gname]["match_type"] = "any"
            else:
                m = n_of_them_pat.search(cond_text)
                if m:
                    # In your model, numeric means "at least N"
                    simple_groups[gname]["match_type"] = m.group(1)
                else:
                    simple_groups[gname]["match_type"] = "all"

        # Emit chain groups (hex with wildcards/gaps)
        for cg in chain_groups:
            rule_out["groups"][cg["group_name"]] = {
                "match_type": "cadena",
                "data_type": "hex",
                "strings": cg["strings"]
            }
            # Sequences go ONLY under conditions, referencing IDs (no hex repetition)
            for seq in cg["seqs"]:
                rule_out["conditions"].append({
                    "sequence": {
                        "group": cg["group_name"],
                        "from": seq["from"],
                        "to": seq["to"],
                        "op": seq["op"]
                    }
                })

        # Emit simple groups
        for gname, gdata in simple_groups.items():
            types = gdata.pop("_types", set())
            items = gdata["strings"]

            if len(types) <= 1:
                # homogeneous -> keep legacy shape if quieres (solo valores) o ya per-item
                only_type = next(iter(types)) if types else "string"
                rule_out["groups"][gname] = {
                    "match_type": gdata["match_type"],
                    "data_type": only_type,
                    "strings": [it["value"] for it in items]  # <- legacy list of values
                    # si prefieres TODO per-item siempre, cambia por: "strings": items
                }
            else:
                # mixed -> per-item data_type
                rule_out["groups"][gname] = {
                    "match_type": gdata["match_type"],
                    "data_type": "mixed",
                    "strings": items  # [{ "value":..., "data_type":... }, ...]
                }

        # Build logical conditions:

        # ----nested boolean logic directly from the YARA condition AST
        
        logic_node = condition_to_or_of_group_ands(rule.condition.text) if rule.condition else None

        if logic_node:
            rule_out["conditions"].append(logic_node)
        else:
            all_simple = list(simple_groups.keys())
            if all_simple:
                rule_out["conditions"].append({"groups": all_simple, "operator": "and"})


        # Store this rule
        result[rule.name] = rule_out

    return result

# ----------------------------
# Run conversion for a file
# ----------------------------
if __name__ == "__main__":
    # Adjust this path to your YARA file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    yara_path = os.path.join(script_dir, "YARA", "Maldoc_PDF.yar")

    out = yara_to_default_dict(yara_path)
    print(json.dumps(out, indent=2, ensure_ascii=False))