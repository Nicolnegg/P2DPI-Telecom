import os
import yaramod
import re
import json
from sympy import symbols
from sympy.logic.boolalg import to_dnf

# ----------------------------
# Utilities (regexes and helpers)
# ----------------------------
HEX_WILDCARD_RE = re.compile(r"\?\?")
HEX_RANGE_RE = re.compile(r"\[(\d+)-(\d+)\]")

LEAF_OF_RE = re.compile(r'\b(any|all|\d+)\s+of\s*\(\s*\$([A-Za-z0-9_]+)\*\s*\)', re.I)
AT_RE      = re.compile(r'\$([A-Za-z0-9_]+)\s+at\s+(\d+)', re.I)

MAGIC_RE = re.compile(r'uint(8|16|32)\s*\(\s*0\s*\)\s*==\s*0x([0-9a-fA-F]+)')
ID_RE = re.compile(r'\$([A-Za-z0-9_]+)(?!\*)')
IN_RANGE_RE   = re.compile(r'(\$[A-Za-z0-9_]+)\s+in\s*\(\s*\d+\s*\.\.\s*\d+\s*\)', re.I)
FILESIZE_RE   = re.compile(r'filesize\s*[<>=!]=?\s*\d+\s*(?:[KMG]?B)?', re.I)
UINT_EQ_RE    = re.compile(r'uint(?:8|16|32|64)\s*\(\s*\d+\s*\)\s*==\s*0x[0-9a-fA-F]+', re.I)
COUNT_RE      = re.compile(r'#\s*[A-Za-z0-9_]+\s*[<>=!]=?\s*\d+', re.I)
THEM_OF_RE = re.compile(r'\b(?:all|any|\d+)\s+of\s+them\b', re.I)

# Literal regexes (specific handling for PDF versions)
LITERAL_RX = re.compile(r'^/(?:[A-Za-z0-9 _:\.\-]|\\[()\/\\])+/$', re.ASCII)
PDF_VER_ALT_RX = re.compile(r'^/%PDF-1\\\.\((\d(?:\|\d)+)\)/$')
PDF_VER_DIGIT_RX = re.compile(r'^/%PDF-1(?:\\\.|\.)\\d\{1\}/$')
PDF_VER_RANGE_RX = re.compile(r'^/%PDF-1\\\.\[([0-9])\-([0-9])\]/$')

COUNT_CAPTURE_RE = re.compile(r'#\s*([A-Za-z0-9_]+)\s*([><]=?|==)\s*(\d+)', re.I)


def clean_string_value(yara_string):
    """
    Extracts the literal text from a quoted YARA string.
    Example: '"From:" nocase' -> 'From:'
    """
    m = re.match(r'"([^"]*)"', yara_string)
    return m.group(1) if m else yara_string


def _preclean_condition(text: str) -> str:
    """
    Light pre-clean of YARA condition text:
      - '$id in (a..b)'  -> keep '$id' (drop the location constraint)
      - 'uintX(off) == 0x...' -> replaced downstream by a dedicated 'magic' group
      - 'filesize ...'    -> replaced by True (we don't enforce filesize here)
    """
    t = text
    t = IN_RANGE_RE.sub(r'\1', t)
    t = UINT_EQ_RE.sub(' $magic ', t)
    t = FILESIZE_RE.sub(' True ', t)
    # Compact duplicate whitespace
    t = re.sub(r'\s+', ' ', t).strip()
    return t


def extract_group_name(identifier):
    """
    Extracts the alphanumeric/underscore prefix from a YARA string identifier
    to use it as a group name.
    Examples:
      $eml_1 -> 'eml'
      $create0 -> 'create'
      $97str1 -> '97str'
      $officemagic -> 'officemagic'
    """
    m = re.match(r"\$([A-Za-z0-9_]+?)(\d*)$", identifier.strip())
    if m:
        return m.group(1)
    return "default_group"
    

def is_hex_with_wildcards_or_gaps(hex_text):
    """Returns True if the hex pattern contains '??' or '[m-n]'."""
    return bool(HEX_WILDCARD_RE.search(hex_text) or HEX_RANGE_RE.search(hex_text))


def split_hex_into_tokens(hex_text):
    """
    Splits a hex string body '{ ... }' into tokens (hex bytes, '??', or '[m-n]').
    Returns a list of tokens as strings.
    """
    body = hex_text.strip()
    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1]
    body = re.sub(r"\s+", " ", body.strip())
    return body.split() if body else []


def contiguous_literal_runs(tokens):
    """
    From the token list, extracts contiguous literal runs (hex bytes only, i.e., no wildcards or ranges).
    Returns a list of strings like "AA BB CC".
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
    Builds sequence constraints (ops) for transitions between literal runs based on wildcards/ranges.
    Mapping:
      - '??'     -> increment gap by exactly 1
      - '[m-n]'  -> increment gap by range m..n
    Aggregates consecutive gaps into a single range per transition.
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
    """
    Returns True if the value is a pure hex sequence (no '??' or '[m-n]').
    Accepts either '{AA BB}' or 'AA BB' format.
    """
    val = value.strip()
    val = val[1:-1] if val.startswith("{") and val.endswith("}") else val
    if HEX_WILDCARD_RE.search(val) or HEX_RANGE_RE.search(val):
        return False
    toks = re.split(r"\s+", val.strip()) if val.strip() else []
    return all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks) and len(toks) > 0


def is_numeric_matchtype(mt: str) -> bool:
    """Returns True if match_type is a numeric string like '14'."""
    return bool(re.fullmatch(r"\d+", str(mt).strip()))


def _add_simple(groups_simple, gname, val, dt):
    """
    Adds a simple (non-chained) item into a prefix-based group.
    For hex, normalizes spacing; for strings, keeps as-is.
    Stores items as dicts with {'value', 'data_type'} and tracks types in '_types'.
    """
    g = groups_simple.setdefault(gname, {"match_type": "all", "strings": [], "_types": set()})
    if dt == "hex":
        val = re.sub(r"\s+", " ", val.strip())
    g["strings"].append({"value": val, "data_type": dt})
    g["_types"].add(dt)


def _hex_le_bytes(value_hex: str, bits: int) -> str:
    """
    Converts a numeric hex literal into a little-endian byte sequence string 'AA BB ...'
    for a given width (8/16/32 bits).
    """
    v = int(value_hex, 16)
    nbytes = {8:1, 16:2, 32:4}[bits]
    b = [(v >> (8*i)) & 0xFF for i in range(nbytes)]  # little-endian
    return " ".join(f"{x:02X}" for x in b)


def inject_magic_group(simple_groups: dict, cond_text: str):
    """
    If the condition contains tests like 'uintX(0) == 0xNN...', create/update group 'magic'
    (match_type='all', data_type='hex') and add the corresponding byte sequences.
    """
    matches = list(MAGIC_RE.finditer(cond_text))
    if not matches:
        return

    g = simple_groups.setdefault("magic", {"match_type":"all", "strings":[], "_types": set()})
    for m in matches:
        bits = int(m.group(1))
        hx   = m.group(2)
        val  = _hex_le_bytes(hx, bits)
        if not any(s["value"] == val and s["data_type"] == "hex" for s in g["strings"]):
            g["strings"].append({"value": val, "data_type": "hex"})
            g["_types"].add("hex")


# ----------------------------
# NEW helpers for count-as-repetition (your requested behavior)
# ----------------------------

def _all_items_are_short_strings(gdata: dict, max_len: int = 8) -> bool:
    """
    Returns True if ALL items in the group are text strings (data_type='string')
    and each has length < max_len. If mixed types (hex) or any string >= max_len,
    returns False.
    """
    for it in gdata["strings"]:
        if isinstance(it, dict):
            val, dt = it.get("value", ""), it.get("data_type", "string")
        else:
            val, dt = it, "string"
        if dt != "string" or len(val) >= max_len:
            return False
    return True


def _repeat_value(val: str, dt: str, times: int) -> str:
    """
    Repeats the literal N times. We only apply this to text strings by policy.
    For hex items, we keep the value as-is (no repetition) in this mode.
    """
    if dt == "hex":
        return val  # do NOT repeat hex here; repetition is only for short strings
    return val * times


def _apply_count_as_repetition_short_strings(gdata: dict, times: int, max_len: int = 8):
    """
    Replaces ONLY short text strings (len < max_len) by their N-times repeated value.
    Keeps other items untouched. Recomputes '_types'.
    """
    new_items, new_types = [], set()
    for it in gdata["strings"]:
        if isinstance(it, dict):
            val, dt = it["value"], it["data_type"]
        else:
            val, dt = it, "string"

        if dt == "string" and len(val) < max_len:
            new_val = _repeat_value(val, dt, times)
            new_items.append({"value": new_val, "data_type": dt})
        else:
            new_items.append({"value": val, "data_type": dt})
        new_types.add(dt)

    gdata["strings"] = new_items
    gdata["_types"] = new_types


# ----------------------------
# Leaves / boolean condition processing
# ----------------------------
def _extract_leaves_for_groups(cond_text: str):
    """
    Extracts references used to infer grouping in conditions:
      - any/all/N of ($pref*)
      - $id at N
      - $id (simple, without asterisk)
      - '#id op N' counters
      - 'all of them'
    Returns a list of (span, group_name).
    """
    leaves = []
    taken = []  # spans already occupied by higher-priority matches

    # 1) any/all/N of ($pref*)
    for m in LEAF_OF_RE.finditer(cond_text):
        pref = m.group(2)
        sp = m.span()
        leaves.append((sp, pref))
        taken.append(sp)

    # 2) $id at N
    for m in AT_RE.finditer(cond_text):
        pref = extract_group_name(f"${m.group(1)}") 
        sp = m.span()
        leaves.append((sp, pref))
        taken.append(sp)

    # 3) $id simple (no '*'), but skip those inside previous spans
    for m in ID_RE.finditer(cond_text):
        sp = m.span()
        if any(sp[0] >= a and sp[1] <= b for (a, b) in taken):
            continue
        pref = extract_group_name(f"${m.group(1)}")
        leaves.append((sp, pref))

    # 4) #id op N counts
    for m in COUNT_CAPTURE_RE.finditer(cond_text):
        sp = m.span()
        if any(sp[0] >= a and sp[1] <= b for (a, b) in taken):
            continue
        pref = extract_group_name(f"${m.group(1)}")
        leaves.append((sp, pref))
        taken.append(sp)

    # 5) 'all of them'
    for m in THEM_OF_RE.finditer(cond_text):
        sp = m.span()
        if any(sp[0] >= a and sp[1] <= b for (a, b) in taken):
            continue
        txt = m.group(0).lower()
        if txt.startswith("all"):
            leaves.append((sp, "__THEM_ALL__"))
            taken.append(sp)

    leaves.sort(key=lambda x: x[0][0])
    return leaves


def _tokenize_to_bool(cond_text: str):
    """
    Replaces group references by symbols Xk and returns a boolean expression string
    plus the mapping symbol -> group name. Also normalizes AND/OR/NOT.
    """
    cond_text = _preclean_condition(cond_text) 
    leaves = _extract_leaves_for_groups(cond_text)
    mapping, out, i, k = {}, [], 0, 0
    for (s,e), g in leaves:
        out.append(cond_text[i:s])
        sym = f"X{k}"
        mapping[sym] = g
        out.append(sym)
        i = e; k += 1
    out.append(cond_text[i:])
    expr = "".join(out)
    expr = re.sub(r'\bAND\b', ' & ', expr, flags=re.I)
    expr = re.sub(r'\bOR\b',  ' | ', expr, flags=re.I)
    expr = re.sub(r'\bNOT\b', ' ~ ', expr, flags=re.I)
    expr = re.sub(r'\s+', ' ', expr).strip()
    return expr, mapping


def condition_to_or_of_group_ands(cond_text: str, all_groups: list[str]):
    """
    Converts the YARA condition into a normalized JSON logic:
      - Plain AND: {"groups":[...], "operator":"and"}
      - OR of ANDs: {"or":[ {"groups":[...], "operator":"and"}, ... ]}
      - With NOT: wrap negatives as {"groups":[...], "operator":"not"} or {"and":[...]}
      - 'all of them' expands to all currently known simple groups.
    """
    expr, mapping = _tokenize_to_bool(cond_text)
    if not mapping:
        return None

    syms = {s: symbols(s) for s in mapping}
    safe = expr
    for s in syms:
        safe = safe.replace(s, f"syms['{s}']")
    dnf = to_dnf(eval(safe), simplify=True)

    def split_pos_neg_from_clause(clause):
        """
        Splits a DNF clause into positive and negative group lists.
        """
        pos, neg = [], []

        def add_lit(lit):
            if getattr(lit, "is_Symbol", False):
                pos.append(mapping[str(lit)])
            elif getattr(lit, "func", None).__name__ == "Not":
                sym = lit.args[0]
                neg.append(mapping[str(sym)])

        if getattr(clause, "is_Symbol", False) or getattr(clause, "func", None).__name__ == "Not":
            add_lit(clause)
        elif getattr(clause, "func", None).__name__ == "And":
            for arg in clause.args:
                add_lit(arg)

        # De-duplicate while preserving order
        def dedup(xs):
            seen, out = set(), []
            for g in xs:
                if g not in seen:
                    seen.add(g); out.append(g)
            return out

        return dedup(pos), dedup(neg)

    def _expand_specials(names: list[str]) -> list[str]:
        out = []
        for g in names:
            if g == "__THEM_ALL__":
                out.extend(all_groups)
            else:
                out.append(g)
        seen, ded = set(), []
        for g in out:
            if g not in seen:
                seen.add(g); ded.append(g)
        return ded

    def block_to_node(pos, neg):
        """Builds a JSON node for one AND block with positives and/or negatives."""
        pos = _expand_specials(pos)
        nodes = []
        if pos:
            nodes.append({"groups": pos, "operator": "and"})
        if neg:
            nodes.append({"groups": neg, "operator": "not"})
        if not nodes:
            return {"groups": [], "operator": "and"}  # Edge case
        if len(nodes) == 1:
            return nodes[0]
        return {"and": nodes}

    if dnf.func.__name__ == "Or":
        blocks = [block_to_node(*split_pos_neg_from_clause(arg)) for arg in dnf.args]
        return {"or": blocks}
    else:
        pos, neg = split_pos_neg_from_clause(dnf)
        node = block_to_node(pos, neg)
        return node


# ----------------------------
# Main conversion
# ----------------------------
def yara_to_default_dict(yara_path: str) -> dict:
    """
    Parses a YARA file and emits a normalized dict with:
      - groups: prefix-based simple groups and 'cadena' chain groups for hex with gaps
      - conditions: logical structure referencing groups and/or sequence constraints
    """
    y = yaramod.Yaramod(yaramod.Features.AllCurrent)
    yr_file = y.parse_file(yara_path)

    result = {}

    for rule in yr_file.rules:
        rule_out = {"groups": {}, "conditions": []}

        # Containers
        simple_groups = {}   # prefix groups for plain strings/hex
        chain_groups = []    # list of {group_name, strings:[{id,value}], seqs:[{from,to,op}]}
        chain_counter = 0
        skip_rule = False   

        # Collect strings/hex/regex from the rule
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
                    # Hex with wildcards/ranges -> create a chain group with literal runs and sequence ops
                    runs = contiguous_literal_runs(tokens)
                    if not runs:
                        # Fully wildcard pattern: ignore (rare)
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
                    # Pure hex without wildcards -> treat as a simple group (by prefix)
                    val = raw.strip()
                    val = val[1:-1] if val.startswith("{") and val.endswith("}") else val
                    gname = extract_group_name(s.identifier)
                    _add_simple(simple_groups, gname, val, "hex")
            
            elif getattr(s, "is_regexp", False):
                raw = s.text.strip()

                # 2.1) PDF headers with numeric alternatives: /%PDF-1\.(3|4|6)/
                m_ver = PDF_VER_ALT_RX.match(raw)
                if m_ver:
                    nums = m_ver.group(1).split('|')              # ["3","4","6"]
                    values = [f"%PDF-1.{n}" for n in nums]        # ["%PDF-1.3", ...]
                    gname = extract_group_name(s.identifier)      # usually "ver" or similar
                    g = simple_groups.setdefault(gname, {"match_type":"all", "strings":[], "_types": set()})
                    for v in values:
                        if not any(it["value"] == v and it["data_type"] == "string" for it in g["strings"]):
                            g["strings"].append({"value": v, "data_type": "string"})
                            g["_types"].add("string")
                    # Force 'any' for version alternatives
                    g["match_type"] = "any"
                    g["_forced_match"] = True
                    continue

                # 2.1b) PDF with a single version digit: /%PDF-1\.\d{1}/
                if PDF_VER_DIGIT_RX.match(raw):
                    values = [f"%PDF-1.{d}" for d in range(10)]  # 1.0 .. 1.9
                    gname = extract_group_name(s.identifier)
                    g = simple_groups.setdefault(gname, {"match_type":"all","strings":[],"_types":set()})
                    for v in values:
                        if not any(it["value"]==v and it["data_type"]=="string" for it in g["strings"]):
                            g["strings"].append({"value": v, "data_type": "string"})
                            g["_types"].add("string")
                    g["match_type"] = "any"
                    g["_forced_match"] = True
                    continue

                # 2.1c) PDF with version range: /%PDF-1\.[3-7]/
                m_rng = PDF_VER_RANGE_RX.match(raw)
                if m_rng:
                    lo = int(m_rng.group(1))
                    hi = int(m_rng.group(2))
                    values = [f"%PDF-1.{d}" for d in range(lo, hi+1)]
                    gname = extract_group_name(s.identifier)
                    g = simple_groups.setdefault(gname, {"match_type":"all", "strings":[], "_types": set()})
                    for v in values:
                        if not any(it["value"] == v and it["data_type"] == "string" for it in g["strings"]):
                            g["strings"].append({"value": v, "data_type": "string"})
                            g["_types"].add("string")
                    g["match_type"] = "any"
                    g["_forced_match"] = True
                    continue

                # 2.2) Regex that is actually a literal -> treat as plain string
                if LITERAL_RX.match(raw):
                    body = raw[1:-1]                 # strip /…/
                    body = (body
                        .replace(r"\/", "/")
                        .replace(r"\(", "(")
                        .replace(r"\)", ")")
                        .replace(r"\\", "\\"))
                    gname = extract_group_name(s.identifier)
                    _add_simple(simple_groups, gname, body, "string")
                    continue

                # 2.3) Unsupported regex -> skip whole rule (conservative)
                skip_rule = True
                break
            else:
                continue

        if skip_rule:
            continue  

        # Deduce match_type for simple groups from the YARA condition text
        cond_text = rule.condition.text.lower() if rule.condition else ""
        inject_magic_group(simple_groups, cond_text)

        for gname in list(simple_groups.keys()):
            # Honor forced 'any' (e.g., PDF versions)
            if simple_groups[gname].get("_forced_match"):
                continue

            # Detect "N of ($gname*)"
            n_of_group_pat = re.compile(rf'\b(\d+)\s+of\s*\(\s*\${re.escape(gname)}\*', re.IGNORECASE)
            mN = n_of_group_pat.search(cond_text)
            if mN:
                simple_groups[gname]["match_type"] = mN.group(1)  # e.g., "2"
                continue

            # Detect "#gname op N" counters
            count_pat = re.compile(rf'#\s*{re.escape(gname)}\s*([><]=?|==)\s*(\d+)', re.IGNORECASE)
            mcount = count_pat.search(cond_text)
            if mcount:
                op = mcount.group(1)   # operator: ">", ">=", "==", "<", etc.
                N  = int(mcount.group(2))

                # Requested policy:
                # - If ALL items are text strings and each has length < 8:
                #       repeat the literal N times and set match_type = "1".
                # - Else:
                #       keep match_type = N and keep original strings untouched.
                if _all_items_are_short_strings(simple_groups[gname], max_len=8):
                    repeat = N  # For "#shell > 10" you asked for "A * 10" with match_type "1".
                                 # If you want strict '>' semantics, use N+1 here instead.
                    _apply_count_as_repetition_short_strings(simple_groups[gname], repeat, max_len=8)
                    simple_groups[gname]["match_type"] = "1"
                    simple_groups[gname]["_count_as_repeat"] = {"op": op, "N": N, "repeat": repeat}
                else:
                    simple_groups[gname]["match_type"] = str(N)
                    simple_groups[gname]["_count_kept_numeric"] = {"op": op, "N": N, "reason": "not all short strings"}

                continue

            # Default deduction for "all/any of ($gname*)", or fallback to 'all'
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
            # Sequence constraints go under conditions, referencing string IDs
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
                # Homogeneous type -> keep legacy shape (values only) if desired
                only_type = next(iter(types)) if types else "string"
                rule_out["groups"][gname] = {
                    "match_type": gdata["match_type"],
                    "data_type": only_type,
                    "strings": [it["value"] for it in items]  # legacy list of values
                }
            else:
                # Mixed types -> keep per-item objects with data_type
                rule_out["groups"][gname] = {
                    "match_type": gdata["match_type"],
                    "data_type": "mixed",
                    "strings": items  # [{ "value":..., "data_type":... }, ...]
                }

        # Build logical conditions node from YARA condition AST
        logic_node = condition_to_or_of_group_ands(rule.condition.text, list(simple_groups.keys())) if rule.condition else None
        if logic_node:
            rule_out["conditions"].append(logic_node)
        else:
            # Fallback: AND of all simple groups if no condition was found
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
    yara_path = os.path.join(script_dir, "YARA", "extortion_email.yar")

    out = yara_to_default_dict(yara_path)

    # Write result to JSON near this script
    out_path = os.path.join(script_dir, "diccioner.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[OK] Wrote JSON to: {out_path}")
