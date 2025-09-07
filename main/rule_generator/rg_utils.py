"""
rg_utils.py — Tokenization helpers for RG, mirroring the Sender behavior.

What this module does:
- Normalize textual patterns like the Sender:
  * ASCII-lowercase (A..Z -> a..z), leave other bytes intact
  * (optional) URL-decode of ALL %xx sequences
  * collapse runs of spaces/tabs within each line to a single space (CR/LF preserved)
- Emit 8-byte tokens:
  * For strings:
      - If normalized len >= 8 -> all sliding-8 windows
      - If < 8 -> emit ONE canonical padded token when pattern matches:
          · "<name>:"      -> "<name>: " padded to 8 (header)
          · "/name"        -> "/name " padded to 8 (slash-name)
          · "name="        -> "name=" padded to 8
          · short word     -> "<word>" padded to 8
        Otherwise, return [] (we avoid tokens the Sender won’t ever emit).
  * For hex literals (pure hex bytes, no wildcards):
      - Parse to bytes and, if len >= 8, emit sliding-8 windows.
      - If len < 8, return [] (there is no general canonical padding for hex).
"""

from typing import List
from urllib.parse import unquote_to_bytes
import re

TOKEN_WINDOW_SIZE = 8

# Keep this flag in sync with Sender (set True only if Sender also decodes %xx globally)
ENABLE_URL_DECODE = True


# ---------- Normalization primitives (ASCII-only lowercase + optional URL-decode + collapse spaces) ----------

def _ascii_lower(b: int) -> int:
    """Lowercase ASCII A..Z only; leave other bytes untouched."""
    return b + 32 if 65 <= b <= 90 else b

def _url_decode_all(data: bytes) -> bytes:
    """
    Decode ALL %xx sequences across the byte stream.
    Round-trip via latin-1 to avoid unicode losses.
    """
    return unquote_to_bytes(data.decode("latin-1", errors="ignore"))

def _collapse_spaces_in_line(data: bytes) -> bytes:
    """
    Collapse consecutive spaces/tabs within the same line into a single space (0x20).
    Preserve CR/LF and reset the collapsing state after each newline.
    """
    out = bytearray()
    in_space = False
    for b in data:
        if b in (0x0D, 0x0A):     # CR or LF
            out.append(b)
            in_space = False
        elif b in (0x20, 0x09):   # space or tab
            if not in_space:
                out.append(0x20)
                in_space = True
        else:
            out.append(b)
            in_space = False
    return bytes(out)

def normalize_view_text(pattern: str) -> bytes:
    """
    Build the canonical view for a textual pattern:
      1) ASCII-lowercase (A..Z -> a..z)
      2) (optional) URL-decode ALL %xx
      3) Collapse spaces/tabs inline (CR/LF preserved)
    Returns bytes; callers can slice into 8-byte tokens safely.
    """
    raw = pattern.encode("latin-1", errors="ignore")
    lowered = bytes(_ascii_lower(b) for b in raw)
    if ENABLE_URL_DECODE:
        lowered = _url_decode_all(lowered)
    return _collapse_spaces_in_line(lowered)


# ---------- Token emission (strings) ----------

def _pad_to_8(b: bytes) -> bytes:
    """Right-pad with ASCII spaces to reach exactly 8 bytes; truncate if longer."""
    return b[:8] if len(b) >= 8 else b + b" " * (8 - len(b))

def emit_sliding8(view: bytes, size: int = TOKEN_WINDOW_SIZE) -> List[bytes]:
    """Return all contiguous 8-byte windows from a normalized view."""
    n = len(view)
    if n < size:
        return []
    return [view[i:i+size] for i in range(n - size + 1)]

def _emit_canonical_for_short(view: bytes) -> List[bytes]:
    """
    Emit ONE canonical padded token for short textual patterns (<8) matching known forms.
    Forms (already normalized to lowercase):
      - Header:  ^([a-z-]{1,15}):$
      - /name:   ^/([a-z0-9_]{1,7})$
      - name=:   ^([a-z0-9_]{1,7})=$
      - word:    ^([a-z0-9_]{1,7})$
    """
    text = view.decode("latin-1", errors="ignore")

    # Header "<name>:"
    m = re.fullmatch(r"([a-z-]{1,15}):", text)
    if m:
        base = (m.group(1) + ":").encode("latin-1")
        token = _pad_to_8(base + (b" " if len(base) < 8 else b""))  # prefer trailing space if it fits
        return [token]

    # Slash-name "/name"
    m = re.fullmatch(r"/([a-z0-9_]{1,7})", text)
    if m:
        base = ("/" + m.group(1)).encode("latin-1")
        token = _pad_to_8(base + (b" " if len(base) < 8 else b""))
        return [token]

    # name=
    m = re.fullmatch(r"([a-z0-9_]{1,7})=", text)
    if m:
        base = (m.group(1) + "=").encode("latin-1")
        return [_pad_to_8(base)]

    # Short word
    m = re.fullmatch(r"([a-z0-9_]{1,7})", text)
    if m:
        base = m.group(1).encode("latin-1")
        return [_pad_to_8(base)]

    # No canonical form recognized
    return []

def emit_tokens_for_pattern(pattern: str) -> List[bytes]:
    """
    Tokenize a textual pattern the same way the Sender will:
      - If normalized len >= 8 -> sliding-8 windows
      - Else -> ONE canonical padded token if form matches, else []
    """
    view = normalize_view_text(pattern)
    return emit_sliding8(view) if len(view) >= TOKEN_WINDOW_SIZE else _emit_canonical_for_short(view)



# --- Canonicalization for short (<8B) hex literals -----------------------------------------------
def _ascii_lower_bytes(data: bytes) -> bytes:
    """
    Apply ASCII lowercase (A..Z -> a..z) to raw bytes, leaving all other bytes intact.
    This mirrors the Sender's normalization on the byte view.
    """
    return bytes(_ascii_lower(b) for b in data)


def fuse_groups_by_base(dictionary):
    """
    Fuse groups that share the same base key.
    Example: If A group has base '706b03041400' and B group has base '706b01021400',
    they will be combined into a single entry.
    """
    fused_dict = {}
    seen = {}

    for group, values in dictionary.items():
        # Extract the base by removing the last 2 characters (which differ)
        base = values[0][:-2]

        if base not in seen:
            # Initialize with the current group
            seen[base] = group
            fused_dict[group] = values.copy()
        else:
            # If base already exists, merge into the first group
            fused_group = seen[base]
            fused_dict[fused_group].extend(values)

    return fused_dict


# --- Add these canonical 8-byte variants (right below your constants/imports) ---
# Canonical 8-byte expansions for common file magics
_MZ_8B     = bytes.fromhex("4D 5A 90 00 03 00 00 00")  # "MZ" + canonical tail
_CFB_8B    = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")  # Compound File Binary (OLE)
_PDF_8B_LIST = [  # %PDF-x.y  -> exactly 8 bytes each
    bytes.fromhex(h) for h in [
        "25 50 44 46 2D 31 2E 30",  # %PDF-1.0
        "25 50 44 46 2D 31 2E 31",
        "25 50 44 46 2D 31 2E 32",
        "25 50 44 46 2D 31 2E 33",
        "25 50 44 46 2D 31 2E 34",
        "25 50 44 46 2D 31 2E 35",
        "25 50 44 46 2D 31 2E 36",
        "25 50 44 46 2D 31 2E 37",
        "25 50 44 46 2D 32 2E 30",  # %PDF-2.0
    ]
]


_ZIP_8B_LIST = [
    bytes.fromhex(h) for h in [
        "50 4B 03 04 14 00 06 00",  # Local file header típico
        "50 4B 03 04 14 00 08 00",  # Variante compresión
        "50 4B 01 02 14 00 06 00",  # Central directory header
        "50 4B 05 06 00 00 00 00",  # End of central directory record
        "50 4B 06 06 00 00 00 00",  # ZIP64 end of central dir
        "50 4B 07 08 00 00 00 00",  # Data descriptor
    ]
]

# Flatten a single list of 8B candidates we can filter by prefix
_CANON_8B_VARIANTS = _PDF_8B_LIST + [_MZ_8B, _CFB_8B] + _ZIP_8B_LIST

# --- Replace your emit_tokens_for_hex_literal() with this version ---

def emit_tokens_for_hex_literal(hex_text: str) -> List[List[bytes]]:
    """
    Build 8-byte tokens from a hex literal, returning VARIANTS grouped by string.
    Each inner list corresponds to variants of a single string (match_type 'any').
    
    - If the provided hex is a short prefix of a known 8-byte magic (<8 bytes),
      return all canonical variants starting with that prefix, grouped together.
    - Otherwise:
      * If len(bytes) >= 8 -> return sliding-8 windows as a single group
      * If len(bytes) <  8 -> zero-pad to 8, return as single token group
    """
    s = hex_text.strip()
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1].strip()
    s = re.sub(r"\s+", " ", s).lower()
    s_hex = s.replace(" ", "")
    if any(c not in "0123456789abcdef" for c in s_hex):
        return []

    candidates: List[bytes] = []
    if len(s_hex) <= 16 and len(s_hex) > 0:
        for v in _CANON_8B_VARIANTS:
            if v.hex().startswith(s_hex):
                candidates.append(_ascii_lower_bytes(v))
        if candidates:
            # Return variants as a single group
            return [[c] for c in candidates]

    try:
        data = bytes.fromhex(s_hex)
    except ValueError:
        return []

    if len(data) >= TOKEN_WINDOW_SIZE:
        return [emit_sliding8(_ascii_lower_bytes(data))]

    padded = _ascii_lower_bytes(data + b"\x00" * (TOKEN_WINDOW_SIZE - len(data)))
    return [[padded]]
