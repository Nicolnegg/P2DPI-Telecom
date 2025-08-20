"""
rg_utils.py — Helper utilities for the Rule Generator (RG).

This module keeps the tokenization logic aligned with the Sender:
- ASCII-only lowercase normalization
- (optional) URL-decode of ALL %xx sequences
- in-line whitespace collapsing (CR/LF preserved)
- sliding-8 tokens for strings >= 8 bytes
- canonical single 8-byte token for short patterns (< 8) in well-known forms:
    * "<header>:"  -> "<header>: " + space + pad to 8
    * "/name"      -> "/name " + pad to 8
    * "name="      -> "name=" + pad to 8
    * short word   -> "word" + pad to 8

NOTE:
- For short patterns that do NOT match any canonical form, we return no tokens.
  This avoids generating tokens that the Sender will never emit (preventing mismatches).
"""

from typing import List
from urllib.parse import unquote_to_bytes
import re

# --- Feature flags (keep in sync with Sender) ---
ENABLE_URL_DECODE = True      # True -> URL-decode ALL %xx sequences before tokenization
TOKEN_WINDOW_SIZE = 8          # fixed window for sliding tokens

# --- Normalization helpers (ASCII lowercase + optional URL-decode + collapse spaces) ---

def _ascii_lower(b: int) -> int:
    """Lowercase only ASCII A..Z; leave all other bytes unchanged."""
    return b + 32 if 65 <= b <= 90 else b

def _url_decode_all(data: bytes) -> bytes:
    """
    Decode ALL %xx sequences. Does NOT map '+' to space (that only applies to forms).
    Uses latin-1 round-trip to avoid data loss.
    """
    return unquote_to_bytes(data.decode('latin-1', errors='ignore'))

def _collapse_spaces_in_line(data: bytes) -> bytes:
    """
    Collapse consecutive spaces/tabs within the same line into a single space (0x20).
    Preserve CR/LF bytes as-is and reset collapsing after each newline.
    """
    out = bytearray()
    in_space = False
    for b in data:
        if b in (0x0D, 0x0A):                 # CR or LF
            out.append(b)
            in_space = False
        elif b in (0x20, 0x09):               # space or tab
            if not in_space:
                out.append(0x20)              # single space
                in_space = True
            # else: drop extra spaces/tabs
        else:
            out.append(b)
            in_space = False
    return bytes(out)

def normalize_view(text_pattern: str) -> bytes:
    """
    Build the canonical view for a rule pattern string:
      1) ASCII lowercase (A..Z -> a..z)
      2) (optional) URL-decode ALL %xx sequences
      3) Collapse spaces/tabs per line (CR/LF preserved)
    Returns bytes; callers can slice into 8-byte tokens safely.
    """
    # Encode as latin-1 to keep a 1:1 mapping of characters->bytes for ASCII rules.
    raw = text_pattern.encode('latin-1', errors='ignore')

    # Step 1: ASCII lowercase
    lowered = bytes(_ascii_lower(b) for b in raw)

    # Step 2: optional URL-decode ALL %xx
    if ENABLE_URL_DECODE:
        lowered = _url_decode_all(lowered)

    # Step 3: collapse spaces/tabs per line
    collapsed = _collapse_spaces_in_line(lowered)
    return collapsed

# --- Token emission ---

def _pad_to_8(b: bytes) -> bytes:
    """Pad with ASCII spaces to reach exactly 8 bytes; truncate if longer."""
    return b[:8] if len(b) >= 8 else b + b" " * (8 - len(b))

def emit_sliding8(view: bytes, size: int = TOKEN_WINDOW_SIZE) -> List[bytes]:
    """
    Emit all contiguous windows of 'size' bytes from the normalized view.
    Returns a list of 8-byte tokens (bytes objects).
    """
    n = len(view)
    if n < size:
        return []
    return [view[i:i+size] for i in range(n - size + 1)]

def _emit_canonical_for_short(view: bytes) -> List[bytes]:
    """
    Emit a single canonical 8-byte token for short patterns (< 8) that match
    well-known textual forms. Returns [] if no canonical form applies.

    Forms recognized (already normalized to lowercase):
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
        # Prefer adding one space after ":" when it fits (robust match in headers)
        token = _pad_to_8(base + (b" " if len(base) < 8 else b""))
        return [token]

    # Slash-name "/name"
    m = re.fullmatch(r"/([a-z0-9_]{1,7})", text)
    if m:
        base = ("/" + m.group(1)).encode("latin-1")
        # Prefer a trailing space if it still fits in 8
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

    # No canonical form recognized -> return no tokens
    return []

def emit_tokens_for_pattern(pattern: str) -> List[bytes]:
    """
    From a raw pattern string, build the list of 8-byte tokens the RG must obfuscate:
      - If normalized length >= 8: return all sliding-8 windows
      - Else (<8): return a single canonical token if the pattern matches a known form
                   (header, /name, name=, word). Otherwise, return [].

    This mirrors what the Sender will generate, preventing false mismatches.
    """
    view = normalize_view(pattern)
    if len(view) >= TOKEN_WINDOW_SIZE:
        return emit_sliding8(view)
    else:
        return _emit_canonical_for_short(view)
