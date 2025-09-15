

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from ctypes import CDLL, c_char_p, c_int, create_string_buffer, c_ubyte, POINTER
from typing import List, Tuple
from urllib.parse import unquote_to_bytes


import struct
import os
import base64
import logging
import hashlib
import re

BUFFER_SIZE = 200
TOKEN_WINDOW_SIZE = 8

# Optional feature flags (tweak as needed)
ENABLE_URL_DECODE = True      # set True if you want URL-decode ALL %xx sequences
ENABLE_CANON_HEADERS = True
ENABLE_CANON_WORDS = True
ENABLE_CANON_NAMEEQ = True
ENABLE_CANON_SLASHNAME = True

# === Load PRF library (FKH_hex) from shared C code ===
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
prf = CDLL(prf_path)

prf.FKH_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_hex.restype = c_int

# Load H2 from the shared library
prf.H2.argtypes = [POINTER(c_ubyte), c_int, POINTER(c_ubyte), POINTER(c_ubyte)]
prf.H2.restype = c_int

prf.EC_POINT_exp_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
prf.EC_POINT_exp_hex.restype  = c_int

# === Load fixed session point h from file ===
h_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'h_fixed.txt'))
with open(h_path, 'r') as f:
    h_fixed_hex = f.read().strip()

# === Path to stored kSR key file ===
ksr_path = os.path.abspath(os.path.join(current_dir, "keys", "shared_ksr.key"))

def extract_tokens_sliding_window(payload: bytes, window_size=TOKEN_WINDOW_SIZE):
    """
    Extracts tokens from a byte payload using a sliding window algorithm.
    Each token is a slice of 'window_size' bytes, sliding by one byte each step.
    Args:
        payload (bytes): The input byte stream to tokenize.
        window_size (int): The fixed size of each token window (default 8).

    Returns:
        List[bytes]: A list of byte tokens extracted from the payload.
    """
    if len(payload) < window_size:
        return []
    return [payload[i:i+window_size] for i in range(len(payload) - window_size + 1)]


def encrypt_tokens(tokens, kSR_hex, counter):
    """
    Encrypt tokens as Ti = H2(c + i, (g^{H1(ti)} h)^{kSR}).
    Returns list of encrypted token bytes.
    """
    encrypted_tokens = []

    for i, token_bytes in enumerate(tokens):
        # Compute (g^{H1(ti)} * h)^{kSR} using FKH_hex

        # pass raw token bytes (not hex ASCII). C expects up to 16 raw bytes.
        key_buf = token_bytes[:16]               # same as strncpy(..., key_str, 16) in C
        output_buffer_fk = create_string_buffer(BUFFER_SIZE)

        res = prf.FKH_hex(
            c_char_p(key_buf),                   # raw bytes, not hex string
            c_char_p(kSR_hex.encode()),          # kSR as hex string (C uses BN_hex2bn)
            c_char_p(h_fixed_hex.encode()),      # h_fixed hex string
            output_buffer_fk,
            BUFFER_SIZE
        )

        if res != 1:
            raise RuntimeError(f"FKH_hex failed for token {i}")

        point_hex = output_buffer_fk.value.decode()
        
        # Convert EC point hex to bytes and hash it to get AES key
        point_bytes = bytes.fromhex(point_hex)
        hash_point = hashlib.sha256(point_bytes).digest()
        h2_key = (c_ubyte * 16).from_buffer_copy(hash_point[:16])

        # Prepare y = counter + i as 16-byte big endian
        y_int = counter + i
        # Pack into 16 bytes: upper 8 bytes zero, lower 8 bytes = y_int
        y_bytes = struct.pack(">QQ", 0, y_int) # payload of 0 for achieve the 16 bytes
        y_cbytes = (c_ubyte * 16).from_buffer_copy(y_bytes)

        # Call H2(y_bytes, 16, h2_key, output_buffer)
        output_h2 = (c_ubyte * 16)()
        success = prf.H2(y_cbytes, 16, h2_key, output_h2)
        if success != 1:
            raise RuntimeError(f"H2 encryption failed for token {i}")

        # Append encrypted token bytes to result list
        encrypted_tokens.append(bytes(output_h2))

    return encrypted_tokens

# === Load RG's public key ===
def load_public_key(path: str):
    try:
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except Exception as e:
        logging.error(f"Failed to load public key from {path}: {e}")
        raise

# === Verify RSA-PSS signature ===
def verify_signature(data: str, signature_b64: str, public_key) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError):
        return False

def compute_intermediate_rules_hex(rules_hex, kSR_hex):
    results = []
    output_buffer = create_string_buffer(BUFFER_SIZE)

    for r in rules_hex:  # r is Ri in hexadecimal string format
        # Previously: prf.FKH_hex(c_char_p(r.encode()), ...)
        # Now: use EC_POINT_exp_hex to compute I_i = Ri ^ kSR
        res = prf.EC_POINT_exp_hex(
            c_char_p(r.encode()),          # Ri as ASCII hex (C will interpret correctly)
            c_char_p(kSR_hex.encode()),    # kSR as hex string
            output_buffer,                 # output buffer to store the resulting EC point
            BUFFER_SIZE                    # maximum buffer size
        )
        if res != 1:
            raise RuntimeError(f"EC_POINT_exp_hex failed for Ri: {r}")

        # Append the computed intermediate rule I_i (as hex string) to results
        results.append(output_buffer.value.decode())

    return results
    
def load_ksr_from_file():
    if not os.path.exists(ksr_path):
        raise FileNotFoundError(f"kSR key file not found: {ksr_path}")
    with open(ksr_path, "r") as f:
        return f.read().strip()
    

def _ascii_lower(b: int) -> int:
    """Lowercase only ASCII A..Z; leave all other bytes unchanged."""
    return b + 32 if 65 <= b <= 90 else b


def _url_decode_all(data: bytes) -> bytes:

    return unquote_to_bytes(data.decode('latin-1', errors='ignore'))

def normalize_view(payload: bytes) -> bytes:
    """
    Build the canonical view of the payload:
      1) ASCII lowercase (A..Z -> a..z) only
      2)  URL-decode ALL %xx sequences
      3) Collapse spaces/tabs within a line into a single space (preserve CRLF)
    """
    lowered = bytes(_ascii_lower(b) for b in payload)
    if ENABLE_URL_DECODE:
        lowered = _url_decode_all(lowered)
    collapsed = _collapse_spaces_in_line(lowered)
    return collapsed

def _collapse_spaces_in_line(data: bytes) -> bytes:
    """
    Collapse consecutive spaces/tabs within the same line into a single space (0x20).
    Preserve CRLF bytes as-is and reset collapsing after each newline.
    """
    out = bytearray()
    in_space = False
    i = 0
    while i < len(data):
        b = data[i]
        if b in (0x0D, 0x0A):  # CR or LF: reset space state and pass through
            out.append(b)
            in_space = False
        elif b in (0x20, 0x09):  # space or tab
            if not in_space:
                out.append(0x20)  # write a single space
                in_space = True
            # else: skip additional spaces/tabs
        else:
            out.append(b)
            in_space = False
        i += 1
    return bytes(out)


def emit_sliding8(view: bytes, size: int = TOKEN_WINDOW_SIZE) -> List[Tuple[int, bytes]]:
    """
    Emit all contiguous windows of 'size' bytes from the canonical view.
    Returns a list of (offset, token8).
    """
    n = len(view)
    if n < size:
        return []
    return [(i, view[i:i+size]) for i in range(n - size + 1)]


def emit_canonical_tokens(view: bytes) -> List[Tuple[int, bytes]]:
    """
    Canonical tokens (rule-agnostic) that preserve punctuation when relevant:
      - Inline labels:   "<name>:"  -> "<name>: "  (padded to 8)
      - name=:           "<name>="  -> "<name>="   (padded to 8)
      - /name:           "/<name>"  -> "/<name> "  (padded to 8)
      - Short words:     "<word>"   -> "<word>"    (padded), BUT ONLY if next char is NOT ':' or '='
    """
    out: List[Tuple[int, bytes]] = []
    text = view.decode("latin-1", errors="ignore")
    n = len(text)

    def _pad_to_8(b: bytes) -> bytes:
        return b[:8] if len(b) >= 8 else b + b" " * (8 - len(b))

    # A) Inline labels ANYWHERE: ([a-z0-9_-]{1,15}):
    #    Prefer adding a single space after ':' when it fits (more robust).
    for m in re.finditer(r"([a-z0-9_-]{1,15}):", text):
        name = m.group(1)
        start = m.start(1)
        base = (name + ":").encode("latin-1")
        token = _pad_to_8(base + (b" " if len(base) < 8 else b""))
        out.append((start, token))

    # B) name= ANYWHERE (you already had this)
    for m in re.finditer(r"\b([a-z0-9_]{1,7})=", text):
        name = m.group(1)
        start = m.start(1)
        base = (name + "=").encode("latin-1")
        token = _pad_to_8(base)
        out.append((start, token))

    # C) /name ANYWHERE (you already had this)
    for m in re.finditer(r"/([a-z0-9_]{1,7})\b", text):
        name = m.group(1)
        start = m.start(0)  # include '/'
        base = ("/" + name).encode("latin-1")
        token = _pad_to_8(base + (b" " if len(base) < 8 else b""))
        out.append((start, token))

    # D') Short words with OPTIONAL 1-char punctuation prefix (generic)
    #     - Captures optional prefix from this set, then [a-z0-9_]{1,7}
    #     - Skips if the next char is ':' or '=' (A/B already handle those)
    PUNCT_PREFIX = r"[%#@$_/\.\-]"  # ajusta el set si lo necesitas
    pattern = rf"(?<![a-z0-9_])(?P<prefix>{PUNCT_PREFIX})?(?P<word>[a-z0-9_]{{1,7}})\b(?![:=])"

    for m in re.finditer(pattern, text):
        prefix = m.group('prefix') or ""
        word   = m.group('word')
        start  = m.start(0)  # incluye el prefijo si existe
        base   = (prefix + word).encode("latin-1")
        token  = _pad_to_8(base)
        out.append((start, token))

    return out


def merge_tokens(
    view: bytes,
    sliding: List[Tuple[int, bytes]],
    canonical: List[Tuple[int, bytes]]
) -> List[bytes]:
    # Index canonical tokens by offset
    # 1) Sliding-8 primero (contiguos para frases largas)
    tokens = [tok for _, tok in sliding]

    # 2) Luego canónicos (headers/short), evitando duplicados exactos
    slid_set = {tok for _, tok in sliding}
    for _, ctok in canonical:
        if ctok in slid_set:
            continue
        tokens.append(ctok)

    return tokens
