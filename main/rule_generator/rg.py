"""
rg.py — Rule Generator (RG) main script for P2DPI.

Responsibilities:
- Load PRF (FKH) shared library and constants (kMB, fixed h)
- Build 8-byte tokens for each rule pattern (using rg_utils)
- Obfuscate each token with FKH (key-homomorphic PRF)
- Sign each obfuscated token (RSA-PSS) and send to the Middlebox (MB)

"""

from ctypes import CDLL, c_char_p, c_int, create_string_buffer
import os
import requests

from crypto_utils import load_private_key, sign_data
from rg_utils import emit_tokens_for_pattern  # <-- our new tokenization utils

# --- Load PRF shared library (compiled C code) ---
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
print("[DEBUG] Loading PRF library from:", prf_path)
prf = CDLL(prf_path)

# Define argtypes and restype for FKH_hex (C function):
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

# --- Example detection rules (no IDs, only 'pattern') ---
RULES = [
    {"pattern": "to: "},          # short word -> canonical "to" + padding
    {"pattern": "Subject:"},  # header -> "subject:" (exact 8) or "subject: " (if you prefer)
    {"pattern": "/Action"},   # slash-name -> "/action " + padding
    {"pattern": "Array"},     # short word -> "array   "
    {"pattern": "%PDF-1.4"},  # >=8 -> sliding-8 (exactly one)
]

def obfuscate_token_fkh(token8: bytes, kmb_hex_str: str, h_fixed_hex: str) -> str:
    """
    Obfuscate a single 8-byte token using key-homomorphic PRF FKH from C.

    Args:
        token8:      8-byte token (bytes), already normalized and padded.
        kmb_hex_str: kMB as hex string.
        h_fixed_hex: fixed EC point h as hex string.

    Returns:
        Obfuscated token Ri as a hex string.
    """
    # IMPORTANT: do NOT lowercase/decode here; token8 is final.
    # CAUTION: we pass bytes via c_char_p. Ensure the C side does NOT rely on strlen,
    # but copies a fixed number of bytes (up to 16). Our tokens have no NULs, so it's OK here.
    output_buffer = create_string_buffer(200)
    res = prf.FKH_hex(
        c_char_p(token8),                         # raw bytes for the PRF input
        c_char_p(kmb_hex_str.encode("utf-8")),    # kMB hex
        c_char_p(h_fixed_hex.encode("utf-8")),    # h hex
        output_buffer,
        200
    )
    if res != 1:
        raise RuntimeError("FKH_hex failed for a token")

    return output_buffer.value.decode()  # ASCII hex string

def generate_and_send_rules(mb_url: str = "http://localhost:9999/upload_rules"):
    """
    Build, obfuscate, sign and POST all tokens from RULES to the Middlebox (MB).
    Payload format (list of dicts), no rule_id:
      [
        { "obfuscated": "<Ri-hex>", "signature": "<base64>" },
        ...
      ]
    """
    session_rules = []
    print("[RG] Generating, obfuscating and signing rules...")

    # Load private RSA key once (for RSA-PSS signatures)
    private_key = load_private_key(os.path.join(current_dir, 'keys', 'rg_private_key.pem'))

    # For each configured rule pattern, emit the exact tokens the Sender will generate
    for rule in RULES:
        raw_pattern = rule["pattern"]
        tokens8 = emit_tokens_for_pattern(raw_pattern)

        if not tokens8:
            print(f"[RG] Pattern '{raw_pattern}' did not produce tokens (short + non-canonical). Skipping.")
            continue

        for idx, tok in enumerate(tokens8):
            # 1) Obfuscate the 8-byte token with FKH
            obf_rule = obfuscate_token_fkh(tok, K_MB_HEX, h_fixed_hex)

            # 2) Sign obfuscated string (hex) with RSA-PSS
            signature_b64 = sign_data(obf_rule, private_key)

            # 3) Append to session list (no rule_id)
            session_rules.append({
                "obfuscated": obf_rule,
                "signature": signature_b64
            })

            dbg_ascii = tok.decode(errors="ignore")
            print(f"[RG] Token {idx} from pattern '{raw_pattern}' -> bytes {tok.hex()} (ASCII: '{dbg_ascii}') obfuscated and signed.")

    # Send all rules to Middlebox
    try:
        print(f"[RG] Sending {len(session_rules)} rules to MB at {mb_url} ...")
        response = requests.post(mb_url, json=session_rules, timeout=5)
        print("[RG] MB response:", response.status_code, response.text)
    except Exception as e:
        print("[RG] Error sending rules to MB:", e)

if __name__ == "__main__":
    generate_and_send_rules()
