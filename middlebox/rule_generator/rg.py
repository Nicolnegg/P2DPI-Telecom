"""
Rule Generator (RG) for the P2DPI system.
This component uses a real PRF to encode detection rules,
and signs them before sending to the Middlebox (MB) for token-based inspection.
"""

from ctypes import CDLL, c_char_p, c_int, create_string_buffer
import requests
import os
from crypto_utils import load_private_key, sign_data

# Load PRF shared library (compiled C code)
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
print("[DEBUG] Loading PRF library from:", prf_path)
prf = CDLL(prf_path)

# Define argtypes and restype for FKH_hex
prf.FKH_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_hex.restype = c_int

# Randomization key kMB as hex string (must be chosen securely and shared with MB)
kmb_path = os.path.join(current_dir, 'keys', 'kmb.key')
with open(kmb_path, 'rb') as f:
    kmb = f.read()

K_MB_HEX = kmb.hex() 

# Load fixed point h from file
h_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'h_fixed.txt'))
with open(h_path, 'r') as f:
    h_fixed_hex = f.read().strip()

print("[DEBUG] Loaded fixed point h from:", h_path)


# Example detection rules
RULES = [
    {"id": "rule1", "pattern": "malicious-content"},
    {"id": "rule2", "pattern": "suspicious-token"},
    {"id": "rule3", "pattern": "cmd.exe"},
]

def obfuscate_rule_fkh(pattern: str, kmb_hex_str: str, h_fixed_hex: str) -> str:
    """
    Obfuscate a detection rule using the key-homomorphic PRF FKH from C.

    Args:
        pattern: The rule pattern string (ri).
        kmb_hex_str: The randomization key kMB as a hex string.
        h_fixed_hex: The fixed EC point h, in hexadecimal form.

    Returns:
        The obfuscated rule Ri as a hex string.
    """
    # Prepare key string: max 16 bytes padded with zeroes
    key_str = pattern.encode("utf-8")
    kmb_hex_bytes = kmb_hex_str.encode("utf-8")
    output_buffer = create_string_buffer(200)

    res = prf.FKH_hex(
        c_char_p(key_str),
        c_char_p(kmb_hex_bytes),
        c_char_p(h_fixed_hex.encode("utf-8")),
        output_buffer,
        200
    )
    if res != 1:
        raise RuntimeError(f"FKH_hex failed for pattern {pattern}")

    return output_buffer.value.decode()

# run before middlebox/mb/rule_receiver.py
def generate_and_send_rules(mb_url="http://localhost:9999/upload_rules"):
    session_rules = []
    print("[RG] Generating, obfuscating and signing rules...")

    # Load private RSA key once
    private_key = load_private_key(os.path.join(current_dir, 'keys', 'rg_private_key.pem'))

    for rule in RULES:
        # 1) Obfuscate the detection rule using the C PRF (FKH_hex)
        obf_rule = obfuscate_rule_fkh(rule["pattern"], K_MB_HEX, h_fixed_hex)

        # 2) Sign the obfuscated rule string using RSA-PSS
        signature = sign_data(obf_rule, private_key)

        # 3) Append obfuscated rule and signature to the list
        session_rules.append({
            "obfuscated": obf_rule,
            "signature": signature
        })

        print(f"[RG] Rule {rule['id']} obfuscated and signed.")

    # Send all rules to Middlebox
    try:
        print(f"[RG] Sending {len(session_rules)} rules to MB at {mb_url} ...")
        response = requests.post(mb_url, json=session_rules)
        print("[RG] MB response:", response.status_code, response.text)
    except Exception as e:
        print("[RG] Error sending rules to MB:", e)

if __name__ == "__main__":
    generate_and_send_rules()
