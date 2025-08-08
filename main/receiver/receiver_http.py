# receiver_http.py
# ----------------------------------
# Flask HTTP server used to receive obfuscated detection rules,
# verify their signature, compute intermediate rules, and forward to MB.

from flask import Flask, request, jsonify
from ctypes import c_char_p, create_string_buffer
from receiver_utils import (
    load_prf_library,
    load_h_fixed,
    load_ksr,
    load_public_key,
    verify_signature
)

import requests
import os

BUFFER_SIZE = 200

# Flask HTTP app instance
app = Flask("receiver_http")

# === Load PRF shared library, h_fixed, public key, and kSR ===
prf = load_prf_library()
h_fixed_hex = load_h_fixed()

# Load RG public key
current_dir = os.path.abspath(__file__)
public_key_path = os.path.abspath(os.path.join(os.path.dirname(current_dir), '..', 'shared', 'keys', 'rg_public_key.pem'))
rg_public_key = load_public_key(public_key_path)



def compute_intermediate_rules_hex(rules_hex, kSR_hex):
    """
    Compute intermediate rules I_i from obfuscated rules R_i using EC_POINT_exp_hex.

    Args:
        rules_hex (list): List of R_i values in hexadecimal string format.
        kSR_hex (str): The shared key kSR in hexadecimal string format.

    Returns:
        list: List of computed intermediate rules I_i as hex strings.

    Raises:
        RuntimeError: If EC_POINT_exp_hex computation fails for any rule.
    """
    results = []
    output_buffer = create_string_buffer(BUFFER_SIZE)

    for r in rules_hex:  # r is R_i in hexadecimal string format
        # Previously: prf.FKH_hex(c_char_p(r.encode()), ...)
        # Now: use EC_POINT_exp_hex to compute I_i = R_i ^ kSR
        res = prf.EC_POINT_exp_hex(
            c_char_p(r.encode()),          # R_i as ASCII hex (C will interpret correctly)
            c_char_p(kSR_hex.encode()),    # kSR as hex string
            output_buffer,                 # output buffer to store the resulting EC point
            BUFFER_SIZE                    # maximum buffer size
        )
        if res != 1:
            raise RuntimeError(f"EC_POINT_exp_hex failed for R_i: {r}")

        # Append the computed intermediate rule I_i (as hex string) to results
        results.append(output_buffer.value.decode())

    return results

# === Receive detection rules, verify, compute I_i, and send to MB ===
@app.route('/receive_rules', methods=['POST'])
def receive_rules():
    data = request.json
    if not data:
        return jsonify({"error": "No rules received"}), 400

    print(f"[Receiver] Received {len(data)} rules.")

    # Signature verification
    for entry in data:
        Ri = entry.get("obfuscated")
        sig = entry.get("signature")
        if not Ri or not sig:
            return jsonify({"error": "Malformed rule entry"}), 400
        if not verify_signature(Ri, sig, rg_public_key):
            return jsonify({"error": "Signature verification failed"}), 400
    print("[Receiver] All signatures verified.")

    # Load shared key kSR
    try:
        kSR = load_ksr()
    except Exception as e:
        print(f"[Receiver] Failed to load kSR: {e}")
        return jsonify({"error": "Failed to load kSR"}), 500

    # Prepare list of R_i values
    rules_hex = [r for r in (entry.get("obfuscated") for entry in data) if r]


    try:
        # Compute intermediate rules using the helper function
        intermediate_rules = compute_intermediate_rules_hex(rules_hex, kSR)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    print("[Receiver] Computed all intermediate rules.")

    # Send to Middlebox
    mb_url = "http://localhost:9999/receive_intermediate"
    try:
        response = requests.post(mb_url, json={"receiver_intermediate": intermediate_rules})
        print("[Receiver] Sent intermediate rules to MB. MB responded:", response.status_code)
    except Exception as e:
        print("[Receiver] Failed to send intermediate rules to MB:", e)

    return jsonify({"intermediate_rules": intermediate_rules}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
