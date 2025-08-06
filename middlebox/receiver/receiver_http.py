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

# Flask HTTP app instance
app = Flask("receiver_http")

# === Load PRF shared library, h_fixed, public key, and kSR ===
prf = load_prf_library()
h_fixed_hex = load_h_fixed()

# Load RG public key
current_dir = __file__
public_key_path = os.path.abspath(os.path.join(os.path.dirname(current_dir), '..', 'shared', 'keys', 'rg_public_key.pem'))
rg_public_key = load_public_key(public_key_path)

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

    # Compute intermediate rules
    output_buffer = create_string_buffer(200)
    intermediate_rules = []
    for entry in data:
        Ri = entry["obfuscated"]
        res = prf.FKH_hex(
            c_char_p(Ri.encode()),
            c_char_p(kSR.encode()),
            c_char_p(h_fixed_hex.encode()),
            output_buffer,
            200
        )
        if res != 1:
            return jsonify({"error": f"FKH failed for rule: {Ri}"}), 500
        Ii = output_buffer.value.decode()
        intermediate_rules.append(Ii)

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
