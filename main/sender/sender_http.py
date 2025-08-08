# sender/sender_http.py

from flask import Flask, request, jsonify
from sender_utils import load_public_key, verify_signature, load_ksr_from_file, compute_intermediate_rules_hex

import os
import requests
import logging


app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# === Path to RG's public key ===
current_dir = os.path.dirname(os.path.abspath(__file__))
public_key_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'keys', 'rg_public_key.pem'))
rg_public_key = load_public_key(public_key_path)

MB_URL = "http://localhost:9999/receive_intermediate"


# === Endpoint: Receive rules from RG ===
@app.route('/receive_rules', methods=['POST'])
def receive_rules():
    data = request.json  # List of objects: {"obfuscated": str, "signature": str}
    if not data:
        return jsonify({"error": "No rules received"}), 400

    print("[Sender] Received", len(data), "rules.")

    for entry in data:
        Ri = entry.get("obfuscated")
        sig = entry.get("signature")
        if not Ri or not sig:
            return jsonify({"error": "Malformed rule entry"}), 400
        if not verify_signature(Ri, sig, rg_public_key):
            return jsonify({"error": "Signature verification failed"}), 400

    print("[Sender] All signatures verified.")

    # === Load kSR from file instead of hardcoded value ===
    try:
        kSR = load_ksr_from_file()
    except Exception as e:
        logging.error(f"Failed to load kSR: {e}")
        return jsonify({"error": f"Failed to load kSR: {str(e)}"}), 500

    # Compute intermediate rules with util function
    rules_hex = [entry["obfuscated"] for entry in data]
    try:
        intermediate_rules = compute_intermediate_rules_hex(rules_hex, kSR)
    except Exception as e:
        logging.error(f"Failed to compute intermediate rules: {e}")
        return jsonify({"error": f"Failed to compute intermediate rules: {str(e)}"}), 500

    logging.info("[Sender] Computed all intermediate rules.")

    # Send intermediate rules to MB
    try:
        response = requests.post(MB_URL, json={"sender_intermediate": intermediate_rules}, timeout=5)
        if response.status_code != 200:
            logging.error(f"MB responded with error code: {response.status_code}")
        else:
            logging.info(f"[Sender] Sent intermediate rules to MB. MB responded: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Failed to send intermediate rules to MB: {e}")

    return jsonify({"intermediate_rules": intermediate_rules}), 200

if __name__ == "__main__":
    app.run(port=11000)


