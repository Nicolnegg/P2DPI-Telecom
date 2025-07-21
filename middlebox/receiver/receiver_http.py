# receiver_http.py
# ----------------------------------
# Flask HTTP server used to receive obfuscated detection rules,
# verify their signature, compute intermediate rules, and forward to MB.

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from ctypes import CDLL, c_char_p, c_int, create_string_buffer
import os, base64, requests

# Flask HTTP app instance
app = Flask("receiver_http")

# === Load PRF shared library ===
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
prf = CDLL(prf_path)
prf.FKH_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_hex.restype = c_int

# === Load RG public key ===
def load_public_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

public_key_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'keys', 'rg_public_key.pem'))
rg_public_key = load_public_key(public_key_path)

# === Load encrypted kSR from disk ===
def load_ksr():
    base_dir = os.path.join(current_dir, 'keys')
    ksr_path = os.path.join(base_dir, "shared_ksr.key")
    key_path = os.path.join(base_dir, "key_for_ksr.key")

    if not os.path.exists(ksr_path) or not os.path.exists(key_path):
        raise ValueError("Missing kSR or encryption key")

    with open(key_path, "rb") as f:
        key = f.read()
    cipher_suite = Fernet(key)

    with open(ksr_path, "rb") as f:
        encrypted_ksr = f.read()

    return cipher_suite.decrypt(encrypted_ksr).decode()

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

# === Receive detection rules, verify, compute I_i, and send to MB ===
@app.route('/receive_rules', methods=['POST'])
def receive_rules():
    data = request.json
    if not data:
        return jsonify({"error": "No rules received"}), 400

    print(f"[Receiver] Received {len(data)} rules.")

    for entry in data:
        Ri = entry.get("obfuscated")
        sig = entry.get("signature")
        if not Ri or not sig:
            return jsonify({"error": "Malformed rule entry"}), 400
        if not verify_signature(Ri, sig, rg_public_key):
            return jsonify({"error": "Signature verification failed"}), 400
    print("[Receiver] All signatures verified.")

    try:
        kSR = load_ksr()
    except Exception as e:
        print(f"[Receiver] Failed to load kSR: {e}")
        return jsonify({"error": "Failed to load kSR"}), 500

    output_buffer = create_string_buffer(200)
    intermediate_rules = []

    for entry in data:
        Ri = entry["obfuscated"]
        res = prf.EC_POINT_exp_hex(Ri.encode(), kSR.encode(), output_buffer, 200)
        if res != 1:
            return jsonify({"error": f"FKH failed for rule: {Ri}"}), 500
        Ii = output_buffer.value.decode()
        intermediate_rules.append(Ii)

    print("[Receiver] Computed all intermediate rules.")

    mb_url = "http://localhost:9999/receive_intermediate"
    try:
        response = requests.post(mb_url, json={"receiver_intermediate": intermediate_rules})
        print("[Receiver] Sent intermediate rules to MB. MB responded:", response.status_code)
    except Exception as e:
        print("[Receiver] Failed to send intermediate rules to MB:", e)

    return jsonify({"intermediate_rules": intermediate_rules}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)