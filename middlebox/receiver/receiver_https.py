# receiver/receiver_https.py

from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import os
import threading

app = Flask("receiver_https")

# Path constants for encrypted kSR and encryption key storage
KSR_ENCRYPTED_PATH = "keys/shared_ksr.key"
KSR_ENCRYPTION_KEY_PATH = "keys/key_for_ksr.key"

@app.route("/receive_ksr", methods=["POST"])
def receive_ksr():
    """
    Receives the shared key (kSR) securely via HTTPS.
    Encrypts it using Fernet symmetric encryption and stores it safely.
    """
    try:
        data = request.json
        ksr = data.get("ksr")
        if not ksr:
            return jsonify({"error": "Missing kSR"}), 400

        # Ensure the keys directory exists
        keys_dir = os.path.dirname(os.path.abspath(KSR_ENCRYPTED_PATH))
        os.makedirs(keys_dir, exist_ok=True)

        # Load or generate the encryption key
        if os.path.exists(KSR_ENCRYPTION_KEY_PATH):
            with open(KSR_ENCRYPTION_KEY_PATH, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(KSR_ENCRYPTION_KEY_PATH, "wb") as f:
                f.write(key)
            os.chmod(KSR_ENCRYPTION_KEY_PATH, 0o600)  # Secure permissions

        cipher_suite = Fernet(key)

        # Encrypt the received kSR
        encrypted_ksr = cipher_suite.encrypt(ksr.encode())
        with open(KSR_ENCRYPTED_PATH, "wb") as f:
            f.write(encrypted_ksr)
        os.chmod(KSR_ENCRYPTED_PATH, 0o600)  # Secure permissions

        print("[Receiver HTTPS] Securely received and stored encrypted kSR.")
        return jsonify({"status": "kSR received securely"}), 200

    except Exception as e:
        print(f"[Receiver HTTPS] Error storing kSR: {e}")
        return jsonify({"error": "Internal server error"}), 500


def run_https():
    """
    Starts the HTTPS Flask server on port 10443 with TLS certificates.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.abspath(os.path.join(current_dir, '..', '..', 'ca', 'certs', 'receiver.crt'))
    key_path = os.path.abspath(os.path.join(current_dir, '..', '..', 'ca', 'private', 'receiver.key'))

    app.run(host="0.0.0.0", port=10443, ssl_context=(cert_path, key_path))


if __name__ == "__main__":
    run_https()
