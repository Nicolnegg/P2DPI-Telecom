# receiver/receiver_https.py

from flask import Flask, request, jsonify, Response
from cryptography.fernet import Fernet
from receiver_utils import encrypt_tokens, load_ksr, load_prf_library, load_h_fixed, send_alert_to_middlebox


import os
import requests
import re


app = Flask("receiver_https")

# Path constants for encrypted kSR and encryption key storage
current_dir = os.path.dirname(os.path.abspath(__file__))
KSR_ENCRYPTED_PATH = os.path.abspath(os.path.join(current_dir, 'keys', 'shared_ksr.key'))
KSR_ENCRYPTION_KEY_PATH = os.path.abspath(os.path.join(current_dir, 'keys', 'key_for_ksr.key'))
REAL_SERVER_URL = "https://server.p2dpi.local:9443/" 
CA_CERT_PATH = os.path.abspath(os.path.join('receiver', '..', 'ca', 'certs', 'ca.cert.pem'))

STORED_ENCRYPTED_TOKENS = []  
STORED_COUNTER = None
ENCRYPTED_TOKENS_EXPECTED = []

prf = load_prf_library()
h_fixed_hex = load_h_fixed()

try:
    kSR = load_ksr()
except Exception as e:
    print(f"[Receiver HTTPS] Failed to load kSR on startup: {e}")
    kSR = None

# Regular expression to match a valid hexadecimal string (case-insensitive)
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

@app.route("/receive_ksr", methods=["POST"])
def receive_ksr():
    """
    Receives the shared key (kSR) securely via HTTPS.
    Encrypts it using Fernet symmetric encryption and stores it safely.
    """
    global kSR
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

        kSR = ksr
        print("[Receiver HTTPS] Securely received and stored encrypted kSR.")
        return jsonify({"status": "kSR received securely"}), 200

    except Exception as e:
        print(f"[Receiver HTTPS] Error storing kSR: {e}")
        return jsonify({"error": "Internal server error"}), 500

# === Endpoint que recibe tráfico del sender y lo reenvía al servidor real ===
@app.route("/", methods=["POST"])
def handle_sender_request():
    """
    Receives a request from Sender containing both tokens and traffic.
    1. Encrypts and compares the tokens {ti} with stored {T'i}.
    2. If they match, forwards the payload to the real server.
    3. If mismatch, alerts the Middlebox and blocks the forwarding.
    """
    global ENCRYPTED_TOKENS_EXPECTED, STORED_ENCRYPTED_TOKENS, STORED_COUNTER

    # Parse JSON body
    try:
        json_data = request.get_json()
        tokens_hex = json_data.get("tokens")
        counter = json_data.get("counter")
        inner_payload = json_data.get("payload")  # Expected to be base64 or raw
        inner_headers = json_data.get("headers", {})
        method = json_data.get("method", "POST")
    except Exception as e:
        return jsonify({"error": "Invalid JSON format"}), 400

    # Check required fields
    if not tokens_hex or counter is None or inner_payload is None:
        return jsonify({"error": "Missing tokens, counter or payload"}), 400
    if kSR is None:
        return jsonify({"error": "kSR not loaded"}), 500

    # After extracting counter from json
    try:
        counter_int = int(counter, 16)  # Convert from hex string to int
    except ValueError:
        return jsonify({"error": "Invalid counter format"}), 400

    
    print(f"[DEBUG] kSR = {kSR}")
    print(f"[DEBUG] h_fixed_hex = {h_fixed_hex}")
    print(f"[DEBUG] prf functions loaded: {dir(prf)}")

    try:
        # Convert tokens
        tokens_bytes = [bytes.fromhex(t) for t in tokens_hex]
        encrypted_tokens = encrypt_tokens(tokens_bytes, kSR, counter_int, prf, h_fixed_hex)
        ENCRYPTED_TOKENS_EXPECTED = [t.hex() for t in encrypted_tokens]

        print("[Receiver HTTPS] Encrypted tokens received:")
        for t in ENCRYPTED_TOKENS_EXPECTED:
            print(t)
            
        print("[Receiver HTTPS] Stored tokens from MB:")
        for t in STORED_ENCRYPTED_TOKENS:
            print(t)

        # Check if reference tokens exist
        if not STORED_ENCRYPTED_TOKENS or STORED_COUNTER is None:
            return jsonify({"error": "No reference tokens available"}), 400

        # Compare counter
        if counter != STORED_COUNTER:
            alert_message = {
                "alert": "Counter mismatch",
                "received_counter": counter,
                "expected_counter": STORED_COUNTER
            }
            send_alert_to_middlebox(alert_message)
            return jsonify({"status": "ALERT: Counter mismatch"}), 403

        # Compare tokens
        for idx, (recv_t, ref_t) in enumerate(zip(ENCRYPTED_TOKENS_EXPECTED, STORED_ENCRYPTED_TOKENS)):
            if recv_t != ref_t:
                alert_message = {
                    "alert": "Token mismatch",
                    "index": idx,
                    "received": recv_t,
                    "expected": ref_t
                }
                send_alert_to_middlebox(alert_message)
                return jsonify({"status": "ALERT: Token mismatch"}), 403

        print("[Receiver HTTPS] Tokens validated successfully. Forwarding to real server.")

        # Prepare headers and send to real server
        excluded_headers = ['host', 'content-length', 'content-encoding', 'transfer-encoding', 'connection']
        forward_headers = {k: v for k, v in inner_headers.items() if k.lower() not in excluded_headers}

        # Reconstruct raw payload
        payload_bytes = bytes.fromhex(inner_payload)

        # Forward to real server
        response = requests.request(
            method=method,
            url=REAL_SERVER_URL,
            headers=forward_headers,
            data=payload_bytes,
            verify=CA_CERT_PATH,
            timeout=10
        )

        # Return response from real server
        resp = Response(response.content, status=response.status_code)
        for key, value in response.headers.items():
            if key.lower() not in excluded_headers:
                resp.headers[key] = value

        return resp

    except Exception as e:
        print(f"[Receiver HTTPS] Error: {e}")
        return jsonify({"error": "Internal error"}), 500
    
# --- ENDPOINT TO RECEIVE AND STORE ENCRYPTED TOKENS AND COUNTER FROM MIDDLEBOX ---
@app.route("/store_tokens", methods=["POST"])
def store_tokens():
    """
    Receives encrypted tokens {T'i} and counter c from the Middlebox (MB),
    stores them in memory for later use.
    """

    global STORED_ENCRYPTED_TOKENS, STORED_COUNTER

    # get json data from the request
    data = request.json

    # extract 'tokens' list and 'counter' hex string from json
    tokens = data.get("tokens")  # list of hex strings
    counter = data.get("counter")  # hex string counter

    # check if tokens or counter are missing, return error if so
    if not tokens or counter is None:
        return jsonify({"error": "Missing tokens or counter"}), 400

    # validate counter is a valid hex string
    if not isinstance(counter, str) or not HEX_PATTERN.fullmatch(counter):
        return jsonify({"error": "Counter is not a valid hexadecimal string"}), 400

    # validate all tokens are valid hex strings
    for t in tokens:
        if not isinstance(t, str) or not HEX_PATTERN.fullmatch(t):
            return jsonify({"error": f"Token '{t}' is not a valid hexadecimal string"}), 400

    # store the received tokens and counter in global variables
    STORED_ENCRYPTED_TOKENS = tokens
    STORED_COUNTER = counter

    # log the storage action
    print(f"[Receiver HTTPS] Stored {len(tokens)} encrypted tokens with counter {counter}")

    # return success status to the middlebox
    return jsonify({"status": "Tokens stored successfully"}), 200

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
