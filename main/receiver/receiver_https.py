# receiver/receiver_https.py

from flask import Flask, request, jsonify, Response
from cryptography.fernet import Fernet
from receiver_utils import encrypt_tokens, load_ksr, load_prf_library, load_h_fixed, send_alert_to_middlebox


import os
import re


app = Flask("receiver_https")

# Path constants for encrypted kSR and encryption key storage
current_dir = os.path.dirname(os.path.abspath(__file__))
KSR_ENCRYPTED_PATH = os.path.abspath(os.path.join(current_dir, 'keys', 'shared_ksr.key'))
KSR_ENCRYPTION_KEY_PATH = os.path.abspath(os.path.join(current_dir, 'keys', 'key_for_ksr.key'))
CA_CERT_PATH = os.path.abspath(os.path.join('receiver', '..', 'ca', 'certs', 'ca.cert.pem'))

STORED_ENCRYPTED_TOKENS = []  
STORED_COUNTER = None
ENCRYPTED_TOKENS_RECEIVED = []

prf = load_prf_library()
h_fixed_hex = load_h_fixed()

try:
    kSR = load_ksr()
except Exception as e:
    print(f"[Receiver HTTPS] Failed to load kSR on startup: {e}")
    kSR = None

# Regular expression to match a valid hexadecimal string (case-insensitive)
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

# === Endpoint to securely receive and store the shared key (kSR) ===
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

# === Endpoint that receives traffic from the Sender and processes it as the final server ===
@app.route("/", methods=["POST"])
def handle_sender_request():
    """
    Main HTTPS endpoint at the Receiver.
    Processes requests from Sender containing encrypted tokens, a counter, and payload.
    Verifies tokens against those from the Middlebox; if valid, parses and responds with the payload data.
    The Receiver is the final server and handles the request directly without forwarding.
    """
    global ENCRYPTED_TOKENS_RECEIVED, STORED_ENCRYPTED_TOKENS, STORED_COUNTER

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

    try:
        # Convert tokens
        tokens_bytes = [bytes.fromhex(t) for t in tokens_hex]
        encrypted_tokens = encrypt_tokens(tokens_bytes, kSR, counter_int, prf, h_fixed_hex)
        ENCRYPTED_TOKENS_RECEIVED = [t.hex() for t in encrypted_tokens]

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

        # Compare tokens Ti and T'i
        for idx, (recv_t, ref_t) in enumerate(zip(ENCRYPTED_TOKENS_RECEIVED, STORED_ENCRYPTED_TOKENS)):
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

        # Reconstruct raw payload from hex string
        payload_bytes = bytes.fromhex(inner_payload)

        # Try to decode the payload as a URL-encoded form 
        try:
            form_data = {}
            raw_text = payload_bytes.decode(errors="ignore")  # Decode bytes to string
            for pair in raw_text.split("&"):  # Split into key-value pairs
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    form_data[k] = v
        except Exception as e:
            # If decoding fails, return raw hex string as fallback
            form_data = {"raw_payload": payload_bytes.hex()}

        # Print extracted form data (or raw data) for debugging
        print("Receiver (server) received POST data:", form_data)

        # Return the processed data back to the sender as JSON
        return jsonify({"status": "received", "data": form_data}), 200

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

# --- ENDPOINT TO DELETE MALICIOUS TOKENS SENT BY SENDER ---
@app.route("/delete_tokens", methods=["POST"])
def delete_tokens():
    """
    Deletes all stored tokens associated with a given counter, 
    effectively blocking that traffic.
    """

    global STORED_ENCRYPTED_TOKENS, STORED_COUNTER

    data = request.json
    counter = data.get("counter")  # hex string

    if counter is None:
        return jsonify({"error": "Missing counter"}), 400

    # Validate counter format (hex string)
    if not isinstance(counter, str) or not HEX_PATTERN.fullmatch(counter):
        return jsonify({"error": "Counter is not a valid hexadecimal string"}), 400

    # Check if there are stored tokens and a valid stored counter
    if not STORED_ENCRYPTED_TOKENS or STORED_COUNTER is None:
        return jsonify({
            "status": "No suspicious traffic stored",
            "message": "No tokens or traffic to delete"
        }), 200

    # Check if the stored counter matches the received counter
    if STORED_COUNTER != counter:
        return jsonify({"error": "Counter mismatch; cannot delete tokens"}), 409

    # Delete all stored tokens and reset the counter
    deleted_count = len(STORED_ENCRYPTED_TOKENS)
    STORED_ENCRYPTED_TOKENS = []
    STORED_COUNTER = None

    print(f"[Receiver HTTPS] Deleted all ({deleted_count}) stored tokens for counter {counter}")

    return jsonify({
        "status": "All tokens deleted",
        "deleted_count": deleted_count
    }), 200


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
