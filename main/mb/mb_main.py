# middlebox/mb/mb_main.py
from flask import Flask, request, jsonify
import requests
from ctypes import cast, CDLL, c_char_p, c_int, create_string_buffer, c_ubyte, POINTER
import os
import hashlib
import struct


app = Flask(__name__)


RULES = []
S_INTERMEDIATE = []
R_INTERMEDIATE = []
SESSION_RULES = []
kmb = None
kmb_buf = None  # Keep a reference so GC doesn't free the buffer

RECEIVER_URL = "https://receiver.p2dpi.local:10443/store_tokens" 
CA_CERT_PATH = os.path.abspath(os.path.join('receiver', '..', 'ca', 'certs', 'ca.cert.pem'))
RECEIVER_DELETE_URL = "https://receiver.p2dpi.local:10443/delete_tokens" 

# === Load PRF (FKH_inv_hex) ===
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
prf = CDLL(prf_path)

prf.FKH_inv_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_inv_hex.restype = c_int

# int H2(const unsigned char *y_bytes, int y_len, const unsigned char *h_key, unsigned char *output)
prf.H2.argtypes = [
    POINTER(c_ubyte),  # y_bytes (input 16 bytes)
    c_int,             # y_len
    POINTER(c_ubyte),  # h_key (16 bytes)
    POINTER(c_ubyte),  # output (16 bytes)
]
prf.H2.restype = c_int

def load_h_fixed():
    global h_fixed
    try:
        shared_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shared'))
        h_path = os.path.join(shared_dir, 'h_fixed.txt')
        with open(h_path, "r") as f:
            h_fixed = f.read().strip()
        print(f"[MB] Loaded fixed point h from {h_path}")
    except Exception as e:
        print("[MB] Failed to load h_fixed:", e)

# Try loading existing key at startup
def load_kmb_from_file():
    global kmb, kmb_buf
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        keys_dir = os.path.join(current_dir, "keys")
        kmb_path = os.path.join(keys_dir, "kmb.key")
        with open(kmb_path, "rb") as f:
            kmb_bytes = f.read()
            kmb_hex_str = kmb_bytes.hex()  # Esto es la clave en ASCII hex
            kmb_buf = create_string_buffer(kmb_hex_str.encode())  # Buffer con ASCII hex
            kmb = c_char_p(kmb_buf.value)
            print(f"[MB] Loaded existing kMB as hex from {kmb_path}")
    except FileNotFoundError:
        print("[MB] No existing kMB key found on startup.")
    except Exception as e:
        print("[MB] Error loading kMB key:", e)

load_kmb_from_file()
load_h_fixed()

def h2_compute(counter_i, session_key_hex):
    """
    Compute H2((c+i), Sj) using the C function.
    counter_i: integer c+i (32-bit int)
    session_key_hex: full EC point Sj in hex (long hex string)
    Returns: 16-byte AES-ECB encrypted output as hex string
    """
    # Prepare input y_bytes: 4 bytes big-endian + 12 zero bytes
    y_bytes = struct.pack(">QQ", 0, counter_i)
    y_buf = create_string_buffer(y_bytes, 16)

    # Convert hex string point Sj to bytes
    sj_bytes = bytes.fromhex(session_key_hex)

    # Hash Sj bytes (e.g. SHA-256)
    hash_sj = hashlib.sha256(sj_bytes).digest()

    # Use first 16 bytes of hash as AES key
    h_key_bytes = hash_sj[:16]

    # Prepare h_key buffer
    h_key_buf = create_string_buffer(h_key_bytes, 16)

    # Output buffer (16 bytes)
    output_buf = create_string_buffer(16)

    # Call C H2 function
    success = prf.H2(
        cast(y_buf, POINTER(c_ubyte)),
        16,
        cast(h_key_buf, POINTER(c_ubyte)),
        cast(output_buf, POINTER(c_ubyte))
    )

    if not success:
        raise RuntimeError("H2 encryption failed")

    return output_buf.raw.hex()


# === Endpoint to receive and forward obfuscated rules ===
@app.route("/upload_rules", methods=["POST"])
def upload_rules():
    global RULES
    RULES = request.json
    print("[MB] Received rules:", RULES)

    # Forward to Receiver (R)
    try:
        r_response = requests.post("http://localhost:10000/receive_rules", json=RULES)
        print("[MB → R] Response:", r_response.status_code)
    except Exception as e:
        print("[MB → R] Error:", e)

    # Forward to Sender (S)
    try:
        s_response = requests.post("http://localhost:11000/receive_rules", json=RULES)
        print("[MB → S] Response:", s_response.status_code)
    except Exception as e:
        print("[MB → S] Error:", e)

    return "Rules received and forwarded to S and R", 200


@app.route("/receive_intermediate", methods=["POST"])
def receive_intermediate():
    global S_INTERMEDIATE, R_INTERMEDIATE, SESSION_RULES

    data = request.json
    if not data:
        return jsonify({"error": "No data received"}), 400

    if "sender_intermediate" in data:
        S_INTERMEDIATE = data["sender_intermediate"]
        print("[MB] Received intermediate rules from Sender:", S_INTERMEDIATE)
    elif "receiver_intermediate" in data:
        R_INTERMEDIATE = data["receiver_intermediate"]
        print("[MB] Received intermediate rules from Receiver:", R_INTERMEDIATE)
    else:
        return jsonify({"error": "Unknown sender"}), 400

    # === Only continue if both have arrived ===
    if not S_INTERMEDIATE or not R_INTERMEDIATE:
        print("[MB] One side received. Waiting for the other party...")
        return jsonify({"status": "Waiting for other party"}), 202

    # Normalize and compare
    s_norm = sorted([x.strip().lower() for x in S_INTERMEDIATE])
    r_norm = sorted([x.strip().lower() for x in R_INTERMEDIATE])

    if s_norm != r_norm:
        print("[MB] Intermediate rules from S and R do not match. Disconnecting.")
        # Clear to avoid reusing old ones
        S_INTERMEDIATE = []
        R_INTERMEDIATE = []
        return jsonify({"error": "Mismatch between S and R"}), 403

    print("[MB] Intermediate rules match. Computing session rules...")

    if kmb is None:
        print("[MB] ERROR: kMB is None. Aborting computation.")
        return jsonify({"error": "kMB not loaded"}), 500

    SESSION_RULES.clear()

    for Ii in s_norm:
        Ii_c = c_char_p(Ii.upper().encode())
        output_buffer = create_string_buffer(200)
        try:
            res = prf.FKH_inv_hex(Ii_c, kmb, output_buffer, 200)
            print(f"[MB] FKH_inv_hex returned: {res}")
        except Exception as e:
            print(f"[MB] Exception during FKH_inv_hex call: {e}")
            return jsonify({"error": f"PRF error: {str(e)}"}), 500

        if res != 1:
            print(f"[MB] FKH_inv_hex failed for Ii: {Ii}")
            return jsonify({"error": f"Failed to compute FKH_inv for Ii: {Ii}"}), 500

        Si = output_buffer.value.decode()
        SESSION_RULES.append(Si)

    print("[MB] Session rules:")
    for s in SESSION_RULES:
        print("  -", s)

    # Clean
    S_INTERMEDIATE = []
    R_INTERMEDIATE = []

    return jsonify({"status": "Intermediate rules processed", "session_rules": SESSION_RULES}), 200



# === Endpoint to receive and store kMB securely ===
@app.route("/receive_kmb", methods=["POST"])
def receive_kmb():
    global kmb, kmb_buf  # Keep a global reference to the key buffer and pointer

    kmb_hex = request.json.get("kmb")
    if not kmb_hex:
        return "Missing kMB", 400

    try:
        kmb_hex_str = kmb_hex.upper()  # ensure uppercase hex
        current_dir = os.path.dirname(os.path.abspath(__file__))
        keys_dir = os.path.join(current_dir, "keys")
        os.makedirs(keys_dir, exist_ok=True)

        kmb_path = os.path.join(keys_dir, "kmb.key")
        with open(kmb_path, "wb") as f:
            f.write(bytes.fromhex(kmb_hex_str))

        kmb_buf = create_string_buffer(kmb_hex_str.encode())
        kmb = c_char_p(kmb_buf.value)

        print(f"[MB] kMB saved in {kmb_path} and updated in memory.")
        return "kMB received", 200

    except Exception as e:
        print("[MB] Error in /receive_kmb:", e)
        return "Internal error", 500

# === Endpoint to receive encrypted tokens from Sender HTTPS ===
@app.route("/receive_tokens", methods=["POST"])
def receive_tokens():
    data = request.get_json()
    # Check if the request JSON contains both 'encrypted_tokens' and counter 'c'
    if not data or "encrypted_tokens" not in data or "c" not in data:
        return jsonify({"error": "Missing encrypted_tokens or counter c"}), 400

    tokens = data["encrypted_tokens"]  # List of encrypted tokens in hex format
    c_hex = data["c"]                  # Counter 'c' sent as hex string
    counter = int(c_hex, 16)           # Convert counter from hex string to integer
    print(f"[MB] Received {len(tokens)} encrypted tokens with counter c={counter}")

    # Perform detection 
    alert_raised = False

    # SESSION_RULES already contains the list of session keys Sj in hex format
    for i, Ti in enumerate(tokens):
        for j, Sj in enumerate(SESSION_RULES):
            # Compute H2(c + i, Sj) using the C function
            h2_val = h2_compute(counter + i, Sj)

            # Compare the computed H2 value with the received token (case-insensitive)
            if h2_val.lower() == Ti.lower():
                print(f"[ALERT] Match found! Token {i} matches H2(c+i, S{j})")
                alert_raised = True
                break
        if alert_raised:
            break
    
    if alert_raised:
        # immediately return a response indicating a malicious token was detected
        
        # Inform the Receiver to delete all stored tokens for this counter
        try:
            delete_payload = {
                "counter": c_hex  # Only the counter is needed now
            }
            delete_response = requests.post(
                RECEIVER_DELETE_URL,
                json=delete_payload,
                verify=CA_CERT_PATH,
                timeout=5
            )
            print(f"[MB ➜ R] Notify Receiver to delete tokens response: {delete_response.status_code} - {delete_response.text}")
        except Exception as e:
            print(f"[MB] Failed to notify Receiver about malicious tokens: {e}")
            
        return jsonify({
            "status": "alert",
            "message": "Malicious token detected. Transmission blocked."
        }), 403  # HTTP 403 Forbidden status code, or any other you prefer

    # Send tokens and counter to the Receiver to store them
    payload = {
        "tokens": tokens,
        "counter": c_hex
    }

    try:
        # Make a POST request to the Receiver's store_tokens endpoint
        response = requests.post(RECEIVER_URL, json=payload, verify=CA_CERT_PATH, timeout=5)
        print(f"[MB ➜ R] Store tokens response: {response.status_code} - {response.text}")

        if response.status_code != 200:
            print(f"[MB] Critical error: Receiver responded with status {response.status_code}")
            return jsonify({"error": "Failed to store tokens at Receiver"}), 500

    except Exception as e:
        print(f"[MB] Critical error sending tokens to Receiver: {e}")
        return jsonify({"error": "Critical failure sending tokens to Receiver"}), 500

    # Return alert if any match is detected, otherwise confirm no matches
    if alert_raised:
        return jsonify({"status": "alert"}), 200
    else:
        print("[MB] ✅ No matches found. Traffic considered safe.")
        return jsonify({"status": "ok"}), 200

# === Endpoint to receive alerts from Receiver indicating possible attack ===
@app.route("/validation", methods=["POST"])
def receive_alert_from_receiver():
    """
    Receives alert JSON from Receiver indicating possible attack or anomaly.
    """
    alert_data = request.get_json()

    if not alert_data:
        return jsonify({"error": "Missing alert data"}), 400

    print("\n[MB] ⚠️ ALERT RECEIVED FROM RECEIVER ⚠️")
    print("[MB] Details:", alert_data)

    return jsonify({"status": "Alert received"}), 200


if __name__ == "__main__":
    print("[MB] Starting Flask server on port 9999...")
    app.run(host="0.0.0.0", port=9999)

