# middlebox/mb/mb_main.py
from flask import Flask, request, jsonify
import requests
from sniffer import start_sniff
import threading
from ctypes import CDLL, c_char_p, c_int, create_string_buffer
import os


app = Flask(__name__)

RULES = []
S_INTERMEDIATE = []
R_INTERMEDIATE = []
SESSION_RULES = []
kmb = None
kmb_buf = None  # Keep a reference so GC doesn't free the buffer


# === Load PRF (FKH_inv_hex) ===
current_dir = os.path.dirname(os.path.abspath(__file__))
prf_path = os.path.abspath(os.path.join(current_dir, '..', 'shared', 'prf.so'))
prf = CDLL(prf_path)

prf.FKH_inv_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_inv_hex.restype = c_int

prf.FKH_hex.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
prf.FKH_hex.restype = c_int

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

    # Opcional: enviar ahora las session rules a R y S si es parte del diseño

    # Limpieza
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
    

if __name__ == "__main__":
    # Start sniffer in background thread
    sniff_thread = threading.Thread(target=start_sniff, kwargs={
        "interface": "lo",
        "bpf_filter": "tcp port 8080"
    }, daemon=True)
    sniff_thread.start()

    print("[MB] Starting Flask server on port 9999...")
    app.run(port=9999)
