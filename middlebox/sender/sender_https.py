from flask import Flask, request, Response
import requests
import random
from sender_utils import extract_tokens_sliding_window, encrypt_tokens, load_ksr_from_file
import os

app = Flask(__name__)

# === Certificate paths ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CA_CERT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "ca", "certs", "ca.cert.pem"))
SENDER_CERT = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "ca", "certs", "sender.crt"))
SENDER_KEY = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "ca", "private", "sender.key"))

# === URL of the receiver service ===
RECEIVER_URL = "https://receiver.p2dpi.local:9443/"

@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy():
    print("=== Incoming client request ===")

    # === Get raw request payload ===
    payload = request.get_data()

    # === Extract and encrypt tokens ===
    try:
        tokens = extract_tokens_sliding_window(payload)  # Extract tokens using sliding window
        kSR = load_ksr_from_file()  # Load shared secret key between Sender and Receiver
        counter = random.randint(0, 2**32 - 1)  # Random nonce/counter for PRF
        encrypted_tokens = encrypt_tokens(tokens, kSR, counter=counter)
        print("Encrypted tokens:", encrypted_tokens.hex())  # Display encrypted tokens in hex
        # Optionally: send encrypted_tokens to the Middlebox here
    except Exception as e:
        print("Error in token processing:", e)

    # === Forward original request to Receiver ===
    try:
        # Filter headers: avoid problematic ones like Host, Content-Length, etc.
        forward_headers = {
            key: value for key, value in request.headers.items()
            if key.lower() not in ['host', 'content-length', 'content-encoding']
        }

        # Send the request to the receiver with same method, data, and headers
        resp = requests.request(
            method=request.method,
            url=RECEIVER_URL,
            headers=forward_headers,
            data=payload,
            verify=CA_CERT_PATH,
            timeout=10
        )

        # Prepare response to send back to the client
        response = Response(resp.content, status=resp.status_code)

        # Copy back relevant headers (skip hop-by-hop headers)
        excluded_headers = ['content-encoding', 'transfer-encoding', 'connection']
        for key, value in resp.headers.items():
            if key.lower() not in excluded_headers:
                response.headers[key] = value

        return response

    except Exception as e:
        print("Forwarding failed:", e)
        return Response("Forwarding error", status=502)

# === Run HTTPS server with Flask SSL context ===
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=(SENDER_CERT, SENDER_KEY)  # TLS server identity for client
    )
