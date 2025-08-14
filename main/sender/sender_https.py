# sender/sender_https.py

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
RECEIVER_URL = "https://receiver.p2dpi.local:10443/"

@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy():
    print("=== Incoming client request ===")

    # === Get raw request payload ===
    payload = request.get_data()

    # === Extract and encrypt tokens ===
    try:
        tokens = extract_tokens_sliding_window(payload)  # Extract tokens using sliding window
        
        # BORRAR ESTO Imprime tokens extraídos en hex para debug
        for token in tokens:
            print(f"Token: {token.hex()} - ASCII: {token.decode(errors='ignore')}")

        
        kSR = load_ksr_from_file()  # Load shared secret key between Sender and Receiver
        counter = random.randint(0, 2**32 - 1)  # Random nonce/counter for PRF
        encrypted_tokens = encrypt_tokens(tokens, kSR, counter=counter)
        
        print(f"Counter used: {counter}")
        print("Encrypted tokens:")
        for t in encrypted_tokens:
            print(t.hex()) 

        # Send encrypted_tokens to the Middlebox 
        tokens_hex = [t.hex() for t in encrypted_tokens]
        counter_hex = counter.to_bytes(4, "big").hex()


        mb_url = "http://localhost:9999/receive_tokens"
        try:
            mb_response = requests.post(
                mb_url,
                json={
                    "encrypted_tokens": tokens_hex,
                    "c": counter_hex
                },
                timeout=3
            )
            print(f"Sent tokens to mb, response status: {mb_response.status_code}")
            
            # === Check MB verdict ===
            if mb_response.status_code != 200:
                print("MB responded with error, blocking request.")
                return Response("Blocked by middlebox", status=403)

            mb_data = mb_response.json()
            if mb_data.get("status") != "ok":
                print("MB detected rule match or suspicious traffic.")
                return Response("Blocked by middlebox", status=403)

        except requests.RequestException as e:
            print(f"Failed to send tokens to MB: {e}")
            return Response("Middlebox communication error", status=502)

    except Exception as e:
        print("Error in token processing:", e)
        return Response("Token processing error", status=500)

     # === Forward structured request to Receiver ===
    try:
        # Encapsulate data to send to receiver
        structured_payload = {
            "tokens": [t.hex() for t in tokens], #traffic without encription
            "counter": counter_hex,
            "payload": payload.hex(),  # send raw payload in hex string
            "headers": dict(request.headers),
            "method": request.method
        }

        # Send JSON to receiver
        resp = requests.post(
            url=RECEIVER_URL,
            json=structured_payload,
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
    
#==Change this payload for test
@app.route("/send_test_data", methods=["GET"])
def trigger_test_client_request():
    """
    Simulates a client request from inside the sender, manually triggered.
    """
    import requests

    data = {
        "username": "alice",
        "password": "tockens"
    }

    try:
        response = requests.post(
            "https://sender.p2dpi.local:8443/",
            data=data,
            verify=CA_CERT_PATH
        )
        return f"[LOCAL CLIENT] POST response: {response.text}", response.status_code

    except Exception as e:
        return f"[LOCAL CLIENT] Error: {str(e)}", 500

# === Run HTTPS server with Flask SSL context ===
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=(SENDER_CERT, SENDER_KEY)  # TLS server identity for client
    )
