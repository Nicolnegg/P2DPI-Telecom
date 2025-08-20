# sender/sender_https.py
#
# Purpose:
#   Proxy incoming client traffic, extract tokens in a deterministic way
#   (normalized sliding-8 + canonical tokens), encrypt them, send to MB,
#   and then forward the original request to the receiver.
#
# Important:
#   - Ensure encrypt_tokens DOES NOT lowercase or re-decode tokens; they arrive as bytes, already normalized.

from flask import Flask, request, Response
import requests
import random
import os

# New: import the orchestrator helpers instead of direct sliding window
from sender_utils import (
    normalize_view,           # bytes -> bytes (canonical view)
    emit_sliding8,            # bytes -> list[(offset:int, token8:bytes)]
    emit_canonical_tokens,    # bytes -> list[(offset:int, token8:bytes)]
    merge_tokens,             # (view, sliding, canon) -> list[bytes] in deterministic order (dedup per offset)
    encrypt_tokens,           # same signature as before; must NOT lowercase/decode internally
    load_ksr_from_file
)

app = Flask(__name__)

# === Certificate paths ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CA_CERT_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "ca", "certs", "ca.cert.pem"))
SENDER_CERT = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "ca", "certs", "sender.crt"))
SENDER_KEY = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "ca", "private", "sender.key"))

# === URL of the receiver service ===
RECEIVER_URL = "https://receiver.p2dpi.local:10443/"

# Debug flags (optional)
DEBUG_PRINT_TOKENS = True
DEBUG_PRINT_ENCRYPTED = False


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy():
    print("=== Incoming client request ===")

    # Raw payload as bytes
    payload = request.get_data()

    content_type = (request.headers.get("Content-Type") or "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        # En forms, '+' representa espacio. Antes de URL-decode, pásalo a 0x20.
        payload = payload.replace(b"+", b" ")

    try:
        # 1) Build canonical view: ASCII lowercase + intra-line whitespace collapse (+ optional URL-decode)
        view = normalize_view(payload)

        # 2) Sliding-8 tokens over the canonical view (offset, token8)
        sliding = emit_sliding8(view)

        # 3) Canonical tokens (offset, token8) — header names, short words, name=, and /name
        canonical = emit_canonical_tokens(view)

        # 4) Merge both sets into a single, deterministic sequence of token bytes.
        #    Deduplicate per offset: if a canonical token equals view[offset:offset+8], skip it.
        tokens = merge_tokens(view, sliding, canonical)

        if DEBUG_PRINT_TOKENS:
            for i, tok in enumerate(tokens):
                try_ascii = tok.decode("ascii", errors="ignore")
                print(f"[TOK{i:04d}] {tok.hex()}  |  ASCII: {try_ascii!r}")

        # 5) Encrypt tokens with current counter
        kSR = load_ksr_from_file()              # shared S↔R secret
        counter = random.randint(0, 2**32 - 1)  # nonce/counter for PRF
        encrypted_tokens = encrypt_tokens(tokens, kSR, counter=counter)

        if DEBUG_PRINT_ENCRYPTED:
            print(f"Counter used: {counter}")
            for i, ct in enumerate(encrypted_tokens):
                print(f"[CT{i:04d}] {ct.hex()}")

        # 6) Send encrypted tokens to the Middlebox
        tokens_hex = [t.hex() for t in encrypted_tokens]
        counter_hex = counter.to_bytes(4, "big").hex()

        mb_url = "http://localhost:9999/receive_tokens"
        try:
            mb_response = requests.post(
                mb_url,
                json={"encrypted_tokens": tokens_hex, "c": counter_hex},
                timeout=3
            )
            print(f"Sent tokens to MB, response status: {mb_response.status_code}")

            # MB verdict: non-200 => block, or status != ok => block
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

    # === Forward the original request to the receiver (unchanged app logic) ===
    try:
        structured_payload = {
            # NOTE: we send the final 8-byte tokens (plain) only for debugging at the receiver
            "tokens": [t.hex() for t in tokens],
            "counter": counter_hex,
            "payload": payload.hex(),          # raw original payload for the receiver
            "headers": dict(request.headers),
            "method": request.method
        }

        resp = requests.post(
            url=RECEIVER_URL,
            json=structured_payload,
            verify=CA_CERT_PATH,
            timeout=10
        )

        # Build response to the client
        response = Response(resp.content, status=resp.status_code)

        # Copy back non hop-by-hop headers
        excluded_headers = ['content-encoding', 'transfer-encoding', 'connection']
        for key, value in resp.headers.items():
            if key.lower() not in excluded_headers:
                response.headers[key] = value

        return response

    except Exception as e:
        print("Forwarding failed:", e)
        return Response("Forwarding error", status=502)


# Local helper endpoint to trigger a test POST (unchanged)
@app.route("/send_test_data", methods=["GET"])
def trigger_test_client_request():
    #BORRAR
    import requests
    data = {
        "username": "alice",
        "password": "Nicol",
        "pdf_hint": "%PDF-1.4 lorem ipsum"
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


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=(SENDER_CERT, SENDER_KEY)
    )
