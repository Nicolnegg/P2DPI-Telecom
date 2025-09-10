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
from urllib.parse import quote_from_bytes


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
    #ctr + k after crt + c -> comment
    #ctr + k after crt + u -> descomment

    #extortion_email
    # fake_email = (
    #     "From: admin@phishy.biz\n"
    #     "To: you@example.com\n"
    #     "Subject: Your account has been hacked! You need to unlock it.\n"
    #     "\n"
    #     "Be sure to read this message! Your personal data is threatened!\n"
    #     "We installed and now we have to your device.\n"
    #     "Send to this (BTC): bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
    #     "You have 24 to make the or your account will be suspended.\n"
    #     "This is your final warning. The will wipe your files.\n"
    # )

    # Email_generic_phishing
    # fake_email = (
    #     "From: admin@phishy.biz\n"
    #     "To: you@example.com\n"
    #     "Subject: Unauthorized access — verify now\n"
    #     "\n"
    #     "Hello sir/madam\n"
    #     "Attention\n"
    #     "Dear user\n"
    #     "Account holder\n"
    #     "\n"
    #     "Click Here Now to Confirm and Verify your identity and Change password.\n"
    #     "\n"
    #     "Your request was Unauthorized and your session is Expired. Some records were Deleted.\n"
    #     "Your account may be Suspended or Revoked, and we are Unable to proceed until you act.\n"
    # )

    #EK_Zeus
    # fake_email = (
    #     "HTTP/1.1 200 OK\n"
    #     "Content-Type: text/html; charset=utf-8\n\n"
    #     "<html><body>\n"
    #     "<script>\n"
    #     "position:absolute; z-index:99' !important;\n"
    #     " -1)jsmSetDisplayStyle('popupmenu' , 'none');\n"
    #     " '<tr><td><a href=\"#\">enlace</a></td></tr>\n"
    #     "  jsmLastMenu = 'popupmenu';\n"
    #     "  var ids = [1,2,3];\n"
    #     "this.target = '_blank';\n"
    #     " jsmPrevMenu, 'none');\n"
    #     "  if(jsmPrevMenu ) { /* demo */ }\n"
    #     ")if(MenuData[i]) { /* demo */ }\n"
    #     " '<div style=\"display:none\">oculto</div>\n"
    #     "popupmenu\n"
    #     "  jsmSetDisplayStyle('popupmenu' , 'block');\n"
    #     "function jsmHideLastMenu() { return; }\n"
    #     " MenuData.length; i++;\n"
    #     "</script>\n"
    #     "</body></html>\n"
    # )

    #Maldoc_Dridex - PHISH_02Dez2015_attach_P_ORD_C_10156_124658
    # ole = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")

    # fake_email =  (
    #     b"From: billing@corp.local\n"
    #     b"To: user@example.com\n"
    #     b"Subject: Attachment\n\n"
    # ) + ole + (
    #     b"\n<meta>sample</meta>\n"
    #     b"Execute\nProcess WriteParameterFiles\nWScript.Shell\nSTOCKMASTER\nInsertEmailFax\n"
    # )

    #Maldoc_Dridex - PHISH_02Dez2015_dropped_p0o6543f
    # mz = bytes.fromhex("4D 5A 90 00 03 00 00 00")
    # fake_email = (
    #     b"From: billing@corp.local\n"
    #     b"To: user@example.com\n"
    #     b"Subject: p0o6543f test\n"
    #     b"\n"
    #     + mz + b"\n"
    #     b"netsh.exe\n"
    #     b"routemon.exe\n"
    #     b"script=\n"
    #     b"disconnect\n"
    #     b"GetClusterResourceTypeKey\n"
    #     b"QueryInformationJobObject\n"
    #     b"interface\n"
    #     b"connect\n"
    #     b"FreeConsole\n"
    # )

    #Maldoc_Dridex - Dridex_Trojan_XML
    # fake_email = (
    #     "From: billing@corp.local\n"
    #     "To: user@example.com\n"
    #     "Subject: Dridex XML test\n"
    #     "\n"
    #     "<?xml version=\"1.0\"?>\n"
    #     "<?mso-application progid=\"Word.Document\"?>\n"
    #     "<w:document>\n"
    #     "  <w:macrosPresent=\"yes\"/>\n"
    #     "  <w:binData w:name=\"Object1\">QUJDRDEyMw==</w:binData>\n"
    #     "  <o:Characters>0</o:Characters> \n"
    #     "  <o:Lines>1</o:Lines> \n"
    #     "</w:document>\n"
    # )

    #Maldoc_VBA_macro_code - rule 1 
    # fake_email = (
    #     b"From: billing@corp.local\n"
    #     b"To: user@example.com\n"
    #     b"Subject: OLE VBA macro test\n"
    #     b"\n"
    #     b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\n"
    #     b"\x41\x74\x74\x72\x69\x62\x75\x74\x00\x65\x20\x56\x42\x5F"
    # )

    #Maldoc_VBA_macro_code - rule 2
    fake_email= (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: ZIP VBA macro test\n"
        b"\n"
        b"\x50\x4B\x03\x04\x14\x00\x08\x00\n"
        b"vbaProject.bin\n"
    )

    #WShell_ChinaChopper-rule1-1
    fake_email= (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: ChinaChopper ASPX test (len=10)\n"
        b"\n"
        b"\x25\x40\x20\x50\x61\x67\x65\x20\x4C\x61\x6E\x67\x75\x61\x67\x65\x3D"
        b"\x30"
        b"\x4A\x73\x63\x72\x31\x70\x74"
        b"\x55"
        b"\x25\x3E\x3C\x25\x65\x76\x61\x6C\x28\x52\x65\x71\x75\x65\x73\x74\x2E\x49\x74\x65\x6D\x5B"
        b"\x70\x61\x73\x73\x77\x6F\x72\x64\x22\x5D"
    )

    #WShell_ChinaChopper-rule1-2
    #fake_email = b"From: billing@corp.local\nTo: user@example.com\nSubject: ChinaChopper ASPX one-liner\n\n%@ Page Language=\"Jscript\"%><%eval(Request.Item[XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXunsafe)%>\n"



    data = (
        "username=alice"
        "&password=Nicol"
        "&pdf_hint=" + quote_from_bytes(b"%PDF-1.4 lorem ipsum") +
        "&message="  + quote_from_bytes(fake_email)
    ).encode("ascii")

    # data = {
    #     "username":"alice",
    #     "password":"Nicol",
    #     "pdf_hint":"%PDF-1.4 lorem ipsum",
    #     "message": fake_email
    # }

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
