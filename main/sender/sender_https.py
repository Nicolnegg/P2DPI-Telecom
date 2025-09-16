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
import sys

import binascii
import html
from pathlib import Path
from urllib.parse import quote_from_bytes

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.append(str(_PROJECT_ROOT))

from main.shared.config import env_path, env_str


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
CA_CERT_PATH = env_path("CA_CERT_PATH", "./ca/certs/ca.cert.pem")
SENDER_CERT = env_path("SENDER_CERT", "./ca/certs/sender.crt")
SENDER_KEY = env_path("SENDER_KEY", "./ca/private/sender.key")
RECEIVER_URL = env_str("RECEIVER_URL", "https://127.0.0.1:10443/")
MB_URL = env_str("MB_URL", "http://127.0.0.1:9999/receive_tokens")
SENDER_PUBLIC_URL = env_str("SENDER_PUBLIC_URL", "https://127.0.0.1:8443/")
# Debug flags (optional)
DEBUG_PRINT_TOKENS = True
DEBUG_PRINT_ENCRYPTED = False


def bytes_to_display(b: bytes, max_len: int = 2048) -> str:
    """
    Produce a readable preview for arbitrary bytes:
    - ASCII-printable characters shown
    - non-printables escaped
    - also include a hex-dump line for short content
    Truncates at max_len bytes for safety.
    """
    if not isinstance(b, (bytes, bytearray)):
        b = bytes(b)

    truncated = False
    if len(b) > max_len:
        b = b[:max_len]
        truncated = True

    # Try to produce a mostly-human readable ascii with escapes
    parts = []
    for c in b:
        if 32 <= c <= 126:  # printable ASCII
            parts.append(chr(c))
        elif c in (9, 10, 13):  # tab, lf, cr -> keep as is for readability
            parts.append(chr(c))
        else:
            parts.append(f"\\x{c:02x}")

    ascii_view = "".join(parts)
    # Hex view (grouped)
    hex_view = b.hex()
    # make grouped hex (pairs with spaces)
    hex_grouped = " ".join(hex_view[i:i+2] for i in range(0, len(hex_view), 2))

    trailer = ("\n\n[TRUNCATED]" if truncated else "")
    return f"--- ASCII/escaped view ---\n{ascii_view}\n\n--- Hex (bytes) ---\n{hex_grouped}{trailer}"


# ---------------------------
# Scenario menu configuration (expanded)
# ---------------------------
# All scenarios return bytes payloads suitable to be URL-encoded into the test form.

def _scenario_clean_simple_email() -> bytes:
    """Benign: plain text email body (no attacks)."""
    return (
        b"From: hr@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: Team update\n\n"
        b"Hi team,\nThis is a normal announcement email.\nThanks!"
    )

def _scenario_clean_form_login() -> bytes:
    """Benign: looks like a login form post (for tokenization sanity checks)."""
    return (
        b"From: webapp@corp.local\n"
        b"To: api@example.com\n"
        b"Subject: Form submit\n\n"
        b"username=alice&action=submit&note=hello"
    )

def _scenario_html_generic() -> bytes:
    """Benign: small HTML page to exercise canonical tokens like tags/attrs."""
    return (
        b"From: web@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: HTML sample\n\n"
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body><h1>Sample</h1><a href=\"/inbox\">Inbox</a></body></html>"
    )

# ---- Phishing / extortion themed tests (non-operational, for MB detection only)
def _scenario_extortion_email() -> bytes:
    """Exercise common ransom/extortion wording and a BTC-like pattern (non-operational)."""
    return (
        b"From: admin@phishy.biz\n"
        b"To: you@example.com\n"
        b"Subject: Your account has been hacked! You need to unlock it.\n\n"
        b"Be sure to read this message! Your personal data is threatened!\n"
        b"We installed and now we have to your device.\n"
        b"Send to this (BTC): bc1qexampleexampleexample0000000000\n"
        b"You have 24 to make the or your account will be suspended.\n"
        b"This is your final warning. The will wipe your files.\n"
    )

def _scenario_email_generic_phishing() -> bytes:
    """Generic phishing wording to trigger rules (no links actually functional)."""
    return (
        b"From: admin@phishy.biz\n"
        b"To: you@example.com\n"
        b"Subject: Unauthorized access \xe2\x80\x94 verify now\n\n"
        b"Hello sir/madam\n"
        b"Attention\n"
        b"Dear user\n"
        b"Account holder\n\n"
        b"Click Here Now to Confirm and Verify your identity and Change password.\n\n"
        b"Your request was Unauthorized and your session is Expired. Some records were Deleted.\n"
        b"Your account may be Suspended or Revoked, and we are Unable to proceed until you act.\n"
    )

# ---- EK/HTML/JS themed
def _scenario_ek_zeus() -> bytes:
    """HTML/JS snippet with noisy tokens often seen in EK-like traffic samples (synthetic)."""
    return (
        b"HTTP/1.1 200 OK\n"
        b"Content-Type: text/html; charset=utf-8\n\n"
        b"<html><body>\n"
        b"<script>\n"
        b"position:absolute; z-index:99' !important;\n"
        b" -1)jsmSetDisplayStyle('popupmenu' , 'none');\n"
        b" '<tr><td><a href=\"#\">enlace</a></td></tr>\n"
        b"  jsmLastMenu = 'popupmenu';\n"
        b"  var ids = [1,2,3];\n"
        b"this.target = '_blank';\n"
        b" jsmPrevMenu, 'none');\n"
        b"  if(jsmPrevMenu ) { /* demo */ }\n"
        b")if(MenuData[i]) { /* demo */ }\n"
        b" '<div style=\"display:none\">oculto</div>\n"
        b"popupmenu\n"
        b"  jsmSetDisplayStyle('popupmenu' , 'block');\n"
        b"function jsmHideLastMenu() { return; }\n"
        b" MenuData.length; i++;\n"
        b"</script>\n"
        b"</body></html>\n"
    )

# ---- Dridex / maldoc themed (headers/markers only for testing)
def _scenario_dridex_attach_ole() -> bytes:
    """Email with OLE magic bytes inline to simulate attachment marker."""
    ole = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")
    return (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: Attachment\n\n"
    ) + ole + (
        b"\n<meta>sample</meta>\n"
        b"Execute\nProcess WriteParameterFiles\nWScript.Shell\nSTOCKMASTER\nInsertEmailFax\n"
    )

def _scenario_dridex_dropped_mz() -> bytes:
    """Email with MZ header and a few API/strings (synthetic)."""
    mz = bytes.fromhex("4D 5A 90 00 03 00 00 00")
    return (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: p0o6543f test\n\n"
        + mz + b"\n"
        b"netsh.exe\n"
        b"routemon.exe\n"
        b"script=\n"
        b"disconnect\n"
        b"GetClusterResourceTypeKey\n"
        b"QueryInformationJobObject\n"
        b"interface\n"
        b"connect\n"
        b"FreeConsole\n"
    )

def _scenario_dridex_trojan_xml() -> bytes:
    """Mild XML/Office markers commonly seen in docx/wordprocessingML (synthetic)."""
    return (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: Dridex XML test\n\n"
        b"<?xml version=\"1.0\"?>\n"
        b"<?mso-application progid=\"Word.Document\"?>\n"
        b"<w:document>\n"
        b"  <w:macrosPresent=\"yes\"/>\n"
        b"  <w:binData w:name=\"Object1\">QUJDRDEyMw==</w:binData>\n"
        b"  <o:Characters>0</o:Characters>\n"
        b"  <o:Lines>1</o:Lines>\n"
        b"</w:document>\n"
    )

def _scenario_maldoc_vba_rule1() -> bytes:
    """OLE header + 'Attribute VB_' marker snippet."""
    return (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: OLE VBA macro test\n\n"
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\n"
        b"\x41\x74\x74\x72\x69\x62\x75\x74\x00\x65\x20\x56\x42\x5F"
    )

def _scenario_maldoc_vba_rule2() -> bytes:
    """ZIP header + vbaProject.bin name (common in macro-enabled docs)."""
    return (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: ZIP VBA macro test\n\n"
        b"\x50\x4B\x03\x04\x14\x00\x08\x00\n"
        b"vbaProject.bin\n"
    )

# ---- ChinaChopper-ish webshell strings (synthetic fragments)
def _scenario_chinachopper_aspx() -> bytes:
    """ASPX-like markers and short segments with non-printables (synthetic)."""
    return (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: ChinaChopper ASPX test (len=10)\n\n"
        b"\x25\x40\x20\x50\x61\x67\x65\x20\x4C\x61\x6E\x67\x75\x61\x67\x65\x3D"
        b"\x10"
        b"\x4A\x73\x63\x72\x69\x70\x74"
        b"\x30"
        b"\x25\x3E\x3C\x25\x65\x76\x61\x6C\x28\x52\x65\x71\x75\x65\x73\x74\x2E\x49\x74\x65\x6D\x5B"
        b"\x66\x65"
    )

def _scenario_chinachopper_php() -> bytes:
    """PHP-like fragment with POST and 'password' (synthetic)."""
    return (
        b"From: billing@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: ChinaChopper PHP test\n\n"
        b"\x3C\x3F\x70\x68\x70\x20\x40\x65\x76\x61\x6C\x28\x24\x5F\x50\x4F\x53\x54\x5B"
        b"\x00"
        b"\x70\x61\x73\x73\x77\x6F\x72\x64"
    )

# ---- PDF-themed variants
def _scenario_pdf_rule1() -> bytes:
    """Just '%PDF' marker plus a line (no version)."""
    return (
        b"From: attacker@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: Suspicious PDF test\n\n"
        b"\x25\x50\x44\x46\n"
        b"This looks like a PDF but has no version header\n"
    )

def _scenario_pdf_date() -> bytes:
    """PDF with CreationDate in Info dict."""
    return (
        b"From: attacker@corp.local\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Suspicious PDF test\r\n\r\n"
        b"%PDF-1.4\r\n"
        b"/Info << /CreationDate (D:20101015142358) >>\r\n"
        b"%%EOF\r\n"
    )

def _scenario_pdf_possible_exploit() -> bytes:
    """PDF-like tokens with /Action, Array and a JS unescape (synthetic)."""
    return (
        b"From: attacker@corp.local\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Exploit PDF Action Test\r\n\r\n"
        b"/Action\r\n"
        b"Array\r\n"
        b"AAAAAAAAAA\r\n"
        b"unescape('%41%41%41%41')\r\n"
        b"endstream\r\n"
        b"%%EOF\r\n"
    )

def _scenario_pdf_js_wrong_version() -> bytes:
    """%PDF marker and /JavaScript token (no version header)."""
    return (
        b"From: attacker@corp.local\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: JS wrong version test\r\n\r\n"
        b"\x25\x50\x44\x46\r\n"
        b"/JavaScript\r\n"
        b"%%EOF\r\n"
    )

def _scenario_pdf_xdp_embedded() -> bytes:
    """XDP wrapper with an embedded %PDF token (synthetic)."""
    return (
        b"From: attacker@corp.local\n"
        b"To: victim@example.com\n"
        b"Subject: XDP Embedded PDF Exploit Test\n\n"
        b"<pdf xmlns=\"http://ns.adobe.com/xdp/\">\n"
        b"<chunk>\n"
        b"\x25\x50\x44\x46 Fake embedded PDF content\n"
        b"</chunk>\n"
        b"</pdf>\n"
    )

def _scenario_pdf_embedded_exe() -> bytes:
    """PDF-like object names suggesting embedded files (synthetic)."""
    return (
        b"From: attacker@corp.local\n"
        b"To: victim@example.com\n"
        b"Subject: Malicious PDF with Embedded EXE\n\n"
        b"\x25\x50\x44\x46\n"
        b"\x3C\x3C\x2F\x53\x2F\x4C\x61\x75\x6E\x63\x68"
        b"\x2F\x54\x79\x70\x65\x2F\x41\x63\x74\x69\x6F"
        b"\x6E\x2F\x57\x69\x6E\x3C\x3C\x2F\x46\n"
        b"\x3C\x3C\x2F\x45\x6D\x62\x65\x64\x64\x65\x64"
        b"\x46\x69\x6C\x65\x73\n"
    )

#SAFE
def _scenario_pdf_magic_header() -> bytes:
    """Minimal PDF magic marker (safe header-only sample)."""
    return (
        b"From: tester@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: PDF header test\n\n"
        b"%PDF-1.4\n%%EOF\n"
    )

#SAFE
def _scenario_zip_magic_header() -> bytes:
    """Minimal ZIP magic header."""
    return (
        b"From: tester@corp.local\n"
        b"To: user@example.com\n"
        b"Subject: ZIP header test\n\n"
        b"\x50\x4B\x03\x04\n"
    )

# Map scenario keys to callables (automatically listed in /test_menu)
SCENARIOS = {
    # Benign
    "clean_simple_email": _scenario_clean_simple_email,
    "clean_form_login": _scenario_clean_form_login,
    "html_generic": _scenario_html_generic,

    # Phishing/extortion themed (non-operational)
    "extortion_email": _scenario_extortion_email,
    "email_generic_phishing": _scenario_email_generic_phishing,

    # EK/HTML/JS
    "ek_zeus": _scenario_ek_zeus,

    # Dridex / maldoc markers
    "dridex_attach_ole": _scenario_dridex_attach_ole,
    "dridex_dropped_mz": _scenario_dridex_dropped_mz,
    "dridex_trojan_xml": _scenario_dridex_trojan_xml,
    "maldoc_vba_rule1": _scenario_maldoc_vba_rule1,
    "maldoc_vba_rule2": _scenario_maldoc_vba_rule2,

    # ChinaChopper-ish
    "chinachopper_aspx": _scenario_chinachopper_aspx,
    "chinachopper_php": _scenario_chinachopper_php,

    # PDF variants
    "pdf_version": _scenario_pdf_rule1,
    "pdf_date": _scenario_pdf_date,
    "pdf_possible_exploit": _scenario_pdf_possible_exploit,
    "pdf_js_wrong_version": _scenario_pdf_js_wrong_version,
    "pdf_xdp_embedded": _scenario_pdf_xdp_embedded,
    "pdf_embedded_exe": _scenario_pdf_embedded_exe,

    # Simple magic headers
    "pdf_magic_header": _scenario_pdf_magic_header,
    "zip_magic_header": _scenario_zip_magic_header,
}

DEFAULT_SCENARIO = "clean_simple_email"



def _build_fake_email(scenario_key: str) -> bytes:
    """
    Resolve the scenario key to a bytes payload.
    Falls back to DEFAULT_SCENARIO if unknown.
    """
    func = SCENARIOS.get(scenario_key, SCENARIOS[DEFAULT_SCENARIO])
    try:
        data = func()
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        return data
    except Exception:
        return SCENARIOS[DEFAULT_SCENARIO]()


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy():
    print("=== Incoming client request ===")

    # Raw payload as bytes
    payload = request.get_data()

    content_type = (request.headers.get("Content-Type") or "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        # In forms, '+' means space. Before URL-decode, normalize '+' to 0x20.
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

        try:
            mb_response = requests.post(
                MB_URL,
                json={"encrypted_tokens": tokens_hex, "c": counter_hex},
                timeout= 120
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


# ---------------------------
# simple HTML menu (GET)
# ---------------------------
@app.route("/test_menu", methods=["GET"])
def test_menu():
    """
    Render a small HTML form to choose which test 'fake email' to send.
    Now includes a preview area that fetches /scenario_preview and an interactive send flow.
    """
    options_html = "\n".join(
        f'<option value="{k}" {"selected" if k == DEFAULT_SCENARIO else ""}>{k}</option>'
        for k in SCENARIOS.keys()
    )
    html_page = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>P2DPI Sender — Test Menu</title>
        <style>
          body {{ font-family: system-ui, sans-serif; padding: 24px; }}
          .card {{ max-width: 880px; margin: 0 auto; padding: 16px; border: 1px solid #ddd; border-radius: 12px; }}
          label, select, button {{ font-size: 16px; }}
          select {{ padding: 6px 8px; }}
          button {{ padding: 8px 12px; cursor: pointer; }}
          .row {{ display: flex; gap: 12px; align-items: center; }}
          pre#preview {{ background:#111; color:#e6e6e6; padding:12px; border-radius:8px; max-height:320px; overflow:auto; white-space:pre-wrap; }}
          #result {{ margin-top:12px; padding:8px; border-radius:8px; background:#f6f6f6; }}
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Choose a test message to send</h2>
          <form id="testForm" method="GET" action="/send_test_data">
            <div class="row">
              <label for="scenario">Scenario:</label>
              <select id="scenario" name="scenario">
                {options_html}
              </select>
              <button id="sendBtn" type="submit">Send</button>
              <button id="refreshPreview" type="button">Refresh preview</button>
            </div>
            <p style="color:#666;margin-top:12px">
              The selected scenario will be URL-encoded into the request body and processed normally by the Sender → MB → Receiver pipeline.
            </p>

            <h3>Scenario preview (read-only)</h3>
            <pre id="preview">Loading preview...</pre>

            <div id="result" aria-live="polite"></div>
          </form>
        </div>

        <script>
          async function loadPreview(scenario) {{
            const res = await fetch('/scenario_preview?scenario=' + encodeURIComponent(scenario));
            const text = await res.text();
            document.getElementById('preview').textContent = text;
            return text;
          }}

          document.addEventListener('DOMContentLoaded', async () => {{
            const select = document.getElementById('scenario');
            // load initial preview
            await loadPreview(select.value);

            select.addEventListener('change', async () => {{
              await loadPreview(select.value);
            }});

            document.getElementById('refreshPreview').addEventListener('click', async (ev) => {{
              ev.preventDefault();
              await loadPreview(select.value);
            }});

            document.getElementById('testForm').addEventListener('submit', async (ev) => {{
              ev.preventDefault();
              const scenario = select.value;
              const previewText = document.getElementById('preview').textContent || '';

              // Ask user to confirm (the preview is visible on the page)
              const ok = window.confirm("Send scenario '" + scenario + "' to the Sender?\\nPreview is shown below. Press OK to send.");
              if (!ok) {{
                document.getElementById('result').textContent = 'Send cancelled by user.';
                return;
              }}

              // Call the backend endpoint (GET for simplicity; original code uses GET)
              document.getElementById('result').textContent = 'Sending...';
              try {{
                const resp = await fetch('/send_test_data?scenario=' + encodeURIComponent(scenario), {{ method: 'GET' }});
                const text = await resp.text();
                document.getElementById('result').textContent = text;
              }} catch (e) {{
                document.getElementById('result').textContent = 'Error sending: ' + String(e);
              }}
            }});
          }});
        </script>
      </body>
    </html>
    """
    return Response(html_page, mimetype="text/html")


@app.route("/scenario_preview", methods=["GET"])
def scenario_preview():
    """
    Return a text/plain preview of the chosen scenario payload.
    Query param: ?scenario=<key>
    """
    scenario = request.args.get("scenario") or DEFAULT_SCENARIO
    payload = _build_fake_email(scenario)
    preview = bytes_to_display(payload, max_len=4096)
    # Devuelve texto plano (fácil de mostrar en un <pre>)
    return Response(preview, mimetype="text/plain")

# ---------------------------------------
# UPDATED: local helper to trigger a POST
# ---------------------------------------
@app.route("/send_test_data", methods=["GET", "POST"])
def trigger_test_client_request():
    """
    Local helper endpoint that crafts a form-encoded POST to the public Sender endpoint (/).
    It accepts a 'scenario' and prints the preview on the server before sending.
    Returns the response text and embeds the preview for convenience.
    """
    scenario = request.args.get("scenario") or request.form.get("scenario") or DEFAULT_SCENARIO
    fake_email = _build_fake_email(scenario)

    # Build a readable preview server-side and print it
    preview = bytes_to_display(fake_email, max_len=8192)
    print(f"=== /send_test_data: selected scenario='{scenario}' ===")
    print(preview)   # esto se ve en la consola del servidor inmediatamente

    # Build application/x-www-form-urlencoded payload, keeping email body as bytes safely URL-encoded
    data_bytes = (
        "username=alice"
        "&password=Nicol"
        "&note=local-test"
        "&scenario=" + scenario +
        "&message=" + quote_from_bytes(fake_email)
    ).encode("ascii")

    try:
        response = requests.post(
            SENDER_PUBLIC_URL,
            data=data_bytes,
            verify=CA_CERT_PATH,
            timeout=10
        )
        return (f"[LOCAL CLIENT] scenario={scenario} • POST response: {response.text}\n\n"), response.status_code
    except Exception as e:
        return (f"[LOCAL CLIENT] Error (scenario={scenario}): {str(e)}\n\n"
                f"--- Server-side preview ---\n{preview}"), 500

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=(SENDER_CERT, SENDER_KEY)
    )
