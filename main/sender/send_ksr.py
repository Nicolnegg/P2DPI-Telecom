import requests
import secrets
import os
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.append(str(_PROJECT_ROOT))

from main.shared.config import env_path, env_str

# === Configuration === Run before to sned the data

# Generate a 128-bit key (16 bytes = 32 hex chars)
ksr = secrets.token_hex(16)
print("[Sender] Generated kSR:", ksr)

# Receiver URL (must match TLS CN/SAN)
url = env_str("RECEIVER_KSR_URL", "https://127.0.0.1:10443/receive_ksr")

# === Resolve paths ===

# Resolve certificate paths via environment configuration
cert_path = env_path("SENDER_CERT", "./ca/certs/sender.crt")
key_path = env_path("SENDER_KEY", "./ca/private/sender.key")
ca_cert_path = env_path("CA_CERT_PATH", "./ca/certs/ca.cert.pem")

# Output directory for storing kSR locally
keys_dir = env_path("SENDER_KEYS_DIR", "./main/sender/keys")
ksr_file_path = os.path.join(keys_dir, "shared_ksr.key")

# Ensure the keys directory exists
os.makedirs(keys_dir, exist_ok=True)

# === Send the kSR using HTTPS + mTLS ===

try:
    response = requests.post(
        url,
        json={"ksr": ksr},
        cert=(cert_path, key_path),
        verify=ca_cert_path,
        timeout=5
    )

    print(f"[Sender] Receiver responded: {response.status_code} {response.text}")

    if response.status_code == 200:
        # Save the generated kSR locally for future use
        with open(ksr_file_path, "w") as f:
            f.write(ksr)
        os.chmod(ksr_file_path, 0o600)  # Restrict file permissions
        print(f"[Sender] Saved kSR to: {ksr_file_path}")

except requests.exceptions.SSLError as ssl_err:
    print("[Sender] SSL error:", ssl_err)

except requests.exceptions.ConnectionError as conn_err:
    print("[Sender] Connection failed:", conn_err)

except requests.exceptions.Timeout:
    print("[Sender] Request timed out.")

except Exception as e:
    print("[Sender] Unexpected error:", e)
