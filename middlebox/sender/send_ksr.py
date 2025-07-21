import requests
import secrets
import os
import sys

# === Configuration ===

# Generate a 128-bit key (16 bytes = 32 hex chars)
ksr = secrets.token_hex(16)
print("[Sender] Generated kSR:", ksr)

# Receiver URL (must match TLS CN/SAN)
url = "https://receiver.p2dpi.local:10000/receive_ksr"

# === Resolve paths ===

# Base directory of this script
base_dir = os.path.dirname(os.path.abspath(__file__))

# CA paths (relative to project structure)
ca_dir = os.path.abspath(os.path.join(base_dir, "..", "..", "ca"))
cert_path = os.path.join(ca_dir, "certs", "sender.crt")
key_path = os.path.join(ca_dir, "private", "sender.key")
ca_cert_path = os.path.join(ca_dir, "certs", "ca.cert.pem")

# Output directory for storing kSR locally
keys_dir = os.path.join(base_dir, "keys")
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
