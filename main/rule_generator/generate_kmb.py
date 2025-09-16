import os
import requests
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.append(str(_PROJECT_ROOT))

from main.shared.config import env_path, env_str

# Generate 128-bit (16 bytes) key 
kmb = os.urandom(16)

# Define output directories
rg_dir = env_path("RG_KEYS_DIR", "./main/rule_generator/keys")

# Create directories if not exist 
os.makedirs(rg_dir, exist_ok=True)

# Write key to RG 
kmb_path = os.path.join(rg_dir, "kmb.key")
with open(kmb_path, "wb") as f:
    f.write(kmb)

print("kMB generated and stored securely in:")
print(" -", kmb_path)

# Send key to MB via API 

# Convert to hex for JSON transmission
kmb_hex = kmb.hex()

# URL of MB API (change hostname/port if needed)
mb_api_url = env_str("MB_RECEIVE_KMB_URL", "http://127.0.0.1:9999/receive_kmb")

try:
    response = requests.post(mb_api_url, json={"kmb": kmb_hex})
    if response.status_code == 200:
        print("[RG] kMB sent successfully to MB.")
    else:
        print(f"[RG] Failed to send kMB, status: {response.status_code}, message: {response.text}")
except Exception as e:
    print("[RG] Exception while sending kMB:", e)
