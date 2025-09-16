# sender/sender_http.py
#
# Purpose:
#   Receive a batch of obfuscated rule tokens from the MB/RG pipeline,
#   verify each signature against RG's public key, compute the Sender-side
#   "intermediate" values Ii = (Ri)^{kSR}, and send them back to the
#   Middlebox tagged with the same batch_id and per-token seq.
#
# Input (from MB → fanout of RG rules):
#   {
#     "batch_id": "<uuid>",
#     "tokens": [
#       { "seq": 0, "obfuscated": "<ri-hex>", "signature": "<base64>" },
#       ...
#     ]
#   }
#
# Output (to MB):
#   POST /receive_intermediate/sender
#   {
#     "batch_id": "<uuid>",
#     "intermediate": [
#       { "seq": 0, "Ii": "<hex>" },
#       ...
#     ]
#   }

from flask import Flask, request, jsonify
import logging
import os
import requests
import sys
from pathlib import Path

from sender_utils import (
    load_public_key,
    verify_signature,
    load_ksr_from_file,
    compute_intermediate_rules_hex,  # takes a list of Ri-hex and returns list of Ii-hex in the same order
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.append(str(_PROJECT_ROOT))

from main.shared.config import env_int, env_path, env_str

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# === Paths & constants ===
public_key_path = env_path("RG_PUBLIC_KEY_PATH", "./main/shared/keys/rg_public_key.pem")
rg_public_key = load_public_key(public_key_path)

# MB endpoint for Sender intermediates (new, with role in path)
MB_INTERMEDIATE_URL = env_str(
    "MB_INTERMEDIATE_URL",
    "http://127.0.0.1:9999/receive_intermediate/sender",
)
APP_PORT = env_int("SENDER_HTTP_PORT", 11000)


@app.route("/receive_rules", methods=["POST"])
def receive_rules():
    """
    Accept the batched tokens from MB (flattened from RG rules),
    verify signatures, compute Ii for each token, and send them back
    to MB with the same batch_id and per-token seq.
    """
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if not payload or "batch_id" not in payload or "tokens" not in payload:
        return jsonify({"error": "Missing batch_id or tokens"}), 400

    batch_id = payload["batch_id"]
    tokens = payload["tokens"]

    if not isinstance(tokens, list) or len(tokens) == 0:
        return jsonify({"error": "Tokens must be a non-empty list"}), 400

    # --- Validate structure and verify signatures per token ---
    ri_list = []          # keep Ri in the same order as received
    seq_list = []         # the corresponding seq numbers
    for idx, entry in enumerate(tokens):
        if not isinstance(entry, dict):
            return jsonify({"error": f"Token at index {idx} is not an object"}), 400

        seq = entry.get("seq")
        ri_hex = entry.get("obfuscated")
        sig_b64 = entry.get("signature")

        if seq is None or not ri_hex or not sig_b64:
            return jsonify({"error": f"Malformed token at index {idx}"}), 400

        # Verify signature on Ri-hex string using RG public key
        if not verify_signature(ri_hex, sig_b64, rg_public_key):
            return jsonify({"error": f"Signature verification failed at seq={seq}"}), 400

        seq_list.append(int(seq))
        ri_list.append(ri_hex)

    app.logger.info(f"[Sender] batch_id={batch_id} | verified {len(ri_list)} signatures.")

    # --- Load kSR and compute intermediates Ii for all Ri in order ---
    try:
        kSR = load_ksr_from_file()
    except Exception as e:
        app.logger.error(f"Failed to load kSR: {e}")
        return jsonify({"error": f"Failed to load kSR: {str(e)}"}), 500

    try:
        # This returns a list of Ii (hex) in the SAME order as ri_list
        Ii_list = compute_intermediate_rules_hex(ri_list, kSR)
    except Exception as e:
        app.logger.error(f"Failed to compute intermediate rules: {e}")
        return jsonify({"error": f"Failed to compute intermediate rules: {str(e)}"}), 500

    # --- Build the response payload with seq alignment ---
    intermediate = []
    for seq, Ii in zip(seq_list, Ii_list):
        intermediate.append({"seq": int(seq), "Ii": Ii})

    # --- Send to MB (role inferred by path '/sender') ---
    try:
        resp = requests.post(
            MB_INTERMEDIATE_URL,
            json={"batch_id": batch_id, "intermediate": intermediate},
            timeout=5
        )
        app.logger.info(f"[Sender] Sent {len(intermediate)} intermediates for batch {batch_id} to MB. "
                        f"MB responded: {resp.status_code}")
        if resp.status_code != 200:
            return jsonify({"error": "MB returned non-200 while receiving intermediates",
                            "mb_status": resp.status_code,
                            "mb_body": resp.text}), 502
    except requests.RequestException as e:
        app.logger.error(f"Failed to send intermediates to MB: {e}")
        return jsonify({"error": "Middlebox communication error"}), 502

    # Local OK echo
    return jsonify({
        "status": "ok",
        "batch_id": batch_id,
        "intermediate_count": len(intermediate)
    }), 200


if __name__ == "__main__":
    # This service is plain HTTP (not the HTTPS traffic proxy).
    app.run(port=APP_PORT)
