# receiver_http.py
# ----------------------------------
# Flask HTTP server that receives a BATCH of obfuscated tokens (flattened by MB),
# verifies each signature against the RG public key, computes Receiver-side
# "intermediate" values Ii = (Ri)^{kSR}, and sends them back to MB with the
# same batch_id and per-token seq.
#
# INPUT (from MB):
# {
#   "batch_id": "<uuid>",
#   "tokens": [
#     { "seq": 0, "obfuscated": "<ri-hex>", "signature": "<base64>" },
#     ...
#   ]
# }
#
# OUTPUT (to MB):
# POST http://localhost:9999/receive_intermediate/receiver
# {
#   "batch_id": "<uuid>",
#   "intermediate": [
#     { "seq": 0, "Ii": "<hex>" },
#     ...
#   ]
# }
#

from flask import Flask, request, jsonify
from ctypes import c_char_p, create_string_buffer
from receiver_utils import (
    load_prf_library,
    load_h_fixed,
    load_ksr,
    load_public_key,
    verify_signature
)
import requests
import os

BUFFER_SIZE = 200

# Flask HTTP app instance
app = Flask("receiver_http")

# === Load PRF shared library, h_fixed, public key, and kSR ===
prf = load_prf_library()        # must expose EC_POINT_exp_hex
h_fixed_hex = load_h_fixed()    # not used directly here, but loaded as in your original code

# Load RG public key
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
public_key_path = os.path.abspath(
    os.path.join(BASE_DIR, '..', 'shared', 'keys', 'rg_public_key.pem')
)
rg_public_key = load_public_key(public_key_path)


def compute_intermediate_rules_hex(rules_hex, kSR_hex):
    """
    Compute intermediate rules I_i from obfuscated rules R_i using EC_POINT_exp_hex.

    Args:
        rules_hex (list): List of R_i values in hexadecimal string format.
        kSR_hex (str): The shared key kSR in hexadecimal string format.

    Returns:
        list: List of computed intermediate rules I_i as hex strings.

    Raises:
        RuntimeError: If EC_POINT_exp_hex computation fails for any rule.
    """
    results = []
    output_buffer = create_string_buffer(BUFFER_SIZE)

    for r in rules_hex:  # r is R_i in hexadecimal string format
        # Ii = (Ri) ^ kSR  (done inside the C lib)
        res = prf.EC_POINT_exp_hex(
            c_char_p(r.encode()),          # Ri as ASCII hex
            c_char_p(kSR_hex.encode()),    # kSR as ASCII hex
            output_buffer,                 # output buffer for Ii as ASCII hex
            BUFFER_SIZE
        )
        if res != 1:
            raise RuntimeError(f"EC_POINT_exp_hex failed for R_i: {r}")

        results.append(output_buffer.value.decode())

    return results


# === Receive batched obfuscated tokens, verify, compute I_i, and send to MB ===
@app.route('/receive_rules', methods=['POST'])
def receive_rules():
    """
    New contract (from MB):
    {
      "batch_id": "<uuid>",
      "tokens": [
        { "seq": N, "obfuscated": "<ri-hex>", "signature": "<base64>" },
        ...
      ]
    }
    We verify each signature on Ri, compute Ii in the same order, and return:
    {
      "batch_id": "<uuid>",
      "intermediate": [ { "seq": N, "Ii": "<hex>" }, ... ]
    }
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

    # Validate + verify signature per token
    seq_list = []
    ri_list = []
    for idx, entry in enumerate(tokens):
        if not isinstance(entry, dict):
            return jsonify({"error": f"Token at index {idx} is not an object"}), 400

        seq = entry.get("seq")
        ri_hex = entry.get("obfuscated")
        sig_b64 = entry.get("signature")

        if seq is None or not ri_hex or not sig_b64:
            return jsonify({"error": f"Malformed token at index {idx}"}), 400

        # Verify RSA-PSS signature on the exact Ri (ASCII hex string)
        if not verify_signature(ri_hex, sig_b64, rg_public_key):
            return jsonify({"error": f"Signature verification failed at seq={seq}"}), 400

        seq_list.append(int(seq))
        ri_list.append(ri_hex)

    print(f"[Receiver] batch_id={batch_id} | verified {len(ri_list)} signatures.")

    # Load shared key kSR
    try:
        kSR = load_ksr()
    except Exception as e:
        print(f"[Receiver] Failed to load kSR: {e}")
        return jsonify({"error": "Failed to load kSR"}), 500

    # Compute Ii in the SAME order as received
    try:
        Ii_list = compute_intermediate_rules_hex(ri_list, kSR)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    print(f"[Receiver] Computed {len(Ii_list)} intermediate values (Ii).")

    # Build response for MB with seq alignment
    intermediate = []
    for seq, Ii in zip(seq_list, Ii_list):
        intermediate.append({"seq": int(seq), "Ii": Ii})

    # Send to Middlebox under the receiver role endpoint
    mb_url = "http://localhost:9999/receive_intermediate/receiver"
    try:
        response = requests.post(
            mb_url,
            json={"batch_id": batch_id, "intermediate": intermediate},
            timeout=5
        )
        print(f"[Receiver] Sent {len(intermediate)} intermediates to MB for batch {batch_id}. "
              f"MB responded: {response.status_code}")
        # Accept 200 (both sides ready) and 202 (MB waiting for the other side)
        if response.status_code not in (200, 202):
            return jsonify({
                "error": "MB returned non-OK while receiving intermediates",
                "mb_status": response.status_code,
                "mb_body": response.text
            }), 502
        
    except Exception as e:
        print("[Receiver] Failed to send intermediate rules to MB:", e)
        return jsonify({"error": "Middlebox communication error"}), 502

    # Local OK echo
    return jsonify({
        "status": "ok" if response.status_code == 200 else "pending",
        "batch_id": batch_id,
        "intermediate_count": len(intermediate)
    }), 200


if __name__ == "__main__":
    # Plain HTTP service
    app.run(host="0.0.0.0", port=10000)
