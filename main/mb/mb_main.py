# middlebox/mb/mb_main.py
#
# Role:
#   - Receive encrypted rule-set (by groups) from RG.
#   - Fan-out obfuscated tokens to Sender/Receiver; receive intermediates; compute Sj.
#   - Rebuild final session ruleset; keep flat SESSION_RULES for H2 online matching.
#   - Evaluate incoming encrypted traffic and enforce block/allow decision.
#
# This file stays small; heavy lifting is in utils.py.

from flask import Flask, request, jsonify
import os, json
import uuid
import requests
import logging
from ctypes import c_char_p, create_string_buffer
import sys
from pathlib import Path

from mb_utils import (
    load_prf, load_h_fixed, load_kmb_from_file,
    h2_compute, flatten_ruleset_from_rg,
    rebuild_session_ruleset, pretty_print_ruleset,
    build_runtime_index, reset_runtime_state,
    process_encrypted_tokens_with_conditions,
    snapshot_rule_status
)

app = Flask(__name__)

# Ensure shared config helpers are importable when running as a script.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.append(str(_PROJECT_ROOT))

from main.shared.config import env_int, env_path, env_str

# Keep logs quiet by default (warnings and errors only)
app.logger.setLevel(logging.WARNING)

# -------------------------
# Config / Constants
# -------------------------

# Receiver endpoints (adjust to your deployment)
RECEIVER_URL = env_str("RECEIVER_STORE_URL", "https://127.0.0.1:10443/store_tokens")
RECEIVER_DELETE_URL = env_str("RECEIVER_DELETE_URL", "https://127.0.0.1:10443/delete_tokens")
CA_CERT_PATH = env_path("CA_CERT_PATH", "./ca/certs/ca.cert.pem")
SENDER_RULES_URL = env_str("SENDER_RULES_URL", "http://127.0.0.1:11000/receive_rules")
RECEIVER_RULES_URL = env_str("RECEIVER_RULES_URL", "http://127.0.0.1:10000/receive_rules")
APP_PORT = env_int("MB_PORT", 9999)

# -------------------------
# Globals (runtime state)
# -------------------------
RULES = []
S_INTERMEDIATE = []
R_INTERMEDIATE = []

# Finalized session artifacts
SESSION_RULES = []       # FLAT list of Sj (hex) used in /receive_tokens
RULESET_SESSION = None   # Structured rule-set with session_tokens (for introspection/logging)

# In-flight batches
# BATCHES[batch_id] = {
#   "ruleset": <copy of RG payload>,
#   "flat":    [ {"seq": int, "obfuscated": ri_hex, "signature": b64}, ... ],
#   "revmap":  { seq: (rule_idx, group_key, string_idx, enc_idx) },
#   "sender_I":   { seq: Ii_hex },
#   "receiver_I": { seq: Ii_hex }
# }
BATCHES = {}

# Runtime matching state (built after finalizing a batch)
RUNTIME = None       # structured rules/groups/strings with run-state
SJ_TARGETS = None    # map sj_hex_lower -> list of (rule_idx, group_key, string_idx, token_pos)

# Crypto handles
prf = load_prf()                     # C library
h_fixed = load_h_fixed()             # Optional: can be None
kmb = None                           # c_char_p with ASCII-hex
_kmb_buf_keepalive = None            # keep buffer reference alive


def _ensure_kmb_loaded():
    """Ensure kMB is loaded into memory before we need it."""
    global kmb, _kmb_buf_keepalive
    if kmb is not None:
        return
    try:
        kmb, _kmb_buf_keepalive = load_kmb_from_file()
    except Exception as e:
        app.logger.warning(f"[MB] kMB not loaded yet: {e}")

# -------------------------
# Endpoints
# -------------------------

@app.route("/upload_rules", methods=["POST"])
def upload_rules():
    """
    RG posts the encrypted-by-group ruleset here.
    MB:
      - Assigns a fresh batch_id
      - Flattens all {ri,sig} into an ordered list with "seq"
      - Stores (ruleset, flat, rev_map) under that batch_id
      - Fan-out to Sender and Receiver
    """
    try:
        ruleset = request.get_json(force=True)
        if not ruleset or "rules" not in ruleset:
            return jsonify({"error": "Malformed ruleset"}), 400
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    batch_id = str(uuid.uuid4())
    flat, rev_map = flatten_ruleset_from_rg(ruleset)

    BATCHES[batch_id] = {
        "ruleset": ruleset,
        "flat": flat,
        "revmap": rev_map,
        "sender_I": {},
        "receiver_I": {}
    }

    # Fan-out payload
    fanout_payload = {"batch_id": batch_id, "tokens": flat}

    # Forward to Receiver (R)
    try:
        r_response = requests.post(RECEIVER_RULES_URL, json=fanout_payload, timeout=5)
        if r_response.status_code != 200:
            app.logger.warning("[MB → R] /receive_rules returned %s", r_response.status_code)
    except Exception as e:
        app.logger.warning("[MB → R] Error: %s", e)

    # Forward to Sender (S)
    try:
        s_response = requests.post(SENDER_RULES_URL, json=fanout_payload, timeout=5)
        if s_response.status_code != 200:
            app.logger.warning("[MB → S] /receive_rules returned %s", s_response.status_code)
    except Exception as e:
        app.logger.warning("[MB → S] Error: %s", e)

    return jsonify({"status": "ok", "batch_id": batch_id}), 200


@app.route("/receive_intermediate/sender", methods=["POST"])
def receive_intermediate_sender():
    """
    Sender returns:
      { "batch_id": "<uuid>", "intermediate": [ { "seq": N, "Ii": "<hex>" }, ... ] }
    Store and try finalize.
    """
    try:
        data = request.get_json(force=True)
        batch_id = data.get("batch_id")
        inter = data.get("intermediate")
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if not batch_id or not isinstance(inter, list):
        return jsonify({"error": "Missing batch_id or intermediate"}), 400
    if batch_id not in BATCHES:
        return jsonify({"error": "Unknown batch_id"}), 404

    BATCHES[batch_id]["sender_I"] = {int(x["seq"]): x["Ii"] for x in inter if "seq" in x and "Ii" in x}
    return _try_finalize_batch(batch_id)


@app.route("/receive_intermediate/receiver", methods=["POST"])
def receive_intermediate_receiver():
    """
    Receiver returns:
      { "batch_id": "<uuid>", "intermediate": [ { "seq": N, "Ii": "<hex>" }, ... ] }
    Store and try finalize.
    """
    try:
        data = request.get_json(force=True)
        batch_id = data.get("batch_id")
        inter = data.get("intermediate")
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if not batch_id or not isinstance(inter, list):
        return jsonify({"error": "Missing batch_id or intermediate"}), 400
    if batch_id not in BATCHES:
        return jsonify({"error": "Unknown batch_id"}), 404

    BATCHES[batch_id]["receiver_I"] = {int(x["seq"]): x["Ii"] for x in inter if "seq" in x and "Ii" in x}
    return _try_finalize_batch(batch_id)


def _try_finalize_batch(batch_id: str):
    """
    When both sender_I and receiver_I exist and match exactly:
      - Compute Sj = FKH_inv_hex(Ii, kMB) for all seq
      - Rebuild final structured rule-set with session_tokens
      - Overwrite SESSION_RULES / RULESET_SESSION
      - Drop batch state
    Else, reply 'waiting'.
    """
    if batch_id not in BATCHES:
        return jsonify({"error": "Unknown batch_id"}), 404

    state = BATCHES[batch_id]
    sI = state.get("sender_I") or {}
    rI = state.get("receiver_I") or {}

    if not sI or not rI:
        return jsonify({"status": "waiting"}), 202

    s_keys = set(sI.keys())
    r_keys = set(rI.keys())
    if s_keys != r_keys:
        del BATCHES[batch_id]
        return jsonify({"error": "Seq set mismatch between S and R"}), 403

    for seq in s_keys:
        if (sI[seq] or "").strip().lower() != (rI[seq] or "").strip().lower():
            del BATCHES[batch_id]
            return jsonify({"error": "Ii mismatch between S and R"}), 403

    _ensure_kmb_loaded()
    if kmb is None:
        del BATCHES[batch_id]
        return jsonify({"error": "kMB not loaded"}), 500

    seq_sorted = sorted(s_keys)
    seq_to_sj = {}
    flat_session = []
    for seq in seq_sorted:
        Ii_hex = sI[seq].upper().encode()
        out_buf = create_string_buffer(200)
        try:
            res = prf.FKH_inv_hex(c_char_p(Ii_hex), kmb, out_buf, 200)
        except Exception:
            del BATCHES[batch_id]
            return jsonify({"error": "PRF error"}), 500
        if res != 1:
            del BATCHES[batch_id]
            return jsonify({"error": f"FKH_inv failed at seq={seq}"}), 500

        Sj_hex = out_buf.value.decode()
        seq_to_sj[seq] = Sj_hex
        flat_session.append(Sj_hex)

    # Rebuild structured ruleset
    ruleset_in = state["ruleset"]
    revmap = state["revmap"]
    final_ruleset = rebuild_session_ruleset(ruleset_in, revmap, seq_to_sj)

    # Publish
    global SESSION_RULES, RULESET_SESSION
    SESSION_RULES = flat_session
    RULESET_SESSION = final_ruleset

    # Build runtime index for structured matching (sequences, groups, conditions)
    global RUNTIME, SJ_TARGETS
    RUNTIME, SJ_TARGETS = build_runtime_index(RULESET_SESSION)
    reset_runtime_state(RUNTIME)

    del BATCHES[batch_id]
    return jsonify({"status": "finalized", "session_rules_count": len(SESSION_RULES)}), 200


@app.route("/receive_kmb", methods=["POST"])
def receive_kmb():
    """
    Accept ASCII-hex kMB from RG (as 'kmb'), persist to keys/kmb.key, and load to memory.
    """
    global kmb, _kmb_buf_keepalive

    kmb_hex = request.json.get("kmb")
    if not kmb_hex:
        return "Missing kMB", 400

    try:
        kmb_hex_str = kmb_hex.upper()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        keys_dir = os.path.join(base_dir, "keys")
        os.makedirs(keys_dir, exist_ok=True)

        kmb_path = os.path.join(keys_dir, "kmb.key")
        with open(kmb_path, "wb") as f:
            f.write(bytes.fromhex(kmb_hex_str))

        _kmb_buf_keepalive = create_string_buffer(kmb_hex_str.encode())
        kmb = c_char_p(_kmb_buf_keepalive.value)

        return "kMB received", 200

    except Exception:
        return "Internal error", 500


@app.route("/receive_tokens", methods=["POST"])
def receive_tokens():
    """
    Online detection with conditions:
      - For each traffic token Ti at index i, for each Sj, compute H2(c+i, Sj) and compare.
      - Maintain per-string run state to require full consecutive sequences for long strings.
      - Per group, apply match_type ('any'/'all').
      - Per rule, evaluate 'conditions' (and/or/not). If a rule is satisfied -> block.
    """
    data = request.get_json()
    if not data or "encrypted_tokens" not in data or "c" not in data:
        return jsonify({"error": "Missing encrypted_tokens or counter c"}), 400

    tokens = data["encrypted_tokens"]
    c_hex = data["c"]
    counter = int(c_hex, 16)

    # If no structured rules were loaded, just forward to Receiver
    if not RULESET_SESSION or not RUNTIME or not SJ_TARGETS:
        payload = {"tokens": tokens, "counter": c_hex}
        try:
            response = requests.post(RECEIVER_URL, json=payload, verify=CA_CERT_PATH, timeout=5)
            if response.status_code != 200:
                return jsonify({"error": "Failed to store tokens at Receiver"}), 500
        except Exception:
            return jsonify({"error": "Critical failure sending tokens to Receiver"}), 500
        return jsonify({"status": "ok", "note": "no structured rules loaded"}), 200

    # Reset run state for this evaluation
    reset_runtime_state(RUNTIME)

    # Use the structured matching engine
    alert, details = process_encrypted_tokens_with_conditions(
        prf=prf,
        tokens=tokens,
        counter=counter,
        runtime=RUNTIME,
        sj_to_targets=SJ_TARGETS,
        h2_func=h2_compute
    )

    if alert:
        # Notify Receiver to delete stored tokens for this counter and block
        try:
            delete_payload = {"counter": c_hex}
            requests.post(RECEIVER_DELETE_URL, json=delete_payload, verify=CA_CERT_PATH, timeout=5)
        except Exception:
            pass

        return jsonify({
            "status": "alert",
            "message": "Rule conditions satisfied. Transmission blocked.",
            "matched_at": details.get("matched_at") if details else None,
            "debug": {
                "rule_idx": details.get("rule_idx") if details else None,
                "clause_idx": details.get("clause_idx") if details else None,
                "g_truth": details.get("g_truth") if details else None,
                "cond": details.get("cond") if details else None
            }
        }), 403

    # No rule satisfied -> forward to Receiver
    payload = {"tokens": tokens, "counter": c_hex}
    try:
        response = requests.post(RECEIVER_URL, json=payload, verify=CA_CERT_PATH, timeout=5)
        if response.status_code != 200:
            return jsonify({"error": "Failed to store tokens at Receiver"}), 500
    except Exception:
        return jsonify({"error": "Critical failure sending tokens to Receiver"}), 500

    return jsonify({"status": "ok"}), 200


@app.route("/validation", methods=["POST"])
def receive_alert_from_receiver():
    """Optional alert channel from Receiver (for validation audits)."""
    alert_data = request.get_json()
    if not alert_data:
        return jsonify({"error": "Missing alert data"}), 400
    # Keep as a warning so it shows up if someone enables INFO later.
    app.logger.warning("[MB] ALERT FROM RECEIVER: %s", alert_data)
    return jsonify({"status": "Alert received"}), 200


if __name__ == "__main__":
    # Try load kMB (if the key file already exists) and h
    _ensure_kmb_loaded()
    if h_fixed:
        app.logger.warning("[MB] Fixed point h loaded")

    app.run(host="0.0.0.0", port=APP_PORT)
