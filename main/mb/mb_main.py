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
import os , json
import uuid
import requests
import logging
from ctypes import c_char_p, create_string_buffer

from mb_utils import (
    load_prf, load_h_fixed, load_kmb_from_file,
    h2_compute, flatten_ruleset_from_rg,
    rebuild_session_ruleset, pretty_print_ruleset,
    build_runtime_index, reset_runtime_state,
    process_encrypted_tokens_with_conditions,
    snapshot_rule_status
)

app = Flask(__name__)

app.logger.setLevel(logging.DEBUG)

# -------------------------
# Config / Constants
# -------------------------

# Receiver endpoints (adjust to your deployment)
RECEIVER_URL = "https://receiver.p2dpi.local:10443/store_tokens"
RECEIVER_DELETE_URL = "https://receiver.p2dpi.local:10443/delete_tokens"
CA_CERT_PATH = os.path.abspath(os.path.join('receiver', '..', 'ca', 'certs', 'ca.cert.pem'))

# -------------------------
# Globals (runtime state)
# -------------------------
# Legacy placeholders for compatibility
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
    """
    Ensure kMB is loaded into memory before we need it.
    """
    global kmb, _kmb_buf_keepalive
    if kmb is not None:
        return
    try:
        kmb, _kmb_buf_keepalive = load_kmb_from_file()
        app.logger.info("[MB] Loaded existing kMB from keys/kmb.key")
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

    app.logger.info(f"[MB] Received RG ruleset. batch_id={batch_id}, tokens={len(flat)}")

    fanout_payload = {
        "batch_id": batch_id,
        "tokens": flat
    }

    # Forward to Receiver (R)
    try:
        r_response = requests.post("http://localhost:10000/receive_rules", json=fanout_payload, timeout=5)
        app.logger.info("[MB → R] /receive_rules: %s", r_response.status_code)
    except Exception as e:
        app.logger.warning("[MB → R] Error: %s", e)

    # Forward to Sender (S)
    try:
        s_response = requests.post("http://localhost:11000/receive_rules", json=fanout_payload, timeout=5)
        app.logger.info("[MB → S] /receive_rules: %s", s_response.status_code)
    except Exception as e:
        app.logger.warning("[MB → S] Error: %s", e)

    try:
        app.logger.debug("[MB] Snapshot (no match):\n%s",
                        json.dumps(snapshot_rule_status(RUNTIME), indent=2, ensure_ascii=False))
    except Exception:
        pass

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
    app.logger.info(f"[MB] Got Sender intermediates for batch {batch_id}: {len(BATCHES[batch_id]['sender_I'])} items")

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
    app.logger.info(f"[MB] Got Receiver intermediates for batch {batch_id}: {len(BATCHES[batch_id]['receiver_I'])} items")

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
        app.logger.error(f"[MB] Mismatch seq sets for batch {batch_id}. Aborting.")
        del BATCHES[batch_id]
        return jsonify({"error": "Seq set mismatch between S and R"}), 403

    for seq in s_keys:
        if (sI[seq] or "").strip().lower() != (rI[seq] or "").strip().lower():
            app.logger.error(f"[MB] Ii mismatch at seq={seq} for batch {batch_id}. Aborting.")
            del BATCHES[batch_id]
            return jsonify({"error": "Ii mismatch between S and R"}), 403

    _ensure_kmb_loaded()
    if kmb is None:
        app.logger.error("[MB] ERROR: kMB is None. Cannot compute session rules.")
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
        except Exception as e:
            app.logger.exception(f"[MB] Exception during FKH_inv_hex (seq={seq}): {e}")
            del BATCHES[batch_id]
            return jsonify({"error": "PRF error"}), 500
        if res != 1:
            app.logger.error(f"[MB] FKH_inv_hex failed at seq={seq}")
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

    app.logger.info(f"[MB] ✅ Finalized batch {batch_id}. session tokens: {len(SESSION_RULES)}")
    app.logger.debug("\n[MB] ===== FINAL RULESET (SESSION) =====\n%s\n[MB] ===== END =====\n",
                     pretty_print_ruleset(RULESET_SESSION))

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

        app.logger.info(f"[MB] kMB saved in {kmb_path} and updated in memory.")
        return "kMB received", 200

    except Exception as e:
        app.logger.exception("[MB] Error in /receive_kmb: %s", e)
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
    app.logger.info(f"[MB] Received {len(tokens)} encrypted tokens with counter c={counter}")

    # If no structured rules were loaded, just forward to Receiver as before
    if not RULESET_SESSION or not RUNTIME or not SJ_TARGETS:
        payload = {"tokens": tokens, "counter": c_hex}
        try:
            response = requests.post(RECEIVER_URL, json=payload, verify=CA_CERT_PATH, timeout=5)
            app.logger.info(f"[MB ➜ R] Store tokens response: {response.status_code} - {response.text}")
            if response.status_code != 200:
                return jsonify({"error": "Failed to store tokens at Receiver"}), 500
        except Exception as e:
            app.logger.exception(f"[MB] Critical error sending tokens to Receiver: {e}")
            return jsonify({"error": "Critical failure sending tokens to Receiver"}), 500
        return jsonify({"status": "ok", "note": "no structured rules loaded"}), 200

    # Reset run state for this evaluation (optional; remove if you want to carry state cross-requests)
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
        try:
            app.logger.debug("[MB] Match details g_truth: %s", json.dumps(details.get("g_truth", {}), ensure_ascii=False))
            app.logger.debug("[MB] Clause hit: %s", json.dumps(details.get("cond", {}), ensure_ascii=False))
            # Si quieres ver snapshot completo:
            if details.get("snapshot"):
                app.logger.debug("[MB] Snapshot at match:\n%s", json.dumps(details["snapshot"], indent=2, ensure_ascii=False))
        except Exception:
            pass

        # Notify Receiver to delete stored tokens for this counter and block
        try:
            delete_payload = {"counter": c_hex}
            delete_response = requests.post(
                RECEIVER_DELETE_URL,
                json=delete_payload,
                verify=CA_CERT_PATH,
                timeout=5
            )
            app.logger.info(f"[MB ➜ R] Notify Receiver delete tokens: {delete_response.status_code} - {delete_response.text}")
        except Exception as e:
            app.logger.warning(f"[MB] Failed to notify Receiver about malicious tokens: {e}")

        return jsonify({
            "status": "alert",
            "message": "Rule conditions satisfied. Transmission blocked.",
            "matched_at": details.get("matched_at"),
            "debug": {
                "rule_idx": details.get("rule_idx"),
                "clause_idx": details.get("clause_idx"),
                "g_truth": details.get("g_truth"),
                "cond": details.get("cond")
            }
        }), 403

    # No rule satisfied -> forward to Receiver
    payload = {"tokens": tokens, "counter": c_hex}
    try:
        response = requests.post(RECEIVER_URL, json=payload, verify=CA_CERT_PATH, timeout=5)
        app.logger.info(f"[MB ➜ R] Store tokens response: {response.status_code} - {response.text}")
        if response.status_code != 200:
            return jsonify({"error": "Failed to store tokens at Receiver"}), 500
    except Exception as e:
        app.logger.exception(f"[MB] Critical error sending tokens to Receiver: {e}")
        return jsonify({"error": "Critical failure sending tokens to Receiver"}), 500

    app.logger.info("[MB] ✅ No rule conditions satisfied. Traffic allowed.")
    return jsonify({"status": "ok"}), 200



@app.route("/validation", methods=["POST"])
def receive_alert_from_receiver():
    """
    Optional alert channel from Receiver (for validation audits).
    """
    alert_data = request.get_json()
    if not alert_data:
        return jsonify({"error": "Missing alert data"}), 400

    app.logger.warning("\n[MB] ⚠️ ALERT RECEIVED FROM RECEIVER ⚠️\n[MB] Details: %s", alert_data)
    return jsonify({"status": "Alert received"}), 200


if __name__ == "__main__":
    # Try load kMB (if the key file already exists) and h
    _ensure_kmb_loaded()
    if h_fixed:
        app.logger.info("[MB] Loaded fixed point h")

    app.logger.info("[MB] Starting Flask server on port 9999...")
    app.run(host="0.0.0.0", port=9999)
