# -*- coding: utf-8 -*-
"""
Flask API для fake-data-prevention проекта.
Production-ready baseline:
- env-driven config
- modular services (db/crypto)
- verified transactions endpoint
- merkle/multi-party endpoints
"""

import os
import sys
import threading
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

try:
    from .crypto_service import (
        canonical_json,
        compute_sha256,
        create_jwt_payload,
        hmac_sign,
        validate_transaction_payload,
        verify_hmac,
    )
    from .db import get_stats as db_get_stats
    from .db import init_db, list_attack_logs, list_transactions, log_attack, save_transaction
except ImportError:
    from crypto_service import (
        canonical_json,
        compute_sha256,
        create_jwt_payload,
        hmac_sign,
        validate_transaction_payload,
        verify_hmac,
    )
    from db import get_stats as db_get_stats
    from db import init_db, list_attack_logs, list_transactions, log_attack, save_transaction

# Подключаем src-модули для Merkle и Multi-party.
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

merkle_import_error = None
multiparty_import_error = None
MerkleTree = None
MultiPartyProtocol = None
try:
    from merkle import MerkleTree
except Exception as e:
    merkle_import_error = str(e)
try:
    from multiparty import MultiPartyProtocol
except Exception as e:
    multiparty_import_error = str(e)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("FDP_MAX_CONTENT_LENGTH", str(1024 * 1024)))

allowed_origins = os.getenv("FDP_ALLOWED_ORIGINS", "*")
if allowed_origins == "*":
    CORS(app)
else:
    CORS(app, resources={r"/api/*": {"origins": [o.strip() for o in allowed_origins.split(",")]}})

protocol_lock = threading.Lock()
multiparty_protocol = MultiPartyProtocol() if MultiPartyProtocol else None


def _verify_row(tx):
    """
    Верификация строки из transactions:
    digest + signature + срок jwt payload.
    """
    source_data = {
        "tx_id": tx.get("tx_id"),
        "timestamp": tx.get("timestamp"),
        "sender": tx.get("sender"),
        "recipient": tx.get("recipient"),
        "amount_eur": tx.get("amount_eur"),
        "currency": tx.get("currency"),
        "category": tx.get("category"),
        "bank": tx.get("bank"),
        "status": tx.get("status"),
        "note": tx.get("note"),
    }
    canonical = canonical_json(source_data)
    recomputed = compute_sha256(canonical)
    digest_valid = recomputed == tx.get("digest")
    signature_valid = verify_hmac(tx.get("digest", ""), tx.get("signature", ""))

    jwt_valid = False
    jwt_payload = tx.get("jwt_payload") if isinstance(tx.get("jwt_payload"), dict) else None
    if jwt_payload:
        exp = jwt_payload.get("exp")
        j_sub = jwt_payload.get("sub")
        j_digest = jwt_payload.get("digest")
        now_ts = int(datetime.now(timezone.utc).timestamp())
        jwt_valid = isinstance(exp, int) and exp >= now_ts and j_sub == tx.get("tx_id") and j_digest == tx.get("digest")

    verdict = "VALID"
    error = None
    if not digest_valid:
        verdict = "MODIFICATION"
        error = "SHA-256 digest mismatch - data was modified"
    elif not signature_valid:
        verdict = "FABRICATION"
        error = "Signature verification failed - forged transaction"
    elif not jwt_valid:
        verdict = "REPLAY"
        error = "JWT is expired or inconsistent"

    tx["verdict"] = verdict
    tx["ver_status"] = "✅ VALID" if verdict == "VALID" else f"❌ {verdict} DETECTED"
    tx["cert_valid"] = True
    tx["jwt_valid"] = jwt_valid
    tx["digest_valid"] = digest_valid
    tx["sig_valid"] = signature_valid
    tx["error"] = error
    tx["computed_digest"] = recomputed
    return tx


@app.route("/api/health", methods=["GET"])
def health_check():
    """Проверка что сервер жив."""
    return jsonify(
        {
            "status": "ok",
            "message": "Fake Data Prevention API is running",
            "version": "1.2.0",
            "merkle_available": MerkleTree is not None,
            "multiparty_available": multiparty_protocol is not None,
        }
    )


@app.route("/api/sign", methods=["POST"])
def sign_transaction():
    """
    Подписывает транзакцию:
    canonical json -> digest -> hmac signature -> jwt payload -> save db.
    """
    try:
        tx_data = request.get_json(silent=True)
        ok, err = validate_transaction_payload(tx_data)
        if not ok:
            return jsonify({"error": err}), 400

        canonical = canonical_json(tx_data)
        digest = compute_sha256(canonical)
        signature = hmac_sign(digest)
        jwt_payload = create_jwt_payload(tx_data, digest, signature)

        saved = save_transaction(tx_data, digest, signature, jwt_payload)
        return jsonify(
            {
                "success": True,
                "tx_id": tx_data["tx_id"],
                "digest": digest,
                "signature": signature,
                "jwt": jwt_payload,
                "saved_to_db": saved,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/verify", methods=["POST"])
def verify_transaction():
    """Проверяет digest и signature для переданной транзакции."""
    try:
        data = request.get_json(silent=True) or {}
        tx_data = data.get("data")
        provided_digest = data.get("digest")
        provided_signature = data.get("signature")

        if not isinstance(tx_data, dict):
            return jsonify({"error": "Field 'data' must be object"}), 400
        if not provided_digest or not provided_signature:
            return jsonify({"error": "Fields 'digest' and 'signature' are required"}), 400

        canonical = canonical_json(tx_data)
        computed_digest = compute_sha256(canonical)
        digest_valid = computed_digest == provided_digest
        signature_valid = verify_hmac(provided_digest, provided_signature)

        verdict = "VALID"
        error = None
        tx_id = tx_data.get("tx_id", "unknown")

        if not digest_valid:
            verdict = "MODIFICATION"
            error = "SHA-256 digest mismatch - data was modified"
            log_attack("modification", tx_id, True)
        elif not signature_valid:
            verdict = "FABRICATION"
            error = "Signature verification failed - forged transaction"
            log_attack("fabrication", tx_id, True)

        return jsonify(
            {
                "verdict": verdict,
                "digest_valid": digest_valid,
                "signature_valid": signature_valid,
                "computed_digest": computed_digest,
                "error": error,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/transactions", methods=["GET"])
def get_transactions():
    """Возвращает последние транзакции."""
    try:
        rows = list_transactions(limit=100)
        return jsonify({"count": len(rows), "transactions": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/attack_logs", methods=["GET"])
def get_attack_logs():
    """Возвращает логи атак."""
    try:
        logs = list_attack_logs(limit=50)
        return jsonify({"count": len(logs), "logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Статистика для дашборда."""
    try:
        return jsonify(db_get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/transactions/verified", methods=["GET"])
def get_verified_transactions():
    """Возвращает транзакции с верификацией для frontend таблицы."""
    try:
        limit = int(request.args.get("limit", "100"))
        limit = max(1, min(limit, 500))
        rows = list_transactions(limit=limit)
        verified = [_verify_row(tx) for tx in rows]
        return jsonify({"count": len(verified), "transactions": verified})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/merkle/root", methods=["GET"])
def merkle_root():
    """Считает Merkle root по digest последних транзакций."""
    if MerkleTree is None:
        return jsonify({"error": f"Merkle module unavailable: {merkle_import_error or 'unknown error'}"}), 500
    try:
        limit = int(request.args.get("limit", "100"))
        limit = max(1, min(limit, 1000))
        txs = list_transactions(limit=limit)
        digests = [tx["digest"] for tx in txs if tx.get("digest")]
        if not digests:
            return jsonify({"error": "No digests found. Sign transactions first."}), 404
        tree = MerkleTree(digests)
        return jsonify(
            {
                "leaf_count": len(digests),
                "merkle_root": tree.get_root(),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/multiparty/init", methods=["POST"])
def multiparty_init():
    """Инициализация подписи цепочки."""
    if multiparty_protocol is None:
        return jsonify({"error": f"Multi-party module unavailable: {multiparty_import_error or 'unknown error'}"}), 500
    try:
        payload = request.get_json(silent=True) or {}
        tx_data = payload.get("transaction")
        initiator = payload.get("initiator", "Alice")
        if not isinstance(tx_data, dict) or not tx_data.get("tx_id"):
            return jsonify({"error": "transaction object with tx_id is required"}), 400
        with protocol_lock:
            chain = multiparty_protocol.initiate_chain(tx_data, initiator=initiator)
            status = multiparty_protocol.get_chain_status(chain.tx_id)
        return jsonify({"success": True, "status": status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/multiparty/sign/<tx_id>", methods=["POST"])
def multiparty_sign(tx_id):
    """Добавление подписи участника к цепочке."""
    if multiparty_protocol is None:
        return jsonify({"error": f"Multi-party module unavailable: {multiparty_import_error or 'unknown error'}"}), 500
    try:
        payload = request.get_json(silent=True) or {}
        party = payload.get("party")
        if not party:
            return jsonify({"error": "party is required"}), 400
        with protocol_lock:
            ok = multiparty_protocol.add_signature(tx_id, party)
            status = multiparty_protocol.get_chain_status(tx_id)
        if not ok:
            return jsonify({"success": False, "status": status, "error": "Failed to add signature"}), 400
        return jsonify({"success": True, "status": status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/multiparty/<tx_id>", methods=["GET"])
def multiparty_status(tx_id):
    """Текущий статус цепочки подписей."""
    if multiparty_protocol is None:
        return jsonify({"error": f"Multi-party module unavailable: {multiparty_import_error or 'unknown error'}"}), 500
    try:
        with protocol_lock:
            status = multiparty_protocol.get_chain_status(tx_id)
        if "error" in status:
            return jsonify(status), 404
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 60)
    print("Fake Data Prevention API Server")
    print("System Security Project - UniMe 2026")
    print("=" * 60)

    print("Initializing database...")
    init_db()
    print("Database ready!")

    port = int(os.getenv("PORT", "5000"))
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    print(f"\nStarting Flask server on http://localhost:{port}")
    print("Press CTRL+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
