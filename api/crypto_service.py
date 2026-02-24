# -*- coding: utf-8 -*-
"""
crypto_service.py
Логика хэширования/подписи и валидации payload для Flask API.
"""

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta

# В production задавать через env:
# export FDP_HMAC_SECRET="very-strong-secret"
DEFAULT_SECRET = "UniMe-SecSec-2024-FDP"
SECRET_KEY = os.getenv("FDP_HMAC_SECRET", DEFAULT_SECRET)

REQUIRED_TX_FIELDS = [
    "tx_id",
    "timestamp",
    "sender",
    "recipient",
    "amount_eur",
    "currency",
]


def validate_transaction_payload(tx_data):
    """Проверяет базовую структуру транзакции."""
    if not isinstance(tx_data, dict):
        return False, "Transaction payload must be JSON object"

    missing = [f for f in REQUIRED_TX_FIELDS if f not in tx_data]
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"

    try:
        float(tx_data["amount_eur"])
    except (TypeError, ValueError):
        return False, "Field amount_eur must be numeric"

    return True, None


def canonical_json(data):
    """
    Canonical JSON для детерминированного хэша.
    Убираем служебные поля вида _internal.
    """
    clean_data = {k: v for k, v in data.items() if not k.startswith("_")}
    return json.dumps(clean_data, sort_keys=True, separators=(",", ":"))


def compute_sha256(text):
    """SHA-256 digest для строки."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hmac_sign(message, key=SECRET_KEY):
    """HMAC-SHA256 подпись."""
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_hmac(message, signature, key=SECRET_KEY):
    """Проверка HMAC подписи с compare_digest."""
    expected = hmac_sign(message, key)
    return hmac.compare_digest(expected, signature)


def create_jwt_payload(tx_data, digest, signature):
    """
    Упрощённый JWT-like payload (без подписи самого JWT).
    """
    now = datetime.utcnow()
    return {
        "iss": "BankSecureGateway",
        "sub": tx_data.get("tx_id", "unknown"),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "jti": str(uuid.uuid4()),
        "data": tx_data,
        "digest": digest,
        "signature": signature,
    }

