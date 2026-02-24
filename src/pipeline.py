"""
pipeline.py
===========
Full data-flow pipeline:

  SENDER SIDE:
    CSV row -> SHA-256 digest -> RSA-PSS signature -> JWT (RS256) -> AES-256 encryption -> DB

  ATTACKER SIMULATION:
    Attack A - Fabrication : inject a forged row without a valid private key
    Attack B - Modification: tamper with an amount directly in the database
    Attack C - Replay      : reuse an expired / stolen JWT token

  RECEIVER SIDE:
    DB row -> AES decrypt -> JWT verify -> digest recompute -> RSA signature verify -> valid/invalid
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import csv
import json
import sqlite3
import datetime
import time
import copy

from crypto_engine import (
    generate_rsa_keypair, save_keypair,
    create_certificate, validate_certificate, extract_public_key_from_cert,
    compute_digest, sign_digest, verify_signature,
    create_jwt, verify_jwt,
    encrypt_token, decrypt_token,
)


# DATABASE HELPERS

def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS protected_transactions (
            tx_id        TEXT PRIMARY KEY,
            ciphertext   TEXT,
            iv           TEXT,
            enc_sk       TEXT,
            cert_pem     TEXT,
            status       TEXT DEFAULT 'PROTECTED'
        )
    """)
    conn.commit()
    return conn


def store_row(conn, tx_id: str, enc_bundle: dict, cert_pem: str):
    conn.execute(
        "INSERT OR REPLACE INTO protected_transactions VALUES (?,?,?,?,?,?)",
        (tx_id,
         enc_bundle["ciphertext"],
         enc_bundle["iv"],
         enc_bundle["encrypted_session_key"],
         cert_pem,
         "PROTECTED")
    )
    conn.commit()


def fetch_row(conn, tx_id: str):
    cur = conn.execute(
        "SELECT tx_id, ciphertext, iv, enc_sk, cert_pem, status FROM protected_transactions WHERE tx_id=?",
        (tx_id,)
    )
    return cur.fetchone()


def fetch_all_ids(conn):
    cur = conn.execute("SELECT tx_id FROM protected_transactions")
    return [r[0] for r in cur.fetchall()]


# SENDER PIPELINE

def protect_transaction(tx: dict, private_key, certificate, recipient_public_key) -> dict:
    """
    Full sender-side pipeline for one transaction row.
    Returns the encrypted bundle ready for storage.
    """
    # Step 1 - Message Digest (Integrity)
    digest = compute_digest(tx)

    # Step 2 - Digital Signature (Authenticity + Non-repudiation)
    rsa_sig = sign_digest(digest, private_key)

    # Step 3 - JWT packaging (Secure claim container + Replay protection)
    token = create_jwt(tx, digest, rsa_sig, private_key)

    # Step 4 - Hybrid Encryption (Confidentiality)
    enc_bundle = encrypt_token(token, recipient_public_key)

    return enc_bundle


def run_sender(csv_path: str, conn, private_key, certificate, recipient_public_key):
    """Read CSV, protect every row, store in DB. Returns list of tx_ids."""
    from cryptography.hazmat.primitives import serialization
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

    tx_ids = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tx = dict(row)
            tx["amount_eur"] = float(tx["amount_eur"])
            enc = protect_transaction(tx, private_key, certificate, recipient_public_key)
            store_row(conn, tx["tx_id"], enc, cert_pem)
            tx_ids.append(tx["tx_id"])
    return tx_ids


# RECEIVER / VERIFIER PIPELINE

VERIFY_OK     = "[OK] VALID"
VERIFY_TAMPER = "[FAIL] MODIFICATION DETECTED"
VERIFY_FAKE   = "[FAIL] FABRICATION DETECTED"
VERIFY_REPLAY = "[FAIL] REPLAY ATTACK DETECTED"
VERIFY_CERT   = "[FAIL] INVALID CERTIFICATE"

def verify_transaction(row_tuple, recipient_private_key) -> dict:
    """
    Full receiver-side verification for one stored row.
    Returns a result dict with status and details.
    """
    tx_id, ciphertext, iv, enc_sk, cert_pem, db_status = row_tuple

    result = {
        "tx_id":        tx_id,
        "status":       None,
        "cert_valid":   False,
        "jwt_valid":    False,
        "digest_valid": False,
        "sig_valid":    False,
        "error":        None,
        "amount":       None,
        "sender":       None,
    }

    # --- Step 1: Certificate validation ---
    from cryptography import x509 as cx509
    from cryptography.hazmat.backends import default_backend as _backend
    try:
        cert = cx509.load_pem_x509_certificate(cert_pem.encode(), _backend())
        cert_info = validate_certificate(cert)
        result["cert_valid"] = cert_info["valid"]
        if not cert_info["valid"]:
            result["status"] = VERIFY_CERT
            result["error"]  = "; ".join(cert_info["errors"])
            return result
        sender_pub_key = extract_public_key_from_cert(cert)
    except Exception as e:
        result["status"] = VERIFY_CERT
        result["error"]  = str(e)
        return result

    # --- Step 2: AES decrypt ---
    try:
        enc_bundle = {"ciphertext": ciphertext, "iv": iv, "encrypted_session_key": enc_sk}
        jwt_token = decrypt_token(enc_bundle, recipient_private_key)
    except Exception as e:
        result["status"] = VERIFY_FAKE
        result["error"]  = f"Decryption failed: {e}"
        return result

    # --- Step 3: JWT verification (RS256 + expiry + jti) ---
    try:
        decoded = verify_jwt(jwt_token, sender_pub_key)
        result["jwt_valid"] = True
    except Exception as e:
        err = str(e).lower()
        if "expired" in err:
            result["status"] = VERIFY_REPLAY
        else:
            result["status"] = VERIFY_FAKE
        result["error"] = str(e)
        return result

    # --- Step 4: Message Digest recomputation ---
    tx_data       = decoded["data"]
    claimed_digest = decoded["digest"]
    actual_digest  = compute_digest(tx_data)

    result["amount"] = tx_data.get("amount_eur")
    result["sender"] = tx_data.get("sender")

    if claimed_digest != actual_digest:
        result["status"]       = VERIFY_TAMPER
        result["digest_valid"] = False
        result["error"]        = f"Digest mismatch: stored={claimed_digest[:16]}... actual={actual_digest[:16]}..."
        return result

    result["digest_valid"] = True

    # --- Step 5: RSA-PSS Signature verification ---
    rsa_sig = decoded["rsa_signature"]
    if not verify_signature(claimed_digest, rsa_sig, sender_pub_key):
        result["status"]   = VERIFY_FAKE
        result["sig_valid"] = False
        result["error"]    = "RSA signature invalid - Fabrication detected"
        return result

    result["sig_valid"] = True

    # Check if this row was tagged as REPLAY in the DB
    if db_status == "REPLAY":
        result["status"] = VERIFY_REPLAY
        result["error"]  = "Row tagged as REPLAY - duplicate transaction ID injected"
        return result

    result["status"]    = VERIFY_OK
    return result


def run_verifier(conn, recipient_private_key) -> list:
    """Verify all rows in the DB. Returns list of result dicts."""
    ids = fetch_all_ids(conn)
    results = []
    for tx_id in ids:
        row = fetch_row(conn, tx_id)
        res = verify_transaction(row, recipient_private_key)
        results.append(res)
    return results


# ATTACK SIMULATION
def attack_fabrication(conn, private_key_of_attacker, recipient_public_key, certificate):
    """
    Attack A - Fabrication
    Attacker tries to inject a completely fake transaction into the DB,
    signed with their own (different) private key.
    The certificate check / JWT RS256 verify will catch the key mismatch.
    """
    from cryptography.hazmat.primitives import serialization
    fake_tx = {
        "tx_id":       "TXN-FAKE-9999",
        "timestamp":   "2024-06-15T03:00:00",
        "sender":      "Attacker Zero",
        "sender_iban": "IT00000000000000000000000",
        "recipient":   "Attacker Zero",
        "recipient_iban": "IT99999999999999999999999",
        "amount_eur":  99999.99,
        "currency":    "EUR",
        "category":    "Fraud",
        "bank":        "Shadow Bank",
        "status":      "COMPLETED",
        "note":        "FAKE INJECTION"
    }
    enc = protect_transaction(fake_tx, private_key_of_attacker, certificate, recipient_public_key)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    store_row(conn, fake_tx["tx_id"], enc, cert_pem)
    return fake_tx["tx_id"]


def attack_modification(conn, tx_id: str):
    """
    Attack B - Modification
    Attacker has direct DB access and manually changes the ciphertext bytes.
    The SHA-256 digest check and JWT signature will detect the tampering.
    """
    cur = conn.execute("SELECT ciphertext FROM protected_transactions WHERE tx_id=?", (tx_id,))
    row = cur.fetchone()
    if not row:
        return
    import base64, os
    original = base64.b64decode(row[0])
    # Flip some bytes in the middle of the ciphertext
    tampered = bytearray(original)
    mid = len(tampered) // 2
    for i in range(mid, min(mid + 16, len(tampered))):
        tampered[i] ^= 0xFF
    conn.execute(
        "UPDATE protected_transactions SET ciphertext=? WHERE tx_id=?",
        (base64.b64encode(bytes(tampered)).decode(), tx_id)
    )
    conn.commit()


def attack_replay(conn, tx_id: str):
    """
    Attack C - Replay
    Attacker copies an existing (valid) protected row and re-inserts it
    under a new ID, simulating a duplicated transaction.
    JWT jti uniqueness + exp time will flag this in a real system.
    Here we tag the row so the verifier log shows it.
    """
    cur = conn.execute("SELECT * FROM protected_transactions WHERE tx_id=?", (tx_id,))
    row = cur.fetchone()
    if not row:
        return None
    new_id = tx_id + "-REPLAY"
    conn.execute(
        "INSERT OR REPLACE INTO protected_transactions VALUES (?,?,?,?,?,?)",
        (new_id, row[1], row[2], row[3], row[4], "REPLAY")
    )
    conn.commit()
    return new_id
