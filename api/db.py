"""
db.py
SQLite data-access layer for Flask API.
"""

import json
import os
import sqlite3


def get_db_path():
    """Return DB path, optionally overridden by FDP_DB_PATH."""
    env_path = os.getenv("FDP_DB_PATH")
    if env_path:
        return env_path
    return os.path.join(os.path.dirname(__file__), "..", "output", "transactions_api.db")


def _connect(row_factory=False):
    conn = sqlite3.connect(get_db_path())
    if row_factory:
        conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize SQLite tables."""
    os.makedirs(os.path.dirname(get_db_path()), exist_ok=True)
    conn = _connect()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_id TEXT UNIQUE,
            timestamp TEXT,
            sender TEXT,
            recipient TEXT,
            amount_eur REAL,
            currency TEXT,
            category TEXT,
            bank TEXT,
            status TEXT,
            note TEXT,
            digest TEXT,
            signature TEXT,
            jwt_payload TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT,
            tx_id TEXT,
            detected BOOLEAN,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    conn.commit()
    conn.close()


def save_transaction(tx_data, digest, signature, jwt_payload):
    """Save transaction row. Return False on duplicate tx_id."""
    conn = _connect()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO transactions
            (tx_id, timestamp, sender, recipient, amount_eur, currency,
             category, bank, status, note, digest, signature, jwt_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                tx_data["tx_id"],
                tx_data["timestamp"],
                tx_data["sender"],
                tx_data["recipient"],
                float(tx_data["amount_eur"]),
                tx_data["currency"],
                tx_data.get("category", "General"),
                tx_data.get("bank", "Unknown"),
                tx_data.get("status", "COMPLETED"),
                tx_data.get("note", ""),
                digest,
                signature,
                json.dumps(jwt_payload),
            ),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def log_attack(attack_type, tx_id, detected):
    """Insert attack log record."""
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO attack_logs (attack_type, tx_id, detected)
        VALUES (?, ?, ?)
    """,
        (attack_type, tx_id, detected),
    )
    conn.commit()
    conn.close()


def list_transactions(limit=100):
    conn = _connect(row_factory=True)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    data = []
    for row in rows:
        tx = dict(row)
        if tx.get("jwt_payload"):
            tx["jwt_payload"] = json.loads(tx["jwt_payload"])
        data.append(tx)
    return data


def list_attack_logs(limit=50):
    conn = _connect(row_factory=True)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = _connect()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM transactions")
    total_tx = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attack_logs")
    total_attacks = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT attack_type, COUNT(*) as count
        FROM attack_logs
        GROUP BY attack_type
    """
    )
    attacks_by_type = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()

    return {
        "total_transactions": total_tx,
        "total_attacks": total_attacks,
        "attacks_by_type": attacks_by_type,
    }
