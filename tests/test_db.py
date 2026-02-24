import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API_DIR = os.path.join(ROOT, "api")
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

import db


class DbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.sqlite")
        os.environ["FDP_DB_PATH"] = self.db_path
        db.init_db()

    def tearDown(self):
        os.environ.pop("FDP_DB_PATH", None)
        self.tmp.cleanup()

    def test_save_list_stats(self):
        tx = {
            "tx_id": "TXN-DB-1",
            "timestamp": "2026-02-24T10:00:00",
            "sender": "Alice",
            "recipient": "Bob",
            "amount_eur": 123.45,
            "currency": "EUR",
            "category": "General",
            "bank": "UniBank",
            "status": "COMPLETED",
            "note": "test",
        }
        jwt_payload = {"sub": tx["tx_id"], "exp": 9999999999}
        saved = db.save_transaction(tx, "abc123", "sig123", jwt_payload)
        self.assertTrue(saved)

        rows = db.list_transactions(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tx_id"], "TXN-DB-1")
        self.assertEqual(rows[0]["jwt_payload"]["sub"], "TXN-DB-1")

        stats = db.get_stats()
        self.assertEqual(stats["total_transactions"], 1)

    def test_duplicate_tx_id_returns_false(self):
        tx = {
            "tx_id": "TXN-DUP-1",
            "timestamp": "2026-02-24T10:00:00",
            "sender": "Alice",
            "recipient": "Bob",
            "amount_eur": 1.0,
            "currency": "EUR",
        }
        self.assertTrue(db.save_transaction(tx, "d1", "s1", {"a": 1}))
        self.assertFalse(db.save_transaction(tx, "d2", "s2", {"a": 2}))


if __name__ == "__main__":
    unittest.main()

