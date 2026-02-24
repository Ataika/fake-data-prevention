import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API_DIR = os.path.join(ROOT, "api")
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

from crypto_service import canonical_json, compute_sha256, hmac_sign, validate_transaction_payload, verify_hmac


class CryptoServiceTests(unittest.TestCase):
    def test_validate_transaction_payload_ok(self):
        tx = {
            "tx_id": "TXN-1",
            "timestamp": "2026-02-24T00:00:00",
            "sender": "Alice",
            "recipient": "Bob",
            "amount_eur": 10.5,
            "currency": "EUR",
        }
        ok, err = validate_transaction_payload(tx)
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_validate_transaction_payload_missing(self):
        ok, err = validate_transaction_payload({"tx_id": "X"})
        self.assertFalse(ok)
        self.assertIn("Missing required fields", err)

    def test_canonical_json_deterministic(self):
        a = {"b": 2, "a": 1, "_tmp": 999}
        b = {"a": 1, "b": 2}
        self.assertEqual(canonical_json(a), canonical_json(b))

    def test_hmac_sign_verify(self):
        digest = compute_sha256("hello")
        sig = hmac_sign(digest)
        self.assertTrue(verify_hmac(digest, sig))
        self.assertFalse(verify_hmac(digest, "deadbeef"))
        self.assertFalse(verify_hmac(compute_sha256("hello2"), sig))


if __name__ == "__main__":
    unittest.main()
