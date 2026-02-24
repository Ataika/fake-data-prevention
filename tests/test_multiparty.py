import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from multiparty import MultiPartyProtocol


class MultiPartyTests(unittest.TestCase):
    def test_full_chain_alice_bob_charlie(self):
        p = MultiPartyProtocol()
        tx = {
            "tx_id": "TXN-MP-1",
            "timestamp": "2026-02-24T10:00:00",
            "sender": "Alice",
            "recipient": "UniMe Fees",
            "amount_eur": 500.0,
            "currency": "EUR",
        }
        chain = p.initiate_chain(tx, initiator="Alice")
        self.assertEqual(chain.tx_id, "TXN-MP-1")
        self.assertTrue(p.add_signature("TXN-MP-1", "Bob"))
        self.assertTrue(p.add_signature("TXN-MP-1", "Charlie"))
        status = p.get_chain_status("TXN-MP-1")
        self.assertTrue(status["valid"])
        self.assertEqual(status["signatures_count"], 3)


if __name__ == "__main__":
    unittest.main()

