"""
Multi-party signature chain example: Alice -> Bob -> Charlie.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List


PARTY_KEYS = {
    "Alice": "alice-secret-key-2026",
    "Bob": "bob-secret-key-2026",
    "Charlie": "charlie-secret-key-2026",
}


@dataclass
class Signature:
    party: str
    timestamp: str
    signature: str
    prev_hash: str


@dataclass
class SignatureChain:
    tx_id: str
    original_data: dict
    signatures: List[Signature]

    def to_dict(self):
        return {
            "tx_id": self.tx_id,
            "original_data": self.original_data,
            "signatures": [asdict(s) for s in self.signatures],
        }


class MultiPartyProtocol:
    """Protocol for chain signing and verification."""

    def __init__(self):
        self.chains: Dict[str, SignatureChain] = {}

    def _compute_data_hash(self, data: dict) -> str:
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _sign_with_hmac(self, message: str, party: str) -> str:
        key = PARTY_KEYS.get(party)
        if not key:
            raise ValueError(f"Unknown party: {party}")
        return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

    def _verify_signature(self, message: str, signature: str, party: str) -> bool:
        expected = self._sign_with_hmac(message, party)
        return hmac.compare_digest(expected, signature)

    def initiate_chain(self, tx_data: dict, initiator: str = "Alice") -> SignatureChain:
        tx_id = tx_data.get("tx_id")
        if not tx_id:
            raise ValueError("Transaction must have tx_id")

        data_hash = self._compute_data_hash(tx_data)
        signature_value = self._sign_with_hmac(data_hash, initiator)

        sig = Signature(
            party=initiator,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signature=signature_value,
            prev_hash="0" * 64,
        )

        chain = SignatureChain(tx_id=tx_id, original_data=tx_data, signatures=[sig])
        self.chains[tx_id] = chain
        return chain

    def add_signature(self, tx_id: str, party: str) -> bool:
        chain = self.chains.get(tx_id)
        if not chain:
            print(f"ERROR: Chain for {tx_id} not found")
            return False

        existing_parties = [s.party for s in chain.signatures]
        if party in existing_parties:
            print(f"ERROR: {party} already signed this transaction")
            return False

        if not self.verify_chain(tx_id):
            print("ERROR: Previous signatures are invalid")
            return False

        prev_state = {"data": chain.original_data, "signatures": [asdict(s) for s in chain.signatures]}
        prev_hash = hashlib.sha256(json.dumps(prev_state, sort_keys=True).encode()).hexdigest()
        signature_value = self._sign_with_hmac(prev_hash, party)

        sig = Signature(
            party=party,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signature=signature_value,
            prev_hash=prev_hash,
        )
        chain.signatures.append(sig)
        return True

    def verify_chain(self, tx_id: str) -> bool:
        chain = self.chains.get(tx_id)
        if not chain:
            return False

        for i, sig in enumerate(chain.signatures):
            if i == 0:
                data_hash = self._compute_data_hash(chain.original_data)
                if not self._verify_signature(data_hash, sig.signature, sig.party):
                    print(f"FAIL: First signature by {sig.party} is invalid")
                    return False
            else:
                prev_state = {
                    "data": chain.original_data,
                    "signatures": [asdict(s) for s in chain.signatures[:i]],
                }
                expected_prev_hash = hashlib.sha256(json.dumps(prev_state, sort_keys=True).encode()).hexdigest()
                if sig.prev_hash != expected_prev_hash:
                    print(f"FAIL: {sig.party} prev_hash mismatch")
                    return False
                if not self._verify_signature(sig.prev_hash, sig.signature, sig.party):
                    print(f"FAIL: Signature by {sig.party} is invalid")
                    return False

        return True

    def get_chain_status(self, tx_id: str) -> dict:
        chain = self.chains.get(tx_id)
        if not chain:
            return {"error": "Chain not found"}

        return {
            "tx_id": tx_id,
            "valid": self.verify_chain(tx_id),
            "signatures_count": len(chain.signatures),
            "parties": [s.party for s in chain.signatures],
            "chain": chain.to_dict(),
        }

    def simulate_attack(self, tx_id: str, attack_type: str) -> dict:
        chain = self.chains.get(tx_id)
        if not chain:
            return {"error": "Chain not found"}

        original_valid = self.verify_chain(tx_id)

        if attack_type == "modify_data":
            chain.original_data["amount_eur"] = 99999.99
        elif attack_type == "forge_signature":
            if len(chain.signatures) > 1:
                chain.signatures[1].signature = "forged_signature_12345"
        elif attack_type == "remove_signature":
            if len(chain.signatures) > 2:
                chain.signatures.pop(1)

        after_valid = self.verify_chain(tx_id)
        return {
            "attack_type": attack_type,
            "before_attack": original_valid,
            "after_attack": after_valid,
            "detected": not after_valid,
        }


if __name__ == "__main__":
    print("=" * 70)
    print("Multi-Party Signature Chain Demo")
    print("Scenario: Alice -> Bob -> Charlie")
    print("=" * 70)

    protocol = MultiPartyProtocol()
    tx = {
        "tx_id": "TXN-MULTI-001",
        "sender": "Alice",
        "recipient": "Charlie",
        "amount_eur": 1000.00,
        "currency": "EUR",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    print("\n[1] Alice initiates chain")
    chain = protocol.initiate_chain(tx, "Alice")
    print(f"    Alice signed at {chain.signatures[0].timestamp}")

    print("\n[2] Bob adds signature")
    if protocol.add_signature("TXN-MULTI-001", "Bob"):
        print("    Bob signed successfully")

    print("\n[3] Charlie adds signature")
    if protocol.add_signature("TXN-MULTI-001", "Charlie"):
        print("    Charlie signed successfully")

    print("\n[4] Verify full chain")
    status = protocol.get_chain_status("TXN-MULTI-001")
    print(f"    Chain valid: {status['valid']}")
    print(f"    Parties: {' -> '.join(status['parties'])}")

    print("\n[5] Simulate modification attack")
    result = protocol.simulate_attack("TXN-MULTI-001", "modify_data")
    print(f"    Attack detected: {result['detected']}")

    print("\n" + "=" * 70)
    print("Demo complete.")
    print("=" * 70)

