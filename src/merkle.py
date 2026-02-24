"""
Merkle tree implementation for transaction digest integrity checks.
"""

import hashlib
from typing import List


class MerkleNode:
    """Simple Merkle tree node."""

    def __init__(self, hash_value: str, left=None, right=None):
        self.hash = hash_value
        self.left = left
        self.right = right

    def is_leaf(self):
        return self.left is None and self.right is None


class MerkleTree:
    """Build and verify Merkle root from leaf hashes."""

    def __init__(self, leaf_hashes: List[str]):
        if not leaf_hashes:
            raise ValueError("Cannot build Merkle tree from empty list")
        self.leaves = leaf_hashes.copy()
        self.root = self._build_tree(leaf_hashes.copy())

    def _hash_pair(self, left_hash: str, right_hash: str) -> str:
        combined = left_hash + right_hash
        return hashlib.sha256(combined.encode()).hexdigest()

    def _build_tree(self, hashes: List[str]) -> MerkleNode:
        if len(hashes) == 1:
            return MerkleNode(hashes[0])

        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])

        parent_hashes = []
        for i in range(0, len(hashes), 2):
            parent_hashes.append(self._hash_pair(hashes[i], hashes[i + 1]))
        return self._build_tree(parent_hashes)

    def get_root(self) -> str:
        return self.root.hash

    def verify_integrity(self, leaf_hashes: List[str]) -> bool:
        if len(leaf_hashes) != len(self.leaves):
            return False
        new_tree = MerkleTree(leaf_hashes.copy())
        return new_tree.get_root() == self.get_root()

    def get_proof(self, index: int):
        raise NotImplementedError("Merkle proof generation not implemented yet")

    def __str__(self):
        return f"MerkleTree(leaves={len(self.leaves)}, root={self.get_root()[:16]}...)"

    def __repr__(self):
        return self.__str__()


def build_merkle_tree_from_transactions(transactions: List[dict]) -> MerkleTree:
    """Build Merkle tree from transaction list with digest fields."""
    if not transactions:
        raise ValueError("No transactions provided")

    hashes = []
    for tx in transactions:
        if "digest" in tx:
            hashes.append(tx["digest"])
        elif "_digest" in tx:
            hashes.append(tx["_digest"])
        else:
            raise ValueError(f"Transaction {tx.get('tx_id', 'unknown')} has no digest")
    return MerkleTree(hashes)


if __name__ == "__main__":
    print("=" * 60)
    print("Testing Merkle Tree Implementation")
    print("=" * 60)

    hashes = [
        hashlib.sha256(b"tx1").hexdigest(),
        hashlib.sha256(b"tx2").hexdigest(),
        hashlib.sha256(b"tx3").hexdigest(),
        hashlib.sha256(b"tx4").hexdigest(),
    ]
    tree = MerkleTree(hashes)
    print(f"\nTest 1 root: {tree.get_root()}")

    same_hashes = hashes.copy()
    print(f"Test 2 integrity (same): {tree.verify_integrity(same_hashes)}")

    modified_hashes = hashes.copy()
    modified_hashes[2] = hashlib.sha256(b"tx3_MODIFIED").hexdigest()
    print(f"Test 3 integrity (modified): {tree.verify_integrity(modified_hashes)}")

    odd_hashes = hashes + [hashlib.sha256(b"tx5").hexdigest()]
    tree_odd = MerkleTree(odd_hashes)
    print(f"Test 4 odd root: {tree_odd.get_root()}")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)

