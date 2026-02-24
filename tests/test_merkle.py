import hashlib
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from merkle import MerkleTree


class MerkleTests(unittest.TestCase):
    def test_root_stable_for_same_data(self):
        leaves = [hashlib.sha256(f"tx{i}".encode()).hexdigest() for i in range(1, 5)]
        t1 = MerkleTree(leaves)
        t2 = MerkleTree(list(leaves))
        self.assertEqual(t1.get_root(), t2.get_root())

    def test_root_changes_when_leaf_changes(self):
        leaves = [hashlib.sha256(f"tx{i}".encode()).hexdigest() for i in range(1, 5)]
        tree = MerkleTree(leaves)
        leaves[2] = hashlib.sha256(b"tx3-modified").hexdigest()
        modified = MerkleTree(leaves)
        self.assertNotEqual(tree.get_root(), modified.get_root())


if __name__ == "__main__":
    unittest.main()

