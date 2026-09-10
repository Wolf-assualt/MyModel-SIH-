"""Merkle Tree implementation for tamper-evident dataset and batch integrity verification."""
from typing import Dict, List
from app.crypto.canonical import hash_bytes


class MerkleTree:
    """Binary Merkle Tree for verifiable inclusion proofs without network dependencies."""

    def __init__(self, leaves: List[str]):
        self.leaves = list(leaves)
        self.levels: List[List[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self.leaves:
            self.root = hash_bytes(b"")
            self.levels = [[]]
            return

        current_level = list(self.leaves)
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level: List[str] = []
            padded_level = list(current_level)
            if len(padded_level) % 2 == 1:
                padded_level.append(padded_level[-1])

            for i in range(0, len(padded_level), 2):
                combined = (padded_level[i] + padded_level[i + 1]).encode("utf-8")
                parent = hash_bytes(combined)
                next_level.append(parent)

            self.levels.append(next_level)
            current_level = next_level

        self.root = self.levels[-1][0] if self.levels[-1] else hash_bytes(b"")

    def get_root(self) -> str:
        """Return the hex-encoded Merkle root hash."""
        return self.root

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        """Generate audit path (sibling hashes and positions) for leaf at given index."""
        if not self.leaves or index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of bounds (total leaves: {len(self.leaves)})")

        proof: List[Dict[str, str]] = []
        idx = index

        for level in self.levels[:-1]:
            padded_level = list(level)
            if len(padded_level) % 2 == 1:
                padded_level.append(padded_level[-1])

            if idx % 2 == 0:
                sibling_idx = idx + 1
                proof.append({"position": "right", "hash": padded_level[sibling_idx]})
            else:
                sibling_idx = idx - 1
                proof.append({"position": "left", "hash": padded_level[sibling_idx]})

            idx = idx // 2

        return proof

    @staticmethod
    def verify_proof(leaf: str, proof: List[Dict[str, str]], root: str) -> bool:
        """Reconstruct root from leaf and audit path, verifying inclusion."""
        current = leaf

        for step in proof:
            sibling = step.get("hash", "")
            position = step.get("position", "")

            if position == "left":
                combined = (sibling + current).encode("utf-8")
            elif position == "right":
                combined = (current + sibling).encode("utf-8")
            else:
                return False

            current = hash_bytes(combined)

        return current == root
