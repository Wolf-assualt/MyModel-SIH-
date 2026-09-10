"""Tamper-evident Hash Chain for audit logs and sequential provenance verification."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from app.crypto.canonical import hash_bytes


class HashChain:
    """Append-only cryptographic hash chain for sequence and tamper verification."""

    def __init__(self, initial_records: Optional[List[Dict[str, Any]]] = None):
        self.records: List[Dict[str, Any]] = list(initial_records) if initial_records else []

    @staticmethod
    def compute_record_hash(index: int, timestamp: str, data_hash: str, prev_hash: str) -> str:
        """Deterministic computation of current_hash: SHA-256(index + timestamp + data_hash + prev_hash)."""
        payload = f"{index}{timestamp}{data_hash}{prev_hash}".encode("utf-8")
        return hash_bytes(payload)

    def append(self, data_hash: str) -> Dict[str, Any]:
        """Create, hash, and append the next block to the chain."""
        index = len(self.records)
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self.records[-1]["current_hash"] if self.records else "0" * 64
        current_hash = self.compute_record_hash(index, timestamp, data_hash, prev_hash)

        record = {
            "index": index,
            "timestamp": timestamp,
            "data_hash": data_hash,
            "prev_hash": prev_hash,
            "current_hash": current_hash,
        }
        self.records.append(record)
        return record

    @classmethod
    def verify_chain(cls, chain_records: List[Dict[str, Any]]) -> Tuple[bool, Optional[int]]:
        """Verify the integrity of a hash chain sequence from genesis to tip.
        
        Returns:
            (True, None) if the chain is unbroken and valid.
            (False, broken_index) if tampering, hash mismatch, or sequence gap is detected.
        """
        if not chain_records:
            return True, None

        for i, record in enumerate(chain_records):
            # 1. Verify sequence index
            if record.get("index") != i:
                return False, i

            # 2. Verify previous hash pointer
            expected_prev = "0" * 64 if i == 0 else chain_records[i - 1].get("current_hash")
            if record.get("prev_hash") != expected_prev:
                return False, i

            # 3. Recompute and verify current hash
            expected_current = cls.compute_record_hash(
                index=record.get("index", -1),
                timestamp=str(record.get("timestamp", "")),
                data_hash=str(record.get("data_hash", "")),
                prev_hash=str(record.get("prev_hash", "")),
            )
            if record.get("current_hash") != expected_current:
                return False, i

        return True, None
