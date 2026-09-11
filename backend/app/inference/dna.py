"""Inference DNA Generation, Provenance Binding, and Replay Defense."""
import json
from datetime import datetime, timezone
from pathlib import Path
import secrets
import threading
from typing import Any, Dict, Optional, Set

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.crypto.chain import HashChain
from app.crypto.signer import KeyManager, default_key_manager
from app.schemas.inference import InferenceDNARecord, InferenceOutput, PreprocessingSpec


class InferenceDNAGenerator:
    """Thread-safe engine for creating cryptographically signed Inference DNA records."""

    def __init__(
        self,
        key_manager: Optional[KeyManager] = None,
        chain: Optional[HashChain] = None,
        storage_dir: Optional[Path] = None,
    ):
        self._lock = threading.Lock()
        self._sequence_counter: int = 0
        self.seen_nonces: Set[str] = set()
        self.key_manager = key_manager or default_key_manager
        self.chain = chain or HashChain()
        self.storage_dir = storage_dir or Path(settings.DATA_DIR) / "inference_dna"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_tuple_dna(
        sequence_id: int,
        timestamp: str,
        nonce: str,
        model_id: str,
        model_digest: str,
        input_hash: str,
        prep_digest: str,
        output_hash: str,
        prev_chain_hash: str,
    ) -> str:
        """Construct the canonical tuple payload and compute its SHA-256 digest."""
        payload: Dict[str, Any] = {
            "sequence_id": sequence_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "model_id": model_id,
            "model_digest": model_digest,
            "input_hash": input_hash,
            "prep_digest": prep_digest,
            "output_hash": output_hash,
            "prev_chain_hash": prev_chain_hash,
        }
        return canonical_json_hash(payload)

    def create_dna_record(
        self,
        model_id: str,
        model_identity_digest: str,
        input_frame_sha256: str,
        prep_spec: PreprocessingSpec,
        output: InferenceOutput,
        nonce: Optional[str] = None,
        record_id: Optional[str] = None,
    ) -> InferenceDNARecord:
        """Generate, sign, and record an immutable Inference DNA proof."""
        with self._lock:
            # 1. Nonce handling and replay detection
            used_nonce = nonce if nonce is not None else secrets.token_hex(16)
            if used_nonce in self.seen_nonces:
                raise ValueError(f"Replay detected: nonce {used_nonce} has already been registered.")
            self.seen_nonces.add(used_nonce)

            # 2. Sequence increment & timestamping
            self._sequence_counter += 1
            seq_id = self._sequence_counter
            timestamp = datetime.now(timezone.utc).isoformat()

            # 3. Canonical preprocessing digest
            prep_digest = canonical_json_hash(prep_spec.model_dump())

            # 4. Fetch tip of current hash chain
            prev_chain_hash = (
                self.chain.records[-1]["current_hash"]
                if self.chain.records
                else "0" * 64
            )

            # 5. Compute canonical DNA hash
            dna_hash = self.compute_tuple_dna(
                sequence_id=seq_id,
                timestamp=timestamp,
                nonce=used_nonce,
                model_id=model_id,
                model_digest=model_identity_digest,
                input_hash=input_frame_sha256,
                prep_digest=prep_digest,
                output_hash=output.raw_output_digest,
                prev_chain_hash=prev_chain_hash,
            )

            # 6. Digital signature using ECDSA SECP256R1
            signature = self.key_manager.sign_hash(dna_hash)

            # 7. Append to tamper-evident audit hash chain
            self.chain.append(dna_hash)

            # 8. Assemble complete record
            rec_id = record_id or f"dna_{secrets.token_hex(8)}"
            record = InferenceDNARecord(
                record_id=rec_id,
                sequence_id=seq_id,
                timestamp=timestamp,
                nonce=used_nonce,
                model_id=model_id,
                model_identity_digest=model_identity_digest,
                input_frame_sha256=input_frame_sha256,
                preprocessing_digest=prep_digest,
                output_digest=output.raw_output_digest,
                dna_hash=dna_hash,
                signature=signature,
                prev_chain_hash=prev_chain_hash,
            )

            # 9. Persist to disk
            record_path = self.storage_dir / f"{rec_id}.json"
            with open(record_path, "w", encoding="utf-8") as f:
                json.dump(record.model_dump(), f, indent=2)

            return record

    def export_public_key_pem(self) -> str:
        """Export signing key's public key in SubjectPublicKeyInfo PEM string format."""
        return self.key_manager.export_public_key_pem().decode("utf-8")

    def get_chain_state(self) -> Dict[str, Any]:
        """Return the current hash chain sequence state and tip hash."""
        with self._lock:
            tip_hash = (
                self.chain.records[-1]["current_hash"]
                if self.chain.records
                else "0" * 64
            )
            return {
                "records_count": len(self.chain.records),
                "tip_hash": tip_hash,
                "records": list(self.chain.records),
            }


# Singleton instance for system-level inference provenance
default_dna_generator = InferenceDNAGenerator()
