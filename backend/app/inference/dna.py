"""Inference DNA Generation, Provenance Binding, and Replay Defense."""
import json
from datetime import datetime, timezone
from pathlib import Path
import secrets
import threading
from typing import Any, Dict, List, Optional, Set

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash
from app.crypto.chain import HashChain
from app.crypto.signer import KeyManager, default_key_manager
from app.db.session import SessionLocal
from app.models.inference import InferenceRecord as DBInferenceRecord
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
        self._last_dna_hash: str = "0" * 64
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
        model_version: str = "1.0.0",
    ) -> str:
        """Construct the canonical tuple payload and compute its SHA-256 digest."""
        payload: Dict[str, Any] = {
            "sequence_id": sequence_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "model_id": model_id,
            "model_version": model_version,
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
        model_version: str = "1.0.0",
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
            prev_chain_hash = self._last_dna_hash

            # 5. Compute canonical DNA hash
            dna_hash = self.compute_tuple_dna(
                sequence_id=seq_id,
                timestamp=timestamp,
                nonce=used_nonce,
                model_id=model_id,
                model_version=model_version,
                model_digest=model_identity_digest,
                input_hash=input_frame_sha256,
                prep_digest=prep_digest,
                output_hash=output.raw_output_digest,
                prev_chain_hash=prev_chain_hash,
            )

            # 6. Digital signature using ECDSA SECP256R1
            signature = self.key_manager.sign_hash(dna_hash)

            # 7. Update chain head pointer and append to audit hash chain
            self._last_dna_hash = dna_hash
            self.chain.append(dna_hash)

            # 8. Assemble complete record
            rec_id = record_id or f"dna_{secrets.token_hex(8)}"
            record = InferenceDNARecord(
                record_id=rec_id,
                sequence_id=seq_id,
                timestamp=timestamp,
                nonce=used_nonce,
                model_id=model_id,
                model_version=model_version,
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
                f.write(canonical_json_dumps(record.model_dump()))

            # 10. Persist into SQLite database lineage
            try:
                with SessionLocal() as db:
                    mean_conf = (
                        float(sum(p.confidence for p in output.predictions) / len(output.predictions))
                        if output.predictions
                        else 0.0
                    )
                    db_rec = DBInferenceRecord(
                        id=rec_id,
                        model_id=model_id,
                        input_sha256=input_frame_sha256,
                        model_sha256=model_identity_digest,
                        preprocessing_sha256=prep_digest,
                        config_sha256=prep_digest,
                        output_sha256=output.raw_output_digest,
                        prediction_json=json.dumps([p.model_dump() for p in output.predictions]),
                        confidence=mean_conf,
                        nonce=used_nonce,
                        sequence_number=seq_id,
                        prev_record_hash=prev_chain_hash,
                        record_hash=dna_hash,
                        signature=signature,
                    )
                    db.add(db_rec)
                    db.commit()
            except Exception:
                pass

            return record

    def load_record(self, record_id: str) -> Optional[InferenceDNARecord]:
        """Load an existing Inference DNA record from storage."""
        record_path = self.storage_dir / f"{record_id}.json"
        if not record_path.is_file():
            return None

        with open(record_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return InferenceDNARecord(**data)

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

    def list_records(self, limit: int = 50) -> List[InferenceDNARecord]:
        """List stored Inference DNA records ordered by sequence number descending."""
        records = []
        if self.storage_dir.exists():
            for p in self.storage_dir.glob("*.json"):
                rec = self.load_record(p.stem)
                if rec:
                    records.append(rec)
        records.sort(key=lambda r: getattr(r, "sequence_id", 0), reverse=True)
        return records[:limit]


# Singleton instance for system-level inference provenance
default_dna_generator = InferenceDNAGenerator()

