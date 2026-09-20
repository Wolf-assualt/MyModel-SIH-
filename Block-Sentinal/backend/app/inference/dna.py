"""Inference DNA Generation, Real Provenance Binding, and Replay Defense."""
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import threading
from typing import Any, Dict, List, Optional, Set, Union

import numpy as np

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash, hash_bytes, hash_file
from app.crypto.chain import HashChain
from app.crypto.signer import KeyManager, default_key_manager
from app.schemas.inference import (
    InferenceConfigSpec,
    InferenceDNARecord,
    InferenceOutput,
    InputMetadataSpec,
    ModelBindingSpec,
    PreprocessingSpec,
)


class InferenceHashChain(HashChain):
    """Hash chain specifically binding consecutive Inference DNA records."""

    @staticmethod
    def compute_record_hash(index: int, timestamp: str, data_hash: str, prev_hash: str) -> str:
        """For inference DNA records, the block hash is directly the DNA hash."""
        return data_hash


def compute_input_hash(spec: Union[InputMetadataSpec, Dict[str, Any], bytes, str]) -> str:
    """Deterministically compute SHA-256 digest of input specification or bytes."""
    if isinstance(spec, bytes):
        return hash_bytes(spec)
    if isinstance(spec, InputMetadataSpec):
        return canonical_json_hash(spec.model_dump())
    if isinstance(spec, dict):
        return canonical_json_hash(spec)
    if isinstance(spec, str):
        if len(spec) == 64 and all(c in "0123456789abcdefABCDEF" for c in spec):
            return spec.lower()
        return hash_bytes(spec.encode("utf-8"))
    raise TypeError(f"Unsupported input type for hashing: {type(spec)}")


def compute_model_hash(spec: Union[ModelBindingSpec, Dict[str, Any], Path, str]) -> str:
    """Deterministically compute SHA-256 digest of model specification, path, or identity."""
    if isinstance(spec, Path) or (isinstance(spec, str) and Path(spec).is_file()):
        return hash_file(str(spec))
    if isinstance(spec, ModelBindingSpec):
        return canonical_json_hash(spec.model_dump())
    if isinstance(spec, dict):
        return canonical_json_hash(spec)
    if isinstance(spec, str):
        if len(spec) == 64 and all(c in "0123456789abcdefABCDEF" for c in spec):
            return spec.lower()
        return hash_bytes(spec.encode("utf-8"))
    raise TypeError(f"Unsupported model type for hashing: {type(spec)}")


def compute_preprocessing_hash(spec: Union[PreprocessingSpec, Dict[str, Any], str]) -> str:
    """Deterministically compute SHA-256 digest of preprocessing configuration."""
    if isinstance(spec, PreprocessingSpec):
        return canonical_json_hash(spec.model_dump())
    if isinstance(spec, dict):
        return canonical_json_hash(spec)
    if isinstance(spec, str):
        if len(spec) == 64 and all(c in "0123456789abcdefABCDEF" for c in spec):
            return spec.lower()
        return hash_bytes(spec.encode("utf-8"))
    raise TypeError(f"Unsupported preprocessing type for hashing: {type(spec)}")


def compute_inference_config_hash(spec: Union[InferenceConfigSpec, Dict[str, Any], str, None]) -> str:
    """Deterministically compute SHA-256 digest of inference configuration."""
    if spec is None:
        return canonical_json_hash(InferenceConfigSpec().model_dump())
    if isinstance(spec, InferenceConfigSpec):
        return canonical_json_hash(spec.model_dump())
    if isinstance(spec, dict):
        return canonical_json_hash(spec)
    if isinstance(spec, str):
        if len(spec) == 64 and all(c in "0123456789abcdefABCDEF" for c in spec):
            return spec.lower()
        return hash_bytes(spec.encode("utf-8"))
    raise TypeError(f"Unsupported inference config type for hashing: {type(spec)}")


def compute_output_hash(spec: Union[InferenceOutput, Dict[str, Any], np.ndarray, List[float], str]) -> str:
    """Deterministically compute SHA-256 digest of inference output."""
    if isinstance(spec, np.ndarray):
        return hash_bytes(spec.tobytes())
    if isinstance(spec, InferenceOutput):
        return spec.raw_output_digest or canonical_json_hash(spec.model_dump())
    if isinstance(spec, dict):
        return canonical_json_hash(spec)
    if isinstance(spec, list):
        return canonical_json_hash({"output": spec})
    if isinstance(spec, str):
        if len(spec) == 64 and all(c in "0123456789abcdefABCDEF" for c in spec):
            return spec.lower()
        return hash_bytes(spec.encode("utf-8"))
    raise TypeError(f"Unsupported output type for hashing: {type(spec)}")


class InferenceDNAGenerator:
    """Thread-safe engine for creating cryptographically signed Inference DNA records."""

    def __init__(
        self,
        key_manager: Optional[KeyManager] = None,
        chain: Optional[HashChain] = None,
        storage_dir: Optional[Path] = None,
    ):
        self._lock = threading.Lock()
        self.key_manager = key_manager or default_key_manager
        self.chain = chain or InferenceHashChain()
        self.storage_dir = storage_dir or Path(settings.DATA_DIR) / "inference_dna"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self._sequence_counter: int = 0
        self.seen_nonces: Set[str] = set()
        self.seen_records: Set[str] = set()
        self.seen_identities: Set[str] = set()

        self._load_state()

    def _state_file(self) -> Path:
        return self.storage_dir / "state.json"

    def _load_state(self) -> None:
        """Load persistent sequence counter, nonces, and chain history from disk."""
        state_file = self._state_file()
        if state_file.is_file():
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    state_data = json.load(f)
                self._sequence_counter = int(state_data.get("last_sequence_number", 0))
                self.seen_nonces = set(state_data.get("seen_nonces", []))
                self.seen_records = set(state_data.get("seen_records", []))
                self.seen_identities = set(state_data.get("seen_identities", []))
                if "chain_records" in state_data and isinstance(state_data["chain_records"], list):
                    self.chain.records = state_data["chain_records"]
            except Exception:
                pass

        # Also inspect existing individual record files
        for fpath in self.storage_dir.glob("*.json"):
            if fpath.name == "state.json":
                continue
            rec_id = fpath.stem
            self.seen_records.add(rec_id)

    def _save_state(self) -> None:
        """Atomically persist sequence counter, nonces, and chain history."""
        state_data = {
            "last_sequence_number": self._sequence_counter,
            "seen_nonces": sorted(list(self.seen_nonces)),
            "seen_records": sorted(list(self.seen_records)),
            "seen_identities": sorted(list(self.seen_identities)),
            "chain_records": self.chain.records,
        }
        temp_file = self.storage_dir / "state.json.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(state_data, f, indent=2)
        temp_file.replace(self._state_file())

    @staticmethod
    def compute_tuple_dna(
        sequence_number: Optional[int] = None,
        sequence_id: Optional[int] = None,
        timestamp: str = "",
        nonce: str = "",
        input_hash: Optional[str] = None,
        input_frame_sha256: Optional[str] = None,
        model_hash: Optional[str] = None,
        model_identity_digest: Optional[str] = None,
        model_digest: Optional[str] = None,
        preprocessing_hash: Optional[str] = None,
        preprocessing_digest: Optional[str] = None,
        prep_digest: Optional[str] = None,
        inference_config_hash: Optional[str] = None,
        output_hash: Optional[str] = None,
        output_digest: Optional[str] = None,
        prev_chain_hash: str = "0" * 64,
        record_id: Optional[str] = None,
        model_id: Optional[str] = None,
        model_version: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Construct deterministic canonical JSON representation of the 5-pillar tuple and compute SHA-256."""
        seq = sequence_number if sequence_number is not None else (sequence_id if sequence_id is not None else 0)
        in_hash = input_hash or input_frame_sha256 or ""
        m_hash = model_hash or model_identity_digest or model_digest or ""
        pr_hash = preprocessing_hash or preprocessing_digest or prep_digest or ""
        out_hash = output_hash or output_digest or ""
        cfg_hash = inference_config_hash or kwargs.get("config_hash", "0" * 64)

        payload: Dict[str, Any] = {
            "sequence_id": seq,
            "timestamp": timestamp,
            "nonce": nonce,
            "input_hash": in_hash,
            "model_digest": m_hash,
            "prep_digest": pr_hash,
            "inference_config_hash": cfg_hash,
            "output_hash": out_hash,
            "prev_chain_hash": prev_chain_hash,
        }
        if model_id is not None:
            payload["model_id"] = model_id
        if model_version is not None:
            payload["model_version"] = model_version
        if record_id is not None:
            payload["record_id"] = record_id

        # Include any additional structured properties deterministically
        for k, v in kwargs.items():
            if k not in payload and v is not None:
                payload[k] = v

        return canonical_json_hash(payload)

    def create_dna_record(
        self,
        model_id: str,
        model_identity_digest: Optional[str] = None,
        input_frame_sha256: Optional[str] = None,
        prep_spec: Optional[PreprocessingSpec] = None,
        output: Optional[InferenceOutput] = None,
        nonce: Optional[str] = None,
        record_id: Optional[str] = None,
        sequence_number: Optional[int] = None,
        model_version: Optional[str] = "1.0.0",
        inference_config: Optional[InferenceConfigSpec] = None,
        model_hash: Optional[str] = None,
        input_hash: Optional[str] = None,
        preprocessing_hash: Optional[str] = None,
        inference_config_hash: Optional[str] = None,
        output_hash: Optional[str] = None,
        **kwargs: Any,
    ) -> InferenceDNARecord:
        """Generate, sign with real ECDSA, and record an immutable Inference DNA proof."""
        with self._lock:
            # 1. Replay & record ID detection
            rec_id = record_id or f"dna_{secrets.token_hex(8)}"
            if rec_id in self.seen_records:
                raise ValueError(f"Replay detected: record_id '{rec_id}' has already been registered.")

            # 2. Nonce replay detection
            used_nonce = nonce if nonce is not None else secrets.token_hex(16)
            if used_nonce in self.seen_nonces:
                raise ValueError(f"Replay detected: nonce {used_nonce} has already been registered.")

            # 3. Sequence monotonicity and sequence rollback defense
            if sequence_number is not None:
                if sequence_number <= self._sequence_counter:
                    raise ValueError(
                        f"Sequence rollback detected: sequence_number {sequence_number} <= last sequence {self._sequence_counter}."
                    )
                self._sequence_counter = sequence_number
            else:
                self._sequence_counter += 1
            seq_id = self._sequence_counter

            timestamp = datetime.now(timezone.utc).isoformat()

            # 4. Deterministically resolve the 5 independent hashes
            in_hash = input_hash or (input_frame_sha256 if input_frame_sha256 else compute_input_hash(b""))
            m_hash = model_hash or (model_identity_digest if model_identity_digest else compute_model_hash(model_id))
            pr_hash = preprocessing_hash or (compute_preprocessing_hash(prep_spec) if prep_spec else compute_preprocessing_hash(PreprocessingSpec()))
            cfg_hash = inference_config_hash or compute_inference_config_hash(inference_config)
            out_hash = output_hash or (compute_output_hash(output) if output else "0" * 64)

            # Duplicate inference identity tracking
            inference_identity = f"{model_id}:{in_hash}:{pr_hash}:{cfg_hash}:{out_hash}"
            self.seen_identities.add(inference_identity)

            # 5. Fetch previous chain tip
            prev_chain_hash = (
                self.chain.records[-1]["current_hash"]
                if self.chain.records
                else "0" * 64
            )

            # 6. Compute canonical tuple DNA
            dna_hash = self.compute_tuple_dna(
                sequence_number=seq_id,
                sequence_id=seq_id,
                timestamp=timestamp,
                nonce=used_nonce,
                input_hash=in_hash,
                input_frame_sha256=in_hash,
                model_hash=m_hash,
                model_identity_digest=m_hash,
                preprocessing_hash=pr_hash,
                preprocessing_digest=pr_hash,
                prep_digest=pr_hash,
                inference_config_hash=cfg_hash,
                output_hash=out_hash,
                output_digest=out_hash,
                prev_chain_hash=prev_chain_hash,
                record_id=rec_id,
                model_id=model_id,
                model_version=model_version,
                **kwargs,
            )

            # 7. Digital signature using real backend ECDSA SECP256R1
            signature = self.key_manager.sign_hash(dna_hash)

            # 8. Append to cryptographic audit chain
            self.chain.append(dna_hash)

            # 9. Register in persistent state sets
            self.seen_nonces.add(used_nonce)
            self.seen_records.add(rec_id)

            # 10. Assemble complete InferenceDNARecord
            record = InferenceDNARecord(
                record_id=rec_id,
                sequence_number=seq_id,
                sequence_id=seq_id,
                timestamp=timestamp,
                nonce=used_nonce,
                model_id=model_id,
                model_version=model_version,
                model_hash=m_hash,
                model_identity_digest=m_hash,
                input_hash=in_hash,
                input_frame_sha256=in_hash,
                preprocessing_hash=pr_hash,
                preprocessing_digest=pr_hash,
                inference_config_hash=cfg_hash,
                output_hash=out_hash,
                output_digest=out_hash,
                dna_hash=dna_hash,
                signature=signature,
                prev_chain_hash=prev_chain_hash,
            )

            # 11. Persist record JSON to disk
            record_path = self.storage_dir / f"{rec_id}.json"
            with open(record_path, "w", encoding="utf-8") as f:
                f.write(canonical_json_dumps(record.model_dump()))

            # 12. Update state journal
            self._save_state()

            return record

    def load_record(self, record_id: str) -> Optional[InferenceDNARecord]:
        """Load persisted Inference DNA record from storage directory."""
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


# Singleton instance for system-level inference provenance
default_dna_generator = InferenceDNAGenerator()
