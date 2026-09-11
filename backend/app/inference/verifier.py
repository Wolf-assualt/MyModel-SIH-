"""Independent cryptographic auditor and verifier for Inference DNA records and Hash Chains."""
import uuid
from typing import Any, Dict, List, Optional, Set

from app.crypto.chain import HashChain
from app.crypto.signer import KeyManager, default_key_manager
from app.inference.dna import InferenceDNAGenerator
from app.schemas.inference import (
    ChainVerificationResponse,
    InferenceDNARecord,
    VerifyDNAResponse,
)


class InferenceDNAVerifier:
    """Performs mathematical, cryptographic, and hash-chain audit of Inference DNA records."""

    @staticmethod
    def verify_record(
        record: InferenceDNARecord,
        public_key_pem: str,
    ) -> VerifyDNAResponse:
        """Verify hash integrity, cryptographic signature, and chain pointer format for a single record."""
        discrepancies: List[str] = []

        # 1. Recompute canonical DNA tuple digest
        computed_dna_hash = InferenceDNAGenerator.compute_tuple_dna(
            sequence_id=record.sequence_id,
            timestamp=record.timestamp,
            nonce=record.nonce,
            model_id=record.model_id,
            model_version=record.model_version,
            model_digest=record.model_identity_digest,
            input_hash=record.input_frame_sha256,
            prep_digest=record.preprocessing_digest,
            output_hash=record.output_digest,
            prev_chain_hash=record.prev_chain_hash,
        )

        hash_integrity_valid = (computed_dna_hash == record.dna_hash)
        if not hash_integrity_valid:
            discrepancies.append(
                f"DNA hash mismatch: recomputed '{computed_dna_hash}' does not match record '{record.dna_hash}'."
            )

        # 2. Cryptographic signature check (ECDSA SECP256R1)
        signature_valid = KeyManager.verify_signature(
            public_key_pem=public_key_pem,
            digest_hex=record.dna_hash,
            signature_hex=record.signature,
        )
        if not signature_valid:
            discrepancies.append("ECDSA SECP256R1 signature is invalid for the given public key and DNA hash.")

        # 3. Chain pointer validation
        chain_pointer_valid = (
            len(record.prev_chain_hash) == 64
            and all(c in "0123456789abcdefABCDEF" for c in record.prev_chain_hash)
        )
        if not chain_pointer_valid:
            discrepancies.append(
                f"Invalid previous chain hash format: '{record.prev_chain_hash}' (must be 64-character hexadecimal)."
            )

        is_valid = hash_integrity_valid and signature_valid and chain_pointer_valid

        return VerifyDNAResponse(
            is_valid=is_valid,
            signature_valid=signature_valid,
            hash_integrity_valid=hash_integrity_valid,
            chain_pointer_valid=chain_pointer_valid,
            discrepancies=discrepancies,
        )

    @staticmethod
    def verify_chain(
        records: List[InferenceDNARecord],
        public_key_pem: Optional[str] = None,
    ) -> ChainVerificationResponse:
        """Verify complete inference hash chain continuity, sequence monotonicity, and anti-replay freshness."""
        if not records:
            return ChainVerificationResponse(
                is_valid=True,
                total_records=0,
                broken_sequence_id=None,
                replay_detected=False,
                evidence_records=[],
                discrepancies=[],
            )

        discrepancies: List[str] = []
        evidence_records: List[Dict[str, Any]] = []
        seen_nonces: Set[str] = set()
        replay_detected = False
        broken_sequence_id: Optional[int] = None

        pubkey = public_key_pem or default_key_manager.export_public_key_pem().decode("utf-8")

        expected_prev_hash = records[0].prev_chain_hash

        # Re-build simulated hash chain to verify block links
        chain_runner = HashChain()

        for i, rec in enumerate(records):
            # 1. Nonce uniqueness check (Replay Detection)
            if rec.nonce in seen_nonces:
                replay_detected = True
                if broken_sequence_id is None:
                    broken_sequence_id = rec.sequence_id
                msg = f"Replay attack detected at sequence {rec.sequence_id}: duplicate nonce '{rec.nonce}' reused."
                discrepancies.append(msg)
                evidence_records.append({
                    "evidence_id": str(uuid.uuid4()),
                    "type": "INFERENCE_REPLAY_ATTACK",
                    "sequence_id": rec.sequence_id,
                    "nonce": rec.nonce,
                    "severity": "CRITICAL",
                    "description": msg,
                })
            seen_nonces.add(rec.nonce)

            # 2. Sequence continuity check
            if i > 0 and rec.sequence_id != records[i - 1].sequence_id + 1:
                if broken_sequence_id is None:
                    broken_sequence_id = rec.sequence_id
                msg = f"Sequence continuity break: expected seq {records[i - 1].sequence_id + 1}, got {rec.sequence_id}."
                discrepancies.append(msg)
                evidence_records.append({
                    "evidence_id": str(uuid.uuid4()),
                    "type": "SEQUENCE_CONTINUITY_BREAK",
                    "sequence_id": rec.sequence_id,
                    "expected_sequence": records[i - 1].sequence_id + 1,
                    "severity": "CRITICAL",
                    "description": msg,
                })

            # 3. Hash chain pointer continuity check
            if i == 0:
                expected_prev = records[0].prev_chain_hash
            else:
                expected_prev = records[i - 1].dna_hash

            if rec.prev_chain_hash != expected_prev:
                if broken_sequence_id is None:
                    broken_sequence_id = rec.sequence_id
                msg = f"Hash chain linkage broken at sequence {rec.sequence_id}: prev_chain_hash does not match preceding DNA hash."
                discrepancies.append(msg)
                evidence_records.append({
                    "evidence_id": str(uuid.uuid4()),
                    "type": "CHAIN_POINTER_MISMATCH",
                    "sequence_id": rec.sequence_id,
                    "prev_hash_in_record": rec.prev_chain_hash,
                    "expected_prev_hash": expected_prev,
                    "severity": "CRITICAL",
                    "description": msg,
                })

            # 4. Individual signature and hash integrity check
            single_audit = InferenceDNAVerifier.verify_record(rec, pubkey)
            if not single_audit.is_valid:
                if broken_sequence_id is None:
                    broken_sequence_id = rec.sequence_id
                for d in single_audit.discrepancies:
                    discrepancies.append(f"Seq {rec.sequence_id}: {d}")
                evidence_records.append({
                    "evidence_id": str(uuid.uuid4()),
                    "type": "RECORD_INTEGRITY_FAILURE",
                    "sequence_id": rec.sequence_id,
                    "hash_integrity_valid": single_audit.hash_integrity_valid,
                    "signature_valid": single_audit.signature_valid,
                    "severity": "CRITICAL",
                    "description": f"Cryptographic integrity failed at seq {rec.sequence_id}",
                })

        is_valid = len(discrepancies) == 0

        return ChainVerificationResponse(
            is_valid=is_valid,
            total_records=len(records),
            broken_sequence_id=broken_sequence_id,
            replay_detected=replay_detected,
            evidence_records=evidence_records,
            discrepancies=discrepancies,
        )
