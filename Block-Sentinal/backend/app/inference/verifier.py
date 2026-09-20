"""Independent cryptographic auditor and verifier for Inference DNA records and chains."""
from typing import Any, Dict, List, Optional, Set

from app.crypto.signer import KeyManager
from app.inference.dna import InferenceDNAGenerator
from app.schemas.inference import ChainVerificationResponse, InferenceDNARecord, VerifyDNAResponse


class InferenceDNAVerifier:
    """Performs mathematical, cryptographic, and sequential audit of Inference DNA proofs."""

    @staticmethod
    def verify_record(
        record: InferenceDNARecord,
        public_key_pem: str,
    ) -> VerifyDNAResponse:
        """Verify 5-pillar hash integrity, real ECDSA signature, and chain pointer format."""
        discrepancies: List[str] = []

        # 1. Recompute canonical DNA tuple digest
        computed_dna_hash = InferenceDNAGenerator.compute_tuple_dna(
            sequence_number=record.sequence_number or record.sequence_id,
            sequence_id=record.sequence_id or record.sequence_number,
            timestamp=record.timestamp,
            nonce=record.nonce,
            input_hash=record.input_hash or record.input_frame_sha256,
            input_frame_sha256=record.input_frame_sha256 or record.input_hash,
            model_id=record.model_id,
            model_version=record.model_version,
            model_hash=record.model_hash or record.model_identity_digest,
            model_identity_digest=record.model_identity_digest or record.model_hash,
            preprocessing_hash=record.preprocessing_hash or record.preprocessing_digest,
            preprocessing_digest=record.preprocessing_digest or record.preprocessing_hash,
            prep_digest=record.preprocessing_digest or record.preprocessing_hash,
            inference_config_hash=record.inference_config_hash,
            output_hash=record.output_hash or record.output_digest,
            output_digest=record.output_digest or record.output_hash,
            prev_chain_hash=record.prev_chain_hash,
            record_id=record.record_id,
        )

        hash_integrity_valid = (computed_dna_hash == record.dna_hash)
        if not hash_integrity_valid:
            discrepancies.append(
                f"DNA hash mismatch: recomputed '{computed_dna_hash}' does not match record '{record.dna_hash}'."
            )

        # 2. Cryptographic signature check (Real ECDSA SECP256R1)
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

        # 4. Field alias consistency check (anti-tampering)
        alias_consistent = True
        if record.input_hash and record.input_frame_sha256 and record.input_hash != record.input_frame_sha256:
            discrepancies.append(
                f"Input hash alias discrepancy: '{record.input_hash}' vs '{record.input_frame_sha256}'."
            )
            alias_consistent = False
        if record.model_hash and record.model_identity_digest and record.model_hash != record.model_identity_digest:
            discrepancies.append(
                f"Model hash alias discrepancy: '{record.model_hash}' vs '{record.model_identity_digest}'."
            )
            alias_consistent = False
        if record.preprocessing_hash and record.preprocessing_digest and record.preprocessing_hash != record.preprocessing_digest:
            discrepancies.append(
                f"Preprocessing hash alias discrepancy: '{record.preprocessing_hash}' vs '{record.preprocessing_digest}'."
            )
            alias_consistent = False
        if record.output_hash and record.output_digest and record.output_hash != record.output_digest:
            discrepancies.append(
                f"Output hash alias discrepancy: '{record.output_hash}' vs '{record.output_digest}'."
            )
            alias_consistent = False
        if record.sequence_number and record.sequence_id and record.sequence_number != record.sequence_id:
            discrepancies.append(
                f"Sequence number alias discrepancy: '{record.sequence_number}' vs '{record.sequence_id}'."
            )
            alias_consistent = False

        if not alias_consistent:
            hash_integrity_valid = False

        is_valid = hash_integrity_valid and signature_valid and chain_pointer_valid and alias_consistent

        return VerifyDNAResponse(
            is_valid=is_valid,
            signature_valid=signature_valid,
            hash_integrity_valid=hash_integrity_valid,
            chain_pointer_valid=chain_pointer_valid,
            replay_detected=False,
            discrepancies=discrepancies,
        )

    @classmethod
    def verify_chain(
        cls,
        records: List[InferenceDNARecord],
        public_key_pem: str,
    ) -> ChainVerificationResponse:
        """Audit full inference hash chain continuity, sequence monotonicity, and anti-replay freshness."""
        if not records:
            return ChainVerificationResponse(is_valid=True, total_records=0)

        seen_nonces: Set[str] = set()
        seen_record_ids: Set[str] = set()
        discrepancies: List[str] = []
        evidence_records: List[Dict[str, Any]] = []
        replay_detected = False
        broken_sequence_id: Optional[int] = None

        for i, rec in enumerate(records):
            seq = rec.sequence_id or rec.sequence_number

            # 1. Cryptographic check on single record
            single_audit = cls.verify_record(rec, public_key_pem)
            if not single_audit.is_valid:
                discrepancies.extend(single_audit.discrepancies)
                if broken_sequence_id is None:
                    broken_sequence_id = seq
                evidence_records.append({
                    "type": "SIGNATURE_OR_HASH_TAMPERING",
                    "record_id": rec.record_id,
                    "sequence_id": seq,
                    "discrepancies": single_audit.discrepancies,
                })

            # 2. Replay attack detection (nonce and record_id reuse)
            if rec.nonce in seen_nonces or rec.record_id in seen_record_ids:
                replay_detected = True
                discrepancies.append(
                    f"Replay attack detected: reused nonce '{rec.nonce}' or record '{rec.record_id}'."
                )
                if broken_sequence_id is None:
                    broken_sequence_id = seq
                evidence_records.append({
                    "type": "INFERENCE_REPLAY_ATTACK",
                    "record_id": rec.record_id,
                    "nonce": rec.nonce,
                    "sequence_id": seq,
                })

            seen_nonces.add(rec.nonce)
            seen_record_ids.add(rec.record_id)

            # 3. Sequence continuity and monotonicity
            if i > 0:
                prev_seq = records[i - 1].sequence_id or records[i - 1].sequence_number
                if seq <= prev_seq or seq != prev_seq + 1:
                    discrepancies.append(
                        f"Sequence continuity break: expected sequence {prev_seq + 1}, but got {seq}."
                    )
                    if broken_sequence_id is None:
                        broken_sequence_id = seq
                    evidence_records.append({
                        "type": "SEQUENCE_CONTINUITY_BREAK",
                        "record_id": rec.record_id,
                        "sequence_id": seq,
                        "expected_sequence_id": prev_seq + 1,
                    })

            # 4. Sequential hash pointer continuity
            if i == 0:
                if rec.prev_chain_hash != "0" * 64 and seq == 1:
                    discrepancies.append(
                        f"Genesis record must point to zero hash, got '{rec.prev_chain_hash}'."
                    )
                    if broken_sequence_id is None:
                        broken_sequence_id = seq
            else:
                prev_dna_hash = records[i - 1].dna_hash
                if rec.prev_chain_hash != prev_dna_hash:
                    discrepancies.append(
                        f"Broken hash pointer at sequence {seq}: prev_chain_hash does not match preceding DNA hash."
                    )
                    if broken_sequence_id is None:
                        broken_sequence_id = seq
                    evidence_records.append({
                        "type": "BROKEN_HASH_CHAIN_POINTER",
                        "record_id": rec.record_id,
                        "sequence_id": seq,
                        "expected_prev_hash": prev_dna_hash,
                        "actual_prev_hash": rec.prev_chain_hash,
                    })

        is_valid = (len(discrepancies) == 0 and not replay_detected and broken_sequence_id is None)

        return ChainVerificationResponse(
            is_valid=is_valid,
            total_records=len(records),
            broken_sequence_id=broken_sequence_id,
            broken_index=broken_sequence_id,
            replay_detected=replay_detected,
            discrepancies=discrepancies,
            evidence_records=evidence_records,
        )
