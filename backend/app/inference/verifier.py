"""Independent cryptographic auditor and verifier for Inference DNA records."""
from typing import List

from app.crypto.signer import KeyManager
from app.inference.dna import InferenceDNAGenerator
from app.schemas.inference import InferenceDNARecord, VerifyDNAResponse


class InferenceDNAVerifier:
    """Performs mathematical and cryptographic audit of an InferenceDNARecord."""

    @staticmethod
    def verify_record(
        record: InferenceDNARecord,
        public_key_pem: str,
    ) -> VerifyDNAResponse:
        """Verify hash integrity, cryptographic signature, and chain pointer format."""
        discrepancies: List[str] = []

        # 1. Recompute canonical DNA tuple digest
        computed_dna_hash = InferenceDNAGenerator.compute_tuple_dna(
            sequence_id=record.sequence_id,
            timestamp=record.timestamp,
            nonce=record.nonce,
            model_id=record.model_id,
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
