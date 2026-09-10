"""Cryptographic Provenance and Integrity Endpoints."""
from fastapi import APIRouter
from app.crypto.canonical import canonical_json_hash
from app.crypto.chain import HashChain
from app.crypto.merkle import MerkleTree
from app.crypto.signer import KeyManager, default_key_manager
from app.schemas.base import ResponseEnvelope
from app.schemas.crypto import (
    ChainVerifyRequest,
    ChainVerifyResponse,
    HashRequest,
    HashResponse,
    MerkleBuildRequest,
    MerkleBuildResponse,
    MerkleVerifyRequest,
    SignRequest,
    SignResponse,
    VerifyResponse,
    VerifySignatureRequest,
)

router = APIRouter(prefix="/crypto", tags=["Cryptographic Provenance"])


@router.post("/hash", response_model=ResponseEnvelope[HashResponse])
def compute_canonical_hash(payload: HashRequest) -> ResponseEnvelope[HashResponse]:
    """Compute deterministic SHA-256 canonical hash of arbitrary dictionary payload."""
    digest = canonical_json_hash(payload.data)
    return ResponseEnvelope(data=HashResponse(canonical_hash=digest))


@router.post("/merkle/build", response_model=ResponseEnvelope[MerkleBuildResponse])
def build_merkle_tree(payload: MerkleBuildRequest) -> ResponseEnvelope[MerkleBuildResponse]:
    """Build a Merkle tree from provided leaf hashes and return its Merkle root."""
    tree = MerkleTree(payload.leaves)
    return ResponseEnvelope(
        data=MerkleBuildResponse(
            root=tree.get_root(),
            leaf_count=len(payload.leaves),
        )
    )


@router.post("/merkle/verify", response_model=ResponseEnvelope[VerifyResponse])
def verify_merkle_proof(payload: MerkleVerifyRequest) -> ResponseEnvelope[VerifyResponse]:
    """Verify an inclusion proof against a specified Merkle root."""
    is_valid = MerkleTree.verify_proof(
        leaf=payload.leaf,
        proof=payload.proof,
        root=payload.root,
    )
    return ResponseEnvelope(
        data=VerifyResponse(
            valid=is_valid,
            details="Inclusion proof valid" if is_valid else "Inclusion proof verification failed",
        )
    )


@router.post("/sign", response_model=ResponseEnvelope[SignResponse])
def sign_digest(payload: SignRequest) -> ResponseEnvelope[SignResponse]:
    """Cryptographically sign a SHA-256 digest using SECP256R1 ECDSA."""
    signature = default_key_manager.sign_hash(payload.digest)
    pubkey_pem = default_key_manager.export_public_key_pem().decode("utf-8")
    return ResponseEnvelope(
        data=SignResponse(
            signature=signature,
            public_key_pem=pubkey_pem,
        )
    )


@router.post("/verify", response_model=ResponseEnvelope[VerifyResponse])
def verify_signature(payload: VerifySignatureRequest) -> ResponseEnvelope[VerifyResponse]:
    """Verify an ECDSA digital signature against the supplied public key and digest."""
    is_valid = KeyManager.verify_signature(
        public_key_pem=payload.public_key_pem.encode("utf-8"),
        digest_hex=payload.digest,
        signature_hex=payload.signature,
    )
    return ResponseEnvelope(
        data=VerifyResponse(
            valid=is_valid,
            details="Signature matches digest" if is_valid else "Invalid or tampered signature",
        )
    )


@router.post("/chain/verify", response_model=ResponseEnvelope[ChainVerifyResponse])
def verify_hash_chain(payload: ChainVerifyRequest) -> ResponseEnvelope[ChainVerifyResponse]:
    """Audit an append-only cryptographic hash chain for tampering or broken linkages."""
    is_valid, broken_idx = HashChain.verify_chain(payload.records)
    message = (
        "Hash chain integrity confirmed. 0 broken links."
        if is_valid
        else f"Tampering detected at block index {broken_idx}."
    )
    return ResponseEnvelope(
        data=ChainVerifyResponse(
            valid=is_valid,
            broken_index=broken_idx,
            message=message,
        )
    )
