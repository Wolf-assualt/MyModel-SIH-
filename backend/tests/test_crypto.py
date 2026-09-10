"""Unit and integration tests for cryptographic foundation and provenance endpoints."""
import os
import tempfile
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.crypto.canonical import (
    canonical_json_dumps,
    canonical_json_hash,
    hash_bytes,
    hash_file,
)
from app.crypto.chain import HashChain
from app.crypto.merkle import MerkleTree
from app.crypto.signer import KeyManager, default_key_manager
from app.main import app

client = TestClient(app)


# 1. Canonical Hashing Tests
def test_canonical_json_invariance():
    """Verify that dictionaries with identical contents in different order yield identical hashes."""
    data_a = {
        "model_id": "yolov8-nano",
        "contributor": "Alpha",
        "version": "1.0.0",
        "metadata": {"batch": 42, "status": "active"},
    }
    data_b = {
        "metadata": {"status": "active", "batch": 42},
        "version": "1.0.0",
        "contributor": "Alpha",
        "model_id": "yolov8-nano",
    }

    hash_a = canonical_json_hash(data_a)
    hash_b = canonical_json_hash(data_b)

    assert hash_a == hash_b
    assert len(hash_a) == 64


def test_canonical_json_datetime_serialization():
    """Verify datetime serialization produces deterministic UTC ISO-8601 formatting."""
    dt = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    payload = {"timestamp": dt, "event": "AUDIT"}
    dumped = canonical_json_dumps(payload)
    assert "2026-09-10T12:00:00+00:00" in dumped


def test_hash_file_and_missing_file():
    """Verify streaming file hash and FileNotFoundError on missing files."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"TRUST-CV DEFENCE EVIDENCE PAYLOAD")
        tmp_path = tmp.name

    try:
        digest = hash_file(tmp_path)
        expected = hash_bytes(b"TRUST-CV DEFENCE EVIDENCE PAYLOAD")
        assert digest == expected
    finally:
        os.remove(tmp_path)

    with pytest.raises(FileNotFoundError):
        hash_file("non_existent_file_trust_cv.bin")


# 2. Merkle Tree Tests
def test_merkle_tree_empty_and_single():
    """Verify Merkle tree behavior on empty and single leaf lists."""
    empty_tree = MerkleTree([])
    assert empty_tree.get_root() == hash_bytes(b"")

    single_leaf = hash_bytes(b"sample_001")
    single_tree = MerkleTree([single_leaf])
    assert single_tree.get_root() == single_leaf
    assert single_tree.get_proof(0) == []
    assert MerkleTree.verify_proof(single_leaf, [], single_leaf) is True


def test_merkle_tree_proof_and_verification():
    """Verify Merkle inclusion proof generation, validation, and tampering rejection."""
    leaves = [hash_bytes(f"leaf_{i}".encode("utf-8")) for i in range(7)]
    tree = MerkleTree(leaves)
    root = tree.get_root()
    assert len(root) == 64

    # Verify inclusion proof for each leaf
    for i, leaf in enumerate(leaves):
        proof = tree.get_proof(i)
        assert MerkleTree.verify_proof(leaf, proof, root) is True

    # Verify tampering detection
    tampered_leaf = hash_bytes(b"tampered_leaf_payload")
    proof_for_0 = tree.get_proof(0)
    assert MerkleTree.verify_proof(tampered_leaf, proof_for_0, root) is False

    # Out of bounds index
    with pytest.raises(IndexError):
        tree.get_proof(999)


# 3. ECDSA Key Management and Signature Tests
def test_ecdsa_signing_and_verification():
    """Verify SECP256R1 ECDSA key generation, digital signing, and verification."""
    km = KeyManager()
    pubkey_pem = km.export_public_key_pem()
    privkey_pem = km.export_private_key_pem()

    assert b"BEGIN PUBLIC KEY" in pubkey_pem
    assert b"BEGIN PRIVATE KEY" in privkey_pem

    digest = hash_bytes(b"INFERENCE_DNA_RECORD_HASH")
    signature_hex = km.sign_hash(digest)
    assert len(signature_hex) > 0

    # Valid verification
    is_valid = KeyManager.verify_signature(pubkey_pem, digest, signature_hex)
    assert is_valid is True

    # Tampered digest should fail
    tampered_digest = hash_bytes(b"TAMPERED_INFERENCE_DNA_RECORD_HASH")
    assert KeyManager.verify_signature(pubkey_pem, tampered_digest, signature_hex) is False

    # Tampered signature should fail
    corrupted_signature = "00" * (len(signature_hex) // 2)
    assert KeyManager.verify_signature(pubkey_pem, digest, corrupted_signature) is False


# 4. Hash Chain Tests
def test_hash_chain_creation_and_tamper_detection():
    """Verify append-only HashChain integrity and exact identification of broken links."""
    chain = HashChain()
    data_hashes = [hash_bytes(f"event_{i}".encode("utf-8")) for i in range(5)]

    for dh in data_hashes:
        chain.append(dh)

    assert len(chain.records) == 5
    assert chain.records[0]["prev_hash"] == "0" * 64
    assert chain.records[1]["prev_hash"] == chain.records[0]["current_hash"]

    # Verify unbroken chain
    is_valid, broken_idx = HashChain.verify_chain(chain.records)
    assert is_valid is True
    assert broken_idx is None

    # Deliberate tampering: mutate payload at block 2
    tampered_records = [dict(r) for r in chain.records]
    tampered_records[2]["data_hash"] = hash_bytes(b"MUTATED_PAYLOAD")

    is_valid, broken_idx = HashChain.verify_chain(tampered_records)
    assert is_valid is False
    assert broken_idx == 2

    # Deliberate sequence tampering: skip index
    tampered_sequence = [dict(r) for r in chain.records]
    tampered_sequence[3]["index"] = 99
    is_valid, broken_idx = HashChain.verify_chain(tampered_sequence)
    assert is_valid is False
    assert broken_idx == 3


# 5. FastAPI Endpoints Integration Tests
def test_api_crypto_hash():
    """Verify POST /api/v1/crypto/hash endpoint."""
    response = client.post(
        "/api/v1/crypto/hash",
        json={"data": {"model": "test", "params": [1, 2, 3]}},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert len(payload["data"]["canonical_hash"]) == 64


def test_api_crypto_merkle_build_and_verify():
    """Verify POST /api/v1/crypto/merkle/build and /api/v1/crypto/merkle/verify."""
    leaves = [hash_bytes(f"item_{i}".encode("utf-8")) for i in range(4)]
    tree = MerkleTree(leaves)
    proof_0 = tree.get_proof(0)

    # Build endpoint
    build_resp = client.post("/api/v1/crypto/merkle/build", json={"leaves": leaves})
    assert build_resp.status_code == 200
    build_data = build_resp.json()["data"]
    root = build_data["root"]
    assert root == tree.get_root()
    assert build_data["leaf_count"] == 4

    # Verify endpoint (valid)
    verify_resp = client.post(
        "/api/v1/crypto/merkle/verify",
        json={"leaf": leaves[0], "proof": proof_0, "root": root},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["data"]["valid"] is True

    # Verify endpoint (tampered)
    tampered_resp = client.post(
        "/api/v1/crypto/merkle/verify",
        json={"leaf": hash_bytes(b"fraud"), "proof": proof_0, "root": root},
    )
    assert tampered_resp.status_code == 200
    assert tampered_resp.json()["data"]["valid"] is False


def test_api_crypto_sign_and_verify():
    """Verify POST /api/v1/crypto/sign and /api/v1/crypto/verify."""
    digest = hash_bytes(b"ASSURANCE_DECISION_REPORT_HASH")

    # Sign endpoint
    sign_resp = client.post("/api/v1/crypto/sign", json={"digest": digest})
    assert sign_resp.status_code == 200
    sign_data = sign_resp.json()["data"]
    sig = sign_data["signature"]
    pubkey = sign_data["public_key_pem"]

    # Verify endpoint (valid)
    verify_resp = client.post(
        "/api/v1/crypto/verify",
        json={"digest": digest, "signature": sig, "public_key_pem": pubkey},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["data"]["valid"] is True

    # Verify endpoint (tampered digest)
    verify_tampered = client.post(
        "/api/v1/crypto/verify",
        json={"digest": hash_bytes(b"WRONG"), "signature": sig, "public_key_pem": pubkey},
    )
    assert verify_tampered.status_code == 200
    assert verify_tampered.json()["data"]["valid"] is False


def test_api_crypto_chain_verify():
    """Verify POST /api/v1/crypto/chain/verify."""
    chain = HashChain()
    chain.append(hash_bytes(b"event_1"))
    chain.append(hash_bytes(b"event_2"))

    # Valid chain
    resp = client.post("/api/v1/crypto/chain/verify", json={"records": chain.records})
    assert resp.status_code == 200
    assert resp.json()["data"]["valid"] is True

    # Tampered chain
    tampered = [dict(r) for r in chain.records]
    tampered[1]["data_hash"] = hash_bytes(b"injected_unverified_sample")
    tampered_resp = client.post("/api/v1/crypto/chain/verify", json={"records": tampered})
    assert tampered_resp.status_code == 200
    assert tampered_resp.json()["data"]["valid"] is False
    assert tampered_resp.json()["data"]["broken_index"] == 1
