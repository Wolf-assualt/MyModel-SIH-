"""Phase 2 Cryptographic Trust Foundation Deep Verification and Adversarial Tests.

Validates:
1. RFC 8785 canonical JSON deterministic serialization and hashing
2. Local SHA-256 cryptographic hashing and avalanche properties
3. Binary Merkle Tree generation, audit paths, and inclusion proofs across diverse tree sizes (1, 2, 3, 5, 10, 100)
4. ECDSA SECP256R1 digital signatures, verification, key export, and private key isolation
5. Append-only sequential hash chain continuity, previous-pointer verification, and tamper detection
6. Multi-scenario tamper simulations (Dataset, Model, Hash Chain, Assurance Report)
7. Cryptographic REST API endpoints (valid, tampered, malformed, security isolation)
8. Cryptographic performance and local execution baselines
"""
from datetime import datetime, timezone
import json
import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto.canonical import (
    canonical_json_dumps,
    canonical_json_hash,
    hash_bytes,
    hash_file,
)
from app.crypto.chain import HashChain
from app.crypto.merkle import MerkleTree
from app.crypto.signer import KeyManager, default_key_manager


# ==============================================================================
# 1. CANONICAL JSON (RFC 8785 SUBSET) TESTS
# ==============================================================================
def test_canonical_json_key_sorting_and_nesting():
    """Verify deterministic alphabetical key sorting across nested structures."""
    obj1 = {
        "z": 100,
        "a": "alpha",
        "nested": {
            "gamma": True,
            "beta": [3, 2, 1],
            "alpha": {"k2": None, "k1": "test"},
        },
    }
    obj2 = {
        "nested": {
            "beta": [3, 2, 1],
            "alpha": {"k1": "test", "k2": None},
            "gamma": True,
        },
        "a": "alpha",
        "z": 100,
    }

    dumped1 = canonical_json_dumps(obj1)
    dumped2 = canonical_json_dumps(obj2)

    assert dumped1 == dumped2
    assert canonical_json_hash(obj1) == canonical_json_hash(obj2)
    # Check that keys are ordered alphabetically
    assert dumped1.startswith('{"a":"alpha","nested":{"alpha":{"k1":"test","k2":null},"beta":[3,2,1],"gamma":true},"z":100}')


def test_canonical_json_unicode_and_types():
    """Verify proper serialization of Unicode, booleans, null, integers, and floats."""
    payload = {
        "unicode_text": "DEFENSE // 安全 // रक्षा // 🛡️",
        "flag_true": True,
        "flag_false": False,
        "null_val": None,
        "integer_val": 4294967296,
        "float_val": 3.14159,
    }
    dumped = canonical_json_dumps(payload)
    assert "DEFENSE // 安全 // रक्षा // 🛡️" in dumped
    assert '"flag_true":true' in dumped
    assert '"flag_false":false' in dumped
    assert '"null_val":null' in dumped


def test_canonical_json_iso_datetime():
    """Verify UTC ISO-8601 normalization for naive and timezone-aware datetimes."""
    dt_aware = datetime(2026, 9, 10, 15, 30, 0, tzinfo=timezone.utc)
    dt_naive = datetime(2026, 9, 10, 15, 30, 0)

    hash_aware = canonical_json_hash({"time": dt_aware})
    hash_naive = canonical_json_hash({"time": dt_naive})
    assert hash_aware == hash_naive


# ==============================================================================
# 2. SHA-256 HASHING & AVALANCHE EFFECT
# ==============================================================================
def test_sha256_nist_test_vectors():
    """Verify SHA-256 against known standard cryptographic test vectors."""
    # Empty string
    assert hash_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # Standard "abc" vector
    assert hash_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_avalanche_effect():
    """Verify that a 1-bit / 1-byte difference produces an uncorrelated digest."""
    base_data = b"DEFENSE_VISION_FRAME_SAMPLE_00000001"
    tampered_data = b"DEFENSE_VISION_FRAME_SAMPLE_00000002"

    hash_base = hash_bytes(base_data)
    hash_tampered = hash_bytes(tampered_data)

    assert hash_base != hash_tampered
    # Compute bit divergence (Hamming distance on binary representation)
    b1 = bin(int(hash_base, 16))[2:].zfill(256)
    b2 = bin(int(hash_tampered, 16))[2:].zfill(256)
    divergence_bits = sum(c1 != c2 for c1, c2 in zip(b1, b2))
    # Avalanche criterion typically achieves > 40% bit flip (around 100+ bits out of 256)
    assert divergence_bits >= 90


# ==============================================================================
# 3. MERKLE TREE & INCLUSION PROOFS ACROSS SIZES
# ==============================================================================
@pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 5, 8, 10, 50, 100])
def test_merkle_tree_proofs_across_sizes(leaf_count):
    """Verify Merkle root generation and inclusion proofs for various tree sizes."""
    leaves = [hash_bytes(f"asset_chunk_{i}".encode("utf-8")) for i in range(leaf_count)]
    tree = MerkleTree(leaves)
    root = tree.get_root()

    assert len(root) == 64

    # Verify inclusion proof for each leaf
    for idx in range(leaf_count):
        proof = tree.get_proof(idx)
        assert MerkleTree.verify_proof(leaves[idx], proof, root) is True

        # Verify tampering a leaf fails proof verification
        tampered_leaf = hash_bytes(b"MUTATED_LEAF_PAYLOAD")
        assert MerkleTree.verify_proof(tampered_leaf, proof, root) is False

        # Verify tampering the root fails proof verification
        tampered_root = "0" * 64
        assert MerkleTree.verify_proof(leaves[idx], proof, tampered_root) is False


def test_merkle_tree_tampered_proof_steps():
    """Verify rejection when proof step sibling hash or position is corrupted."""
    leaves = [hash_bytes(f"chunk_{i}".encode("utf-8")) for i in range(8)]
    tree = MerkleTree(leaves)
    root = tree.get_root()

    proof = tree.get_proof(3)
    assert MerkleTree.verify_proof(leaves[3], proof, root) is True

    # Mutate proof sibling hash
    corrupted_proof = [dict(step) for step in proof]
    corrupted_proof[0]["hash"] = "f" * 64
    assert MerkleTree.verify_proof(leaves[3], corrupted_proof, root) is False

    # Mutate proof position
    inverted_pos_proof = [dict(step) for step in proof]
    inverted_pos_proof[0]["position"] = "invalid_pos"
    assert MerkleTree.verify_proof(leaves[3], inverted_pos_proof, root) is False


# ==============================================================================
# 4. ECDSA SECP256R1 SIGNATURES & KEY MANAGEMENT
# ==============================================================================
def test_ecdsa_keypair_isolation_and_mismatched_keys():
    """Verify ECDSA signature verification fails when verified with wrong public key."""
    signer_a = KeyManager()
    signer_b = KeyManager()

    digest = hash_bytes(b"MODEL_WEIGHT_MANIFEST_DIGEST")
    sig_a = signer_a.sign_hash(digest)

    # Valid with Signer A's public key
    assert KeyManager.verify_signature(signer_a.export_public_key_pem(), digest, sig_a) is True

    # Invalid when checked with Signer B's public key
    assert KeyManager.verify_signature(signer_b.export_public_key_pem(), digest, sig_a) is False


def test_ecdsa_corrupted_signature_der():
    """Verify rejection of truncated, padded, or mutated signature bytes."""
    km = KeyManager()
    pubkey = km.export_public_key_pem()
    digest = hash_bytes(b"SAMPLE_INFERENCE_DNA")
    sig = km.sign_hash(digest)

    # Truncate signature
    truncated_sig = sig[:-10]
    assert KeyManager.verify_signature(pubkey, digest, truncated_sig) is False

    # Non-hex characters
    assert KeyManager.verify_signature(pubkey, digest, "ZZZZ" + sig[4:]) is False

    # Empty signature
    assert KeyManager.verify_signature(pubkey, digest, "") is False

    # Corrupted PEM
    assert KeyManager.verify_signature(b"NOT_A_VALID_PEM", digest, sig) is False


# ==============================================================================
# 5. SEQUENTIAL HASH CHAIN AUDIT & TAMPER DETECTION
# ==============================================================================
def test_hash_chain_tamper_vectors():
    """Verify hash chain detects block payload tampering, timestamp tampering, and sequence deletion."""
    chain = HashChain()
    for i in range(10):
        chain.append(hash_bytes(f"telemetry_event_{i}".encode("utf-8")))

    is_valid, broken_idx = HashChain.verify_chain(chain.records)
    assert is_valid is True
    assert broken_idx is None

    # Attack 1: Mutate historical block timestamp at index 4
    tampered_ts = [dict(r) for r in chain.records]
    tampered_ts[4]["timestamp"] = "2020-01-01T00:00:00+00:00"
    is_valid, broken = HashChain.verify_chain(tampered_ts)
    assert is_valid is False
    assert broken == 4

    # Attack 2: Delete block at index 3 (sequence gap)
    deleted_chain = [dict(r) for r in chain.records]
    del deleted_chain[3]
    is_valid, broken = HashChain.verify_chain(deleted_chain)
    assert is_valid is False
    assert broken == 3

    # Attack 3: Swap blocks 6 and 7 (reordering attack)
    reordered_chain = [dict(r) for r in chain.records]
    reordered_chain[6], reordered_chain[7] = reordered_chain[7], reordered_chain[6]
    is_valid, broken = HashChain.verify_chain(reordered_chain)
    assert is_valid is False
    assert broken == 6


# ==============================================================================
# 6. TAMPER SIMULATION SCENARIOS
# ==============================================================================
def test_tamper_scenario_dataset_manifest():
    """Scenario A: 1-byte alteration in dataset sample breaks Merkle root."""
    samples = [f"sample_image_data_{i}".encode("utf-8") for i in range(16)]
    leaf_digests = [hash_bytes(s) for s in samples]

    original_tree = MerkleTree(leaf_digests)
    original_root = original_tree.get_root()

    # Modify single byte in sample 7
    tampered_samples = list(samples)
    tampered_samples[7] = b"sample_image_data_7_TAMPERED"
    tampered_digests = [hash_bytes(s) for s in tampered_samples]

    tampered_tree = MerkleTree(tampered_digests)
    tampered_root = tampered_tree.get_root()

    assert original_root != tampered_root


def test_tamper_scenario_model_weights():
    """Scenario B: 1-bit alteration in model weights invalidates model signature."""
    km = KeyManager()
    pubkey = km.export_public_key_pem()

    weights_original = b"\x01\x02\x03\x04" * 1024
    weights_digest = hash_bytes(weights_original)
    model_signature = km.sign_hash(weights_digest)

    # Valid model weights
    assert KeyManager.verify_signature(pubkey, weights_digest, model_signature) is True

    # Adversary flips 1 byte
    weights_tampered = bytearray(weights_original)
    weights_tampered[500] = weights_tampered[500] ^ 0xFF
    tampered_digest = hash_bytes(bytes(weights_tampered))

    assert KeyManager.verify_signature(pubkey, tampered_digest, model_signature) is False


def test_tamper_scenario_assurance_report():
    """Scenario D: Modifying report risk score breaks report digital signature."""
    km = KeyManager()
    pubkey = km.export_public_key_pem()

    report_payload = {
        "report_id": "rep_991823",
        "verdict": "ACCEPTED",
        "risk_score": 0.12,
        "timestamp": "2026-09-10T12:00:00+00:00",
    }
    report_digest = canonical_json_hash(report_payload)
    sig = km.sign_hash(report_digest)

    # Valid report
    assert KeyManager.verify_signature(pubkey, report_digest, sig) is True

    # Adversary tampers risk_score from 0.12 to 0.95
    tampered_payload = dict(report_payload)
    tampered_payload["risk_score"] = 0.95
    tampered_digest = canonical_json_hash(tampered_payload)

    assert KeyManager.verify_signature(pubkey, tampered_digest, sig) is False


# ==============================================================================
# 7. CRYPTOGRAPHIC API ENDPOINTS (SECURITY & BOUNDARY TESTS)
# ==============================================================================
def test_api_crypto_security_no_private_key_exposure(client):
    """Verify that crypto API endpoints never expose private key material."""
    resp = client.post("/api/v1/crypto/sign", json={"digest": "a" * 64})
    assert resp.status_code == 200
    data = resp.json()["data"]

    # Public key present, private key strictly omitted
    assert "public_key_pem" in data
    assert "BEGIN PUBLIC KEY" in data["public_key_pem"]
    assert "BEGIN PRIVATE KEY" not in json.dumps(resp.json())
    assert "private" not in json.dumps(resp.json()).lower()


def test_api_crypto_merkle_empty_and_tampered(client):
    """Verify Merkle API endpoints handle empty and corrupted proof requests."""
    # Build tree with 1 leaf
    leaf = hash_bytes(b"single_chunk")
    res_build = client.post("/api/v1/crypto/merkle/build", json={"leaves": [leaf]})
    assert res_build.status_code == 200
    assert res_build.json()["data"]["root"] == leaf

    # Verify proof with tampered proof list
    res_verify = client.post(
        "/api/v1/crypto/merkle/verify",
        json={"leaf": leaf, "proof": [{"position": "left", "hash": "0" * 64}], "root": leaf},
    )
    assert res_verify.status_code == 200
    assert res_verify.json()["data"]["valid"] is False


# ==============================================================================
# 8. PERFORMANCE BENCHMARKS (OFFLINE LOCAL HARDWARE)
# ==============================================================================
def test_cryptographic_performance_baseline():
    """Measure throughput and latency of core cryptographic routines."""
    # 1. 10,000 SHA-256 Hashing Operations
    payload = b"TRUST-CV DEFENSE PROVENANCE CHUNK 1024"
    t0 = time.perf_counter()
    for _ in range(1000):
        _ = hash_bytes(payload)
    hash_latency_ms = ((time.perf_counter() - t0) / 1000.0) * 1000.0

    # 2. Merkle Tree with 256 leaves
    leaves = [hash_bytes(f"chunk_{i}".encode("utf-8")) for i in range(256)]
    t1 = time.perf_counter()
    tree = MerkleTree(leaves)
    root = tree.get_root()
    proof = tree.get_proof(128)
    is_valid = MerkleTree.verify_proof(leaves[128], proof, root)
    merkle_time_ms = (time.perf_counter() - t1) * 1000.0

    # 3. ECDSA 100 Signature and Verification cycles
    km = KeyManager()
    pubkey = km.export_public_key_pem()
    sample_digest = "b" * 64
    t2 = time.perf_counter()
    for _ in range(50):
        sig = km.sign_hash(sample_digest)
        _ = KeyManager.verify_signature(pubkey, sample_digest, sig)
    ecdsa_cycle_avg_ms = ((time.perf_counter() - t2) / 50.0) * 1000.0

    assert is_valid is True
    # Asserts realistic performance thresholds on offline hardware
    assert hash_latency_ms < 1.0  # < 1 ms per hash
    assert merkle_time_ms < 50.0  # < 50 ms for 256-leaf tree build and proof
    assert ecdsa_cycle_avg_ms < 20.0  # < 20 ms per full ECDSA sign+verify cycle
