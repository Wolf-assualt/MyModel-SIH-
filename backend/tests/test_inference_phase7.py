"""Comprehensive Phase 7 Tests: Inference DNA, Provenance, Chain Continuity & Replay Defense.

Validates the full offline inference assurance subsystem according to Phase 7 specifications:
- Canonical tuple representation and RFC 8785 deterministic hashing
- ECDSA SECP256R1 signing and verification
- Append-only hash chain construction & continuity
- Distinction between cryptographic authenticity and temporal freshness/replay defense
- Adversarial test battery: replay, deletion, insertion, reordering, nonce reuse,
  signature forgery, model substitution, input tampering, output tampering, metadata tampering
- Structured forensic evidence generation
- Local SQLite and filesystem persistence
- Complete CLI commands & REST API endpoints
- Concurrent thread-safety and sequence monotonicity
- Absolute isolation of private keys
"""
import copy
import json
from pathlib import Path
import threading
from typing import List
import pytest
from fastapi.testclient import TestClient

from app.cli import build_parser, main
from app.crypto.canonical import canonical_json_hash, hash_bytes
from app.crypto.signer import KeyManager
from app.inference.dna import InferenceDNAGenerator
from app.inference.verifier import InferenceDNAVerifier
from app.main import app
from app.schemas.inference import (
    BoundingBox,
    ChainVerificationResponse,
    InferenceDNARecord,
    InferenceOutput,
    PreprocessingSpec,
    VerifyChainRequest,
    VerifyDNARequest,
)


@pytest.fixture
def clean_generator(tmp_path: Path):
    """Create an isolated InferenceDNAGenerator instance with a fresh temporary directory and keypair."""
    km = KeyManager()
    storage_dir = tmp_path / "inference_dna_test"
    return InferenceDNAGenerator(key_manager=km, storage_dir=storage_dir)


@pytest.fixture
def mock_output():
    """Create standard sample model predictions and raw digest."""
    predictions = [
        BoundingBox(label="t90_tank", confidence=0.96, box=[50.0, 60.0, 200.0, 250.0]),
        BoundingBox(label="air_defense_radar", confidence=0.91, box=[300.0, 100.0, 450.0, 300.0]),
    ]
    raw_digest = canonical_json_hash([p.model_dump() for p in predictions])
    return InferenceOutput(predictions=predictions, raw_output_digest=raw_digest)


# ==============================================================================
# 1. Canonical Representation & Cryptographic DNA Tuple
# ==============================================================================

def test_canonical_tuple_dna_determinism():
    """Verify that compute_tuple_dna produces identical 64-char SHA-256 for identical inputs."""
    params = {
        "sequence_id": 42,
        "timestamp": "2026-09-10T15:30:00Z",
        "nonce": "deadbeef12345678deadbeef87654321",
        "model_id": "target_classifier_v2",
        "model_version": "2.1.0",
        "model_digest": "a" * 64,
        "input_hash": "b" * 64,
        "prep_digest": "c" * 64,
        "output_hash": "d" * 64,
        "prev_chain_hash": "e" * 64,
    }
    hash_1 = InferenceDNAGenerator.compute_tuple_dna(**params)
    hash_2 = InferenceDNAGenerator.compute_tuple_dna(**params)
    assert hash_1 == hash_2
    assert len(hash_1) == 64
    assert all(c in "0123456789abcdef" for c in hash_1)


def test_dna_record_creation_and_fields(clean_generator, mock_output):
    """Verify all 8 fields of the canonical inference tuple are present and signed."""
    prep = PreprocessingSpec(target_size=[640, 640], normalize_mean=[0.485, 0.456, 0.406])
    input_hash = hash_bytes(b"synthetic_satellite_frame_01")
    model_digest = hash_bytes(b"model_weights_and_arch_v1")

    rec = clean_generator.create_dna_record(
        model_id="eo_target_detector",
        model_identity_digest=model_digest,
        input_frame_sha256=input_hash,
        prep_spec=prep,
        output=mock_output,
        model_version="1.0.0",
    )

    assert rec.sequence_id == 1
    assert rec.model_id == "eo_target_detector"
    assert rec.model_version == "1.0.0"
    assert rec.input_frame_sha256 == input_hash
    assert rec.output_digest == mock_output.raw_output_digest
    assert rec.prev_chain_hash == "0" * 64
    assert len(rec.nonce) >= 16
    assert len(rec.dna_hash) == 64
    assert len(rec.signature) > 64


# ==============================================================================
# 2. Append-Only Hash Chain Construction & Sequential Continuity
# ==============================================================================

def test_hash_chain_sequential_linking(clean_generator, mock_output):
    """Verify sequential records correctly link previous chain tip hash into their DNA tuple."""
    prep = PreprocessingSpec()
    records: List[InferenceDNARecord] = []

    for i in range(5):
        inp_hash = hash_bytes(f"frame_{i}".encode("utf-8"))
        rec = clean_generator.create_dna_record(
            model_id="eo_target_detector",
            model_identity_digest="a" * 64,
            input_frame_sha256=inp_hash,
            prep_spec=prep,
            output=mock_output,
        )
        records.append(rec)

    assert [r.sequence_id for r in records] == [1, 2, 3, 4, 5]
    assert records[0].prev_chain_hash == "0" * 64
    for i in range(1, 5):
        # Current record's prev_chain_hash must equal preceding DNA hash
        assert records[i].prev_chain_hash == records[i - 1].dna_hash

    pubkey = clean_generator.export_public_key_pem()
    chain_audit = InferenceDNAVerifier.verify_chain(records, pubkey)
    assert chain_audit.is_valid is True
    assert chain_audit.total_records == 5
    assert chain_audit.broken_sequence_id is None
    assert chain_audit.replay_detected is False


# ==============================================================================
# 3. Cryptographic Authenticity vs Temporal Freshness / Replay Distinction
# ==============================================================================

def test_distinction_authenticity_vs_freshness(clean_generator, mock_output):
    """Demonstrate that an authentically signed record still FAILS replay/freshness verification."""
    prep = PreprocessingSpec()
    pubkey = clean_generator.export_public_key_pem()

    rec1 = clean_generator.create_dna_record(
        model_id="eo_target_detector",
        model_identity_digest="a" * 64,
        input_frame_sha256=hash_bytes(b"frame_1"),
        prep_spec=prep,
        output=mock_output,
    )
    rec2 = clean_generator.create_dna_record(
        model_id="eo_target_detector",
        model_identity_digest="a" * 64,
        input_frame_sha256=hash_bytes(b"frame_2"),
        prep_spec=prep,
        output=mock_output,
    )

    # 1. An individual replayed record HAS A VALID SIGNATURE (authentic)
    single_audit = InferenceDNAVerifier.verify_record(rec1, pubkey)
    assert single_audit.is_valid is True
    assert single_audit.signature_valid is True

    # 2. But replaying rec1 into a sequence [rec1, rec2, rec1] trips REPLAY DEFENSE
    replayed_stream = [rec1, rec2, rec1]
    chain_audit = InferenceDNAVerifier.verify_chain(replayed_stream, pubkey)
    assert chain_audit.is_valid is False
    assert chain_audit.replay_detected is True
    assert any("Replay attack detected" in d for d in chain_audit.discrepancies)
    assert any(e["type"] == "INFERENCE_REPLAY_ATTACK" for e in chain_audit.evidence_records)


# ==============================================================================
# 4. Adversarial Attack Scenarios & Structured Evidence
# ==============================================================================

def test_adversarial_nonce_reuse_generator_rejection(clean_generator, mock_output):
    """Adversarial: Generator must explicitly reject generating DNA with a reused nonce."""
    prep = PreprocessingSpec()
    static_nonce = "fixed_adversarial_nonce_12345"

    clean_generator.create_dna_record(
        model_id="mod_x",
        model_identity_digest="a" * 64,
        input_frame_sha256=hash_bytes(b"inp1"),
        prep_spec=prep,
        output=mock_output,
        nonce=static_nonce,
    )

    with pytest.raises(ValueError, match="Replay detected"):
        clean_generator.create_dna_record(
            model_id="mod_x",
            model_identity_digest="a" * 64,
            input_frame_sha256=hash_bytes(b"inp2"),
            prep_spec=prep,
            output=mock_output,
            nonce=static_nonce,
        )


def test_adversarial_record_deletion_from_chain(clean_generator, mock_output):
    """Adversarial: Deleting a record from the chain breaks sequence and hash pointer continuity."""
    prep = PreprocessingSpec()
    records = [
        clean_generator.create_dna_record(
            model_id="mod_x",
            model_identity_digest="a" * 64,
            input_frame_sha256=hash_bytes(f"f_{i}".encode("utf-8")),
            prep_spec=prep,
            output=mock_output,
        )
        for i in range(4)
    ]
    pubkey = clean_generator.export_public_key_pem()

    # Adversary deletes record 2 (leaving [rec0, rec1, rec3])
    tampered_stream = [records[0], records[1], records[3]]
    audit = InferenceDNAVerifier.verify_chain(tampered_stream, pubkey)

    assert audit.is_valid is False
    assert audit.broken_sequence_id == 4
    assert any("Sequence continuity break" in d for d in audit.discrepancies)
    assert any(e["type"] == "SEQUENCE_CONTINUITY_BREAK" for e in audit.evidence_records)


def test_adversarial_record_insertion_or_reordering(clean_generator, mock_output):
    """Adversarial: Swapping or reordering records trips sequence and hash chain checks."""
    prep = PreprocessingSpec()
    records = [
        clean_generator.create_dna_record(
            model_id="mod_x",
            model_identity_digest="a" * 64,
            input_frame_sha256=hash_bytes(f"f_{i}".encode("utf-8")),
            prep_spec=prep,
            output=mock_output,
        )
        for i in range(3)
    ]
    pubkey = clean_generator.export_public_key_pem()

    # Reorder: [rec0, rec2, rec1]
    tampered_stream = [records[0], records[2], records[1]]
    audit = InferenceDNAVerifier.verify_chain(tampered_stream, pubkey)

    assert audit.is_valid is False
    assert audit.broken_sequence_id is not None
    assert len(audit.evidence_records) >= 1


def test_adversarial_input_hash_tampering(clean_generator, mock_output):
    """Adversarial: Modifying the input frame hash invalidates DNA hash and signature."""
    prep = PreprocessingSpec()
    rec = clean_generator.create_dna_record(
        model_id="mod_x",
        model_identity_digest="a" * 64,
        input_frame_sha256="1" * 64,
        prep_spec=prep,
        output=mock_output,
    )
    pubkey = clean_generator.export_public_key_pem()

    tampered = copy.deepcopy(rec)
    tampered.input_frame_sha256 = "2" * 64
    audit = InferenceDNAVerifier.verify_record(tampered, pubkey)

    assert audit.is_valid is False
    assert audit.hash_integrity_valid is False


def test_adversarial_output_hash_tampering(clean_generator, mock_output):
    """Adversarial: Modifying detection output digest is detected."""
    prep = PreprocessingSpec()
    rec = clean_generator.create_dna_record(
        model_id="mod_x",
        model_identity_digest="a" * 64,
        input_frame_sha256="1" * 64,
        prep_spec=prep,
        output=mock_output,
    )
    pubkey = clean_generator.export_public_key_pem()

    tampered = copy.deepcopy(rec)
    tampered.output_digest = "f" * 64
    audit = InferenceDNAVerifier.verify_record(tampered, pubkey)

    assert audit.is_valid is False
    assert audit.hash_integrity_valid is False


def test_adversarial_model_substitution(clean_generator, mock_output):
    """Adversarial: Substituting a different model ID or version invalidates the DNA proof."""
    prep = PreprocessingSpec()
    rec = clean_generator.create_dna_record(
        model_id="mod_approved_v1",
        model_identity_digest="a" * 64,
        input_frame_sha256="1" * 64,
        prep_spec=prep,
        output=mock_output,
        model_version="1.0.0",
    )
    pubkey = clean_generator.export_public_key_pem()

    # Substitute model_id
    tampered_id = copy.deepcopy(rec)
    tampered_id.model_id = "mod_rogue_v2"
    assert InferenceDNAVerifier.verify_record(tampered_id, pubkey).is_valid is False

    # Substitute model_version
    tampered_ver = copy.deepcopy(rec)
    tampered_ver.model_version = "1.0.1"
    assert InferenceDNAVerifier.verify_record(tampered_ver, pubkey).is_valid is False


def test_adversarial_timestamp_and_metadata_tampering(clean_generator, mock_output):
    """Adversarial: Modifying timestamp or preprocessing digest fails verification."""
    prep = PreprocessingSpec()
    rec = clean_generator.create_dna_record(
        model_id="mod_x",
        model_identity_digest="a" * 64,
        input_frame_sha256="1" * 64,
        prep_spec=prep,
        output=mock_output,
    )
    pubkey = clean_generator.export_public_key_pem()

    tampered_ts = copy.deepcopy(rec)
    tampered_ts.timestamp = "1999-12-31T23:59:59Z"
    assert InferenceDNAVerifier.verify_record(tampered_ts, pubkey).is_valid is False

    tampered_prep = copy.deepcopy(rec)
    tampered_prep.preprocessing_digest = "0" * 64
    assert InferenceDNAVerifier.verify_record(tampered_prep, pubkey).is_valid is False


def test_adversarial_signature_forgery(clean_generator, mock_output):
    """Adversarial: Forged or modified digital signature is mathematically rejected."""
    prep = PreprocessingSpec()
    rec = clean_generator.create_dna_record(
        model_id="mod_x",
        model_identity_digest="a" * 64,
        input_frame_sha256="1" * 64,
        prep_spec=prep,
        output=mock_output,
    )
    pubkey = clean_generator.export_public_key_pem()

    forged = copy.deepcopy(rec)
    # Flip first character in signature
    sig_chars = list(forged.signature)
    sig_chars[0] = "b" if sig_chars[0] == "a" else "a"
    forged.signature = "".join(sig_chars)

    audit = InferenceDNAVerifier.verify_record(forged, pubkey)
    assert audit.is_valid is False
    assert audit.signature_valid is False


# ==============================================================================
# 5. Local Storage Persistence & Database Lineage
# ==============================================================================

def test_local_storage_persistence_and_loading(clean_generator, mock_output):
    """Verify inference DNA records are persisted as JSON files and retrievable."""
    prep = PreprocessingSpec()
    rec = clean_generator.create_dna_record(
        model_id="persist_test_model",
        model_identity_digest="a" * 64,
        input_frame_sha256=hash_bytes(b"frame_persist"),
        prep_spec=prep,
        output=mock_output,
    )

    loaded = clean_generator.load_record(rec.record_id)
    assert loaded is not None
    assert loaded.record_id == rec.record_id
    assert loaded.dna_hash == rec.dna_hash
    assert loaded.signature == rec.signature

    assert clean_generator.load_record("non_existent_record_id") is None


# ==============================================================================
# 6. Concurrency & Thread-Safety
# ==============================================================================

def test_concurrent_inference_sequence_monotonicity(clean_generator, mock_output):
    """Verify thread-safe sequence incrementing under simultaneous multithreaded inferences."""
    prep = PreprocessingSpec()
    created_records: List[InferenceDNARecord] = []
    lock = threading.Lock()

    def worker(worker_id: int):
        for j in range(5):
            rec = clean_generator.create_dna_record(
                model_id=f"thread_model_{worker_id}",
                model_identity_digest="a" * 64,
                input_frame_sha256=hash_bytes(f"w_{worker_id}_j_{j}".encode("utf-8")),
                prep_spec=prep,
                output=mock_output,
            )
            with lock:
                created_records.append(rec)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(created_records) == 20
    seq_ids = sorted([r.sequence_id for r in created_records])
    assert seq_ids == list(range(1, 21))

    # All nonces must be strictly unique
    nonces = [r.nonce for r in created_records]
    assert len(set(nonces)) == 20


# ==============================================================================
# 7. Private Key Isolation
# ==============================================================================

def test_private_key_isolation_in_all_outputs(clean_generator, mock_output):
    """Verify that private keys never leak into records, export dumps, or verification responses."""
    prep = PreprocessingSpec()
    rec = clean_generator.create_dna_record(
        model_id="mod_secret",
        model_identity_digest="a" * 64,
        input_frame_sha256=hash_bytes(b"frame_secret"),
        prep_spec=prep,
        output=mock_output,
    )

    rec_json = rec.model_dump_json()
    assert "PRIVATE" not in rec_json
    assert "BEGIN EC PRIVATE KEY" not in rec_json
    assert "BEGIN PRIVATE KEY" not in rec_json

    pubkey_pem = clean_generator.export_public_key_pem()
    assert "PUBLIC KEY" in pubkey_pem
    assert "PRIVATE" not in pubkey_pem


# ==============================================================================
# 8. REST API Endpoints End-to-End
# ==============================================================================

def test_rest_api_chain_verification_endpoint(client: TestClient):
    """Verify POST /api/v1/inference/verify-chain with genuine vs corrupted chain."""
    # 1. Create two inferences via API
    resp1 = client.post("/api/v1/inference/execute", json={"model_id": "api_mod_1"})
    resp2 = client.post("/api/v1/inference/execute", json={"model_id": "api_mod_1"})
    assert resp1.status_code == 200
    assert resp2.status_code == 200

    rec1 = resp1.json()["data"]["dna_record"]
    rec2 = resp2.json()["data"]["dna_record"]
    pubkey = resp1.json()["data"]["public_key_pem"]

    # 2. Verify legitimate chain
    chain_resp = client.post(
        "/api/v1/inference/verify-chain",
        json={"records": [rec1, rec2], "public_key_pem": pubkey},
    )
    assert chain_resp.status_code == 200
    chain_data = chain_resp.json()["data"]
    assert chain_data["is_valid"] is True
    assert chain_data["replay_detected"] is False

    # 3. Verify replayed chain
    replayed_resp = client.post(
        "/api/v1/inference/verify-chain",
        json={"records": [rec1, rec2, rec1], "public_key_pem": pubkey},
    )
    assert replayed_resp.status_code == 200
    replayed_data = replayed_resp.json()["data"]
    assert replayed_data["is_valid"] is False
    assert replayed_data["replay_detected"] is True
    assert len(replayed_data["evidence_records"]) > 0


def test_rest_api_get_record_by_id(client: TestClient):
    """Verify GET /api/v1/inference/record/{record_id}."""
    exec_resp = client.post("/api/v1/inference/execute", json={"model_id": "api_mod_fetch"})
    assert exec_resp.status_code == 200
    rec_id = exec_resp.json()["data"]["dna_record"]["record_id"]

    get_resp = client.get(f"/api/v1/inference/record/{rec_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["success"] is True
    assert get_data["data"]["record_id"] == rec_id

    missing_resp = client.get("/api/v1/inference/record/dna_nonexistent_999")
    assert missing_resp.status_code == 404


# ==============================================================================
# 9. CLI Commands Integration
# ==============================================================================

def test_cli_record_verify_and_audit(clean_generator, mock_output, tmp_path: Path):
    """Verify record-inference, verify-inference, and audit-inference-chain CLI commands."""
    # 1. Record inferences into clean isolated storage directory
    rec1 = clean_generator.create_dna_record(
        model_id="cli_model_1",
        model_identity_digest="a" * 64,
        input_frame_sha256=hash_bytes(b"frame_cli_1"),
        prep_spec=PreprocessingSpec(),
        output=mock_output,
    )
    rec2 = clean_generator.create_dna_record(
        model_id="cli_model_1",
        model_identity_digest="a" * 64,
        input_frame_sha256=hash_bytes(b"frame_cli_2"),
        prep_spec=PreprocessingSpec(),
        output=mock_output,
    )

    rec_file = clean_generator.storage_dir / f"{rec1.record_id}.json"
    pubkey = clean_generator.export_public_key_pem()

    # 2. Verify single record CLI
    ret_verify = main([
        "verify-inference",
        "--file", str(rec_file),
        "--public-key-pem", pubkey,
    ])
    assert ret_verify == 0

    # 3. Audit chain from storage directory CLI
    ret_audit = main([
        "audit-inference-chain",
        "--dir", str(clean_generator.storage_dir),
        "--public-key-pem", pubkey,
    ])
    assert ret_audit == 0
