"""Unit and integration tests for Inference DNA, Cryptographic Provenance, and Replay Defense."""
import copy
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.crypto.canonical import canonical_json_hash, hash_bytes
from app.crypto.signer import KeyManager
from app.inference.dna import InferenceDNAGenerator
from app.inference.verifier import InferenceDNAVerifier
from app.main import app
from app.schemas.inference import (
    BoundingBox,
    InferenceOutput,
    PreprocessingSpec,
)


@pytest.fixture
def temp_dna_generator(tmp_path: Path):
    """Provides an isolated InferenceDNAGenerator with temporary storage and unique keypair."""
    km = KeyManager()
    storage_dir = tmp_path / "inference_dna"
    return InferenceDNAGenerator(key_manager=km, storage_dir=storage_dir)


@pytest.fixture
def sample_output():
    """Generates standard detection outputs for testing."""
    boxes = [
        BoundingBox(label="recon_drone", confidence=0.97, box=[10.0, 20.0, 100.0, 150.0]),
        BoundingBox(label="military_truck", confidence=0.88, box=[150.0, 200.0, 350.0, 450.0]),
    ]
    raw_digest = canonical_json_hash([b.model_dump() for b in boxes])
    return InferenceOutput(predictions=boxes, raw_output_digest=raw_digest)


def test_deterministic_tuple_dna_calculation():
    """Verify that compute_tuple_dna yields strictly identical SHA-256 hashes for identical inputs."""
    fixed_params = {
        "sequence_id": 1,
        "timestamp": "2026-09-10T12:00:00Z",
        "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "model_id": "yolo_v8_target_detect",
        "model_digest": "a" * 64,
        "input_hash": "b" * 64,
        "prep_digest": "c" * 64,
        "output_hash": "d" * 64,
        "prev_chain_hash": "0" * 64,
    }

    hash1 = InferenceDNAGenerator.compute_tuple_dna(**fixed_params)
    hash2 = InferenceDNAGenerator.compute_tuple_dna(**fixed_params)

    assert hash1 == hash2
    assert len(hash1) == 64
    assert all(c in "0123456789abcdef" for c in hash1)


def test_sequential_sequence_ids_and_unique_nonces(temp_dna_generator, sample_output):
    """Verify sequence monotonic increment and nonce uniqueness across multiple inferences."""
    prep = PreprocessingSpec()
    input_hash = "1" * 64
    model_digest = "2" * 64

    rec1 = temp_dna_generator.create_dna_record(
        model_id="mod_alpha",
        model_identity_digest=model_digest,
        input_frame_sha256=input_hash,
        prep_spec=prep,
        output=sample_output,
    )
    rec2 = temp_dna_generator.create_dna_record(
        model_id="mod_alpha",
        model_identity_digest=model_digest,
        input_frame_sha256=input_hash,
        prep_spec=prep,
        output=sample_output,
    )

    assert rec1.sequence_id == 1
    assert rec2.sequence_id == 2
    assert rec1.nonce != rec2.nonce
    assert rec1.prev_chain_hash == "0" * 64
    assert rec2.prev_chain_hash == temp_dna_generator.chain.records[0]["current_hash"]
    assert temp_dna_generator.chain.records[0]["data_hash"] == rec1.dna_hash


def test_valid_inference_dna_verification(temp_dna_generator, sample_output):
    """Verify authentic inference record passes cryptographic audit cleanly."""
    prep = PreprocessingSpec()
    record = temp_dna_generator.create_dna_record(
        model_id="recon_optics",
        model_identity_digest="e" * 64,
        input_frame_sha256="f" * 64,
        prep_spec=prep,
        output=sample_output,
    )
    pubkey_pem = temp_dna_generator.export_public_key_pem()

    audit = InferenceDNAVerifier.verify_record(record, pubkey_pem)

    assert audit.is_valid is True
    assert audit.signature_valid is True
    assert audit.hash_integrity_valid is True
    assert audit.chain_pointer_valid is True
    assert len(audit.discrepancies) == 0


def test_tamper_detection_in_inference_record(temp_dna_generator, sample_output):
    """Verify any field mutation in the DNA record trips cryptographic integrity check."""
    prep = PreprocessingSpec()
    record = temp_dna_generator.create_dna_record(
        model_id="recon_optics",
        model_identity_digest="e" * 64,
        input_frame_sha256="f" * 64,
        prep_spec=prep,
        output=sample_output,
    )
    pubkey_pem = temp_dna_generator.export_public_key_pem()

    # 1. Tamper with output digest
    tampered_output = copy.deepcopy(record)
    tampered_output.output_digest = "0" * 64
    audit_output = InferenceDNAVerifier.verify_record(tampered_output, pubkey_pem)

    assert audit_output.is_valid is False
    assert audit_output.hash_integrity_valid is False
    assert any("DNA hash mismatch" in d for d in audit_output.discrepancies)

    # 2. Tamper with timestamp
    tampered_ts = copy.deepcopy(record)
    tampered_ts.timestamp = "2020-01-01T00:00:00Z"
    audit_ts = InferenceDNAVerifier.verify_record(tampered_ts, pubkey_pem)

    assert audit_ts.is_valid is False
    assert audit_ts.hash_integrity_valid is False


def test_signature_forgery_and_key_mismatch_detection(temp_dna_generator, sample_output):
    """Verify invalid signatures and unrecognized public keys are rejected."""
    prep = PreprocessingSpec()
    record = temp_dna_generator.create_dna_record(
        model_id="recon_optics",
        model_identity_digest="e" * 64,
        input_frame_sha256="f" * 64,
        prep_spec=prep,
        output=sample_output,
    )

    # 1. Mutated signature bytes
    forged_rec = copy.deepcopy(record)
    # Flip bytes in signature
    sig_chars = list(forged_rec.signature)
    sig_chars[0] = "a" if sig_chars[0] != "a" else "b"
    forged_rec.signature = "".join(sig_chars)

    pubkey_pem = temp_dna_generator.export_public_key_pem()
    audit_forged = InferenceDNAVerifier.verify_record(forged_rec, pubkey_pem)
    assert audit_forged.is_valid is False
    assert audit_forged.signature_valid is False

    # 2. Authentic signature verified with untrusted/foreign key
    foreign_km = KeyManager()
    foreign_pubkey_pem = foreign_km.export_public_key_pem().decode("utf-8")
    audit_foreign = InferenceDNAVerifier.verify_record(record, foreign_pubkey_pem)
    assert audit_foreign.is_valid is False
    assert audit_foreign.signature_valid is False


def test_replay_attack_nonce_rejection(temp_dna_generator, sample_output):
    """Verify that resubmitting a previously recorded nonce raises an explicit replay error."""
    prep = PreprocessingSpec()
    static_nonce = "deadbeefcafebabefeedfacedeadbeef"

    temp_dna_generator.create_dna_record(
        model_id="recon_optics",
        model_identity_digest="e" * 64,
        input_frame_sha256="f" * 64,
        prep_spec=prep,
        output=sample_output,
        nonce=static_nonce,
    )

    # Attempting replay with identical nonce must fail
    with pytest.raises(ValueError, match="Replay detected"):
        temp_dna_generator.create_dna_record(
            model_id="recon_optics",
            model_identity_digest="e" * 64,
            input_frame_sha256="f" * 64,
            prep_spec=prep,
            output=sample_output,
            nonce=static_nonce,
        )


def test_api_inference_flow_execute_and_verify():
    """Verify full end-to-end inference execution, receipt generation, and DNA verification API."""
    client = TestClient(app)

    # 1. Execute inference
    exec_resp = client.post(
        "/api/v1/inference/execute",
        json={"model_id": "drone_detector_v1", "image_sha256": "3" * 64},
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["success"] is True

    receipt = exec_data["data"]
    dna_record = receipt["dna_record"]
    pubkey_pem = receipt["public_key_pem"]

    assert dna_record["model_id"] == "drone_detector_v1"
    assert dna_record["sequence_id"] >= 1
    assert len(dna_record["dna_hash"]) == 64
    assert len(receipt["output"]["predictions"]) == 2

    # 2. Verify DNA receipt via API
    verify_resp = client.post(
        "/api/v1/inference/verify",
        json={"dna_record": dna_record, "public_key_pem": pubkey_pem},
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["success"] is True
    assert verify_data["data"]["is_valid"] is True
    assert verify_data["data"]["signature_valid"] is True
    assert verify_data["data"]["hash_integrity_valid"] is True

    # 3. Verify tampered receipt rejected via API
    tampered_dna = copy.deepcopy(dna_record)
    tampered_dna["input_frame_sha256"] = "9" * 64
    tampered_resp = client.post(
        "/api/v1/inference/verify",
        json={"dna_record": tampered_dna, "public_key_pem": pubkey_pem},
    )
    assert tampered_resp.status_code == 200
    assert tampered_resp.json()["data"]["is_valid"] is False

    # 4. Inspect audit hash chain
    chain_resp = client.get("/api/v1/inference/chain")
    assert chain_resp.status_code == 200
    chain_data = chain_resp.json()
    assert chain_data["success"] is True
    assert chain_data["data"]["records_count"] >= 1
