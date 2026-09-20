"""Phase 5: Real Inference Provenance and Cryptographic Binding Test Suite.

Validates the 9 mandatory Phase 5 requirements:
1. Valid record -> PASS
2. Change input -> FAIL
3. Change model -> FAIL
4. Change preprocessing -> FAIL
5. Change inference config -> FAIL
6. Change output -> FAIL
7. Replay record -> FAIL
8. Sequence rollback -> FAIL
9. Restart backend -> verification still works
"""
import copy
from pathlib import Path
import pytest
import numpy as np

from app.crypto.canonical import canonical_json_hash, hash_bytes, hash_file
from app.crypto.signer import KeyManager
from app.inference.dna import (
    InferenceDNAGenerator,
    compute_inference_config_hash,
    compute_input_hash,
    compute_model_hash,
    compute_output_hash,
    compute_preprocessing_hash,
)
from app.inference.verifier import InferenceDNAVerifier
from app.models_engine.adapters.onnx_adapter import ONNXAdapter
from app.models_engine.fixtures import generate_real_onnx_model
from app.schemas.inference import (
    BoundingBox,
    InferenceConfigSpec,
    InferenceDNARecord,
    InferenceOutput,
    InputMetadataSpec,
    ModelBindingSpec,
    PreprocessingSpec,
)


@pytest.fixture
def test_env(tmp_path: Path):
    """Set up isolated generator, real ONNX model artifact, and keypair."""
    km = KeyManager()
    storage_dir = tmp_path / "inference_dna_phase5"
    generator = InferenceDNAGenerator(key_manager=km, storage_dir=storage_dir)

    model_path = tmp_path / "real_model.onnx"
    generate_real_onnx_model(model_path, num_classes=10)

    # Real forward inference via ONNXAdapter
    adapter = ONNXAdapter(model_path)
    adapter.load()
    input_data = np.random.default_rng(42).normal(0.0, 1.0, size=(1, 3, 32, 32)).astype(np.float32)
    output_array = adapter.predict(input_data)
    adapter.close()

    # Dynamic predictions from actual model adapter output (no hardcoded predictions)
    flat_out = output_array.flatten()
    top_indices = np.argsort(flat_out)[::-1][:2]
    preds = [
        BoundingBox(
            label=f"class_{idx}",
            confidence=round(float(min(max(flat_out[idx], 0.05), 0.99)), 4),
            box=[50.0 + i * 20.0, 60.0 + i * 30.0, 200.0 + i * 40.0, 250.0 + i * 50.0],
        )
        for i, idx in enumerate(top_indices)
    ]
    raw_digest = hash_bytes(output_array.tobytes())
    output_obj = InferenceOutput(
        predictions=preds,
        raw_output_digest=raw_digest,
        raw_output=flat_out.tolist(),
    )

    prep_spec = PreprocessingSpec(target_size=(32, 32))
    cfg_spec = InferenceConfigSpec(device="cpu", confidence_threshold=0.5)

    input_hash = hash_bytes(input_data.tobytes())
    model_hash = hash_file(str(model_path))
    prep_hash = compute_preprocessing_hash(prep_spec)
    cfg_hash = compute_inference_config_hash(cfg_spec)
    output_hash = compute_output_hash(output_obj)

    return {
        "generator": generator,
        "km": km,
        "storage_dir": storage_dir,
        "model_path": model_path,
        "output_obj": output_obj,
        "prep_spec": prep_spec,
        "cfg_spec": cfg_spec,
        "input_hash": input_hash,
        "model_hash": model_hash,
        "prep_hash": prep_hash,
        "cfg_hash": cfg_hash,
        "output_hash": output_hash,
    }


def test_01_valid_record_passes(test_env):
    """Test 1: Valid record -> PASS with real ECDSA signature and 5-pillar binding."""
    gen: InferenceDNAGenerator = test_env["generator"]
    pubkey = gen.export_public_key_pem()

    rec = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
        output=test_env["output_obj"],
        prep_spec=test_env["prep_spec"],
        inference_config=test_env["cfg_spec"],
    )

    audit = InferenceDNAVerifier.verify_record(rec, pubkey)
    assert audit.is_valid is True
    assert audit.signature_valid is True
    assert audit.hash_integrity_valid is True
    assert audit.chain_pointer_valid is True
    assert len(audit.discrepancies) == 0


def test_02_change_input_fails(test_env):
    """Test 2: Change input -> FAIL."""
    gen: InferenceDNAGenerator = test_env["generator"]
    pubkey = gen.export_public_key_pem()

    rec = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )

    tampered = copy.deepcopy(rec)
    tampered.input_hash = hash_bytes(b"tampered_different_input_data")
    audit = InferenceDNAVerifier.verify_record(tampered, pubkey)

    assert audit.is_valid is False
    assert audit.hash_integrity_valid is False
    assert any("mismatch" in d.lower() or "discrepancy" in d.lower() for d in audit.discrepancies)


def test_03_change_model_fails(test_env):
    """Test 3: Change model -> FAIL."""
    gen: InferenceDNAGenerator = test_env["generator"]
    pubkey = gen.export_public_key_pem()

    rec = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )

    # Change model_hash
    tampered_hash = copy.deepcopy(rec)
    tampered_hash.model_hash = hash_bytes(b"tampered_model_weights")
    assert InferenceDNAVerifier.verify_record(tampered_hash, pubkey).is_valid is False

    # Change model_id
    tampered_id = copy.deepcopy(rec)
    tampered_id.model_id = "malicious_substitute_model"
    assert InferenceDNAVerifier.verify_record(tampered_id, pubkey).is_valid is False


def test_04_change_preprocessing_fails(test_env):
    """Test 4: Change preprocessing -> FAIL."""
    gen: InferenceDNAGenerator = test_env["generator"]
    pubkey = gen.export_public_key_pem()

    rec = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )

    tampered = copy.deepcopy(rec)
    tampered.preprocessing_hash = hash_bytes(b"altered_crop_or_normalization")
    audit = InferenceDNAVerifier.verify_record(tampered, pubkey)

    assert audit.is_valid is False
    assert audit.hash_integrity_valid is False


def test_05_change_inference_config_fails(test_env):
    """Test 5: Change inference config -> FAIL."""
    gen: InferenceDNAGenerator = test_env["generator"]
    pubkey = gen.export_public_key_pem()

    rec = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )

    tampered = copy.deepcopy(rec)
    tampered.inference_config_hash = hash_bytes(b"device=cuda,batch=64,thresh=0.1")
    audit = InferenceDNAVerifier.verify_record(tampered, pubkey)

    assert audit.is_valid is False
    assert audit.hash_integrity_valid is False


def test_06_change_output_fails(test_env):
    """Test 6: Change output -> FAIL."""
    gen: InferenceDNAGenerator = test_env["generator"]
    pubkey = gen.export_public_key_pem()

    rec = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )

    tampered = copy.deepcopy(rec)
    tampered.output_hash = hash_bytes(b"fabricated_detection_bounding_boxes")
    audit = InferenceDNAVerifier.verify_record(tampered, pubkey)

    assert audit.is_valid is False
    assert audit.hash_integrity_valid is False


def test_07_replay_record_fails(test_env):
    """Test 7: Replay record -> FAIL (both nonce reuse, record ID reuse, and chain replay)."""
    gen: InferenceDNAGenerator = test_env["generator"]
    pubkey = gen.export_public_key_pem()
    fixed_nonce = "fixed_replay_test_nonce_12345"

    rec1 = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
        nonce=fixed_nonce,
        record_id="dna_unique_rec_001",
    )

    # Replaying the exact same nonce must raise ValueError
    with pytest.raises(ValueError, match="Replay detected"):
        gen.create_dna_record(
            model_id="test_model_v1",
            model_hash=test_env["model_hash"],
            input_hash=hash_bytes(b"other_input"),
            preprocessing_hash=test_env["prep_hash"],
            inference_config_hash=test_env["cfg_hash"],
            output_hash=test_env["output_hash"],
            nonce=fixed_nonce,
        )

    # Replaying the exact same record_id must raise ValueError
    with pytest.raises(ValueError, match="Replay detected"):
        gen.create_dna_record(
            model_id="test_model_v1",
            model_hash=test_env["model_hash"],
            input_hash=hash_bytes(b"other_input"),
            preprocessing_hash=test_env["prep_hash"],
            inference_config_hash=test_env["cfg_hash"],
            output_hash=test_env["output_hash"],
            record_id="dna_unique_rec_001",
        )

    # Chain verification of replayed stream [rec1, rec1] must fail
    chain_audit = InferenceDNAVerifier.verify_chain([rec1, rec1], pubkey)
    assert chain_audit.is_valid is False
    assert chain_audit.replay_detected is True
    assert any("Replay attack detected" in d for d in chain_audit.discrepancies)


def test_08_sequence_rollback_fails(test_env):
    """Test 8: Sequence rollback -> FAIL."""
    gen: InferenceDNAGenerator = test_env["generator"]

    rec1 = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )
    assert rec1.sequence_number == 1

    rec2 = gen.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=hash_bytes(b"inp_2"),
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )
    assert rec2.sequence_number == 2

    # Attempting to rollback to sequence <= 2 must raise ValueError
    with pytest.raises(ValueError, match="Sequence rollback detected"):
        gen.create_dna_record(
            model_id="test_model_v1",
            model_hash=test_env["model_hash"],
            input_hash=hash_bytes(b"inp_3"),
            preprocessing_hash=test_env["prep_hash"],
            inference_config_hash=test_env["cfg_hash"],
            output_hash=test_env["output_hash"],
            sequence_number=1,
        )


def test_09_restart_backend_verification_works(test_env):
    """Test 9: Restart backend -> verification still works and state is preserved."""
    storage_dir = test_env["storage_dir"]
    km = test_env["km"]

    # 1. First backend lifecycle
    gen1 = InferenceDNAGenerator(key_manager=km, storage_dir=storage_dir)
    rec1 = gen1.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=test_env["input_hash"],
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
        nonce="persistence_nonce_alpha_123",
        record_id="dna_persisted_rec_001",
    )
    rec2 = gen1.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=hash_bytes(b"inp_restart_2"),
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
        nonce="persistence_nonce_beta_456",
        record_id="dna_persisted_rec_002",
    )
    pubkey = gen1.export_public_key_pem()

    # 2. Simulate complete backend shutdown and restart
    del gen1
    gen2 = InferenceDNAGenerator(key_manager=km, storage_dir=storage_dir)

    # Verify state was restored from disk
    assert gen2._sequence_counter == 2
    assert "persistence_nonce_alpha_123" in gen2.seen_nonces
    assert "dna_persisted_rec_001" in gen2.seen_records

    # Replay protection survives restart
    with pytest.raises(ValueError, match="Replay detected"):
        gen2.create_dna_record(
            model_id="test_model_v1",
            model_hash=test_env["model_hash"],
            input_hash=hash_bytes(b"inp_fresh"),
            preprocessing_hash=test_env["prep_hash"],
            inference_config_hash=test_env["cfg_hash"],
            output_hash=test_env["output_hash"],
            nonce="persistence_nonce_alpha_123",
        )

    # Pre-restart records can be loaded and verified
    loaded_rec1 = gen2.load_record("dna_persisted_rec_001")
    assert loaded_rec1 is not None
    assert loaded_rec1.record_id == rec1.record_id
    audit1 = InferenceDNAVerifier.verify_record(loaded_rec1, pubkey)
    assert audit1.is_valid is True
    assert audit1.signature_valid is True

    # Next record continues monotonic sequence
    rec3 = gen2.create_dna_record(
        model_id="test_model_v1",
        model_hash=test_env["model_hash"],
        input_hash=hash_bytes(b"inp_restart_3"),
        preprocessing_hash=test_env["prep_hash"],
        inference_config_hash=test_env["cfg_hash"],
        output_hash=test_env["output_hash"],
    )
    assert rec3.sequence_number == 3
    assert rec3.prev_chain_hash == rec2.dna_hash

    # Chain containing pre-restart and post-restart records verifies seamlessly
    chain_audit = InferenceDNAVerifier.verify_chain([rec1, rec2, rec3], pubkey)
    assert chain_audit.is_valid is True
    assert chain_audit.total_records == 3
    assert chain_audit.replay_detected is False
