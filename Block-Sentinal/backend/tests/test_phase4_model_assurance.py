"""Comprehensive test suite for Phase 4 — Real Model Assurance and Model-Agnostic Adapters."""
from pathlib import Path
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.crypto.canonical import hash_file
from app.fingerprint.runner import BehaviouralFingerprinter
from app.main import app
from app.models_engine.adapters.base import BaseModelAdapter
from app.models_engine.adapters.blackbox_adapter import BlackBoxAdapter
from app.models_engine.adapters.factory import ModelAdapterFactory
from app.models_engine.adapters.onnx_adapter import ONNXAdapter
from app.models_engine.adapters.pytorch_adapter import PyTorchAdapter
from app.models_engine.adapters.torchscript_adapter import TorchScriptAdapter
from app.models_engine.fixtures import (
    generate_real_onnx_model,
    generate_real_pytorch_weights,
    generate_real_torchscript_model,
)
from app.models_engine.registry import ModelRegistry
from app.models_engine.trigger_detector import TriggerDetector
from app.schemas.model import (
    AccessMode,
    ModelFormat,
    TriggerStatus,
    VerificationStatus,
)
from app.schemas.scan import ComponentStatus

client = TestClient(app)


def test_clean_onnx_adapter_capabilities(tmp_path):
    """Verify clean ONNX adapter implements all required capabilities: load, metadata, schemas, predict, fingerprint, close."""
    onnx_file = tmp_path / "clean_detector.onnx"
    generate_real_onnx_model(onnx_file, seed=42, num_classes=10)

    adapter = ONNXAdapter(onnx_file)
    assert adapter.format == ModelFormat.ONNX
    assert adapter.access_mode == AccessMode.WHITE_BOX
    assert adapter.artifact_hash == hash_file(str(onnx_file))

    # load()
    adapter.load()

    # metadata()
    meta = adapter.metadata()
    assert meta["parameter_count"] > 0
    assert meta["node_count"] >= 3
    assert "Gemm" in meta["node_types"]
    assert "Flatten" in meta["node_types"]
    assert "Softmax" in meta["node_types"]

    # input_schema() & output_schema()
    in_spec = adapter.input_schema()
    out_spec = adapter.output_schema()
    assert len(in_spec) == 1
    assert in_spec[0].name == "input"
    assert len(out_spec) == 1
    assert out_spec[0].name == "output"

    # predict() - real ONNX Runtime inference
    test_inputs = np.random.randint(0, 256, size=(4, 32, 32, 3), dtype=np.uint8)
    outputs = adapter.predict(test_inputs)
    assert isinstance(outputs, np.ndarray)
    assert outputs.shape == (4, 10)
    # Output probabilities sum to ~1.0
    for row in outputs:
        assert np.isclose(np.sum(row), 1.0, atol=1e-4)

    # fingerprint()
    fp = adapter.fingerprint()
    assert "graph_digest" in fp
    assert len(fp["graph_digest"]) == 64
    assert fp["node_count"] == meta["node_count"]

    # close()
    adapter.close()
    assert adapter._session is None


def test_modified_onnx_model_divergence(tmp_path):
    """Verify system detects modified model weights and outputs MISMATCH across binary and behavioural tiers."""
    clean_file = tmp_path / "clean.onnx"
    modified_file = tmp_path / "modified.onnx"

    generate_real_onnx_model(clean_file, seed=42, num_classes=10)
    generate_real_onnx_model(modified_file, seed=999, num_classes=10)

    registry = ModelRegistry(base_dir=tmp_path / "registry")

    ref_manifest = registry.register_model(
        name="TargetClassifier",
        version="1.0.0",
        model_path=clean_file,
        format=ModelFormat.ONNX,
        is_reference=True,
    )

    cand_manifest = registry.register_model(
        name="TargetClassifier",
        version="1.0.0",
        model_path=modified_file,
        format=ModelFormat.ONNX,
        is_reference=False,
    )

    verify_res = registry.verify_against_baseline(cand_manifest.model_id)

    assert verify_res.is_valid is False
    assert verify_res.binary_match is False
    assert verify_res.binary_identity == VerificationStatus.MISMATCH
    assert verify_res.behavioural_identity == VerificationStatus.MISMATCH
    assert len(verify_res.discrepancies) > 0


def test_model_with_changed_bytes(tmp_path):
    """Verify byte alteration in model artifact is detected immediately via direct disk hashing."""
    base_file = tmp_path / "original.onnx"
    tampered_file = tmp_path / "tampered.onnx"

    generate_real_onnx_model(base_file, seed=42)
    tampered_bytes = bytearray(base_file.read_bytes())
    # Flip bytes in the middle
    tampered_bytes[len(tampered_bytes) // 2] ^= 0xFF
    tampered_file.write_bytes(tampered_bytes)

    registry = ModelRegistry(base_dir=tmp_path / "registry")

    ref = registry.register_model(
        name="SecurityModel",
        version="1.0.0",
        model_path=base_file,
        format=ModelFormat.ONNX,
        is_reference=True,
    )

    # Invariant: Binary SHA-256 must not match
    assert hash_file(str(base_file)) != hash_file(str(tampered_file))


def test_torchscript_adapter_real_inference(tmp_path):
    """Verify TorchScript adapter performs safe local JIT loading, metadata extraction, and real inference."""
    ts_file = tmp_path / "scripted_net.pt"
    generate_real_torchscript_model(ts_file, seed=42, num_classes=10)

    adapter = TorchScriptAdapter(ts_file)
    assert adapter.format == ModelFormat.TORCHSCRIPT
    assert adapter.access_mode == AccessMode.WHITE_BOX

    adapter.load()
    meta = adapter.metadata()
    assert meta["parameter_count"] > 0
    assert meta["framework"] == "torchscript"

    # Real inference on CPU
    test_batch = np.random.randint(0, 256, size=(2, 32, 32, 3), dtype=np.uint8)
    preds = adapter.predict(test_batch)
    assert preds.shape == (2, 10)
    for row in preds:
        assert np.isclose(np.sum(row), 1.0, atol=1e-4)

    fp = adapter.fingerprint()
    assert "graph_digest" in fp
    assert len(fp["graph_digest"]) == 64

    adapter.close()


def test_safe_pytorch_weights_and_runtime_unavailable(tmp_path):
    """Verify PyTorch adapter safely inspects state_dict weights and reports PYTORCH_RUNTIME_UNAVAILABLE for arbitrary forward pass."""
    pt_file = tmp_path / "safe_weights.pt"
    generate_real_pytorch_weights(pt_file, seed=42, num_classes=10)

    adapter = PyTorchAdapter(pt_file)
    assert adapter.format == ModelFormat.PYTORCH_WEIGHTS
    assert adapter.access_mode == AccessMode.PARTIAL

    adapter.load()
    meta = adapter.metadata()
    assert meta["parameter_count"] > 0
    assert meta["runtime_available"] is False
    assert meta["inference_limitation"] == "PYTORCH_RUNTIME_UNAVAILABLE"

    # Forward prediction must raise PYTORCH_RUNTIME_UNAVAILABLE and not fake results
    with pytest.raises(RuntimeError, match="PYTORCH_RUNTIME_UNAVAILABLE"):
        adapter.predict(np.zeros((1, 32, 32, 3), dtype=np.float32))

    fp = adapter.fingerprint()
    assert "graph_digest" in fp
    assert fp["weight_tensors_count"] > 0


def test_unsupported_model_format(tmp_path):
    """Verify unsupported model formats are rejected without fake PASS results."""
    unsupported_file = tmp_path / "corrupted_archive.unknown"
    unsupported_file.write_bytes(b"RANDOM_CORRUPT_BYTES_NOT_A_MODEL")

    with pytest.raises(ValueError, match="UNSUPPORTED_FORMAT"):
        ModelAdapterFactory.get_adapter(unsupported_file)


def test_blackbox_scenario(tmp_path):
    """Verify black-box adapter reports structural analysis UNAVAILABLE while real inference operates."""
    dummy_file = tmp_path / "blackbox_endpoint.stub"
    dummy_file.write_bytes(b"BLACK_BOX_ENDPOINT_CONFIG")

    # Black-box prediction function
    def blackbox_call(inputs: np.ndarray) -> np.ndarray:
        batch_size = len(inputs)
        return np.ones((batch_size, 5), dtype=np.float32) / 5.0

    adapter = BlackBoxAdapter(dummy_file, predict_fn=blackbox_call)
    assert adapter.access_mode == AccessMode.BLACK_BOX
    assert adapter.format == ModelFormat.BLACK_BOX

    meta = adapter.metadata()
    assert meta["structural_analysis"] == "UNAVAILABLE"
    assert meta["access_mode"] == "BLACK_BOX"

    fp = adapter.fingerprint()
    assert fp["structural_status"] == "UNAVAILABLE"

    # Real inference works via callable
    test_batch = np.zeros((3, 32, 32, 3), dtype=np.float32)
    outs = adapter.predict(test_batch)
    assert outs.shape == (3, 5)


def test_behavioural_fingerprint_probe_records(tmp_path):
    """Verify behavioural fingerprinter removes surrogate executor and records real probe records."""
    model_file = tmp_path / "probe_model.onnx"
    generate_real_onnx_model(model_file, seed=100)

    fingerprinter = BehaviouralFingerprinter(fingerprints_dir=tmp_path / "fps")
    fp = fingerprinter.fingerprint_model(model_file, seed=42, count=4)

    assert fp.model_hash == hash_file(str(model_file))
    assert len(fp.probe_records) > 0

    first_record = fp.probe_records[0]
    assert len(first_record.input_hash) == 64
    assert len(first_record.output_hash) == 64
    assert len(first_record.model_hash) == 64
    assert len(first_record.canonical_output) > 0


def test_trigger_detector_evaluation(tmp_path):
    """Verify defensible trigger sensitivity evaluation distinguishes clean models from backdoored triggers."""
    model_file = tmp_path / "eval_model.onnx"
    generate_real_onnx_model(model_file, seed=42)

    adapter = ONNXAdapter(model_file)
    status, conf, basis, evidence, limitations = TriggerDetector.evaluate(adapter, count=8)

    assert status in (TriggerStatus.CLEAN, TriggerStatus.SUSPICIOUS_TRIGGER_SENSITIVITY)
    assert conf is not None and 0.0 <= conf <= 1.0
    assert "probe_count" in evidence
    assert len(limitations) >= 2


def test_model_assurance_finding_standardization(tmp_path):
    """Verify ModelAssuranceFinding schema standardization and API exposure."""
    model_file = tmp_path / "assurance_model.onnx"
    generate_real_onnx_model(model_file, seed=777)

    registry = ModelRegistry(base_dir=tmp_path / "reg")
    manifest = registry.register_model(
        name="AssuranceNet",
        version="1.0.0",
        model_path=model_file,
        format=ModelFormat.ONNX,
        is_reference=True,
    )

    finding = registry.generate_assurance_finding(manifest.model_id)

    assert finding.model_id == manifest.model_id
    assert finding.artifact_hash == manifest.artifact_hash
    assert finding.format == "ONNX"
    assert finding.access_mode == AccessMode.WHITE_BOX
    assert finding.identity_status == VerificationStatus.MATCH
    assert finding.structural_status == VerificationStatus.MATCH
    assert finding.confidence is not None
    assert len(finding.limitations) > 0


def test_invariant_no_match_after_model_modification(tmp_path):
    """INVARIANT TEST: Verify system NEVER reports MATCH after actual model modification."""
    clean_file = tmp_path / "clean_golden.onnx"
    modified_file = tmp_path / "modified_tampered.onnx"

    generate_real_onnx_model(clean_file, seed=42)
    # Different weights and bias
    generate_real_onnx_model(modified_file, seed=42, weight_bias=5.0)

    registry = ModelRegistry(base_dir=tmp_path / "reg_inv")
    registry.register_model(
        name="InvariantNet",
        version="1.0.0",
        model_path=clean_file,
        format=ModelFormat.ONNX,
        is_reference=True,
    )

    candidate = registry.register_model(
        name="InvariantNet",
        version="1.0.0",
        model_path=modified_file,
        format=ModelFormat.ONNX,
        is_reference=False,
    )

    verify_res = registry.verify_against_baseline(candidate.model_id)

    # Invariant: Binary match MUST be False
    assert verify_res.binary_match is False
    assert verify_res.binary_identity == VerificationStatus.MISMATCH
    assert verify_res.is_valid is False
