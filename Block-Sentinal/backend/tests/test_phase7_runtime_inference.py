"""Phase 7 Test Suite: Real Model Runtime & Inference Execution.

Validates:
1. Model structural validation and 10-stage lifecycle state machine
2. Real ONNX execution via onnxruntime
3. Deterministic input preprocessing strictly adhering to model contracts
4. Strict output validation (presence, dtype, shape, finiteness, serialization)
5. Cryptographic binding of real outputs to Inference DNA records
6. No fabricated evidence rule (missing inputs or models strictly report UNAVAILABLE)
7. REST API execution and audit endpoints
8. Evidence graph and fusion gatekeeper integration
"""
import base64
import io
from pathlib import Path
from typing import Any, Dict
import numpy as np
from PIL import Image
# pyrefly: ignore [missing-import]
import pytest
from fastapi.testclient import TestClient

from app.crypto.canonical import hash_bytes, hash_file
from app.crypto.signer import KeyManager
from app.inference.dna import InferenceDNAGenerator
from app.inference.verifier import InferenceDNAVerifier
from app.main import app
from app.models_engine.fixtures import generate_real_onnx_model
from app.models_engine.registry import ModelRegistry
from app.runtime.engine import ModelRuntimeEngine
from app.runtime.preprocessor import DeterministicPreprocessor
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceItem,
    EvidenceSource,
    EvidenceSourceDomain,
)
from app.schemas.integrity import IntegritySeverity
from app.schemas.model import ModelFormat, ModelInputSpec
from app.schemas.runtime import (
    ModelRuntimeState,
    OutputValidationStatus,
)


@pytest.fixture
def runtime_env(tmp_path: Path):
    """Isolated environment with dedicated ModelRegistry, InferenceDNAGenerator, and real ONNX model."""
    km = KeyManager()
    dna_dir = tmp_path / "inference_dna"
    registry_dir = tmp_path / "models"
    dna_gen = InferenceDNAGenerator(key_manager=km, storage_dir=dna_dir)
    registry = ModelRegistry(base_dir=registry_dir)
    engine = ModelRuntimeEngine(registry=registry, dna_generator=dna_gen)

    # Generate real ONNX model artifact (e.g. 3-channel input -> 10-class output)
    models_dir = tmp_path / "binaries"
    models_dir.mkdir(parents=True, exist_ok=True)
    model_path = models_dir / "real_recon_v1.onnx"
    generate_real_onnx_model(model_path, num_classes=10)

    # Register model in registry
    manifest = registry.register_model(
        name="real_recon_v1",
        version="1.0.0",
        model_path=model_path,
        format=ModelFormat.ONNX,
    )

    # Create real input image (64x64 RGB)
    img_arr = np.random.default_rng(42).integers(0, 256, (64, 64, 3), dtype=np.uint8)
    pil_img = Image.fromarray(img_arr)
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    raw_image_bytes = buf.getvalue()

    return {
        "engine": engine,
        "dna_gen": dna_gen,
        "registry": registry,
        "model_path": model_path,
        "manifest": manifest,
        "image_bytes": raw_image_bytes,
        "pil_img": pil_img,
        "tmp_path": tmp_path,
    }


# =============================================================================
# 1. Model Validation & State Machine Lifecycle
# =============================================================================

def test_model_validation_and_state_transitions(runtime_env):
    """Verify structural validation transitions: DISCOVERED -> VALIDATING -> VALID."""
    engine: ModelRuntimeEngine = runtime_env["engine"]
    model_path: Path = runtime_env["model_path"]

    report = engine.validate_model(model_path, model_id="real_recon_v1")

    assert report.is_valid is True
    assert report.state == ModelRuntimeState.VALID
    assert report.model_sha256 == hash_file(str(model_path))
    assert report.node_count > 0
    assert report.parameter_count > 0
    assert len(report.input_specs) >= 1
    assert len(report.output_specs) >= 1
    assert report.validation_errors == []

    # Verify event audit log
    history = engine.get_lifecycle_history("real_recon_v1")
    assert len(history) >= 1
    assert history[0].to_state == ModelRuntimeState.VALIDATING
    assert history[1].to_state == ModelRuntimeState.VALID


def test_invalid_corrupted_model_state_transition(runtime_env):
    """Verify corrupted model transitions to INVALID and records errors."""
    engine: ModelRuntimeEngine = runtime_env["engine"]
    tmp_path: Path = runtime_env["tmp_path"]

    bad_model = tmp_path / "corrupted.onnx"
    bad_model.write_bytes(b"NOT_A_VALID_ONNX_PROTO_HEADER_DATA_1234567890")

    report = engine.validate_model(bad_model, model_id="bad_model_01")
    assert report.is_valid is False
    assert report.state == ModelRuntimeState.INVALID
    assert len(report.validation_errors) > 0

    history = engine.get_lifecycle_history("bad_model_01")
    assert any(e.to_state == ModelRuntimeState.INVALID for e in history)


# =============================================================================
# 2. Real ONNX Execution via onnxruntime
# =============================================================================

def test_real_onnx_execution_and_determinism(runtime_env):
    """Verify real forward pass via onnxruntime produces non-empty, finite, deterministic outputs."""
    engine: ModelRuntimeEngine = runtime_env["engine"]
    model_path: Path = runtime_env["model_path"]
    image_bytes: bytes = runtime_env["image_bytes"]

    # 1. Execute forward pass
    exec_rec, dna_rec, output_arr = engine.execute_inference(
        model_path=model_path,
        image_input=image_bytes,
        model_id="real_recon_v1",
    )

    # 2. Verify execution record
    assert exec_rec.runtime == "onnxruntime"
    assert exec_rec.latency_ms > 0.0
    assert exec_rec.output_shape == list(output_arr.shape)
    assert exec_rec.validation_report.validation_status == OutputValidationStatus.PASSED
    assert exec_rec.validation_report.all_values_finite is True
    assert exec_rec.validation_report.output_exists is True

    # 3. Verify output tensor
    assert output_arr.size == 10  # 10 classes
    assert np.all(np.isfinite(output_arr))
    assert exec_rec.output_sha256 == hash_bytes(output_arr.tobytes())

    # 4. Verify determinism: repeating execution on identical input yields identical output SHA-256
    exec_rec2, dna_rec2, output_arr2 = engine.execute_inference(
        model_path=model_path,
        image_input=image_bytes,
        model_id="real_recon_v1",
    )
    assert exec_rec.output_sha256 == exec_rec2.output_sha256
    np.testing.assert_allclose(output_arr, output_arr2, rtol=1e-5, atol=1e-6)

    # 5. Verify state machine reached COMPLETED
    assert engine.get_state("real_recon_v1") == ModelRuntimeState.COMPLETED


# =============================================================================
# 3. Deterministic Preprocessing Contract
# =============================================================================

def test_deterministic_preprocessing_contract(runtime_env):
    """Verify input preprocessing strictly conforms to model tensor shape and normalization."""
    input_spec = ModelInputSpec(
        name="input_tensor",
        shape=[1, 3, 32, 32],
        data_type="float32",
    )
    pil_img: Image.Image = runtime_env["pil_img"]

    tensor_arr, prep_rec, inp_hash = DeterministicPreprocessor.preprocess_image(
        image_input=pil_img,
        input_spec=input_spec,
    )

    assert tensor_arr.shape == (1, 3, 32, 32)
    assert tensor_arr.dtype == np.float32
    assert prep_rec.channel_order == "NCHW"
    assert prep_rec.resize == (32, 32)
    assert len(prep_rec.preprocessing_hash) == 64
    assert len(inp_hash) == 64


def test_ambiguous_contract_raises_unavailable():
    """Verify ambiguous spatial contract without override raises INFERENCE = UNAVAILABLE."""
    ambiguous_spec = ModelInputSpec(
        name="dynamic_input",
        shape=[1, 3, None, None],  # Unknown H, W
        data_type="float32",
    )
    dummy_img = Image.new("RGB", (64, 64))

    with pytest.raises(RuntimeError, match="INFERENCE = UNAVAILABLE"):
        DeterministicPreprocessor.preprocess_image(
            image_input=dummy_img,
            input_spec=ambiguous_spec,
        )


# =============================================================================
# 4. Output Validation & Finiteness Failure
# =============================================================================

def test_output_validation_finiteness_check(runtime_env):
    """Verify output containing non-finite values (NaN/Inf) triggers INFERENCE_VALIDATION = FAILED."""
    engine: ModelRuntimeEngine = runtime_env["engine"]
    model_path: Path = runtime_env["model_path"]
    image_bytes: bytes = runtime_env["image_bytes"]

    # Load session and mock run output to return NaN
    session = engine.load_session(model_path, model_id="real_recon_v1")
    nan_output = np.array([[np.nan, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]], dtype=np.float32)

    original_run = session.run
    session.run = lambda names, feeds: [nan_output]

    try:
        with pytest.raises(RuntimeError, match="INFERENCE_VALIDATION = FAILED"):
            engine.execute_inference(
                model_path=model_path,
                image_input=image_bytes,
                model_id="real_recon_v1",
            )
        assert engine.get_state("real_recon_v1") == ModelRuntimeState.FAILED
    finally:
        session.run = original_run


# =============================================================================
# 5. Inference DNA Cryptographic Binding
# =============================================================================

def test_inference_dna_binding_and_verification(runtime_env):
    """Verify real inference output is cryptographically bound into Inference DNA and verifies."""
    engine: ModelRuntimeEngine = runtime_env["engine"]
    dna_gen: InferenceDNAGenerator = runtime_env["dna_gen"]
    model_path: Path = runtime_env["model_path"]
    image_bytes: bytes = runtime_env["image_bytes"]

    exec_rec, dna_rec, output_arr = engine.execute_inference(
        model_path=model_path,
        image_input=image_bytes,
        model_id="real_recon_v1",
    )

    # Verify DNA fields bound to actual execution artifacts
    assert dna_rec.model_hash == exec_rec.model_sha256
    assert dna_rec.input_hash == exec_rec.input_sha256
    assert dna_rec.output_hash == exec_rec.output_sha256
    assert len(dna_rec.signature) > 64

    # Audit verification
    pubkey = dna_gen.export_public_key_pem()
    audit = InferenceDNAVerifier.verify_record(dna_rec, pubkey)
    assert audit.is_valid is True
    assert audit.signature_valid is True
    assert audit.hash_integrity_valid is True


# =============================================================================
# 6. REST API: /api/v1/inference/execute End-to-End
# =============================================================================

def test_api_inference_execute_endpoint_success(runtime_env):
    """Verify REST API /api/v1/inference/execute performs real execution and returns authentic receipt."""
    model_path: Path = runtime_env["model_path"]
    image_bytes: bytes = runtime_env["image_bytes"]
    b64_str = base64.b64encode(image_bytes).decode("ascii")

    client = TestClient(app)

    payload = {
        "model_id": str(model_path),  # Pass direct path or registered ID
        "image_bytes_b64": b64_str,
    }
    response = client.post("/api/v1/inference/execute", json=payload)
    assert response.status_code == 200

    data = response.json()["data"]
    assert "dna_record" in data
    assert "output" in data
    assert data["output"]["predictions"] == []  # No fake bounding boxes!
    assert len(data["output"]["raw_output_digest"]) == 64
    assert len(data["output"]["raw_output"]) == 10


def test_api_inference_missing_model_fails_unavailable():
    """Verify missing model returns HTTP 404 with UNAVAILABLE message (no silent mock generation)."""
    client = TestClient(app)
    b64_dummy = base64.b64encode(b"some_image_bytes").decode("ascii")
    payload = {
        "model_id": "nonexistent_mission_model_99",
        "image_bytes_b64": b64_dummy,
    }
    response = client.post("/api/v1/inference/execute", json=payload)
    assert response.status_code == 404
    err_msg = response.json().get("error") or response.json().get("detail", "")
    assert "INFERENCE = UNAVAILABLE" in err_msg


def test_api_inference_missing_image_fails_unavailable(runtime_env):
    """Verify missing image data returns HTTP 400 with UNAVAILABLE message (no synthetic demo bytes)."""
    model_path: Path = runtime_env["model_path"]
    client = TestClient(app)
    payload = {
        "model_id": str(model_path),
        # No image_bytes_b64 provided
    }
    response = client.post("/api/v1/inference/execute", json=payload)
    assert response.status_code == 400
    err_msg = response.json().get("error") or response.json().get("detail", "")
    assert "INFERENCE = UNAVAILABLE" in err_msg


# =============================================================================
# 7. Evidence Graph & Fusion Gatekeeper Integration
# =============================================================================

def test_inference_evidence_fusion_and_hard_veto(runtime_env):
    """Verify real inference output creates valid evidence items, attaches to graph, and drives fusion."""
    from app.fusion.engine import EvidenceFusionEngine
    from app.graph.engine import EvidenceGraphEngine

    engine: ModelRuntimeEngine = runtime_env["engine"]
    model_path: Path = runtime_env["model_path"]
    image_bytes: bytes = runtime_env["image_bytes"]
    tmp_path: Path = runtime_env["tmp_path"]

    exec_rec, dna_rec, _ = engine.execute_inference(
        model_path=model_path,
        image_input=image_bytes,
        model_id="real_recon_v1",
    )

    fusion_engine = EvidenceFusionEngine(storage_dir=tmp_path / "fusion")
    graph_engine = EvidenceGraphEngine(storage_dir=tmp_path / "graph")

    # 1. Clean inference evidence item
    ev_clean = EvidenceItem(
        evidence_id=f"ev_inf_{exec_rec.inference_id}",
        source=EvidenceSource.INFERENCE_DNA,
        domain=EvidenceSourceDomain.INFERENCE,
        severity=IntegritySeverity.LOW,
        metric_value=0.0,
        description="Inference provenance chain verified; nonce and signatures authenticated.",
        subject_id=exec_rec.inference_id,
    )
    fusion_engine.register_evidence(ev_clean)

    # 2. Build graph lineage: MODEL -> INFERENCE -> OUTPUT
    graph_engine.build_lineage(
        model_id="real_recon_v1",
        inference_id=exec_rec.inference_id,
        output_id=f"out_{exec_rec.output_sha256[:12]}",
    )
    graph_engine.attach_evidence(
        evidence_id=ev_clean.evidence_id,
        subject_id=exec_rec.inference_id,
        source_domain="INFERENCE",
        severity="LOW",
        description=ev_clean.description,
    )

    # Verify graph connectivity
    trace = graph_engine.trace_downstream("real_recon_v1")
    trace_ids = [n.id for n in trace]
    assert exec_rec.inference_id in trace_ids
    assert f"out_{exec_rec.output_sha256[:12]}" in trace_ids

    # Verify edge has valid evidence_id
    for edge in graph_engine.edges:
        assert edge.evidence_id is not None
        assert len(edge.evidence_id.strip()) > 0

    # 3. Clean inference fuses to ACCEPTED
    assmt_clean = fusion_engine.fuse(exec_rec.inference_id, [ev_clean])
    assert assmt_clean.overall_status == AssetStatus.ACCEPTED
    assert assmt_clean.action == AssuranceAction.ALLOW
    assert assmt_clean.hard_veto_triggered is False

    # 4. Tampered inference sequence/replay triggers Hard Veto
    ev_tampered = EvidenceItem(
        evidence_id=f"ev_inf_tamper_{exec_rec.inference_id}",
        source=EvidenceSource.INFERENCE_DNA,
        domain=EvidenceSourceDomain.INFERENCE,
        severity=IntegritySeverity.CRITICAL,
        metric_value=1.0,
        description="Inference provenance sequence break detected: nonce replay attack.",
        subject_id=exec_rec.inference_id,
    )
    assmt_veto = fusion_engine.fuse(exec_rec.inference_id, [ev_tampered])
    assert assmt_veto.hard_veto_triggered is True
    assert assmt_veto.overall_status == AssetStatus.QUARANTINED
    assert assmt_veto.action == AssuranceAction.BLOCK
    assert assmt_veto.risk_level == AssuranceRiskLevel.CRITICAL
