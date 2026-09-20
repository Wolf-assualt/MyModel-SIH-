"""Tests for Model Ingestion, Cryptographic Identity, Inspectors, and API endpoints."""
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.crypto.canonical import hash_file
from app.main import app
from app.models_engine.registry import ModelRegistry
from app.schemas.model import ModelFormat

client = TestClient(app)


from app.models_engine.fixtures import generate_real_onnx_model


def create_dummy_model(path: Path, seed: int = 42):
    """Helper to create a reproducible real model file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    generate_real_onnx_model(path, seed=seed)


def test_model_identity_digest_generation(tmp_path):
    """Verify model file SHA-256 calculation and canonical identity digest generation."""
    model_file = tmp_path / "models" / "detector.onnx"
    create_dummy_model(model_file, seed=123)

    registry = ModelRegistry(base_dir=tmp_path / "model_store")
    manifest = registry.register_model(
        name="TacticalDetector",
        version="1.0.0",
        model_path=model_file,
        format=ModelFormat.ONNX,
    )

    assert manifest.name == "TacticalDetector"
    assert manifest.version == "1.0.0"
    assert manifest.binary_sha256 == hash_file(str(model_file))
    assert len(manifest.identity_digest) == 64
    assert manifest.parameter_count > 0
    assert len(manifest.inputs) >= 1
    assert len(manifest.outputs) >= 1
    assert (registry.manifests_dir / f"{manifest.model_id}.json").is_file()


def test_baseline_verification_success(tmp_path):
    """Verify model passes integrity verification against an identical reference baseline."""
    models_dir = tmp_path / "models"
    base_file = models_dir / "golden_baseline.onnx"
    cand_file = models_dir / "approved_candidate.onnx"

    create_dummy_model(base_file, seed=42)
    cand_file.write_bytes(base_file.read_bytes())

    registry = ModelRegistry(base_dir=tmp_path / "registry")

    # 1. Register reference baseline
    baseline = registry.register_model(
        name="BorderReconNet",
        version="2.0.0",
        model_path=base_file,
        format=ModelFormat.ONNX,
        is_reference=True,
    )
    assert (registry.baselines_dir / "BorderReconNet_2.0.0.json").is_file()

    # 2. Register candidate
    candidate = registry.register_model(
        name="BorderReconNet",
        version="2.0.0",
        model_path=cand_file,
        format=ModelFormat.ONNX,
        is_reference=False,
    )

    # 3. Verify
    verification = registry.verify_against_baseline(candidate.model_id)
    assert verification.is_valid is True
    assert verification.binary_match is True
    assert verification.structural_match is True
    assert verification.discrepancies == []


def test_baseline_verification_tampering_failure(tmp_path):
    """Verify model verification fails with descriptive discrepancies when weights are altered."""
    models_dir = tmp_path / "models"
    base_file = models_dir / "reference_model.onnx"
    tampered_file = models_dir / "backdoored_candidate.onnx"

    create_dummy_model(base_file, seed=42)
    create_dummy_model(tampered_file, seed=99)

    registry = ModelRegistry(base_dir=tmp_path / "registry")

    registry.register_model(
        name="TargetClassifier",
        version="1.5.0",
        model_path=base_file,
        format=ModelFormat.ONNX,
        is_reference=True,
    )

    candidate = registry.register_model(
        name="TargetClassifier",
        version="1.5.0",
        model_path=tampered_file,
        format=ModelFormat.ONNX,
        is_reference=False,
    )

    verification = registry.verify_against_baseline(candidate.model_id)
    assert verification.is_valid is False
    assert verification.binary_match is False
    assert len(verification.discrepancies) >= 1
    assert "Binary SHA-256 mismatch" in verification.discrepancies[0]


def test_api_models_endpoints(tmp_path):
    """Verify /api/v1/models/register, manifest retrieval, and verification endpoints."""
    model_file = tmp_path / "api_test_model.onnx"
    create_dummy_model(model_file, seed=42)

    # 1. Register reference baseline via API
    reg_payload = {
        "name": "NavalVesselDetector",
        "version": "1.0.0",
        "model_path": str(model_file),
        "format": "ONNX",
        "is_reference": True,
    }
    reg_resp = client.post("/api/v1/models/register", json=reg_payload)
    assert reg_resp.status_code == 200
    res_data = reg_resp.json()["data"]
    model_id = res_data["model_id"]
    assert res_data["name"] == "NavalVesselDetector"
    assert len(res_data["identity_digest"]) == 64

    # 2. Retrieve manifest
    get_resp = client.get(f"/api/v1/models/{model_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["model_id"] == model_id

    # 3. Verify against baseline
    verify_resp = client.post(f"/api/v1/models/{model_id}/verify")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()["data"]
    assert verify_data["is_valid"] is True
    assert verify_data["binary_match"] is True

    # 4. Error handling: non-existent model file
    bad_reg = client.post(
        "/api/v1/models/register",
        json={
            "name": "BadModel",
            "version": "1.0.0",
            "model_path": "/invalid/path/model.bin",
            "format": "GENERIC_BINARY",
        },
    )
    assert bad_reg.status_code == 400

    # 5. Error handling: non-existent model ID
    not_found_resp = client.get("/api/v1/models/non-existent-id")
    assert not_found_resp.status_code == 404
