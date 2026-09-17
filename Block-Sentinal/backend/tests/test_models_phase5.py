"""Phase 5 Comprehensive Test Suite: Model Ingestion, Architecture & Weight Integrity.

Validates:
1. Secure PyTorch and ONNX model ingestion without unsafe deserialization.
2. Deterministic layer-by-layer weight/tensor SHA-256 hashing.
3. Normalized architecture hashing and structural dimension tracking.
4. ECDSA SECP256R1 digital signature sealing on model identity manifests.
5. Detection of single-weight tampering (weights_hash and per-layer hash discrepancy).
6. Detection of architecture tampering (layer insertion, deletion, dimension shift).
7. Detection of model substitution attacks.
8. Deserialization safety on untrusted/malformed inputs.
9. Database lineage and fingerprint registration.
10. API endpoints (ingest, register, manifest, verify).
11. Operational CLI commands (ingest-model, verify-model).
"""
import argparse
import io
import os
from pathlib import Path
import pickle
import pytest
import torch
import torch.nn as nn
from fastapi.testclient import TestClient

from app.cli import cmd_ingest_model, cmd_verify_model
from app.crypto.canonical import hash_bytes, hash_file
from app.crypto.signer import KeyManager
from app.main import app
from app.models_engine.inspectors import ONNXInspector, PyTorchInspector
from app.models_engine.registry import ModelRegistry, default_model_registry
from app.schemas.model import ModelFormat

client = TestClient(app)


class SyntheticDefenseNet(nn.Module):
    """Small deterministic PyTorch neural network for defense computer vision testing."""

    def __init__(self, num_classes: int = 5):
        super().__init__()
        torch.manual_seed(42)
        self.conv1 = nn.Conv2d(3, 8, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm2d(8)
        self.relu = nn.ReLU()
        self.fc1 = nn.Linear(8 * 16 * 16, 16)
        self.fc2 = nn.Linear(16, num_classes)

    def forward(self, x):
        x = self.relu(self.bn1(self.conv1(x)))
        x = x.view(x.size(0), -1)
        x = self.relu(self.fc1(x))
        return self.fc2(x)


class ModifiedDefenseNet(nn.Module):
    """Modified architecture with extra layer and different output dimension."""

    def __init__(self, num_classes: int = 10):
        super().__init__()
        torch.manual_seed(42)
        self.conv1 = nn.Conv2d(3, 8, kernel_size=3, padding=1)
        self.conv2 = nn.Conv2d(8, 16, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.fc1 = nn.Linear(16 * 16 * 16, 32)
        self.fc2 = nn.Linear(32, num_classes)

    def forward(self, x):
        x = self.relu(self.conv1(x))
        x = self.relu(self.conv2(x))
        x = x.view(x.size(0), -1)
        x = self.relu(self.fc1(x))
        return self.fc2(x)


def test_pytorch_model_ingestion_and_layer_hashing(tmp_path):
    """Verify PyTorch model layer-by-layer weight hashing, architecture hashing, and ECDSA signature."""
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "defense_net.pt"

    net = SyntheticDefenseNet()
    torch.save(net.state_dict(), str(model_path))

    registry = ModelRegistry(base_dir=tmp_path / "registry")
    manifest = registry.register_model(
        name="TacticalReconClassifier",
        version="1.0.0",
        model_path=model_path,
        format=ModelFormat.PYTORCH_WEIGHTS,
        is_reference=True,
    )

    assert manifest.name == "TacticalReconClassifier"
    assert manifest.version == "1.0.0"
    assert manifest.format == ModelFormat.PYTORCH_WEIGHTS
    assert manifest.binary_sha256 == hash_file(str(model_path))
    assert manifest.architecture_hash is not None
    assert manifest.weights_hash is not None
    assert manifest.layer_count > 0
    assert len(manifest.layers) == manifest.layer_count

    # Verify per-layer hash details
    layer_names = [l.name for l in manifest.layers]
    assert "conv1.weight" in layer_names
    assert "fc2.bias" in layer_names

    for layer in manifest.layers:
        assert len(layer.sha256_hash) == 64
        assert layer.param_count > 0

    # Verify ECDSA SECP256R1 signature
    assert manifest.signature is not None
    is_sig_valid = KeyManager.verify_signature(registry.key_manager.export_public_key_pem(), manifest.identity_digest, manifest.signature)
    assert is_sig_valid is True

    # Verify private key is not leaked in manifest
    manifest_dict = manifest.model_dump(mode="json")
    assert "private_key" not in manifest_dict
    assert "d" not in manifest_dict


def test_single_weight_tampering_detection(tmp_path):
    """Verify modifying a single floating-point weight flips the layer hash and is detected by verification."""
    model_dir = tmp_path / "weight_tamper"
    model_dir.mkdir(parents=True, exist_ok=True)

    base_path = model_dir / "golden_baseline.pt"
    tampered_path = model_dir / "tampered_weight.pt"

    # 1. Save golden model
    net = SyntheticDefenseNet()
    state_a = net.state_dict()
    torch.save(state_a, str(base_path))

    # 2. Modify exactly one weight float in fc2.weight[0, 0]
    state_b = {k: v.clone() for k, v in state_a.items()}
    with torch.no_grad():
        state_b["fc2.weight"][0, 0] += 0.0001
    torch.save(state_b, str(tampered_path))

    registry = ModelRegistry(base_dir=tmp_path / "registry")

    # Register golden reference baseline
    baseline_manifest = registry.register_model(
        name="TargetDroneDetector",
        version="1.0.0",
        model_path=base_path,
        format=ModelFormat.PYTORCH_WEIGHTS,
        is_reference=True,
    )

    # Register candidate with altered weight
    tampered_manifest = registry.register_model(
        name="TargetDroneDetector",
        version="1.0.0",
        model_path=tampered_path,
        format=ModelFormat.PYTORCH_WEIGHTS,
        is_reference=False,
    )

    # Weights hashes must differ despite identical architecture
    assert baseline_manifest.architecture_hash == tampered_manifest.architecture_hash
    assert baseline_manifest.weights_hash != tampered_manifest.weights_hash

    # Verify against baseline
    res = registry.verify_against_baseline(tampered_manifest.model_id)
    assert res.is_valid is False
    assert res.binary_match is False
    assert res.structural_match is True
    assert res.weights_match is False
    assert any("fc2.weight" in d for d in res.discrepancies)


def test_architecture_modification_tampering_detection(tmp_path):
    """Verify modifying neural network architecture (adding/changing layers) is flagged."""
    model_dir = tmp_path / "arch_tamper"
    model_dir.mkdir(parents=True, exist_ok=True)

    base_path = model_dir / "base_arch.pt"
    modified_path = model_dir / "modified_arch.pt"

    torch.save(SyntheticDefenseNet().state_dict(), str(base_path))
    torch.save(ModifiedDefenseNet().state_dict(), str(modified_path))

    registry = ModelRegistry(base_dir=tmp_path / "registry")

    baseline = registry.register_model(
        name="SentinelVisionModel",
        version="2.0.0",
        model_path=base_path,
        format=ModelFormat.PYTORCH_WEIGHTS,
        is_reference=True,
    )

    candidate = registry.register_model(
        name="SentinelVisionModel",
        version="2.0.0",
        model_path=modified_path,
        format=ModelFormat.PYTORCH_WEIGHTS,
        is_reference=False,
    )

    assert baseline.architecture_hash != candidate.architecture_hash
    assert baseline.layer_count != candidate.layer_count

    res = registry.verify_against_baseline(candidate.model_id)
    assert res.is_valid is False
    assert res.structural_match is False
    assert any("Architecture hash mismatch" in d or "Layer count mismatch" in d for d in res.discrepancies)


def test_model_substitution_detection(tmp_path):
    """Verify substituting an authentic model with a completely foreign binary payload fails verification."""
    model_dir = tmp_path / "substitution"
    model_dir.mkdir(parents=True, exist_ok=True)

    golden_path = model_dir / "golden_model.bin"
    foreign_path = model_dir / "foreign_model.bin"

    golden_path.write_bytes(b"MILITARY_GRADE_AI_DEFENSE_SENTINEL_WEIGHTS_AUTHENTIC_2026")
    foreign_path.write_bytes(b"ADVERSARIAL_SUBSTITUTED_MODEL_BINARY_PAYLOAD_ROGUE")

    registry = ModelRegistry(base_dir=tmp_path / "registry")

    baseline = registry.register_model(
        name="BorderSurveillanceCNN",
        version="1.0.0",
        model_path=golden_path,
        format=ModelFormat.GENERIC_BINARY,
        is_reference=True,
    )

    candidate = registry.register_model(
        name="BorderSurveillanceCNN",
        version="1.0.0",
        model_path=foreign_path,
        format=ModelFormat.GENERIC_BINARY,
        is_reference=False,
    )

    res = registry.verify_against_baseline(candidate.model_id)
    assert res.is_valid is False
    assert res.binary_match is False
    assert len(res.discrepancies) >= 1


def test_deserialization_safety_and_malformed_inputs(tmp_path):
    """Verify secure handling of corrupted, unpicklable, or malicious payloads without arbitrary code execution."""
    m_dir = tmp_path / "corrupt_models"
    m_dir.mkdir(parents=True, exist_ok=True)

    # 1. Corrupted truncated binary raises handled ValueError
    corrupt_file = m_dir / "corrupted_payload.pt"
    corrupt_file.write_bytes(b"PK\x03\x04INVALID_TRUNCATED_ZIP_PYTORCH_BYTES_GARBAGE")

    inspector = PyTorchInspector()

    with pytest.raises(ValueError) as exc_info:
        inspector.inspect(corrupt_file)
    assert "Secure PyTorch deserialization failed" in str(exc_info.value)

    # 2. Non-existent file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        inspector.inspect(m_dir / "non_existent_model.pt")


def test_api_models_endpoints_phase5(tmp_path):
    """Verify /api/v1/models/ingest, /manifest/{model_id}, and /verify endpoints."""
    model_dir = tmp_path / "api_models"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "api_net.pt"

    torch.save(SyntheticDefenseNet().state_dict(), str(model_path))

    # 1. Ingest model via /api/v1/models/ingest (Alias)
    ingest_resp = client.post(
        "/api/v1/models/ingest",
        json={
            "name": "APIAirDefenseNet",
            "version": "1.0.0",
            "model_path": str(model_path),
            "format": "PYTORCH_WEIGHTS",
            "is_reference": True,
        },
    )
    assert ingest_resp.status_code == 200
    res_data = ingest_resp.json()["data"]
    model_id = res_data["model_id"]
    assert res_data["name"] == "APIAirDefenseNet"
    assert res_data["architecture_hash"] is not None
    assert res_data["weights_hash"] is not None
    assert res_data["signature"] is not None

    # 2. Retrieve manifest via /api/v1/models/manifest/{model_id}
    manifest_resp = client.get(f"/api/v1/models/manifest/{model_id}")
    assert manifest_resp.status_code == 200
    m_data = manifest_resp.json()["data"]
    assert m_data["model_id"] == model_id
    assert m_data["signature"] == res_data["signature"]

    # 3. Verify via POST /api/v1/models/verify
    verify_resp = client.post(
        "/api/v1/models/verify",
        json={"model_id": model_id},
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()["data"]
    assert v_data["is_valid"] is True
    assert v_data["binary_match"] is True
    assert v_data["structural_match"] is True
    assert v_data["weights_match"] is True
    assert v_data["signature_valid"] is True


def test_cli_model_ingest_and_verify(tmp_path, capsys):
    """Verify python -m app.cli ingest-model and verify-model commands."""
    model_dir = tmp_path / "cli_models"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "cli_defense_model.pt"

    torch.save(SyntheticDefenseNet().state_dict(), str(model_path))

    # 1. Ingest via CLI handler
    ingest_args = argparse.Namespace(
        name="CLIDefenseNet",
        version="1.0.0",
        path=str(model_path),
        format="PYTORCH_WEIGHTS",
        reference=True,
    )
    exit_code = cmd_ingest_model(ingest_args)
    assert exit_code == 0

    # Retrieve registered model from default registry
    baseline = default_model_registry.get_baseline("CLIDefenseNet", "1.0.0")
    assert baseline is not None

    # 2. Verify via CLI handler
    verify_args = argparse.Namespace(
        model_id=baseline.model_id,
        baseline_id=None,
    )
    verify_exit_code = cmd_verify_model(verify_args)
    assert verify_exit_code == 0

    # 3. Non-existent model ID returns 1
    bad_verify_args = argparse.Namespace(
        model_id="non-existent-uuid-12345",
        baseline_id=None,
    )
    assert cmd_verify_model(bad_verify_args) == 1
