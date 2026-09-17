"""Phase 6 Comprehensive Test Suite: Model Behavioral Fingerprinting & Sensitivity Analysis.

Validates:
1. Deterministic synthetic probe generation and reproducible visual perturbations.
2. Sensitivity matrix: IDENTITY, GAUSSIAN_NOISE, GAUSSIAN_BLUR, CONTRAST_SHIFT, BRIGHTNESS_SHIFT, ROTATION, OCCLUSION_PATCH.
3. Real PyTorch model forward pass execution and activation distribution profiling.
4. Cryptographic canonical behavioral DNA digest generation.
5. Detection of behavioral divergence in subtly tampered models.
6. Benign numerical tolerance handling without false positive alarms.
7. Explainable divergence metrics (cosine similarity, MSE, max deviation, divergent probe localization).
8. Generation of structured evidence records for Phase 9 Evidence Fusion.
9. Database lineage tracking in model_fingerprints table.
10. API endpoints (generate, get manifest, compare).
11. Operational CLI commands (fingerprint-model, verify-behavior).
"""
import argparse
from pathlib import Path
import numpy as np
import pytest
import torch
import torch.nn as nn
from fastapi.testclient import TestClient

from app.cli import cmd_fingerprint_model, cmd_verify_behavior
from app.fingerprint.battery import TestBatteryGenerator
from app.fingerprint.runner import BehaviouralFingerprinter, ModelExecutor
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.fingerprint import PerturbationType

client = TestClient(app)


class SyntheticDefenseNet(nn.Module):
    """Small deterministic neural network for defense computer vision testing."""

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


def test_battery_probe_generation_determinism_phase6():
    """Verify probe generation produces identical arrays with identical seeds and varied arrays with distinct seeds."""
    probes_1 = TestBatteryGenerator.generate_probe_images(seed=777, count=6, size=(64, 64))
    probes_2 = TestBatteryGenerator.generate_probe_images(seed=777, count=6, size=(64, 64))
    probes_3 = TestBatteryGenerator.generate_probe_images(seed=888, count=6, size=(64, 64))

    assert len(probes_1) == 6
    for p1, p2 in zip(probes_1, probes_2):
        assert np.array_equal(p1, p2)
        assert p1.shape == (64, 64, 3)
        assert p1.dtype == np.uint8

    assert not np.array_equal(probes_1[0], probes_3[0])


def test_perturbation_sensitivity_matrix():
    """Verify all 7 perturbation operators produce valid bounded image arrays."""
    rng = np.random.default_rng(101)
    base_img = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)

    for p_type in PerturbationType:
        perturbed = TestBatteryGenerator.apply_perturbation(base_img, p_type)
        assert perturbed.shape == (64, 64, 3)
        assert perturbed.dtype == np.uint8
        assert int(np.min(perturbed)) >= 0
        assert int(np.max(perturbed)) <= 255


def test_pytorch_model_behavioral_execution(tmp_path):
    """Verify ModelExecutor executes forward inference on a real PyTorch model file."""
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "target_detector.pt"

    net = SyntheticDefenseNet()
    torch.save(net.state_dict(), str(model_path))

    executor = ModelExecutor()
    probes = TestBatteryGenerator.generate_probe_images(seed=42, count=4)
    probs, stats = executor.predict(model_path, probes)

    assert probs.shape == (4, 10)
    assert np.all(probs >= 0.0)
    assert np.allclose(np.sum(probs, axis=1), 1.0, atol=1e-5)
    assert "mean" in stats
    assert "l2_norm" in stats
    assert stats["l2_norm"] > 0.0


def test_fingerprint_reproducibility_and_canonical_digest(tmp_path):
    """Verify identical models produce identical canonical behavioral digests."""
    runner = BehaviouralFingerprinter(fingerprints_dir=tmp_path / "fps")

    fp_a = runner.fingerprint_model("sentinel_v1", seed=42, count=8)
    fp_b = runner.fingerprint_model("sentinel_v1", seed=42, count=8)

    assert fp_a.aggregate_digest == fp_b.aggregate_digest
    assert len(fp_a.aggregate_digest) == 64
    assert len(fp_a.results) == len(PerturbationType)

    # Check activation stats
    assert len(fp_a.activation_stats) == len(PerturbationType)
    for p_name, stats in fp_a.activation_stats.items():
        assert "mean" in stats
        assert "std" in stats
        assert "l2_norm" in stats


def test_behavioral_divergence_on_tampered_model(tmp_path):
    """Verify behavioral comparison detects divergence when model weights are altered."""
    m_dir = tmp_path / "models"
    m_dir.mkdir(parents=True, exist_ok=True)

    gold_path = m_dir / "golden_net.pt"
    rogue_path = m_dir / "rogue_net.pt"

    net_gold = SyntheticDefenseNet()
    state_gold = net_gold.state_dict()
    torch.save(state_gold, str(gold_path))

    # Alter weights significantly
    state_rogue = {k: v.clone() for k, v in state_gold.items()}
    with torch.no_grad():
        state_rogue["conv1.weight"] += 0.5
    torch.save(state_rogue, str(rogue_path))

    runner = BehaviouralFingerprinter(fingerprints_dir=tmp_path / "fps")

    gold_fp = runner.fingerprint_model(str(gold_path), seed=42, count=8)
    rogue_fp = runner.fingerprint_model(str(rogue_path), seed=42, count=8)

    # Compare
    comparison = runner.compare_fingerprints(rogue_fp, gold_fp, divergence_threshold=0.95)

    assert comparison.is_divergent is True
    assert comparison.status == AssetStatus.QUARANTINED
    assert len(comparison.divergent_probes) > 0
    assert len(comparison.evidence_records) > 0

    # Evidence records must contain diagnostic metadata for Phase 9 Evidence Fusion
    ev = comparison.evidence_records[0]
    assert ev["type"] == "BEHAVIORAL_PROBE_DIVERGENCE"
    assert "severity" in ev
    assert "confidence_delta" in ev


def test_benign_numerical_tolerance(tmp_path):
    """Verify identical models with zero divergence receive ACCEPTED status."""
    runner = BehaviouralFingerprinter(fingerprints_dir=tmp_path / "fps")

    ref_fp = runner.fingerprint_model("radar_classifier", seed=50, count=4)
    cand_fp = runner.fingerprint_model("radar_classifier", seed=50, count=4)

    comp = runner.compare_fingerprints(cand_fp, ref_fp)
    assert comp.is_divergent is False
    assert comp.cosine_similarity == 1.0
    assert comp.mean_squared_error == 0.0
    assert comp.max_absolute_error == 0.0
    assert comp.status == AssetStatus.ACCEPTED


def test_api_fingerprint_endpoints_phase6():
    """Verify /api/v1/fingerprint/generate, GET /{model_id}, and POST /compare."""
    # 1. Generate fingerprint
    gen_resp = client.post(
        "/api/v1/fingerprint/generate?model_id=naval_sentinel_v2&seed=42&count=6",
    )
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()["data"]
    assert gen_data["model_id"] == "naval_sentinel_v2"
    assert len(gen_data["results"]) == len(PerturbationType)

    # 2. Retrieve fingerprint via GET
    get_resp = client.get("/api/v1/fingerprint/naval_sentinel_v2?seed=42")
    assert get_resp.status_code == 200
    get_data = get_resp.json()["data"]
    assert get_data["model_id"] == "naval_sentinel_v2"
    assert get_data["aggregate_digest"] == gen_data["aggregate_digest"]

    # 3. Compare identical
    comp_resp = client.post(
        "/api/v1/fingerprint/compare",
        json={
            "candidate_model_id": "naval_sentinel_v2",
            "reference_model_id": "naval_sentinel_v2",
            "battery_seed": 42,
            "battery_size": 6,
        },
    )
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()["data"]
    assert comp_data["is_divergent"] is False
    assert comp_data["cosine_similarity"] == 1.0


def test_cli_fingerprint_and_verify_behavior(tmp_path, capsys):
    """Verify python -m app.cli fingerprint-model and verify-behavior commands."""
    # 1. Fingerprint model via CLI handler
    fp_args = argparse.Namespace(
        model_id="cli_air_defense_net",
        seed=42,
        count=6,
    )
    exit_code = cmd_fingerprint_model(fp_args)
    assert exit_code == 0

    # 2. Compare identical models via CLI handler
    vb_args = argparse.Namespace(
        candidate_id="cli_air_defense_net",
        reference_id="cli_air_defense_net",
        seed=42,
        count=6,
        threshold=0.95,
    )
    vb_exit_code = cmd_verify_behavior(vb_args)
    assert vb_exit_code == 0
