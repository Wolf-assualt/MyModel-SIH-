"""Tests for Model Behavioural Fingerprinting, perturbation batteries, and comparative audits."""
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.fingerprint.battery import TestBatteryGenerator
from app.fingerprint.runner import BehaviouralFingerprinter, ModelExecutor
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.fingerprint import PerturbationType

client = TestClient(app)


def test_battery_probe_generation_determinism():
    """Verify probe image generation produces identical arrays with the same seed."""
    probes_a = TestBatteryGenerator.generate_probe_images(seed=123, count=4, size=(32, 32))
    probes_b = TestBatteryGenerator.generate_probe_images(seed=123, count=4, size=(32, 32))
    probes_diff = TestBatteryGenerator.generate_probe_images(seed=456, count=4, size=(32, 32))

    assert len(probes_a) == 4
    for a, b in zip(probes_a, probes_b):
        assert np.array_equal(a, b)
        assert a.shape == (32, 32, 3)
        assert a.dtype == np.uint8

    # Different seed yields different inputs
    assert not np.array_equal(probes_a[0], probes_diff[0])


def test_perturbation_transformations_invariants():
    """Verify all perturbation operators preserve (H, W, 3) shape and [0, 255] uint8 range."""
    rng = np.random.default_rng(42)
    sample_img = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)

    for p_type in PerturbationType:
        perturbed = TestBatteryGenerator.apply_perturbation(sample_img, p_type)
        assert perturbed.shape == (64, 64, 3)
        assert perturbed.dtype == np.uint8
        assert int(np.min(perturbed)) >= 0
        assert int(np.max(perturbed)) <= 255


def test_fingerprint_generation_reproducibility(tmp_path):
    """Verify identical models produce identical aggregate digests and perturbation results."""
    runner = BehaviouralFingerprinter(fingerprints_dir=tmp_path / "fps")

    fp1 = runner.fingerprint_model("tactical_yolo_v1", seed=42, count=6)
    fp2 = runner.fingerprint_model("tactical_yolo_v1", seed=42, count=6)

    assert fp1.model_id == "tactical_yolo_v1"
    assert fp1.battery_seed == 42
    assert fp1.aggregate_digest == fp2.aggregate_digest
    assert len(fp1.results) == len(PerturbationType)
    assert len(fp1.aggregate_digest) == 64


def test_fingerprint_comparison_identical_and_divergent(tmp_path):
    """Verify comparison returns 1.0 for identical models and flags divergence for altered models."""
    runner = BehaviouralFingerprinter(fingerprints_dir=tmp_path / "fps")

    ref_fp = runner.fingerprint_model("border_sentinel_gold", seed=42, count=8)
    cand_identical_fp = runner.fingerprint_model("border_sentinel_gold", seed=42, count=8)
    cand_mutated_fp = runner.fingerprint_model("backdoored_sentinel_trojan", seed=42, count=8)

    # 1. Identical model test
    comp_identical = runner.compare_fingerprints(cand_identical_fp, ref_fp)
    assert comp_identical.cosine_similarity == 1.0
    assert comp_identical.mean_squared_error == 0.0
    assert comp_identical.is_divergent is False
    assert comp_identical.status == AssetStatus.ACCEPTED

    # 2. Mutated/Trojan model test
    comp_mutated = runner.compare_fingerprints(cand_mutated_fp, ref_fp, divergence_threshold=0.95)
    assert comp_mutated.is_divergent is True
    assert comp_mutated.status == AssetStatus.QUARANTINED
    assert comp_mutated.cosine_similarity < 0.95
    assert comp_mutated.mean_squared_error > 0.0
    assert len(comp_mutated.details) == len(PerturbationType)


def test_api_fingerprint_endpoints():
    """Verify POST /api/v1/fingerprint/generate and /api/v1/fingerprint/compare REST endpoints."""
    # 1. Generate fingerprint
    gen_resp = client.post(
        "/api/v1/fingerprint/generate?model_id=drone_recon_v3&seed=100&count=4",
    )
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()["data"]
    assert gen_data["model_id"] == "drone_recon_v3"
    assert len(gen_data["aggregate_digest"]) == 64
    assert len(gen_data["results"]) == len(PerturbationType)

    # 2. Compare identical models via API
    comp_resp = client.post(
        "/api/v1/fingerprint/compare",
        json={
            "candidate_model_id": "drone_recon_v3",
            "reference_model_id": "drone_recon_v3",
            "battery_seed": 100,
            "battery_size": 4,
        },
    )
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()["data"]
    assert comp_data["cosine_similarity"] == 1.0
    assert comp_data["is_divergent"] is False
    assert comp_data["status"] == AssetStatus.ACCEPTED.value

    # 3. Compare divergent models via API
    comp_divergent = client.post(
        "/api/v1/fingerprint/compare",
        json={
            "candidate_model_id": "altered_recon_v3",
            "reference_model_id": "drone_recon_v3",
            "battery_seed": 100,
            "battery_size": 4,
        },
    )
    assert comp_divergent.status_code == 200
    div_data = comp_divergent.json()["data"]
    assert div_data["is_divergent"] is True
    assert div_data["status"] == AssetStatus.QUARANTINED.value
