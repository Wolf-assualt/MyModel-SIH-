"""Unit and integration tests for Phase 8: Distribution-Shift Engine."""
from pathlib import Path
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.drift.engine import DistributionShiftEngine
from app.drift.extractor import ImageDistributionExtractor
from app.drift.stats import (
    compute_ks_distance,
    compute_psi,
    wasserstein_distance_1d,
)
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.drift import DriftType


@pytest.fixture
def temp_drift_engine(tmp_path: Path):
    """Provides an isolated DistributionShiftEngine instance using temporary directories."""
    return DistributionShiftEngine(storage_dir=tmp_path / "drift")


@pytest.fixture
def reference_features():
    """Generates standard baseline feature distribution vectors."""
    rng = np.random.default_rng(42)
    return {
        "brightness": rng.normal(128.0, 10.0, size=50).tolist(),
        "contrast": rng.normal(45.0, 5.0, size=50).tolist(),
        "sharpness": rng.normal(85.0, 8.0, size=50).tolist(),
        "color_temperature": rng.normal(1.05, 0.05, size=50).tolist(),
        "channel_entropy": rng.normal(7.2, 0.2, size=50).tolist(),
    }


def test_statistical_distances_identical_vs_disjoint():
    """Verify KS distance, PSI, and Wasserstein metrics on identical vs separated data."""
    u = np.linspace(10.0, 100.0, 100)
    v_identical = np.linspace(10.0, 100.0, 100)
    v_disjoint = np.linspace(200.0, 300.0, 100)

    # Identical distributions
    assert compute_ks_distance(u, v_identical) == 0.0
    assert compute_psi(u, v_identical) < 0.001
    assert wasserstein_distance_1d(u, v_identical) == 0.0

    # Disjoint distributions
    assert compute_ks_distance(u, v_disjoint) == 1.0
    assert compute_psi(u, v_disjoint) > 0.8
    assert wasserstein_distance_1d(u, v_disjoint) > 100.0


def test_image_distribution_feature_extraction():
    """Verify ImageDistributionExtractor extracts radiometric and sharpness statistics accurately."""
    # 1. Flat constant image: zero contrast and sharpness
    flat_img = np.full((64, 64, 3), 120, dtype=np.uint8)
    flat_features = ImageDistributionExtractor.extract_image_features(flat_img)

    assert flat_features["brightness"] == 120.0
    assert flat_features["contrast"] == 0.0
    assert flat_features["sharpness"] == 0.0
    assert flat_features["color_temperature"] == pytest.approx(1.0, abs=0.01)

    # 2. Random synthetic pattern: non-zero variance and entropy
    rng = np.random.default_rng(42)
    textured_img = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    textured_features = ImageDistributionExtractor.extract_image_features(textured_img)

    assert textured_features["contrast"] > 20.0
    assert textured_features["sharpness"] > 0.0
    assert textured_features["channel_entropy"] > 6.0

    # 3. Batch extraction
    batch = [flat_img, textured_img]
    batch_dist = ImageDistributionExtractor.extract_batch_distributions(batch)
    assert len(batch_dist["brightness"]) == 2
    assert isinstance(batch_dist["brightness"], np.ndarray)


def test_no_drift_evaluation(temp_drift_engine, reference_features):
    """Verify identical target distributions produce NO_DRIFT and ACCEPTED status."""
    temp_drift_engine.register_baseline("cctv_alpha", reference_features)

    # Target is identical to baseline
    report = temp_drift_engine.evaluate_shift(
        baseline_id="cctv_alpha",
        target_features=reference_features,
        target_batch_id="batch_live_01",
        threshold=0.25,
    )

    assert report.overall_drift_score <= 0.05
    assert report.detected_drift_type == DriftType.NO_DRIFT
    assert report.status == AssetStatus.ACCEPTED
    assert len(report.report_digest) == 64
    assert all(not m.is_drifted for m in report.feature_metrics)


def test_sensor_degradation_shift(temp_drift_engine, reference_features):
    """Verify optical blur affecting only sharpness flags SENSOR_DEGRADATION and UNDER_REVIEW."""
    temp_drift_engine.register_baseline("cctv_alpha", reference_features)

    target_features = {k: list(v) for k, v in reference_features.items()}
    # Drastic drop in sharpness simulating blur / defocus, others remain steady
    target_features["sharpness"] = [10.0] * len(target_features["sharpness"])

    report = temp_drift_engine.evaluate_shift(
        baseline_id="cctv_alpha",
        target_features=target_features,
        target_batch_id="batch_defocus_02",
        threshold=0.25,
    )

    assert report.detected_drift_type == DriftType.SENSOR_DEGRADATION
    assert report.status == AssetStatus.UNDER_REVIEW
    sharpness_metric = next(m for m in report.feature_metrics if m.feature_name == "sharpness")
    assert sharpness_metric.is_drifted is True


def test_operational_environmental_shift(temp_drift_engine, reference_features):
    """Verify illumination changes trigger OPERATIONAL_ENVIRONMENTAL and UNDER_REVIEW."""
    temp_drift_engine.register_baseline("cctv_alpha", reference_features)

    target_features = {k: list(v) for k, v in reference_features.items()}
    # Shifts in brightness and contrast simulating dusk/low-light
    target_features["brightness"] = [v - 40.0 for v in target_features["brightness"]]
    target_features["contrast"] = [v - 20.0 for v in target_features["contrast"]]

    report = temp_drift_engine.evaluate_shift(
        baseline_id="cctv_alpha",
        target_features=target_features,
        target_batch_id="batch_dusk_03",
        threshold=0.25,
    )

    assert report.detected_drift_type == DriftType.OPERATIONAL_ENVIRONMENTAL
    assert report.status == AssetStatus.UNDER_REVIEW


def test_adversarial_anomaly_quarantine(temp_drift_engine, reference_features):
    """Verify extreme distribution distortion or entropy collapse triggers ADVERSARIAL_ANOMALY and QUARANTINED."""
    temp_drift_engine.register_baseline("cctv_alpha", reference_features)

    target_features = {k: list(v) for k, v in reference_features.items()}
    # Severe perturbation across entropy and all distribution dimensions
    target_features["channel_entropy"] = [1.2] * len(target_features["channel_entropy"])
    target_features["brightness"] = [250.0] * len(target_features["brightness"])
    target_features["contrast"] = [1.0] * len(target_features["contrast"])

    report = temp_drift_engine.evaluate_shift(
        baseline_id="cctv_alpha",
        target_features=target_features,
        target_batch_id="batch_attack_04",
        threshold=0.25,
    )

    assert report.detected_drift_type == DriftType.ADVERSARIAL_ANOMALY
    assert report.status == AssetStatus.QUARANTINED
    assert report.overall_drift_score > 0.5


def test_api_drift_endpoints(reference_features):
    """Verify full end-to-end API baseline registration, evaluation, and report retrieval."""
    client = TestClient(app)

    # 1. Register baseline
    reg_resp = client.post(
        "/api/v1/drift/baselines/register",
        json={
            "baseline_id": "sensor_tower_07",
            "features": reference_features,
            "metadata": {"location": "Sector 4", "resolution": "1080p"},
        },
    )
    assert reg_resp.status_code == 200
    assert reg_resp.json()["success"] is True
    assert reg_resp.json()["data"]["baseline_id"] == "sensor_tower_07"

    # 2. Evaluate distribution shift
    eval_resp = client.post(
        "/api/v1/drift/evaluate",
        json={
            "baseline_id": "sensor_tower_07",
            "target_batch_id": "batch_recon_09",
            "drift_threshold": 0.25,
            "target_features": reference_features,
        },
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["success"] is True
    report = eval_data["data"]
    assert report["detected_drift_type"] == DriftType.NO_DRIFT.value
    assert report["status"] == AssetStatus.ACCEPTED.value

    # 3. Retrieve report by ID
    report_id = report["report_id"]
    get_resp = client.get(f"/api/v1/drift/reports/{report_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["report_id"] == report_id
