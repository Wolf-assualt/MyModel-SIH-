"""Comprehensive Phase 8 Tests: Distribution Shift, Statistical Drift Metrics & Evidence Generation.

Validates the full offline distribution-shift assurance subsystem according to Phase 8 specifications:
- Mathematical verification of 4 statistical metrics: Wasserstein, KS (stat & p-val), PSI, Energy distance
- Numerical edge cases: zero-variance, flat constants, empty distributions, disjoint boundaries
- Deterministic feature extraction and summary statistics
- Cryptographically signed baseline profiles, canonical hashing, and signature integrity
- Defense against baseline tampering and baseline identity mismatch
- Single-feature drift isolation vs multi-feature severe shifts
- Four-tier severity calibration (NO_DRIFT, MILD_DRIFT, SIGNIFICANT_DRIFT, CRITICAL_SHIFT)
- Explainable diagnostic evidence without arbitrary ungrounded trust scores
- Structured evidence records generation for Phase 9 Evidence Fusion
- Complete REST API endpoints and CLI commands
"""
import copy
import json
from pathlib import Path
from typing import Dict, List
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.cli import main
from app.crypto.signer import KeyManager
from app.drift.engine import DistributionShiftEngine
from app.drift.extractor import ImageDistributionExtractor
from app.drift.stats import (
    compute_energy_distance,
    compute_ks_distance,
    compute_ks_p_value,
    compute_psi,
    wasserstein_distance_1d,
)
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.drift import (
    BaselineProfile,
    DistributionShiftReport,
    DriftSeverity,
    DriftType,
)


@pytest.fixture
def clean_drift_engine(tmp_path: Path):
    """Provides an isolated DistributionShiftEngine with fresh storage and dedicated keypair."""
    km = KeyManager()
    storage_dir = tmp_path / "drift_test"
    return DistributionShiftEngine(storage_dir=storage_dir, key_manager=km)


@pytest.fixture
def standard_baseline_features():
    """Generates a reproducible 100-sample reference feature distribution."""
    rng = np.random.default_rng(1337)
    return {
        "brightness": rng.normal(128.0, 12.0, size=100).tolist(),
        "contrast": rng.normal(48.0, 6.0, size=100).tolist(),
        "sharpness": rng.normal(90.0, 10.0, size=100).tolist(),
        "color_temperature": rng.normal(1.02, 0.04, size=100).tolist(),
        "channel_entropy": rng.normal(7.35, 0.15, size=100).tolist(),
    }


# ==============================================================================
# 1. Statistical Distance Metrics & Numerical Edge Cases
# ==============================================================================

def test_four_statistical_metrics_on_identical_distributions():
    """Verify all 4 metrics return zero / near-zero for identical empirical samples."""
    rng = np.random.default_rng(42)
    sample_a = rng.normal(100.0, 15.0, size=150)
    sample_b = np.copy(sample_a)

    ks_stat = compute_ks_distance(sample_a, sample_b)
    ks_pval = compute_ks_p_value(sample_a, sample_b, ks_stat)
    psi_val = compute_psi(sample_a, sample_b)
    wass_val = wasserstein_distance_1d(sample_a, sample_b)
    energy_val = compute_energy_distance(sample_a, sample_b)

    assert ks_stat == 0.0
    assert ks_pval == 1.0
    assert psi_val == 0.0
    assert wass_val == 0.0
    assert energy_val == 0.0


def test_four_statistical_metrics_on_disjoint_distributions():
    """Verify all 4 metrics flag extreme divergence for non-overlapping distributions."""
    u = np.linspace(10.0, 50.0, 100)
    v = np.linspace(150.0, 200.0, 100)

    ks_stat = compute_ks_distance(u, v)
    ks_pval = compute_ks_p_value(u, v, ks_stat)
    psi_val = compute_psi(u, v)
    wass_val = wasserstein_distance_1d(u, v)
    energy_val = compute_energy_distance(u, v)

    assert ks_stat == 1.0
    assert ks_pval < 1e-6
    assert psi_val > 0.8
    assert wass_val > 100.0
    assert energy_val > 100.0


def test_statistical_metrics_numerical_edge_cases():
    """Verify zero-variance, empty, and constant inputs behave safely without throwing exceptions."""
    empty_arr = np.array([], dtype=np.float64)
    flat_arr = np.full(50, 128.0, dtype=np.float64)
    flat_diff = np.full(50, 200.0, dtype=np.float64)

    # Empty inputs
    assert compute_ks_distance(empty_arr, flat_arr) == 0.0
    assert compute_ks_p_value(empty_arr, flat_arr, 0.0) == 1.0
    assert compute_psi(empty_arr, flat_arr) == 0.0
    assert wasserstein_distance_1d(empty_arr, flat_arr) == 0.0
    assert compute_energy_distance(empty_arr, flat_arr) == 0.0

    # Constant distributions (identical)
    assert compute_psi(flat_arr, flat_arr) == 0.0
    assert compute_energy_distance(flat_arr, flat_arr) == 0.0
    assert wasserstein_distance_1d(flat_arr, flat_arr) == 0.0

    # Constant distributions (different constant values)
    assert compute_ks_distance(flat_arr, flat_diff) == 1.0
    assert wasserstein_distance_1d(flat_arr, flat_diff) == pytest.approx(72.0, abs=1e-3)
    assert compute_energy_distance(flat_arr, flat_diff) == pytest.approx(144.0, abs=1e-3)


# ==============================================================================
# 2. Deterministic Feature Extraction & Summary Moments
# ==============================================================================

def test_image_feature_extraction_and_summary_moments():
    """Verify optical feature extractor and statistical moment calculations."""
    # Synthetic constant image
    img_flat = np.full((64, 64, 3), 100, dtype=np.uint8)
    feats = ImageDistributionExtractor.extract_image_features(img_flat)
    assert feats["brightness"] == 100.0
    assert feats["contrast"] == 0.0
    assert feats["sharpness"] == 0.0

    # Summary moments
    vals = [10.0, 20.0, 30.0, 40.0, 50.0]
    summary = ImageDistributionExtractor.compute_feature_summary(vals)
    assert summary.count == 5
    assert summary.mean == 30.0
    assert summary.min == 10.0
    assert summary.max == 50.0
    assert summary.median == 30.0


# ==============================================================================
# 3. Cryptographic Baseline Profile & Tamper Verification
# ==============================================================================

def test_baseline_profile_creation_signing_and_verification(clean_drift_engine, standard_baseline_features):
    """Verify baseline registration creates a signed profile with valid cryptographic digest."""
    profile = clean_drift_engine.register_baseline(
        baseline_id="approved_sat_base_01",
        name="Satellite Optical Baseline v1",
        features=standard_baseline_features,
        metadata={"region": "Northern Sector", "sensor": "EO-HighRes"},
    )

    assert profile.baseline_id == "approved_sat_base_01"
    assert profile.sample_count == 100
    assert len(profile.baseline_digest) == 64
    assert profile.signature is not None
    assert "brightness" in profile.feature_summaries

    # Verify integrity
    is_valid, discrepancies = clean_drift_engine.verify_baseline_integrity("approved_sat_base_01")
    assert is_valid is True
    assert len(discrepancies) == 0


def test_baseline_tamper_detection(clean_drift_engine, standard_baseline_features):
    """Adversarial: Modifying baseline JSON file trips cryptographic integrity verification."""
    profile = clean_drift_engine.register_baseline(
        baseline_id="tamper_target_base",
        features=standard_baseline_features,
    )

    # Tamper with stored baseline file on disk
    filepath = clean_drift_engine.baselines_dir / "tamper_target_base.json"
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Mutate feature values
    data["features"]["brightness"][0] = 999.0
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f)

    is_valid, discrepancies = clean_drift_engine.verify_baseline_integrity("tamper_target_base")
    assert is_valid is False
    assert any("Baseline digest mismatch" in d for d in discrepancies)


def test_baseline_identity_mismatch_rejection(clean_drift_engine, standard_baseline_features):
    """Adversarial: Evaluating drift against an unexpected baseline digest is rejected."""
    clean_drift_engine.register_baseline(
        baseline_id="base_alpha",
        features=standard_baseline_features,
    )

    # Attempt evaluate_shift with mismatched expected digest
    with pytest.raises(ValueError, match="Baseline identity mismatch"):
        clean_drift_engine.evaluate_shift(
            baseline_id="base_alpha",
            target_features=standard_baseline_features,
            expected_baseline_digest="0" * 64,
        )


# ==============================================================================
# 4. Drift Evaluation, Severity Calibration & Single-Feature Isolation
# ==============================================================================

def test_no_drift_evaluation(clean_drift_engine, standard_baseline_features):
    """Verify identical target batch yields NO_DRIFT severity and ACCEPTED status."""
    clean_drift_engine.register_baseline("base_normal", standard_baseline_features)

    report = clean_drift_engine.evaluate_shift(
        baseline_id="base_normal",
        target_features=standard_baseline_features,
        target_batch_id="batch_identical",
        threshold=0.25,
    )

    assert report.severity == DriftSeverity.NO_DRIFT
    assert report.detected_drift_type == DriftType.NO_DRIFT
    assert report.status == AssetStatus.ACCEPTED
    assert report.overall_drift_score <= 0.05
    assert len(report.affected_features) == 0
    assert len(report.evidence_records) == 0


def test_single_feature_drift_isolation(clean_drift_engine, standard_baseline_features):
    """Verify that only the drifted feature is flagged while untouched features stay stable."""
    clean_drift_engine.register_baseline("base_sensor", standard_baseline_features)

    target_features = {k: list(v) for k, v in standard_baseline_features.items()}
    # Defocus blur: only sharpness collapses, brightness/contrast/entropy unaffected
    target_features["sharpness"] = [12.0] * len(target_features["sharpness"])

    report = clean_drift_engine.evaluate_shift(
        baseline_id="base_sensor",
        target_features=target_features,
        target_batch_id="batch_defocused",
        threshold=0.25,
    )

    assert report.detected_drift_type == DriftType.SENSOR_DEGRADATION
    assert report.status == AssetStatus.UNDER_REVIEW
    assert "sharpness" in report.affected_features
    assert "brightness" not in report.affected_features
    assert "contrast" not in report.affected_features

    sharp_metric = next(m for m in report.feature_metrics if m.feature_name == "sharpness")
    assert sharp_metric.is_drifted is True
    assert "sharpness:" in sharp_metric.explanation
    assert "PSI=" in sharp_metric.explanation
    assert "Wasserstein=" in sharp_metric.explanation


def test_severe_adversarial_drift_and_quarantine(clean_drift_engine, standard_baseline_features):
    """Verify catastrophic entropy collapse and distortion triggers CRITICAL_SHIFT and QUARANTINED."""
    clean_drift_engine.register_baseline("base_adv", standard_baseline_features)

    target_features = {k: list(v) for k, v in standard_baseline_features.items()}
    # Extreme distortion across all dimensions
    target_features["brightness"] = [250.0] * 100
    target_features["contrast"] = [1.0] * 100
    target_features["channel_entropy"] = [0.5] * 100

    report = clean_drift_engine.evaluate_shift(
        baseline_id="base_adv",
        target_features=target_features,
        target_batch_id="batch_adversarial_tampered",
        threshold=0.25,
    )

    assert report.severity == DriftSeverity.CRITICAL_SHIFT
    assert report.detected_drift_type == DriftType.ADVERSARIAL_ANOMALY
    assert report.status == AssetStatus.QUARANTINED
    assert len(report.evidence_records) >= 3

    # Check structured evidence format for Phase 9 Evidence Fusion
    ev = report.evidence_records[0]
    assert "evidence_id" in ev
    assert ev["source"] == "DRIFT_ENGINE"
    assert ev["baseline_id"] == "base_adv"
    assert len(ev["baseline_digest"]) == 64
    assert ev["severity"] in ["CRITICAL", "HIGH"]


# ==============================================================================
# 5. REST API Endpoints End-to-End
# ==============================================================================

def test_api_drift_lifecycle_and_baselines(client: TestClient, standard_baseline_features):
    """Verify API registration, listing, retrieval, evaluation, and report fetching."""
    # 1. Register baseline via API
    reg_resp = client.post(
        "/api/v1/drift/baselines/register",
        json={
            "baseline_id": "api_patrol_base",
            "name": "Patrol Drone Optical Baseline",
            "features": standard_baseline_features,
            "metadata": {"altitude_m": 500, "camera": "Thermal-EO"},
            "sign_baseline": True,
        },
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["success"] is True
    profile = reg_data["data"]
    assert profile["baseline_id"] == "api_patrol_base"
    assert len(profile["baseline_digest"]) == 64

    # 2. List baselines
    list_resp = client.get("/api/v1/drift/baselines")
    assert list_resp.status_code == 200
    assert any(b["baseline_id"] == "api_patrol_base" for b in list_resp.json()["data"])

    # 3. Get single baseline
    get_resp = client.get("/api/v1/drift/baselines/api_patrol_base")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["baseline_id"] == "api_patrol_base"

    # 4. Evaluate shift via API
    eval_resp = client.post(
        "/api/v1/drift/evaluate",
        json={
            "baseline_id": "api_patrol_base",
            "target_batch_id": "api_candidate_batch_01",
            "drift_threshold": 0.25,
            "target_features": standard_baseline_features,
        },
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["success"] is True
    report = eval_data["data"]
    assert report["severity"] == DriftSeverity.NO_DRIFT.value
    assert report["status"] == AssetStatus.ACCEPTED.value

    # 5. Retrieve report by ID
    rep_id = report["report_id"]
    rep_resp = client.get(f"/api/v1/drift/reports/{rep_id}")
    assert rep_resp.status_code == 200
    assert rep_resp.json()["data"]["report_id"] == rep_id


# ==============================================================================
# 6. CLI Commands Integration
# ==============================================================================

def test_cli_create_baseline_and_analyze_drift(tmp_path: Path):
    """Verify create-drift-baseline and analyze-drift CLI subcommands."""
    # 1. Create synthetic baseline
    ret_create = main([
        "create-drift-baseline",
        "--baseline-id", "cli_test_baseline",
        "--name", "CLI Golden Baseline",
        "--sample-count", "30",
    ])
    assert ret_create == 0

    # 2. Analyze drift against registered baseline
    ret_eval = main([
        "analyze-drift",
        "--baseline-id", "cli_test_baseline",
        "--batch-id", "cli_batch_eval",
        "--threshold", "0.25",
    ])
    assert ret_eval == 0
