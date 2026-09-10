"""Unit and integration tests for Phase 9: Evidence Fusion Engine."""
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.fusion.correlator import ThreatCorrelator
from app.fusion.engine import EvidenceFusionEngine
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.fusion import EvidenceItem, EvidenceSource
from app.schemas.integrity import IntegritySeverity


@pytest.fixture
def temp_fusion_engine(tmp_path: Path):
    """Provides an isolated EvidenceFusionEngine instance using temporary directories."""
    return EvidenceFusionEngine(storage_dir=tmp_path / "fusion")


def test_clean_evidence_accepted(temp_fusion_engine):
    """Verify that benign/low-severity evidence produces low risk and ACCEPTED verdict."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_01",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.LOW,
            metric_value=0.01,
            description="All training samples verified against perceptual hash baseline.",
        ),
        EvidenceItem(
            evidence_id="ev_02",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.LOW,
            metric_value=0.0,
            description="Model identity digest matches reference baseline manifest.",
        ),
        EvidenceItem(
            evidence_id="ev_03",
            source=EvidenceSource.INFERENCE_DNA,
            severity=IntegritySeverity.LOW,
            metric_value=0.0,
            description="Inference DNA signature valid, sequence unbroken.",
        ),
    ]

    assessment = temp_fusion_engine.fuse("pipeline_run_clean", evidence)

    assert assessment.risk_score < 0.20
    assert assessment.verdict == AssetStatus.ACCEPTED
    assert len(assessment.assessment_digest) == 64
    assert assessment.coverage.coverage_ratio == 0.60


def test_critical_evidence_quarantined(temp_fusion_engine):
    """Verify that a single CRITICAL evidence item forces risk score >= 0.85 and QUARANTINED verdict."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_dna_tamper",
            source=EvidenceSource.INFERENCE_DNA,
            severity=IntegritySeverity.CRITICAL,
            metric_value=1.0,
            description="Cryptographic signature mismatch: telemetry tamper detected in transit.",
        )
    ]

    assessment = temp_fusion_engine.fuse("pipeline_run_critical", evidence)

    assert assessment.risk_score >= 0.85
    assert assessment.verdict == AssetStatus.QUARANTINED
    assert any("Cryptographic Provenance Failure" in f for f in assessment.correlated_findings)


def test_cross_layer_correlation_backdoor(temp_fusion_engine):
    """Verify cross-layer correlation detects targeted backdoor poisoning campaign."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_data_trig",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.HIGH,
            metric_value=0.92,
            description="Synthetic trigger backdoor patch detected on multiple training samples.",
        ),
        EvidenceItem(
            evidence_id="ev_model_fp",
            source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            severity=IntegritySeverity.HIGH,
            metric_value=0.45,
            description="Model behavioural divergence observed under probe battery test.",
        ),
    ]

    findings = ThreatCorrelator.correlate(evidence)
    assert any("Targeted Backdoor Poisoning Campaign" in f for f in findings)

    assessment = temp_fusion_engine.fuse("backdoor_test_target", evidence)
    assert any("Backdoor Poisoning Campaign" in f for f in assessment.correlated_findings)


def test_cross_layer_correlation_model_substitution(temp_fusion_engine):
    """Verify correlation detects unauthorized model substitution and telemetry tampering."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_dna",
            source=EvidenceSource.INFERENCE_DNA,
            severity=IntegritySeverity.CRITICAL,
            metric_value=1.0,
            description="Inference DNA tamper detected in hash chain verification.",
        ),
        EvidenceItem(
            evidence_id="ev_model_id",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.CRITICAL,
            metric_value=1.0,
            description="Model identity digest mismatch against reference baseline.",
        ),
    ]

    assessment = temp_fusion_engine.fuse("sub_target", evidence)
    assert any("Unauthorized Model Substitution" in f for f in assessment.correlated_findings)
    assert assessment.verdict == AssetStatus.QUARANTINED


def test_cross_layer_correlation_adversarial_evasion(temp_fusion_engine):
    """Verify correlation detects coordinated adversarial perturbation and evasion attacks."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_drift_adv",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            severity=IntegritySeverity.HIGH,
            metric_value=0.88,
            description="Adversarial anomaly detected with severe entropy collapse.",
        ),
        EvidenceItem(
            evidence_id="ev_fp_drift",
            source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            severity=IntegritySeverity.HIGH,
            metric_value=0.52,
            description="Model output divergence observed under perturbation test.",
        ),
    ]

    assessment = temp_fusion_engine.fuse("adv_target", evidence)
    assert any("Adversarial Perturbation Attack" in f for f in assessment.correlated_findings)


def test_cross_layer_correlation_benign_environmental(temp_fusion_engine):
    """Verify benign environmental drift is identified when other layers remain secure."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_env",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            severity=IntegritySeverity.MEDIUM,
            metric_value=0.32,
            description="Operational environmental shift observed due to low illumination at dusk.",
        ),
        EvidenceItem(
            evidence_id="ev_model_clean",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.LOW,
            metric_value=0.0,
            description="Model weights verified against baseline.",
        ),
    ]

    assessment = temp_fusion_engine.fuse("env_target", evidence)
    assert any("Benign Operational Environmental Drift" in f for f in assessment.correlated_findings)
    assert assessment.verdict == AssetStatus.UNDER_REVIEW


def test_evidence_coverage_calculation(temp_fusion_engine):
    """Verify coverage ratio, checked sources, and missing sources accounting."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_01",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.LOW,
            metric_value=0.0,
            description="Data integrity clean.",
        ),
        EvidenceItem(
            evidence_id="ev_02",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.LOW,
            metric_value=0.0,
            description="Model identity clean.",
        ),
    ]

    assessment = temp_fusion_engine.fuse("coverage_target", evidence)
    assert assessment.coverage.coverage_ratio == 0.40
    assert len(assessment.coverage.sources_checked) == 2
    assert len(assessment.coverage.missing_sources) == 3
    assert EvidenceSource.INFERENCE_DNA in assessment.coverage.missing_sources


def test_api_fusion_endpoints():
    """Verify full end-to-end API evaluate and retrieval endpoints via TestClient."""
    client = TestClient(app)

    items = [
        {
            "evidence_id": "ev_api_01",
            "source": EvidenceSource.DATA_INTEGRITY.value,
            "severity": IntegritySeverity.LOW.value,
            "metric_value": 0.05,
            "description": "Perceptual hashing integrity verified.",
            "metadata": {},
        },
        {
            "evidence_id": "ev_api_02",
            "source": EvidenceSource.INFERENCE_DNA.value,
            "severity": IntegritySeverity.CRITICAL.value,
            "metric_value": 1.0,
            "description": "Signature forgery detected in telemetry receipt.",
            "metadata": {},
        },
    ]

    # 1. Post evaluation
    eval_resp = client.post(
        "/api/v1/fusion/evaluate",
        json={"target_entity_id": "pipeline_run_99", "evidence_items": items},
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["success"] is True

    assessment = eval_data["data"]
    assessment_id = assessment["assessment_id"]
    assert assessment["verdict"] == AssetStatus.QUARANTINED.value
    assert assessment["risk_score"] >= 0.85

    # 2. Retrieve assessment
    get_resp = client.get(f"/api/v1/fusion/assessment/{assessment_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["data"]["assessment_id"] == assessment_id
