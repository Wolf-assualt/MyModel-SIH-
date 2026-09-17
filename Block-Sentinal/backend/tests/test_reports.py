"""Unit and integration tests for Phase 11: Assurance Reports Engine."""
import copy
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.crypto.signer import KeyManager
from app.fusion.engine import default_fusion_engine
from app.main import app
from app.reports.engine import AssuranceReportEngine
from app.reports.formatter import ReportFormatter
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    EvidenceCoverage,
    EvidenceItem,
    EvidenceSource,
    FusedAssessment,
)
from app.schemas.integrity import IntegritySeverity
from app.schemas.report import ReportFormat


@pytest.fixture
def temp_report_engine(tmp_path: Path):
    """Provides an isolated AssuranceReportEngine instance using temporary storage."""
    return AssuranceReportEngine(storage_dir=tmp_path / "reports")


@pytest.fixture
def sample_assessment():
    """Generates a mock FusedAssessment with mixed findings."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_01",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.CRITICAL,
            metric_value=0.95,
            description="Synthetic backdoor trigger pattern confirmed in training batch.",
        ),
        EvidenceItem(
            evidence_id="ev_02",
            source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            severity=IntegritySeverity.HIGH,
            metric_value=0.55,
            description="Model output divergence detected on perturbation battery.",
        ),
        EvidenceItem(
            evidence_id="ev_03",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            severity=IntegritySeverity.MEDIUM,
            metric_value=0.35,
            description="Operational environmental illumination shift observed.",
        ),
    ]

    coverage = EvidenceCoverage(
        sources_checked=[
            EvidenceSource.DATA_INTEGRITY,
            EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            EvidenceSource.DISTRIBUTION_SHIFT,
        ],
        coverage_ratio=0.60,
        missing_sources=[
            EvidenceSource.MODEL_IDENTITY,
            EvidenceSource.INFERENCE_DNA,
        ],
    )

    return FusedAssessment(
        assessment_id="fused_test_12345",
        target_entity_id="yolov8_tactical_v1",
        risk_score=0.8850,
        confidence_score=0.5400,
        verdict=AssetStatus.QUARANTINED,
        coverage=coverage,
        correlated_findings=[
            "Correlated Targeted Backdoor Poisoning Campaign detected: Training data contains synthetic triggers."
        ],
        raw_evidence=evidence,
        assessment_digest="a" * 64,
        created_at=datetime.now(timezone.utc),
    )


def test_report_generation_from_assessment(temp_report_engine, sample_assessment):
    """Verify that AssuranceReport compiles finding summaries, digests, and signatures accurately."""
    km = KeyManager()
    report = temp_report_engine.generate_report(
        target_asset_id="yolov8_tactical_v1",
        target_asset_type="MODEL",
        assessment=sample_assessment,
        key_manager=km,
        include_limitations=True,
    )

    assert report.target_asset_id == "yolov8_tactical_v1"
    assert report.target_asset_type == "MODEL"
    assert report.overall_verdict == AssetStatus.QUARANTINED
    assert report.risk_score == pytest.approx(0.8850)
    assert report.findings_summary == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0}
    assert len(report.report_digest) == 64
    assert len(report.signature) > 0
    assert "BEGIN PUBLIC KEY" in report.signer_public_key_pem
    assert len(report.limitations_and_disclaimers) >= 2


def test_cryptographic_sealing_and_verification(temp_report_engine, sample_assessment):
    """Verify that an untampered report passes cryptographic audit cleanly."""
    report = temp_report_engine.generate_report(
        target_asset_id="yolov8_tactical_v1",
        target_asset_type="MODEL",
        assessment=sample_assessment,
    )

    verification = temp_report_engine.verify_report(report)
    assert verification.is_valid is True
    assert verification.digest_match is True
    assert verification.signature_valid is True
    assert len(verification.discrepancies) == 0


def test_tampering_detection(temp_report_engine, sample_assessment):
    """Verify that modifying report verdict or metrics trips the cryptographic digest check."""
    report = temp_report_engine.generate_report(
        target_asset_id="yolov8_tactical_v1",
        target_asset_type="MODEL",
        assessment=sample_assessment,
    )

    # 1. Tamper with overall verdict
    tampered_verdict = copy.deepcopy(report)
    tampered_verdict.overall_verdict = AssetStatus.ACCEPTED
    audit_verdict = temp_report_engine.verify_report(tampered_verdict)
    assert audit_verdict.is_valid is False
    assert audit_verdict.digest_match is False
    assert any("Report digest mismatch" in d for d in audit_verdict.discrepancies)

    # 2. Tamper with risk score
    tampered_risk = copy.deepcopy(report)
    tampered_risk.risk_score = 0.05
    audit_risk = temp_report_engine.verify_report(tampered_risk)
    assert audit_risk.is_valid is False
    assert audit_risk.digest_match is False


def test_signature_forgery_detection(temp_report_engine, sample_assessment):
    """Verify that signature modifications or key replacements fail signature verification."""
    report = temp_report_engine.generate_report(
        target_asset_id="yolov8_tactical_v1",
        target_asset_type="MODEL",
        assessment=sample_assessment,
    )

    # Mutate signature characters
    forged_report = copy.deepcopy(report)
    sig_list = list(forged_report.signature)
    sig_list[0] = "a" if sig_list[0] != "a" else "b"
    forged_report.signature = "".join(sig_list)

    audit = temp_report_engine.verify_report(forged_report)
    assert audit.is_valid is False
    assert audit.digest_match is True  # Digest itself is unchanged
    assert audit.signature_valid is False
    assert any("signature verification failed" in d for d in audit.discrepancies)


def test_markdown_formatting_structure(temp_report_engine, sample_assessment):
    """Verify that Markdown rendering conforms to defense classification and presentation standards."""
    report = temp_report_engine.generate_report(
        target_asset_id="yolov8_tactical_v1",
        target_asset_type="MODEL",
        assessment=sample_assessment,
    )

    md_output = ReportFormatter.format_markdown(report)

    assert "[RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT]" in md_output
    assert "### OPERATIONAL VERDICT: QUARANTINED" in md_output
    assert "## Threat & Integrity Metrics Matrix" in md_output
    assert "## Verified Findings Breakdown" in md_output
    assert "## Cryptographic Provenance Seal" in md_output
    assert "```pem" in md_output
    assert report.report_digest in md_output
    assert report.signature in md_output


def test_executive_summary_formatting(temp_report_engine, sample_assessment):
    """Verify plain-text commander executive situation briefing."""
    report = temp_report_engine.generate_report(
        target_asset_id="yolov8_tactical_v1",
        target_asset_type="MODEL",
        assessment=sample_assessment,
    )

    exec_output = ReportFormatter.format_executive_summary(report)

    assert "TRUST-CV EXECUTIVE SECURITY SITUATION BRIEF" in exec_output
    assert "OPERATIONAL VERDICT: QUARANTINED" in exec_output
    assert "CRITICAL: 1" in exec_output
    assert "HIGH: 1" in exec_output


def test_api_reports_endpoints(sample_assessment):
    """Verify full end-to-end API report generation, multi-format retrieval, and verification."""
    # Register the assessment in the default fusion engine so the reports endpoint can find it
    default_fusion_engine.assessments_dir.mkdir(parents=True, exist_ok=True)
    assessment_file = default_fusion_engine.assessments_dir / f"{sample_assessment.assessment_id}.json"
    import json
    with open(assessment_file, "w", encoding="utf-8") as f:
        json.dump(sample_assessment.model_dump(mode="json"), f, indent=2)

    client = TestClient(app)

    # 1. Test POST /api/v1/reports/generate
    gen_resp = client.post(
        "/api/v1/reports/generate",
        json={
            "target_asset_id": "yolov8_tactical_v1",
            "target_asset_type": "MODEL",
            "assessment_id": sample_assessment.assessment_id,
            "include_limitations": True,
        },
    )
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()
    assert gen_data["success"] is True
    report = gen_data["data"]
    report_id = report["report_id"]
    assert report["overall_verdict"] == AssetStatus.QUARANTINED.value

    # 2. Test GET /api/v1/reports/{report_id} as JSON
    get_json = client.get(f"/api/v1/reports/{report_id}?format=JSON_MANIFEST")
    assert get_json.status_code == 200
    assert get_json.json()["data"]["report_id"] == report_id

    # 3. Test GET /api/v1/reports/{report_id} as MARKDOWN
    get_md = client.get(f"/api/v1/reports/{report_id}?format=MARKDOWN")
    assert get_md.status_code == 200
    assert get_md.json()["data"]["format"] == "MARKDOWN"
    assert "[RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT]" in get_md.json()["data"]["content"]

    # 4. Test GET /api/v1/reports/{report_id} as EXECUTIVE_SUMMARY
    get_exec = client.get(f"/api/v1/reports/{report_id}?format=EXECUTIVE_SUMMARY")
    assert get_exec.status_code == 200
    assert get_exec.json()["data"]["format"] == "EXECUTIVE_SUMMARY"
    assert "TRUST-CV EXECUTIVE SECURITY SITUATION BRIEF" in get_exec.json()["data"]["content"]

    # 5. Test POST /api/v1/reports/verify
    verify_resp = client.post(
        "/api/v1/reports/verify",
        json={"report": report},
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["success"] is True
    assert verify_data["data"]["is_valid"] is True
    assert verify_data["data"]["digest_match"] is True
    assert verify_data["data"]["signature_valid"] is True
