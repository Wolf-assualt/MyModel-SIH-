"""Comprehensive Phase 9 Tests: Evidence Fusion, Risk Decision Engine, and Automatic Quarantine.

Validates the complete assurance decision layer according to Phase 9 specifications:
- Reliability-weighted multi-source fusion
- Hard-veto precedence (cryptographic failure, inference chain break, model substitution)
- Drift isolation rule (statistical drift alone never automatically triggers quarantine)
- Cross-domain corroborating threat correlations
- Subject & identity mismatch defense (prevent mixing evidence across unrelated models/datasets)
- Transparent forensic explanations without opaque trust scores
- Automatic and manual quarantine management (quarantine, audit, resolution)
- Evidence traceability back to source IDs and canonical SHA-256 digests
- Full REST API lifecycle and CLI subcommands
"""
import copy
import json
from pathlib import Path
from typing import List
import pytest
from fastapi.testclient import TestClient

from app.cli import main
from app.crypto.signer import KeyManager
from app.fusion.correlator import ThreatCorrelator
from app.fusion.engine import EvidenceFusionEngine
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceItem,
    EvidenceSource,
    EvidenceSourceDomain,
    FusedAssessment,
    QuarantineRecord,
)
from app.schemas.integrity import IntegritySeverity


@pytest.fixture
def clean_fusion_engine(tmp_path: Path):
    """Provides an isolated EvidenceFusionEngine with temporary storage and unique keypair."""
    km = KeyManager()
    storage_dir = tmp_path / "fusion_test"
    return EvidenceFusionEngine(storage_dir=storage_dir, key_manager=km)


# ==============================================================================
# 1. Single & Multiple Low-Risk Evidence Fusion
# ==============================================================================

def test_single_low_severity_evidence_accepted(clean_fusion_engine):
    """Verify single low-severity evidence produces LOW risk, ACCEPTED verdict, and ALLOW action."""
    item = EvidenceItem(
        evidence_id="ev_clean_01",
        source=EvidenceSource.DATA_INTEGRITY,
        severity=IntegritySeverity.LOW,
        metric_value=0.01,
        description="Dataset hash matches manifest.",
        subject_id="target_clean",
    )
    assessment = clean_fusion_engine.fuse("target_clean", [item])

    assert assessment.risk_level == AssuranceRiskLevel.LOW
    assert assessment.verdict == AssetStatus.ACCEPTED
    assert assessment.action == AssuranceAction.ALLOW
    assert assessment.hard_veto_triggered is False
    assert len(assessment.assessment_digest) == 64


def test_multiple_low_risk_evidence_aggregation(clean_fusion_engine):
    """Verify multiple independent low-risk evidence sources aggregate safely to ALLOW."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_data_clean",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.LOW,
            description="Dataset clean.",
        ),
        EvidenceItem(
            evidence_id="ev_model_clean",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.LOW,
            description="Model weights clean.",
        ),
        EvidenceItem(
            evidence_id="ev_dna_clean",
            source=EvidenceSource.INFERENCE_DNA,
            severity=IntegritySeverity.LOW,
            description="Inference sequence clean.",
        ),
    ]
    assessment = clean_fusion_engine.fuse("target_multi_clean", evidence)

    assert assessment.risk_level == AssuranceRiskLevel.LOW
    assert assessment.verdict == AssetStatus.ACCEPTED
    assert assessment.action == AssuranceAction.ALLOW
    assert assessment.coverage.coverage_ratio == 0.60


# ==============================================================================
# 2. Medium and High Evidence Aggregation
# ==============================================================================

def test_medium_and_high_evidence_aggregation(clean_fusion_engine):
    """Verify medium + high evidence produces elevated risk, UNDER_REVIEW verdict, and REVIEW action."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_drift_med",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            severity=IntegritySeverity.MEDIUM,
            metric_value=0.32,
            description="Operational environmental drift (low illumination).",
        ),
        EvidenceItem(
            evidence_id="ev_data_high",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.HIGH,
            metric_value=0.65,
            description="High label inconsistency rate in training partition.",
        ),
    ]
    assessment = clean_fusion_engine.fuse("target_elevated", evidence)

    assert assessment.risk_score >= 0.50
    assert assessment.verdict == AssetStatus.UNDER_REVIEW
    assert assessment.action == AssuranceAction.REVIEW
    assert assessment.hard_veto_triggered is False


# ==============================================================================
# 3. Hard Quarantine Veto Conditions
# ==============================================================================

def test_hard_cryptographic_veto_overrides_low_evidence(clean_fusion_engine):
    """Hard Veto: Forged signature forces QUARANTINED and BLOCK regardless of other clean layers."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_clean_1",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.LOW,
            description="Data clean.",
        ),
        EvidenceItem(
            evidence_id="ev_clean_2",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.LOW,
            description="Model clean.",
        ),
        EvidenceItem(
            evidence_id="ev_forged_sig",
            source=EvidenceSource.CRYPTO_VERIFICATION,
            severity=IntegritySeverity.CRITICAL,
            description="Invalid ECDSA signature: signature forgery detected.",
        ),
    ]
    assessment = clean_fusion_engine.fuse("target_crypto_fail", evidence)

    assert assessment.hard_veto_triggered is True
    assert assessment.risk_level == AssuranceRiskLevel.CRITICAL
    assert assessment.verdict == AssetStatus.QUARANTINED
    assert assessment.action == AssuranceAction.BLOCK
    assert any("Invalid or forged cryptographic signature" in r for r in assessment.veto_reasons)
    assert "ev_forged_sig" in assessment.decisive_evidence

    # Verify automatic quarantine was persisted
    quarantines = clean_fusion_engine.list_quarantines(active_only=True)
    assert any(q.subject_id == "target_crypto_fail" for q in quarantines)


def test_hard_broken_inference_chain_veto(clean_fusion_engine):
    """Hard Veto: Inference replay / sequence continuity break forces QUARANTINED and BLOCK."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_replay",
            source=EvidenceSource.INFERENCE_DNA,
            severity=IntegritySeverity.CRITICAL,
            description="Replay attack detected at sequence 4: duplicate nonce reused.",
        )
    ]
    assessment = clean_fusion_engine.fuse("target_replay", evidence)

    assert assessment.hard_veto_triggered is True
    assert assessment.verdict == AssetStatus.QUARANTINED
    assert assessment.action == AssuranceAction.BLOCK
    assert any("Inference provenance" in r for r in assessment.veto_reasons)


def test_hard_model_identity_mismatch_veto(clean_fusion_engine):
    """Hard Veto: Model weights mismatch forces QUARANTINED and BLOCK."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_model_tamper",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.CRITICAL,
            description="Model weights hash mismatch: unauthorized weight substitution.",
        )
    ]
    assessment = clean_fusion_engine.fuse("target_model_tampered", evidence)

    assert assessment.hard_veto_triggered is True
    assert assessment.verdict == AssetStatus.QUARANTINED
    assert assessment.action == AssuranceAction.BLOCK
    assert any("Model identity" in r for r in assessment.veto_reasons)


# ==============================================================================
# 4. Drift Isolation Principle
# ==============================================================================

def test_drift_alone_does_not_automatically_quarantine(clean_fusion_engine):
    """Principle: Severe statistical drift alone triggers UNDER_REVIEW / REVIEW, not automatic QUARANTINE."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_severe_drift",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            severity=IntegritySeverity.HIGH,
            metric_value=0.85,
            description="Critical distribution shift: severe weather / nighttime illumination.",
        )
    ]
    assessment = clean_fusion_engine.fuse("target_drift_only", evidence)

    assert assessment.hard_veto_triggered is False
    assert assessment.verdict == AssetStatus.UNDER_REVIEW
    assert assessment.action == AssuranceAction.REVIEW
    assert assessment.risk_level in [AssuranceRiskLevel.MEDIUM, AssuranceRiskLevel.HIGH]


# ==============================================================================
# 5. Cross-Domain Corroborating Signals
# ==============================================================================

def test_corroboration_drift_plus_behavioral_divergence(clean_fusion_engine):
    """Corroboration: Drift combined with behavioral probe divergence triggers coordinated alert."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_drift",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            severity=IntegritySeverity.HIGH,
            description="Severe distribution shift detected in input stream.",
        ),
        EvidenceItem(
            evidence_id="ev_behavior",
            source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            severity=IntegritySeverity.HIGH,
            description="Model probe output divergence across perturbation batteries.",
        ),
    ]
    assessment = clean_fusion_engine.fuse("target_drift_fp", evidence)
    assert any("Coordinated Evasion" in f for f in assessment.correlated_findings)


def test_corroboration_drift_plus_model_integrity_failure(clean_fusion_engine):
    """Corroboration: Drift combined with model integrity discrepancies."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_drift",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            severity=IntegritySeverity.HIGH,
            description="Operational drift observed.",
        ),
        EvidenceItem(
            evidence_id="ev_model_weight",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.HIGH,
            description="Model layer weight discrepancy detected.",
        ),
    ]
    assessment = clean_fusion_engine.fuse("target_drift_model", evidence)
    assert any("Input distribution anomalies accompany model weight integrity" in f for f in assessment.correlated_findings)


def test_corroboration_dataset_anomaly_plus_behavior_change(clean_fusion_engine):
    """Corroboration: Dataset backdoor triggers + model probe divergence."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_poison",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.HIGH,
            description="Trigger backdoor artifact pattern detected in training batch.",
        ),
        EvidenceItem(
            evidence_id="ev_div",
            source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            severity=IntegritySeverity.HIGH,
            description="Behavioral divergence under occlusion probes.",
        ),
    ]
    assessment = clean_fusion_engine.fuse("target_backdoor", evidence)
    assert any("Targeted Backdoor Poisoning Campaign" in f for f in assessment.correlated_findings)


# ==============================================================================
# 6. Subject & Identity Binding Mismatch Defense
# ==============================================================================

def test_subject_mismatch_model_id_rejected(clean_fusion_engine):
    """Adversarial: Submitting evidence belonging to conflicting model IDs is rejected."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_mod_a",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.LOW,
            related_model_id="approved_model_v1",
            description="Model A verified.",
        ),
        EvidenceItem(
            evidence_id="ev_mod_b",
            source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            severity=IntegritySeverity.LOW,
            related_model_id="unrelated_rogue_model_v2",
            description="Model B tested.",
        ),
    ]
    with pytest.raises(ValueError, match="Evidence subject mismatch: conflicting related_model_ids"):
        clean_fusion_engine.fuse("pipeline_mixed_models", evidence, strict_subject_binding=True)


def test_subject_mismatch_dataset_id_rejected(clean_fusion_engine):
    """Adversarial: Submitting evidence belonging to conflicting dataset IDs is rejected."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_ds_1",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.LOW,
            related_dataset_id="dataset_alpha",
            description="Dataset Alpha verified.",
        ),
        EvidenceItem(
            evidence_id="ev_ds_2",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.LOW,
            related_dataset_id="dataset_beta",
            description="Dataset Beta verified.",
        ),
    ]
    with pytest.raises(ValueError, match="Evidence subject mismatch: conflicting related_dataset_ids"):
        clean_fusion_engine.fuse("pipeline_mixed_datasets", evidence, strict_subject_binding=True)


# ==============================================================================
# 7. Reliability Weighting, Determinism & Edge Cases
# ==============================================================================

def test_deterministic_repeated_fusion(clean_fusion_engine):
    """Verify identical evidence inputs produce strictly identical digests and scores."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_det_01",
            source=EvidenceSource.DATA_INTEGRITY,
            severity=IntegritySeverity.LOW,
            description="Data clean.",
        ),
        EvidenceItem(
            evidence_id="ev_det_02",
            source=EvidenceSource.MODEL_IDENTITY,
            severity=IntegritySeverity.MEDIUM,
            description="Minor quantization variance.",
        ),
    ]
    a1 = clean_fusion_engine.fuse("target_det", evidence)
    a2 = clean_fusion_engine.fuse("target_det", evidence)

    assert a1.risk_score == a2.risk_score
    assert a1.verdict == a2.verdict
    assert a1.action == a2.action


def test_empty_evidence_set(clean_fusion_engine):
    """Verify empty evidence set produces low baseline risk, clean coverage, and ALLOW action."""
    assessment = clean_fusion_engine.fuse("target_empty", [])
    assert assessment.risk_score == 0.0
    assert assessment.verdict == AssetStatus.ACCEPTED
    assert assessment.action == AssuranceAction.ALLOW
    assert assessment.coverage.coverage_ratio == 0.0


def test_quarantine_lifecycle_and_resolution(clean_fusion_engine):
    """Verify manual quarantine, audit retrieval, and explicit resolution."""
    # 1. Quarantine entity
    rec = clean_fusion_engine.quarantine_entity(
        subject_id="compromised_node_42",
        reason="Suspected physical sensor tampering",
        evidence_ids=["ev_tamper_01"],
        subject_type="SENSOR_NODE",
    )
    assert rec.is_active is True
    assert rec.subject_id == "compromised_node_42"

    # 2. List active
    active = clean_fusion_engine.list_quarantines(active_only=True)
    assert any(q.quarantine_id == rec.quarantine_id for q in active)

    # 3. Resolve quarantine with forensic notes
    resolved = clean_fusion_engine.resolve_quarantine(
        quarantine_id=rec.quarantine_id,
        resolved_by="SecurityOfficer_Admin",
        resolution_notes="Hardware sensor inspected, recalibrated, and re-authenticated.",
    )
    assert resolved.is_active is False
    assert resolved.resolved_by == "SecurityOfficer_Admin"

    # 4. Check active list no longer includes resolved
    active_post = clean_fusion_engine.list_quarantines(active_only=True)
    assert not any(q.quarantine_id == rec.quarantine_id for q in active_post)


# ==============================================================================
# 8. REST API Endpoints End-to-End
# ==============================================================================

def test_rest_api_evidence_and_fusion_lifecycle(client: TestClient):
    """Verify API evidence registration, evaluation, assessment lookup, and quarantine resolution."""
    # 1. Submit evidence item via API
    ev_resp = client.post(
        "/api/v1/fusion/evidence",
        json={
            "evidence_id": "ev_api_dna_fail",
            "source": EvidenceSource.INFERENCE_DNA.value,
            "severity": IntegritySeverity.CRITICAL.value,
            "description": "Cryptographic hash chain broken at sequence 8.",
            "metric_value": 1.0,
            "confidence": 1.0,
        },
    )
    assert ev_resp.status_code == 200
    assert ev_resp.json()["data"]["evidence_id"] == "ev_api_dna_fail"

    # 2. Get evidence item
    get_ev = client.get("/api/v1/fusion/evidence/ev_api_dna_fail")
    assert get_ev.status_code == 200
    assert get_ev.json()["data"]["evidence_id"] == "ev_api_dna_fail"

    # 3. Evaluate fusion using registered evidence ID
    eval_resp = client.post(
        "/api/v1/fusion/evaluate",
        json={
            "target_entity_id": "pipeline_run_api_01",
            "evidence_ids": ["ev_api_dna_fail"],
        },
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()["data"]
    assert eval_data["hard_veto_triggered"] is True
    assert eval_data["verdict"] == AssetStatus.QUARANTINED.value
    assert eval_data["action"] == AssuranceAction.BLOCK.value

    # 4. Get assessment
    ass_id = eval_data["assessment_id"]
    get_ass = client.get(f"/api/v1/fusion/assessment/{ass_id}")
    assert get_ass.status_code == 200
    assert get_ass.json()["data"]["assessment_id"] == ass_id

    # 5. Quarantine API operations
    quar_list = client.get("/api/v1/fusion/quarantine")
    assert quar_list.status_code == 200
    quar_data = quar_list.json()["data"]
    assert len(quar_data) >= 1
    qid = quar_data[0]["quarantine_id"]

    res_resp = client.post(
        f"/api/v1/fusion/quarantine/{qid}/resolve",
        json={
            "resolved_by": "Commander_SOC",
            "resolution_notes": "Forensic hash chain audit cleared by human operator.",
        },
    )
    assert res_resp.status_code == 200
    assert res_resp.json()["data"]["is_active"] is False


# ==============================================================================
# 9. CLI Operations Integration
# ==============================================================================

def test_cli_evidence_and_fusion_commands(tmp_path: Path):
    """Verify submit-evidence, fuse-evidence, show-fusion, quarantine, and list-quarantine CLI commands."""
    # 1. Submit evidence CLI
    ret_ev = main([
        "submit-evidence",
        "--evidence-id", "cli_ev_01",
        "--source", "MODEL_IDENTITY",
        "--severity", "LOW",
        "--description", "Model weights authenticated against reference baseline.",
    ])
    assert ret_ev == 0

    # 2. Fuse evidence CLI
    ret_fuse = main([
        "fuse-evidence",
        "--target-id", "cli_pipeline_target",
        "--evidence-ids", "cli_ev_01",
    ])
    assert ret_fuse == 0

    # 3. Quarantine CLI
    ret_quar = main([
        "quarantine",
        "--subject-id", "cli_sensor_09",
        "--reason", "Optical cover blocked",
        "--type", "SENSOR_NODE",
    ])
    assert ret_quar == 0

    # 4. List quarantine CLI
    ret_list = main(["list-quarantine"])
    assert ret_list == 0
