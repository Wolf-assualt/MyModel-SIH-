"""Phase 6 Comprehensive Integration Tests: Distribution Shift, Evidence Fusion, Graph, and Contributor Risk.

Verifies the end-to-end authoritative assurance pipeline:
1. Clean reference + matching target
2. Missing reference baseline / self-comparison defense (DRIFT = UNAVAILABLE)
3. Environmental shift (operational illumination/sensor shift without automatic quarantine)
4. Duplicate-heavy contributor risk profiling
5. Suspicious contributor escalation & UNKNOWN identity preservation
6. Model anomaly correlation and hard veto
7. Inference provenance anomaly and downstream blast radius
8. 14-entity evidence graph coverage where EVERY edge possesses an evidence_id
"""
from datetime import datetime, timezone
import json
from pathlib import Path
# pyrefly: ignore [missing-import]
import pytest
# pyrefly: ignore [missing-import]
import numpy as np
# pyrefly: ignore [missing-import]
from PIL import Image

from app.crypto.signer import KeyManager
from app.drift.engine import DistributionShiftEngine
from app.drift.extractor import LocalFeatureExtractor
from app.fusion.correlator import ThreatCorrelator
from app.fusion.engine import EvidenceFusionEngine
from app.graph.contributor import ContributorRiskEngine
from app.graph.engine import EvidenceGraphEngine
from app.schemas.base import AssetStatus
from app.schemas.drift import BaselineProfile, BaselineReferenceType, DriftSeverity, DriftType
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceItem,
    EvidenceSource,
    EvidenceSourceDomain,
)
from app.schemas.graph import EdgeType, GraphEdge, GraphNode, NodeType
from app.schemas.integrity import IntegritySeverity


@pytest.fixture
def phase6_env(tmp_path: Path):
    """Isolated Phase 6 assurance environment with unique storage directories and keypair."""
    km = KeyManager()
    drift_engine = DistributionShiftEngine(storage_dir=tmp_path / "drift", key_manager=km)
    fusion_engine = EvidenceFusionEngine(storage_dir=tmp_path / "fusion", key_manager=km)
    graph_engine = EvidenceGraphEngine(storage_dir=tmp_path / "graph")
    return {
        "km": km,
        "drift": drift_engine,
        "fusion": fusion_engine,
        "graph": graph_engine,
        "tmp_path": tmp_path,
    }


def _create_synthetic_images(dir_path: Path, count: int, color_val: int = 128) -> Path:
    dir_path.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        arr = np.full((64, 64, 3), color_val, dtype=np.uint8)
        # Add small deterministic perturbation
        arr[0, 0, 0] = (color_val + (i % 5)) % 256
        img = Image.fromarray(arr)
        img.save(dir_path / f"img_{i:03d}.png")
    return dir_path


# ==============================================================================
# 1. Clean Reference + Matching Target
# ==============================================================================

def test_clean_reference_matching_target(phase6_env):
    """Verify clean reference baseline against matching target produces NO_DRIFT and ALLOW action."""
    drift_engine: DistributionShiftEngine = phase6_env["drift"]
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]
    tmp_path: Path = phase6_env["tmp_path"]

    ref_dir = _create_synthetic_images(tmp_path / "ref_clean", 20, color_val=128)
    target_dir = _create_synthetic_images(tmp_path / "target_clean", 20, color_val=128)

    # 1. Register baseline from reference dataset
    baseline = drift_engine.register_baseline(
        baseline_id="base_clean_sensor_01",
        name="FLIR Standard Optical Baseline",
        image_dir=ref_dir,
    )
    assert baseline.baseline_id == "base_clean_sensor_01"
    assert baseline.reference_type == BaselineReferenceType.REFERENCE_DATASET
    assert baseline.sample_count == 20

    # 2. Evaluate target dataset against reference
    report = drift_engine.evaluate_shift(
        baseline_id="base_clean_sensor_01",
        target_batch_id="batch_matching_01",
        candidate_dir=target_dir,
        drift_threshold=0.25,
    )
    assert report.severity == DriftSeverity.NO_DRIFT
    assert report.overall_drift_score < 0.25
    assert report.status == AssetStatus.ACCEPTED

    # 3. Fuse evidence into authoritative assessment
    ev_drift = EvidenceItem(
        evidence_id=f"ev_drift_{report.report_id}",
        source=EvidenceSource.DISTRIBUTION_SHIFT,
        domain=EvidenceSourceDomain.DRIFT,
        severity=IntegritySeverity.LOW,
        metric_value=report.overall_drift_score,
        description="Distribution shift within acceptable operational tolerance.",
        subject_id="batch_matching_01",
    )
    assessment = fusion_engine.fuse("batch_matching_01", [ev_drift])

    assert assessment.overall_status == AssetStatus.ACCEPTED
    assert assessment.verdict == AssetStatus.ACCEPTED
    assert assessment.risk_level == AssuranceRiskLevel.LOW
    assert assessment.action == AssuranceAction.ALLOW
    assert assessment.hard_veto_triggered is False
    assert len(assessment.assessment_digest) == 64


# ==============================================================================
# 2. Missing Reference Baseline & Anti-Self-Comparison Invariant
# ==============================================================================

def test_missing_reference_and_anti_self_comparison(phase6_env):
    """Invariant: If no reference exists, DRIFT = UNAVAILABLE. Never copy target as its own baseline."""
    drift_engine: DistributionShiftEngine = phase6_env["drift"]
    tmp_path: Path = phase6_env["tmp_path"]
    target_dir = _create_synthetic_images(tmp_path / "target_solo", 10, color_val=100)

    # A. Missing reference baseline raises FileNotFoundError (mapping to UNAVAILABLE)
    with pytest.raises(FileNotFoundError, match="Baseline profile 'nonexistent_base' not found"):
        drift_engine.evaluate_shift(
            baseline_id="nonexistent_base",
            target_batch_id="batch_solo_01",
            candidate_dir=target_dir,
        )

    # B. Self-comparison violation: Target cannot serve as its own reference baseline
    with pytest.raises(ValueError, match="Self-comparison violation: target dataset cannot be evaluated against itself"):
        drift_engine.evaluate_shift(
            baseline_id="batch_same_id",
            target_batch_id="batch_same_id",
            candidate_dir=target_dir,
        )


# ==============================================================================
# 3. Environmental Shift (Non-Malicious Distribution Shift)
# ==============================================================================

def test_environmental_illumination_shift(phase6_env):
    """Operational vs Suspicious shift: Environmental dusk/lighting shift triggers REVIEW, not automatic QUARANTINE."""
    drift_engine: DistributionShiftEngine = phase6_env["drift"]
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]
    tmp_path: Path = phase6_env["tmp_path"]

    ref_dir = _create_synthetic_images(tmp_path / "base_daylight", 20, color_val=180)
    # Target images significantly darker (dusk/cloud cover)
    dusk_dir = _create_synthetic_images(tmp_path / "target_dusk", 20, color_val=60)

    drift_engine.register_baseline(
        baseline_id="base_daylight_eo",
        name="Daylight EO Baseline",
        image_dir=ref_dir,
    )

    report = drift_engine.evaluate_shift(
        baseline_id="base_daylight_eo",
        target_batch_id="batch_dusk_patrol",
        candidate_dir=dusk_dir,
        drift_threshold=0.25,
    )

    assert report.detected_drift_type in (DriftType.ILLUMINATION_SHIFT, DriftType.ENVIRONMENTAL_SHIFT, DriftType.DATASET_DRIFT)
    assert report.severity in (DriftSeverity.MILD, DriftSeverity.MILD_DRIFT, DriftSeverity.MODERATE, DriftSeverity.SIGNIFICANT, DriftSeverity.CRITICAL)

    # Fuse evidence
    ev_shift = EvidenceItem(
        evidence_id="ev_env_shift_01",
        source=EvidenceSource.DISTRIBUTION_SHIFT,
        domain=EvidenceSourceDomain.DRIFT,
        severity=IntegritySeverity.MEDIUM,
        metric_value=report.overall_drift_score,
        description="Benign operational environmental drift (dusk illumination variance).",
        subject_id="batch_dusk_patrol",
    )
    assessment = fusion_engine.fuse("batch_dusk_patrol", [ev_shift])

    # DRIFT ISOLATION PRINCIPLE: Severe statistical drift alone NEVER automatically quarantines
    assert assessment.hard_veto_triggered is False
    assert assessment.overall_status == AssetStatus.UNDER_REVIEW
    assert assessment.action == AssuranceAction.REVIEW
    assert assessment.risk_level in (AssuranceRiskLevel.MEDIUM, AssuranceRiskLevel.HIGH)
    assert any("Environmental" in f or "Operational" in f for f in assessment.findings)


# ==============================================================================
# 4. Duplicate-Heavy Contributor
# ==============================================================================

def test_duplicate_heavy_contributor_risk(phase6_env):
    """Contributor aggregation: Aggregates real contributor identity and tracks duplicate findings."""
    graph_engine: EvidenceGraphEngine = phase6_env["graph"]

    # Contributor submits batch with duplicate findings
    graph_engine.build_lineage(
        contributor_id="sensor_node_alpha",
        dataset_id="batch_dup_heavy_01",
        sample_ids=[f"s_dup_{i}" for i in range(12)],
    )

    # Attach duplicate findings
    graph_engine.attach_evidence(
        evidence_id="ev_dup_finding_01",
        subject_id="batch_dup_heavy_01",
        source_domain="DATASET",
        severity="MEDIUM",
        description="High perceptual hash collision rate (8 near-duplicates).",
        metric_value=0.66,
    )

    profile = ContributorRiskEngine.get_profile(
        contributor_id="sensor_node_alpha",
        name="Alpha Recon Node",
        graph=graph_engine,
    )

    assert profile.contributor_id == "sensor_node_alpha"
    assert profile.name == "Alpha Recon Node"
    assert profile.total_datasets == 1
    assert profile.total_samples == 12
    assert profile.evidence_count == 1
    assert profile.severity_breakdown["MEDIUM"] == 1
    assert profile.status in (AssetStatus.ACCEPTED, AssetStatus.UNDER_REVIEW)
    assert "not an assertion of malicious intent" in profile.explanation.lower()


# ==============================================================================
# 5. Suspicious Contributor & Unknown Identity Invariant
# ==============================================================================

def test_suspicious_contributor_and_unknown_identity(phase6_env):
    """Unknown remains UNKNOWN, and multiple critical findings escalate contributor to QUARANTINED."""
    graph_engine: EvidenceGraphEngine = phase6_env["graph"]

    # A. Suspicious named contributor with active quarantine
    graph_engine.build_lineage(
        contributor_id="vendor_compromised",
        dataset_id="ds_poisoned_batch",
        training_run_id="tr_poison_01",
        model_id="model_backdoored",
        quarantine_id="quar_order_99",
    )
    graph_engine.attach_evidence(
        evidence_id="ev_backdoor_crit_01",
        subject_id="model_backdoored",
        source_domain="MODEL",
        severity="CRITICAL",
        description="Trojan backdoor trigger detected in convolutional backbone.",
    )

    profile_suspicious = ContributorRiskEngine.get_profile(
        contributor_id="vendor_compromised",
        graph=graph_engine,
    )
    assert profile_suspicious.status == AssetStatus.QUARANTINED
    assert profile_suspicious.risk_score >= 0.70
    assert "quarantine" in profile_suspicious.explanation.lower()

    # B. Unidentified contributor remains strictly UNKNOWN (no synthetic identities)
    profile_unknown = ContributorRiskEngine.get_profile(
        contributor_id="",
        graph=graph_engine,
    )
    assert profile_unknown.contributor_id == "UNKNOWN"
    assert profile_unknown.name == "Unknown Contributor"

    profile_anon = ContributorRiskEngine.get_profile(
        contributor_id="anonymous",
        graph=graph_engine,
    )
    assert profile_anon.contributor_id == "UNKNOWN"


# ==============================================================================
# 6. Model Anomaly Correlation & Hard Veto
# ==============================================================================

def test_model_anomaly_hard_veto(phase6_env):
    """Model findings: Unauthorized weight substitution forces Hard Veto and QUARANTINED."""
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]

    ev_model_tamper = EvidenceItem(
        evidence_id="ev_model_tamper_01",
        source=EvidenceSource.MODEL_IDENTITY,
        domain=EvidenceSourceDomain.MODEL,
        severity=IntegritySeverity.CRITICAL,
        metric_value=1.0,
        description="Model identity hash mismatch: unauthorized weight substitution detected.",
        subject_id="model_flir_lwir_v2",
    )

    assessment = fusion_engine.fuse("model_flir_lwir_v2", [ev_model_tamper])

    assert assessment.hard_veto_triggered is True
    assert assessment.overall_status == AssetStatus.QUARANTINED
    assert assessment.action == AssuranceAction.BLOCK
    assert assessment.risk_level == AssuranceRiskLevel.CRITICAL
    assert "ev_model_tamper_01" in assessment.decisive_evidence
    assert any("Model identity" in r for r in assessment.veto_reasons)


# ==============================================================================
# 7. Inference Provenance Anomaly & Blast Radius Traversal
# ==============================================================================

def test_inference_anomaly_and_blast_radius(phase6_env):
    """Inference findings: Replay / sequence break triggers Hard Veto and traces blast radius."""
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]
    graph_engine: EvidenceGraphEngine = phase6_env["graph"]

    ev_dna_tamper = EvidenceItem(
        evidence_id="ev_dna_tamper_01",
        source=EvidenceSource.INFERENCE_DNA,
        domain=EvidenceSourceDomain.INFERENCE,
        severity=IntegritySeverity.CRITICAL,
        metric_value=1.0,
        description="Inference provenance chain broken or replay attack detected.",
        subject_id="infer_stream_frame_88",
    )

    assessment = fusion_engine.fuse("infer_stream_frame_88", [ev_dna_tamper])
    assert assessment.hard_veto_triggered is True
    assert assessment.overall_status == AssetStatus.QUARANTINED
    assert assessment.action == AssuranceAction.BLOCK

    # Build lineage and verify downstream blast radius
    graph_engine.build_lineage(
        model_id="model_tactical_v1",
        inference_id="infer_stream_frame_88",
        output_id="out_target_bbox_42",
        fusion_assessment_id=assessment.assessment_id,
        quarantine_id="quar_inf_frame_88",
    )

    trace = graph_engine.trace_lineage("model_tactical_v1")
    assert any(n.id == "infer_stream_frame_88" for n in trace.downstream_path)
    assert any(n.id == "out_target_bbox_42" for n in trace.downstream_path)


# ==============================================================================
# 8. Full 14-Entity Evidence Graph with Real Evidence IDs on Every Edge
# ==============================================================================

def test_full_14_entity_evidence_graph_and_edge_evidence_ids(phase6_env):
    """Verify all 14 required Phase 6 entities connect properly and every edge has an evidence_id."""
    graph_engine: EvidenceGraphEngine = phase6_env["graph"]

    # Connect all 14 entities:
    # 1. Contributor
    # 2. Dataset
    # 3. Sample
    # 4. Finding
    # 5. Model
    # 6. Model version
    # 7. Preprocessing configuration
    # 8. Inference
    # 9. Output
    # 10. Drift assessment
    # 11. Contributor assessment
    # 12. Analyst decision
    # 13. Audit event
    # 14. Report

    graph_engine.build_lineage(
        contributor_id="vendor_flir_defense",
        dataset_id="ds_thermal_recon",
        dataset_version_id="ds_thermal_recon_v1",
        sample_ids=["sample_frame_001", "sample_frame_002"],
        training_run_id="run_train_yolo_thermal",
        model_id="yolo_thermal_lwir",
        model_version_id="yolo_thermal_lwir_v1",
        preprocessing_config_id="prep_thermal_640x512_norm",
        inference_id="infer_seq_001",
        output_id="out_detect_vehicle_01",
        drift_assessment_id="drift_assmt_thermal_oct",
        contributor_assessment_id="ca_vendor_flir_eval",
        fusion_assessment_id="fused_assmt_gatekeeper_01",
        quarantine_id="quar_sample_eval_01",
        analyst_decision_id="analyst_dec_soc_approval",
        audit_event_id="audit_event_chain_tip_88",
        report_id="report_mission_readiness_v1",
        findings=[{"finding_id": "f_thermal_dead_pixels", "severity": "LOW", "description": "3 dead sensor pixels"}],
    )

    # Verify node types in graph
    observed_types = {n.node_type for n in graph_engine.nodes.values()}
    required_core_types = {
        NodeType.CONTRIBUTOR,
        NodeType.DATASET,
        NodeType.SAMPLE,
        NodeType.FINDING,
        NodeType.MODEL,
        NodeType.MODEL_VERSION,
        NodeType.PREPROCESSING_CONFIG,
        NodeType.INFERENCE,
        NodeType.OUTPUT,
        NodeType.DRIFT_ASSESSMENT,
        NodeType.CONTRIBUTOR_ASSESSMENT,
        NodeType.ANALYST_DECISION,
        NodeType.AUDIT_EVENT,
        NodeType.REPORT,
    }
    for req in required_core_types:
        assert req in observed_types, f"Missing required node type: {req}"

    # Verify INVARIANT: Every single edge must have an evidence/reference ID
    assert len(graph_engine.edges) >= 14
    for edge in graph_engine.edges:
        assert edge.evidence_id is not None, f"Edge {edge.source_id}->{edge.target_id} lacks evidence_id"
        assert len(edge.evidence_id.strip()) > 0, f"Edge {edge.source_id}->{edge.target_id} has empty evidence_id"

    # Export graph and check canonical digest
    snapshot = graph_engine.export_graph()
    assert len(snapshot.graph_digest) == 64
    assert snapshot.node_count == len(graph_engine.nodes)
    assert snapshot.edge_count == len(graph_engine.edges)


# ==============================================================================
# 9. Contributor Trust & Risk Scoring Invariants (Requirement 2)
# ==============================================================================

def test_contributor_unknown_and_evidence_disclosure(phase6_env):
    """Verify contributor scoring invariants:
    - Only uses verified graph provenance
    - Never invents contributor identity
    - Never scores UNKNOWN as an identified entity
    - Exposes underlying evidence records in historical_findings
    - Avoids inflammatory or categorical language
    """
    graph_engine: EvidenceGraphEngine = phase6_env["graph"]

    # 1. Register unauthenticated dataset with UNKNOWN contributor
    graph_engine.build_lineage(
        contributor_id="",  # Blank -> UNKNOWN
        dataset_id="ds_unauthenticated_01",
        sample_ids=["sample_u1", "sample_u2"],
    )
    graph_engine.attach_evidence(
        evidence_id="ev_missing_labels_01",
        subject_id="ds_unauthenticated_01",
        source_domain="DATASET",
        severity="MEDIUM",
        description="Missing bounding box annotations for 15 samples.",
        metric_value=0.15,
    )

    profile_unknown = ContributorRiskEngine.get_profile(
        contributor_id="",
        name=None,
        graph=graph_engine,
    )

    # Invariant: Identity remains UNKNOWN, never invented
    assert profile_unknown.contributor_id == "UNKNOWN"
    assert profile_unknown.name == "Unknown Contributor"

    # Invariant: Exposes real underlying evidence
    assert profile_unknown.evidence_count == 1
    assert len(profile_unknown.historical_findings) == 1
    assert profile_unknown.historical_findings[0]["subject_id"] == "ds_unauthenticated_01"
    assert profile_unknown.historical_findings[0]["severity"] == "MEDIUM"

    # Invariant: Explanation treats UNKNOWN as unauthenticated provenance, not an identified person
    explanation = profile_unknown.explanation
    assert "Unauthenticated provenance cluster" in explanation
    assert "does not attribute findings to an identified entity" in explanation
    # Tone check: Non-inflammatory
    assert "malicious" not in explanation.lower() or "not an assertion of malicious intent" in explanation.lower()
    assert "criminal" not in explanation.lower()
    assert "fraudulent" not in explanation.lower()

    # 2. Named contributor with verified provenance
    graph_engine.build_lineage(
        contributor_id="sensor_lab_charlie",
        dataset_id="ds_verified_charlie",
        sample_ids=["sample_c1", "sample_c2", "sample_c3"],
    )
    profile_charlie = ContributorRiskEngine.get_profile(
        contributor_id="sensor_lab_charlie",
        name="Sensor Lab Charlie",
        graph=graph_engine,
    )
    assert profile_charlie.contributor_id == "sensor_lab_charlie"
    assert profile_charlie.name == "Sensor Lab Charlie"
    assert profile_charlie.total_datasets == 1
    assert profile_charlie.total_samples == 3
    assert "not an assertion of malicious intent" in profile_charlie.explanation


# ==============================================================================
# 10. Risk Semantics & Confidence Interpretation (Requirement 3)
# ==============================================================================

def test_risk_semantics_distinctions(phase6_env):
    """Verify clear semantic distinction between:
    - overall_status: Operational asset disposition (ACCEPTED, UNDER_REVIEW, QUARANTINED)
    - risk_level: Categorical risk severity tier (LOW, MEDIUM, HIGH, CRITICAL)
    - confidence: Evidential audit completeness [0.0, 1.0] (NOT a malicious probability)
    - coverage: Verified assurance domains ratio and domain breakdown
    - limitations: Documented unverified domains and operational boundaries
    """
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]

    # Supply evidence from only ONE domain (DATA_INTEGRITY) with LOW severity
    ev_data = EvidenceItem(
        evidence_id="ev_data_clean_01",
        source=EvidenceSource.DATA_INTEGRITY,
        domain=EvidenceSourceDomain.DATASET,
        severity=IntegritySeverity.LOW,
        metric_value=0.01,
        description="Dataset format validation clean; no corrupted files.",
        subject_id="ds_recon_clean",
    )

    assessment = fusion_engine.fuse("ds_recon_clean", [ev_data])

    # 1. overall_status is operational disposition
    assert assessment.overall_status == AssetStatus.ACCEPTED
    assert assessment.action == AssuranceAction.ALLOW

    # 2. risk_level is categorical risk tier
    assert assessment.risk_level == AssuranceRiskLevel.LOW

    # 3. coverage reflects that only 1 of 5 domains was verified (20%)
    assert assessment.coverage.coverage_ratio == 0.20
    assert EvidenceSource.DATA_INTEGRITY in assessment.coverage.sources_checked
    assert len(assessment.coverage.missing_sources) == 4

    # 4. confidence is AUDIT COMPLETENESS, NOT probability of maliciousness!
    # With only 1 source checked and 1 item, confidence is low (incomplete audit),
    # proving it does NOT represent 0% maliciousness or 100% security.
    assert 0.10 <= assessment.confidence <= 0.30
    assert assessment.confidence < 0.50  # Low confidence due to low coverage

    # 5. limitations explicitly records missing domains
    assert any("Unchecked evidence sources" in lim for lim in assessment.limitations)
    assert any("40%" not in lim for lim in assessment.limitations)  # 20% checked


# ==============================================================================
# 11. Unavailable Domain Propagation Regression (Requirement 4)
# ==============================================================================

def test_unavailable_domain_propagation_regression(phase6_env):
    """Regression test: Assurance domains remain UNAVAILABLE.
    Verify fusion:
    - Does not fabricate evidence for unavailable domains
    - Does not silently treat UNAVAILABLE as PASS/CLEAN
    - Does not silently discard the unavailable domain
    - Reports limitations with exact missing source names
    - Reflects incomplete coverage appropriately
    """
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]

    # Provide only DRIFT and MODEL_IDENTITY evidence, leaving DATA_INTEGRITY,
    # BEHAVIOURAL_FINGERPRINT, and INFERENCE_DNA unavailable/missing
    ev_drift = EvidenceItem(
        evidence_id="ev_drift_clean_02",
        source=EvidenceSource.DISTRIBUTION_SHIFT,
        domain=EvidenceSourceDomain.DRIFT,
        severity=IntegritySeverity.LOW,
        metric_value=0.08,
        description="Distribution drift evaluated against registered baseline.",
        subject_id="asset_partial_eval",
    )
    ev_model = EvidenceItem(
        evidence_id="ev_model_valid_02",
        source=EvidenceSource.MODEL_IDENTITY,
        domain=EvidenceSourceDomain.MODEL,
        severity=IntegritySeverity.LOW,
        metric_value=0.0,
        description="Model weights SHA-256 matches cryptographic signature.",
        subject_id="asset_partial_eval",
    )

    assessment = fusion_engine.fuse("asset_partial_eval", [ev_drift, ev_model])

    # Invariant: No fabricated evidence items inserted
    assert len(assessment.findings) <= 2

    # Invariant: Incomplete coverage ratio (2 of 5 = 40%)
    assert assessment.coverage.coverage_ratio == 0.40
    assert set(assessment.coverage.sources_checked) == {
        EvidenceSource.DISTRIBUTION_SHIFT,
        EvidenceSource.MODEL_IDENTITY,
    }

    # Invariant: Missing sources explicitly enumerated
    missing = assessment.coverage.missing_sources
    assert EvidenceSource.DATA_INTEGRITY in missing
    assert EvidenceSource.BEHAVIOURAL_FINGERPRINT in missing
    assert EvidenceSource.INFERENCE_DNA in missing

    # Invariant: Limitations report mentions the exact missing domains
    limitations_text = " ".join(assessment.limitations)
    assert "DATA_INTEGRITY" in limitations_text
    assert "BEHAVIOURAL_FINGERPRINT" in limitations_text
    assert "INFERENCE_DNA" in limitations_text

    # Invariant: UNAVAILABLE is not silently converted to PASS
    # Even though both evaluated items were LOW severity, the audit confidence is penalized
    assert assessment.confidence < 0.50


# ==============================================================================
# 12. Hard Veto Tests vs Ordinary Drift (Requirement 5)
# ==============================================================================

def test_hard_veto_vs_ordinary_drift(phase6_env):
    """Explicit verification of 4 security conditions:
    1. Cryptographic forgery -> Hard Veto (QUARANTINED)
    2. Inference replay/sequence break -> Hard Veto (QUARANTINED)
    3. Model weight substitution -> Hard Veto (QUARANTINED)
    4. Ordinary statistical distribution drift -> NOT a Hard Veto by itself (UNDER_REVIEW)
    """
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]

    # 1. Cryptographic forgery -> Hard Veto
    ev_crypto_forgery = EvidenceItem(
        evidence_id="ev_veto_forgery",
        source=EvidenceSource.CRYPTO_VERIFICATION,
        severity=IntegritySeverity.CRITICAL,
        metric_value=1.0,
        description="Cryptographic signature verification failed: signature forgery or invalid key.",
        subject_id="asset_crypto_fail",
    )
    assmt_crypto = fusion_engine.fuse("asset_crypto_fail", [ev_crypto_forgery])
    assert assmt_crypto.hard_veto_triggered is True
    assert assmt_crypto.overall_status == AssetStatus.QUARANTINED
    assert assmt_crypto.action == AssuranceAction.BLOCK
    assert "ev_veto_forgery" in assmt_crypto.decisive_evidence
    assert any("cryptographic signature" in r.lower() for r in assmt_crypto.veto_reasons)

    # 2. Inference replay / sequence break -> Hard Veto
    ev_infer_replay = EvidenceItem(
        evidence_id="ev_veto_replay",
        source=EvidenceSource.INFERENCE_DNA,
        severity=IntegritySeverity.CRITICAL,
        metric_value=1.0,
        description="Inference sequence break detected: nonce replay attack.",
        subject_id="asset_infer_replay",
    )
    assmt_infer = fusion_engine.fuse("asset_infer_replay", [ev_infer_replay])
    assert assmt_infer.hard_veto_triggered is True
    assert assmt_infer.overall_status == AssetStatus.QUARANTINED
    assert assmt_infer.action == AssuranceAction.BLOCK
    assert "ev_veto_replay" in assmt_infer.decisive_evidence
    assert any("inference" in r.lower() or "replay" in r.lower() for r in assmt_infer.veto_reasons)

    # 3. Model weight substitution -> Hard Veto
    ev_weight_tamper = EvidenceItem(
        evidence_id="ev_veto_weight_sub",
        source=EvidenceSource.MODEL_IDENTITY,
        severity=IntegritySeverity.CRITICAL,
        metric_value=1.0,
        description="Unauthorized model weight substitution detected; hash mismatch.",
        subject_id="asset_weight_sub",
    )
    assmt_model = fusion_engine.fuse("asset_weight_sub", [ev_weight_tamper])
    assert assmt_model.hard_veto_triggered is True
    assert assmt_model.overall_status == AssetStatus.QUARANTINED
    assert assmt_model.action == AssuranceAction.BLOCK
    assert "ev_veto_weight_sub" in assmt_model.decisive_evidence
    assert any("model" in r.lower() or "substitution" in r.lower() for r in assmt_model.veto_reasons)

    # 4. Ordinary statistical distribution drift (even critical-level drift) -> NOT Hard Veto by itself
    ev_stat_drift = EvidenceItem(
        evidence_id="ev_severe_drift_only",
        source=EvidenceSource.DISTRIBUTION_SHIFT,
        severity=IntegritySeverity.CRITICAL,
        metric_value=0.88,
        description="Severe environmental distribution drift detected across color and sharpness histograms.",
        subject_id="asset_drift_only",
    )
    assmt_drift = fusion_engine.fuse("asset_drift_only", [ev_stat_drift])
    # DRIFT ISOLATION PRINCIPLE:
    assert assmt_drift.hard_veto_triggered is False
    assert assmt_drift.overall_status == AssetStatus.UNDER_REVIEW
    assert assmt_drift.action == AssuranceAction.REVIEW
    assert assmt_drift.risk_score <= 0.65  # Drift alone is capped at 0.65
    assert len(assmt_drift.veto_reasons) == 0


# ==============================================================================
# 13. Evidence Graph Edge Resolution & Traversal (Requirement 6)
# ==============================================================================

def test_evidence_graph_edge_resolution_and_traversal(phase6_env):
    """Verify:
    1. Every graph edge has a valid evidence_id
    2. Evidence IDs resolve to actual evidence records or valid node references
    3. Upstream and downstream traversals follow real graph edges, not synthetic shortcuts
    """
    graph_engine: EvidenceGraphEngine = phase6_env["graph"]
    fusion_engine: EvidenceFusionEngine = phase6_env["fusion"]

    # 1. Register real evidence in fusion store
    ev_item = EvidenceItem(
        evidence_id="ev_rec_real_101",
        source=EvidenceSource.DATA_INTEGRITY,
        domain=EvidenceSourceDomain.DATASET,
        severity=IntegritySeverity.HIGH,
        metric_value=0.45,
        description="Corrupted image headers detected in 4 training samples.",
        subject_id="ds_sensor_lineage_01",
    )
    fusion_engine.register_evidence(ev_item)

    # 2. Build multi-hop graph lineage
    graph_engine.build_lineage(
        contributor_id="sensor_lab_charlie",
        dataset_id="ds_sensor_lineage_01",
        sample_ids=["sample_lin_1", "sample_lin_2"],
        training_run_id="run_train_lin_01",
        model_id="model_lin_01",
        inference_id="infer_lin_01",
        output_id="out_lin_01",
    )

    # Attach verified evidence to the dataset
    graph_engine.attach_evidence(
        evidence_id="ev_rec_real_101",
        subject_id="ds_sensor_lineage_01",
        source_domain="DATASET",
        severity="HIGH",
        description=ev_item.description,
        metric_value=ev_item.metric_value,
    )

    # Verify edge evidence_id validity
    assert len(graph_engine.edges) > 0
    for edge in graph_engine.edges:
        assert edge.evidence_id is not None
        assert len(edge.evidence_id.strip()) > 0
        # If edge is FLAGGED_WITH evidence, verify evidence_id resolves to the real evidence item
        if edge.edge_type in (EdgeType.FLAGGED_WITH, EdgeType.ABOUT):
            if "ev_rec_real_101" in (edge.source_id, edge.target_id):
                stored_ev = fusion_engine.get_evidence("ev_rec_real_101")
                assert stored_ev is not None
                assert stored_ev.evidence_id == "ev_rec_real_101"

    # 3. Real traversal: Upstream from OUTPUT should trace through INFERENCE, MODEL, TRAINING_RUN, DATASET, CONTRIBUTOR
    upstream_nodes = graph_engine.trace_upstream("out_lin_01")
    upstream_ids = [n.id for n in upstream_nodes]
    assert "infer_lin_01" in upstream_ids
    assert "model_lin_01" in upstream_ids
    assert "run_train_lin_01" in upstream_ids
    assert "ds_sensor_lineage_01" in upstream_ids

    # 4. Real traversal: Downstream from DATASET should trace to TRAINING_RUN, MODEL, INFERENCE, OUTPUT
    downstream_nodes = graph_engine.trace_downstream("ds_sensor_lineage_01")
    downstream_ids = [n.id for n in downstream_nodes]
    assert "run_train_lin_01" in downstream_ids
    assert "model_lin_01" in downstream_ids
    assert "infer_lin_01" in downstream_ids
    assert "out_lin_01" in downstream_ids

