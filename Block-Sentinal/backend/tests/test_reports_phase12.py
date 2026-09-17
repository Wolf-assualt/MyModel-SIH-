"""Phase 12 Dedicated Test Suite: Forensic Security Assurance Reports & Export.

Comprehensive test battery covering:
- Cross-domain evidence synthesis (Phases 3–11: dataset, model, behavior, inference, drift, fusion, quarantine, graph, blast radius)
- Canonical digest sealing (RFC 8785) and ECDSA SECP256R1 digital signatures
- Zero-trust tamper detection (altered verdicts, risk scores, hard veto, findings tally)
- Forged signature and illegitimate public key rejection
- Multi-format rendering (Defense Markdown, Executive Situation Brief, Air-Gapped Standalone HTML, JSON Manifest)
- Disk export lifecycle and content integrity digests
- Storage persistence, indexing, and retrieval across sessions
- Full CLI commands lifecycle (generate-report, show-report, verify-report, list-reports, export-report)
- REST API endpoints lifecycle (/reports/generate, /reports/{id}, /reports, /reports/{id}/export, /reports/verify)
"""
import json
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.cli import main as cli_main
from app.crypto.canonical import canonical_json_hash
from app.crypto.signer import KeyManager
from app.fusion.engine import EvidenceFusionEngine
from app.graph.engine import EvidenceGraphEngine
from app.reports.engine import AssuranceReportEngine
from app.reports.formatter import ReportFormatter
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceItem,
    EvidenceSource,
    FusedAssessment,
)
from app.schemas.graph import EdgeType, GraphEdge, GraphNode, NodeType
from app.schemas.integrity import IntegritySeverity
from app.schemas.report import AssuranceReport, ReportFormat


@pytest.fixture
def temp_dirs():
    with tempfile.TemporaryDirectory() as td:
        storage_path = Path(td) / "assurance_reports"
        storage_path.mkdir(parents=True, exist_ok=True)
        fusion_path = Path(td) / "fusion_store"
        fusion_path.mkdir(parents=True, exist_ok=True)
        graph_path = Path(td) / "graph_store"
        graph_path.mkdir(parents=True, exist_ok=True)
        yield storage_path, fusion_path, graph_path


@pytest.fixture
def mock_engines(temp_dirs):
    storage_path, fusion_path, graph_path = temp_dirs
    km = KeyManager()
    fusion_engine = EvidenceFusionEngine(storage_dir=fusion_path, key_manager=km)
    graph_engine = EvidenceGraphEngine(storage_dir=graph_path)
    report_engine = AssuranceReportEngine(
        storage_dir=storage_path,
        fusion_engine=fusion_engine,
        graph_engine=graph_engine,
    )
    return report_engine, fusion_engine, graph_engine, km


@pytest.fixture
def comprehensive_fused_setup(mock_engines):
    report_engine, fusion_engine, graph_engine, km = mock_engines

    # 1. Populate provenance graph
    ds_node = GraphNode(
        id="ds_recon_recon",
        node_type=NodeType.DATASET,
        label="Tactical Recon Dataset v1",
        digest="sha256_ds_manifest_recon",
    )
    mod_node = GraphNode(
        id="mod_yolo_tactical",
        node_type=NodeType.MODEL,
        label="YOLO-Tactical Recon",
        digest="sha256_mod_weights_yolo",
    )
    inf_node = GraphNode(
        id="inf_recon_frame_042",
        node_type=NodeType.INFERENCE,
        label="Runtime Inference Frame 042",
        digest="sha256_inf_frame_042",
    )
    graph_engine.add_node(ds_node)
    graph_engine.add_node(mod_node)
    graph_engine.add_node(inf_node)
    graph_engine.add_edge(GraphEdge(source_id=mod_node.id, target_id=ds_node.id, edge_type=EdgeType.TRAINED_ON))
    graph_engine.add_edge(GraphEdge(source_id=inf_node.id, target_id=mod_node.id, edge_type=EdgeType.GENERATED_BY))

    # 2. Add multi-domain evidence items
    ev_dataset = EvidenceItem(
        evidence_id="ev_data_backdoor_01",
        source=EvidenceSource.DATA_INTEGRITY,
        severity=IntegritySeverity.HIGH,
        subject_id="mod_yolo_tactical",
        related_dataset_id="ds_recon_recon",
        description="Near-duplicate trigger pattern detected in training batch.",
        metrics={"hamming_distance": 2},
        confidence=0.92,
    )
    ev_model = EvidenceItem(
        evidence_id="ev_model_weight_01",
        source=EvidenceSource.MODEL_IDENTITY,
        severity=IntegritySeverity.CRITICAL,
        subject_id="mod_yolo_tactical",
        description="Layer weight hash discrepancy in backbone layer 4.",
        metrics={"binary_sha256": "sha256_mod_weights_yolo"},
        confidence=1.0,
    )
    ev_behavior = EvidenceItem(
        evidence_id="ev_beh_probe_01",
        source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
        severity=IntegritySeverity.MEDIUM,
        subject_id="mod_yolo_tactical",
        description="Behavioral divergence exceeded threshold under contrast perturbation.",
        metrics={"divergence_score": 0.38},
        confidence=0.88,
    )
    ev_inference = EvidenceItem(
        evidence_id="ev_inf_replay_01",
        source=EvidenceSource.INFERENCE_DNA,
        severity=IntegritySeverity.CRITICAL,
        subject_id="mod_yolo_tactical",
        description="Duplicate nonce detected in runtime inference pipeline.",
        metrics={"nonce": "nonce_duplicate_99"},
        confidence=1.0,
    )
    ev_drift = EvidenceItem(
        evidence_id="ev_drift_shift_01",
        source=EvidenceSource.DISTRIBUTION_SHIFT,
        severity=IntegritySeverity.HIGH,
        subject_id="mod_yolo_tactical",
        description="Significant Wasserstein-1 distance detected on optical channel.",
        metrics={"wasserstein_distance": 0.42},
        confidence=0.95,
    )

    for ev in [ev_dataset, ev_model, ev_behavior, ev_inference, ev_drift]:
        fusion_engine.register_evidence(ev)

    # 3. Fuse evidence
    assessment = fusion_engine.fuse(
        target_entity_id="mod_yolo_tactical",
        evidence=[ev_dataset, ev_model, ev_behavior, ev_inference, ev_drift],
        strict_subject_binding=False,
    )

    # 4. Quarantine
    fusion_engine.quarantine_entity(
        subject_id="mod_yolo_tactical",
        reason="Critical layer weight discrepancy and runtime replay detection.",
        evidence_ids=[ev_model.evidence_id, ev_inference.evidence_id],
        subject_type="MODEL",
    )

    return report_engine, assessment, km, "mod_yolo_tactical"


# ===========================================================================
# 1. Generation & Cross-Domain Synthesis Tests
# ===========================================================================


def test_report_generation_from_fused_assessment(comprehensive_fused_setup):
    """Test full cross-domain forensic report synthesis from fused assessment."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(
        target_asset_id=target_id,
        target_asset_type="MODEL",
        assessment=assessment,
        key_manager=km,
    )

    assert report.report_id.startswith("rep_")
    assert report.target_asset_id == target_id
    assert report.target_asset_type == "MODEL"
    assert report.overall_verdict == AssetStatus.QUARANTINED
    assert report.gatekeeper_action == AssuranceAction.BLOCK

    assert report.hard_veto_triggered is True
    assert report.findings_summary["CRITICAL"] == 2
    assert report.findings_summary["HIGH"] == 2
    assert report.findings_summary["MEDIUM"] == 1
    assert len(report.section_overviews) == 5
    assert len(report.dataset_findings) == 1
    assert len(report.model_findings) == 1
    assert len(report.behavioral_findings) == 1
    assert len(report.inference_findings) == 1
    assert len(report.drift_findings) == 1
    assert len(report.quarantine_records) >= 1
    assert len(report.limitations_and_disclaimers) >= 3
    assert report.cryptographic_proofs.canonical_report_digest == report.report_digest
    assert report.cryptographic_proofs.ecdsa_signature == report.signature


def test_section_overviews_status_assignment(comprehensive_fused_setup):
    """Verify each section overview correctly derives status and risk contribution."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(
        target_asset_id=target_id,
        assessment=assessment,
        key_manager=km,
    )

    layer_map = {sec.layer_name: sec for sec in report.section_overviews}
    assert layer_map["Model Identity & Weight Integrity"].status == AssetStatus.QUARANTINED
    assert layer_map["Runtime Inference DNA & Nonce Integrity"].status == AssetStatus.QUARANTINED
    assert layer_map["Dataset & Training Data Integrity"].status == AssetStatus.UNDER_REVIEW
    assert layer_map["Behavioral Fingerprint & Probes"].status == AssetStatus.UNDER_REVIEW
    assert layer_map["Distribution Shift & Drift Analysis"].status == AssetStatus.UNDER_REVIEW


def test_upstream_lineage_and_blast_radius_attachment(comprehensive_fused_setup):
    """Verify upstream provenance lineage and downstream blast radius are computed and attached."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(
        target_asset_id=target_id,
        assessment=assessment,
        key_manager=km,
        include_lineage=True,
        include_blast_radius=True,
    )

    assert len(report.upstream_lineage) >= 1
    upstream_ids = [n.get("id") if isinstance(n, dict) else n.id for n in report.upstream_lineage]
    assert "ds_recon_recon" in upstream_ids

    assert report.downstream_blast_radius is not None
    assert report.downstream_blast_radius.root_cause_id == target_id
    assert report.downstream_blast_radius.total_downstream_count >= 1


# ===========================================================================
# 2. Canonical Digest & Cryptographic Verification Tests
# ===========================================================================


def test_canonical_digest_sealing_integrity(comprehensive_fused_setup):
    """Verify canonical digest calculation is strictly reproducible and tamper-evident."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(
        target_asset_id=target_id,
        assessment=assessment,
        key_manager=km,
    )

    expected_payload = {
        "report_id": report.report_id,
        "target_asset_id": report.target_asset_id,
        "target_asset_type": report.target_asset_type,
        "assessment_id": report.assessment_id,
        "overall_verdict": report.overall_verdict.value,
        "gatekeeper_action": report.gatekeeper_action.value,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level.value,
        "confidence_score": report.confidence_score,
        "coverage_ratio": report.coverage_ratio,
        "hard_veto_triggered": report.hard_veto_triggered,
        "findings_summary": report.findings_summary,
    }
    recomputed = canonical_json_hash(expected_payload)
    assert recomputed == report.report_digest


def test_ecdsa_signature_verification_success(comprehensive_fused_setup):
    """Verify valid report passes full cryptographic verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(
        target_asset_id=target_id,
        assessment=assessment,
        key_manager=km,
    )

    verif = report_engine.verify_report(report)
    assert verif.is_valid is True
    assert verif.digest_match is True
    assert verif.signature_valid is True
    assert len(verif.discrepancies) == 0


def test_tamper_detection_altered_verdict(comprehensive_fused_setup):
    """Tampering with verdict must invalidate digest and trigger verification failure."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    tampered_data = report.model_dump(mode="json")
    tampered_data["overall_verdict"] = "ACCEPTED"
    tampered_report = AssuranceReport.model_validate(tampered_data)

    verif = report_engine.verify_report(tampered_report)
    assert verif.is_valid is False
    assert verif.digest_match is False
    assert any("Report digest mismatch" in d for d in verif.discrepancies)


def test_tamper_detection_altered_risk_score(comprehensive_fused_setup):
    """Tampering with composite risk score must be detected."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    tampered_data = report.model_dump(mode="json")
    tampered_data["risk_score"] = 0.01
    tampered_report = AssuranceReport.model_validate(tampered_data)

    verif = report_engine.verify_report(tampered_report)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_tamper_detection_altered_hard_veto_flag(comprehensive_fused_setup):
    """Tampering with hard veto flag must be detected."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    tampered_data = report.model_dump(mode="json")
    tampered_data["hard_veto_triggered"] = False
    tampered_report = AssuranceReport.model_validate(tampered_data)

    verif = report_engine.verify_report(tampered_report)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_tamper_detection_altered_findings_summary(comprehensive_fused_setup):
    """Tampering with findings summary count must be detected."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    tampered_data = report.model_dump(mode="json")
    tampered_data["findings_summary"]["CRITICAL"] = 0
    tampered_report = AssuranceReport.model_validate(tampered_data)

    verif = report_engine.verify_report(tampered_report)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_forged_signature_rejection(comprehensive_fused_setup):
    """Forged signature hex must fail ECDSA cryptographic verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    tampered_data = report.model_dump(mode="json")
    tampered_data["signature"] = "deadbeef" * 16
    tampered_report = AssuranceReport.model_validate(tampered_data)

    verif = report_engine.verify_report(tampered_report)
    assert verif.is_valid is False
    assert verif.signature_valid is False
    assert any("signature verification failed" in d for d in verif.discrepancies)


def test_wrong_signer_public_key_rejection(comprehensive_fused_setup):
    """Replacing signer public key with another key pair must fail verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    other_km = KeyManager()
    other_pem = other_km.export_public_key_pem().decode("utf-8")

    tampered_data = report.model_dump(mode="json")
    tampered_data["signer_public_key_pem"] = other_pem
    tampered_report = AssuranceReport.model_validate(tampered_data)

    verif = report_engine.verify_report(tampered_report)
    assert verif.is_valid is False
    assert verif.signature_valid is False


# ===========================================================================
# 3. Formatting & Export Tests
# ===========================================================================


def test_format_markdown_rendering(comprehensive_fused_setup):
    """Verify Markdown rendering produces all defense-grade sections and headers."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)

    md = ReportFormatter.format_markdown(report)
    assert "[RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT]" in md
    assert "SIH26228 — Ministry of Defence" in md
    assert f"**Report ID**: `{report.report_id}`" in md
    assert f"### OPERATIONAL VERDICT: {report.overall_verdict.value}" in md
    assert "## Threat & Integrity Metrics Matrix" in md
    assert "## Verified Findings Breakdown" in md
    assert "## Cryptographic Provenance Seal" in md
    assert f"`{report.report_digest}`" in md
    assert f"`{report.signature}`" in md


def test_format_executive_summary_rendering(comprehensive_fused_setup):
    """Verify Executive Situation Brief plain-text formatting."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)

    summary = ReportFormatter.format_executive_summary(report)
    assert "TRUST-CV EXECUTIVE SECURITY SITUATION BRIEF" in summary
    assert f"TARGET ASSET       : {target_id} (MODEL)" in summary
    assert f"OPERATIONAL VERDICT: {report.overall_verdict.value}" in summary
    assert "FINDINGS TALLY     : CRITICAL: 2 | HIGH: 2 | MEDIUM: 1 | LOW: 0" in summary
    assert "CRYPTOGRAPHIC SEAL :" in summary


def test_format_html_rendering(comprehensive_fused_setup):
    """Verify standalone air-gapped HTML forensic report formatting."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)

    html = ReportFormatter.format_html(report)
    assert "<!DOCTYPE html>" in html
    assert f"<title>TRUST-CV Forensic Report - {report.report_id}</title>" in html
    assert "RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT" in html
    assert f"OPERATIONAL VERDICT: {report.overall_verdict.value}" in html
    assert "Assurance Layer Status Overview" in html
    assert report.report_digest in html
    assert report.signature in html


def test_export_to_file_all_formats(comprehensive_fused_setup, temp_dirs):
    """Verify exporting report to file across all supported formats."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    storage_path, _, _ = temp_dirs

    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)

    for fmt in [ReportFormat.JSON_MANIFEST, ReportFormat.MARKDOWN, ReportFormat.EXECUTIVE_SUMMARY, ReportFormat.HTML]:
        res = report_engine.export_report_to_file(report_id=report.report_id, export_format=fmt)
        assert res.report_id == report.report_id
        assert res.format == fmt
        assert Path(res.export_path).is_file()
        assert res.file_size_bytes > 0
        assert len(res.export_digest) == 64


# ===========================================================================
# 4. Storage & Retrieval Tests
# ===========================================================================


def test_report_persistence_and_list_indexing(comprehensive_fused_setup):
    """Verify multiple reports can be persisted, retrieved by ID, and listed."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup

    rep1 = report_engine.generate_report(target_asset_id="asset_alpha", assessment=assessment, key_manager=km)
    rep2 = report_engine.generate_report(target_asset_id="asset_beta", assessment=assessment, key_manager=km)

    retrieved_1 = report_engine.get_report(rep1.report_id)
    assert retrieved_1 is not None
    assert retrieved_1.report_id == rep1.report_id
    assert retrieved_1.target_asset_id == "asset_alpha"

    all_reports = report_engine.list_reports()
    report_ids = [r.report_id for r in all_reports]
    assert rep1.report_id in report_ids
    assert rep2.report_id in report_ids


# ===========================================================================
# 5. CLI Lifecycle Tests
# ===========================================================================


def test_cli_generate_report(capsys):
    """Test CLI generate-report command."""
    from app.fusion.engine import default_fusion_engine

    ev = EvidenceItem(
        evidence_id="ev_cli_test_01",
        source=EvidenceSource.DATA_INTEGRITY,
        severity=IntegritySeverity.LOW,
        subject_id="cli_target_01",
        description="CLI test evidence baseline",
    )
    default_fusion_engine.register_evidence(ev)
    assmt = default_fusion_engine.fuse(target_entity_id="cli_target_01", evidence=[ev])

    code = cli_main(["generate-report", "--target-id", "cli_target_01", "--assessment-id", assmt.assessment_id, "--format", "MARKDOWN"])
    assert code == 0
    captured = capsys.readouterr()
    assert "TRUST-CV SECURITY ASSURANCE REPORT" in captured.out
    assert "Report generated and sealed successfully" in captured.out


def test_cli_list_and_show_report(capsys, comprehensive_fused_setup, temp_dirs):
    """Test CLI list-reports and show-report commands."""
    from app.reports.engine import default_report_engine

    report_engine, assessment, km, target_id = comprehensive_fused_setup
    storage_path, _, _ = temp_dirs
    rep = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    rep_file = storage_path / f"{rep.report_id}.json"

    # 1. list-reports via default storage
    default_report = default_report_engine.generate_report(target_asset_id="cli_list_target", assessment=assessment)
    code_list = cli_main(["list-reports"])
    assert code_list == 0
    out_list = capsys.readouterr().out
    assert default_report.report_id in out_list

    # 2. show-report via file
    code_show = cli_main(["show-report", "--file", str(rep_file), "--format", "EXECUTIVE_SUMMARY"])
    assert code_show == 0
    out_show = capsys.readouterr().out
    assert "EXECUTIVE SECURITY SITUATION BRIEF" in out_show


def test_cli_verify_report_valid_and_tampered(comprehensive_fused_setup, capsys, temp_dirs):
    """Test CLI verify-report command on valid and tampered reports."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    storage_path, _, _ = temp_dirs
    rep = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    rep_file = storage_path / f"{rep.report_id}.json"

    # 1. Valid report verification
    code_val = cli_main(["verify-report", "--file", str(rep_file)])
    assert code_val == 0
    out_val = capsys.readouterr().out
    assert "Overall Validity:    VALID" in out_val

    # 2. Tampered report file verification
    tampered_path = storage_path / "tampered.json"
    data = rep.model_dump(mode="json")
    data["overall_verdict"] = "ACCEPTED"
    with open(tampered_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    code_tampered = cli_main(["verify-report", "--file", str(tampered_path)])
    assert code_tampered == 1
    out_tampered = capsys.readouterr().out
    assert "Overall Validity:    TAMPERED / INVALID" in out_tampered


def test_cli_export_report(capsys, comprehensive_fused_setup, temp_dirs):
    """Test CLI export-report command."""
    from app.reports.engine import default_report_engine

    _, assessment, _, _ = comprehensive_fused_setup
    storage_path, _, _ = temp_dirs
    rep = default_report_engine.generate_report(target_asset_id="cli_export_target", assessment=assessment)

    out_file = storage_path / "custom_export.html"
    code_exp = cli_main(["export-report", "--report-id", rep.report_id, "--format", "HTML", "--out", str(out_file)])
    assert code_exp == 0
    assert out_file.is_file()
    out_msg = capsys.readouterr().out
    assert "REPORT EXPORT SUCCESSFUL" in out_msg


# ===========================================================================
# 6. REST API Lifecycle Tests
# ===========================================================================


def test_api_generate_and_get_report():
    """Test FastAPI /reports/generate, /reports/{id}, /reports, and /reports/{id}/export endpoints."""
    from app.fusion.engine import default_fusion_engine
    from app.reports.engine import default_report_engine

    # Ensure clean fused assessment registered in default engines
    ev = EvidenceItem(
        evidence_id="ev_api_test_01",
        source=EvidenceSource.MODEL_IDENTITY,
        severity=IntegritySeverity.HIGH,
        subject_id="api_model_test",
        description="API test model discrepancy",
    )
    default_fusion_engine.register_evidence(ev)
    assmt = default_fusion_engine.fuse(target_entity_id="api_model_test", evidence=[ev])

    client = TestClient(app)

    # 1. POST /reports/generate
    gen_payload = {
        "target_asset_id": "api_model_test",
        "target_asset_type": "MODEL",
        "assessment_id": assmt.assessment_id,
        "include_limitations": True,
    }
    res_gen = client.post("/api/v1/reports/generate", json=gen_payload)
    assert res_gen.status_code == 200
    report_data = res_gen.json()["data"]
    rep_id = report_data["report_id"]
    assert rep_id.startswith("rep_")

    # 2. GET /reports/{id} default JSON
    res_get = client.get(f"/api/v1/reports/{rep_id}")
    assert res_get.status_code == 200
    assert res_get.json()["data"]["report_id"] == rep_id

    # 3. GET /reports/{id}?format=MARKDOWN
    res_md = client.get(f"/api/v1/reports/{rep_id}?format=MARKDOWN")
    assert res_md.status_code == 200
    assert "TRUST-CV SECURITY ASSURANCE REPORT" in res_md.json()["data"]["content"]

    # 4. GET /reports/{id}?format=HTML
    res_html = client.get(f"/api/v1/reports/{rep_id}?format=HTML")
    assert res_html.status_code == 200
    assert "<!DOCTYPE html>" in res_html.json()["data"]["content"]

    # 5. GET /reports
    res_list = client.get("/api/v1/reports")
    assert res_list.status_code == 200
    assert any(r["report_id"] == rep_id for r in res_list.json()["data"])

    # 6. POST /reports/{id}/export
    res_exp = client.post(f"/api/v1/reports/{rep_id}/export?format=HTML")
    assert res_exp.status_code == 200
    assert res_exp.json()["data"]["format"] == "HTML"
    assert Path(res_exp.json()["data"]["export_path"]).is_file()

    # 7. POST /reports/verify
    res_ver = client.post("/api/v1/reports/verify", json={"report": report_data})
    assert res_ver.status_code == 200
    assert res_ver.json()["data"]["is_valid"] is True
    assert res_ver.json()["data"]["signature_valid"] is True


def test_tamper_detection_altered_confidence_score(comprehensive_fused_setup):
    """Tampering with confidence score must fail verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    data = report.model_dump(mode="json")
    data["confidence_score"] = 0.50
    tampered = AssuranceReport.model_validate(data)
    verif = report_engine.verify_report(tampered)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_tamper_detection_altered_coverage_ratio(comprehensive_fused_setup):
    """Tampering with coverage ratio must fail verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    data = report.model_dump(mode="json")
    data["coverage_ratio"] = 0.50
    tampered = AssuranceReport.model_validate(data)
    verif = report_engine.verify_report(tampered)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_tamper_detection_altered_target_asset_id(comprehensive_fused_setup):
    """Tampering with target asset ID must fail verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    data = report.model_dump(mode="json")
    data["target_asset_id"] = "fraudulent_model_target"
    tampered = AssuranceReport.model_validate(data)
    verif = report_engine.verify_report(tampered)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_tamper_detection_altered_assessment_id(comprehensive_fused_setup):
    """Tampering with assessment ID must fail verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    data = report.model_dump(mode="json")
    data["assessment_id"] = "fused_fake_assessment"
    tampered = AssuranceReport.model_validate(data)
    verif = report_engine.verify_report(tampered)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_tamper_detection_altered_gatekeeper_action(comprehensive_fused_setup):
    """Tampering with gatekeeper action must fail verification."""
    report_engine, assessment, km, target_id = comprehensive_fused_setup
    report = report_engine.generate_report(target_asset_id=target_id, assessment=assessment, key_manager=km)
    data = report.model_dump(mode="json")
    data["gatekeeper_action"] = "ALLOW"
    tampered = AssuranceReport.model_validate(data)
    verif = report_engine.verify_report(tampered)
    assert verif.is_valid is False
    assert verif.digest_match is False


def test_canonical_json_ordering_invariance():
    """Verify RFC 8785 canonical serialization produces identical digests regardless of dictionary key order."""
    dict1 = {"zebra": 1, "alpha": 2, "middle": {"gamma": 3, "beta": 4}}
    dict2 = {"alpha": 2, "middle": {"beta": 4, "gamma": 3}, "zebra": 1}
    assert canonical_json_hash(dict1) == canonical_json_hash(dict2)


def test_report_engine_get_nonexistent_report(temp_dirs):
    """Retrieving a non-existent report should return None."""
    storage_path, _, _ = temp_dirs
    engine = AssuranceReportEngine(storage_dir=storage_path)
    assert engine.get_report("rep_nonexistent_id") is None


def test_export_nonexistent_report_raises_error(temp_dirs):
    """Exporting a non-existent report should raise FileNotFoundError."""
    storage_path, _, _ = temp_dirs
    engine = AssuranceReportEngine(storage_dir=storage_path)
    with pytest.raises(FileNotFoundError):
        engine.export_report_to_file("rep_nonexistent_id", ReportFormat.HTML)


def test_api_get_nonexistent_report_404():
    """API GET /reports/{id} with invalid ID returns 404."""
    client = TestClient(app)
    res = client.get("/api/v1/reports/rep_missing_999")
    assert res.status_code == 404


def test_api_generate_report_invalid_assessment_404():
    """API POST /reports/generate with invalid assessment ID returns 404."""
    client = TestClient(app)
    res = client.post("/api/v1/reports/generate", json={
        "target_asset_id": "asset_x",
        "target_asset_type": "MODEL",
        "assessment_id": "fused_does_not_exist_999",
    })
    assert res.status_code == 404


def test_api_export_nonexistent_report_404():
    """API POST /reports/{id}/export with invalid report ID returns 404."""
    client = TestClient(app)
    res = client.post("/api/v1/reports/rep_missing_999/export?format=HTML")
    assert res.status_code == 404


def test_cli_show_report_missing_args(capsys):
    """CLI show-report without --report-id or --file returns 1."""
    code = cli_main(["show-report"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Must specify either --report-id or --file" in captured.out


def test_cli_verify_report_missing_args(capsys):
    """CLI verify-report without --report-id or --file returns 1."""
    code = cli_main(["verify-report"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Must specify either --report-id or --file" in captured.out

