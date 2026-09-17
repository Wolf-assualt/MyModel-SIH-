"""Unit and integration tests for Phase 12: Analyst SOC Dashboard & Investigation Endpoints."""
import json
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.crypto.chain import HashChain
from app.dashboard.service import DashboardService
from app.graph.engine import EvidenceGraphEngine
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.dashboard import (
    ActivityTimelineItem,
    ContributorLeaderboardItem,
    InvestigationView,
    SystemHealthOverview,
)
from app.schemas.graph import GraphNode, NodeType
from app.schemas.integrity import IntegritySeverity


@pytest.fixture
def temp_dashboard_service(tmp_path: Path):
    """Provides an isolated DashboardService using temporary directories."""
    return DashboardService(data_dir=tmp_path)


@pytest.fixture
def temp_graph_engine(tmp_path: Path):
    """Provides an isolated EvidenceGraphEngine using temporary storage."""
    return EvidenceGraphEngine(storage_dir=tmp_path / "graph")


def test_system_overview_metrics(temp_dashboard_service, temp_graph_engine):
    """Verify system overview aggregates counts, statuses, threats, and hash chain head."""
    # 1. Create mock dataset manifest
    temp_dashboard_service.manifests_dir.mkdir(parents=True, exist_ok=True)
    ds_file = temp_dashboard_service.manifests_dir / "batch_001.json"
    with open(ds_file, "w", encoding="utf-8") as f:
        json.dump({"batch_id": "batch_001", "total_samples": 42}, f)

    # 2. Create mock model manifest
    model_man_dir = temp_dashboard_service.models_dir / "manifests"
    model_man_dir.mkdir(parents=True, exist_ok=True)
    mod_file = model_man_dir / "model_001.json"
    with open(mod_file, "w", encoding="utf-8") as f:
        json.dump({"model_id": "model_001", "format": "ONNX"}, f)

    # 3. Create mock inference DNA record
    temp_dashboard_service.inference_dir.mkdir(parents=True, exist_ok=True)
    inf_file = temp_dashboard_service.inference_dir / "inf_001.json"
    with open(inf_file, "w", encoding="utf-8") as f:
        json.dump({"record_id": "inf_001", "sequence_id": 1, "model_id": "model_001"}, f)

    # 4. Create mock assurance reports
    temp_dashboard_service.reports_dir.mkdir(parents=True, exist_ok=True)
    rep_quarantined = temp_dashboard_service.reports_dir / "rep_001.json"
    with open(rep_quarantined, "w", encoding="utf-8") as f:
        json.dump({
            "report_id": "rep_001",
            "target_asset_id": "model_001",
            "overall_verdict": AssetStatus.QUARANTINED.value,
            "risk_score": 0.85,
        }, f)

    rep_accepted = temp_dashboard_service.reports_dir / "rep_002.json"
    with open(rep_accepted, "w", encoding="utf-8") as f:
        json.dump({
            "report_id": "rep_002",
            "target_asset_id": "batch_001",
            "overall_verdict": AssetStatus.ACCEPTED.value,
            "risk_score": 0.05,
        }, f)

    # 5. Populate graph with a critical finding
    temp_graph_engine.add_node(
        GraphNode(
            id="find_01",
            node_type=NodeType.FINDING,
            label="Poison Detected",
            properties={"severity": "CRITICAL"},
        )
    )

    # 6. Initialize mock hash chain
    chain = HashChain()
    chain.append({"event": "INIT_AUDIT"})

    overview = temp_dashboard_service.get_system_overview(
        graph_engine=temp_graph_engine,
        hash_chain=chain,
    )

    assert isinstance(overview, SystemHealthOverview)
    assert overview.total_datasets == 1
    assert overview.total_models == 1
    assert overview.total_inferences == 1
    assert overview.total_reports == 2
    assert overview.quarantined_assets == 1
    assert overview.accepted_assets == 1
    assert overview.active_threats_count == 1
    assert len(overview.chain_head_hash) == 64
    assert overview.system_integrity_status == "CRITICAL_ALERT"


def test_activity_timeline_ordering(temp_dashboard_service):
    """Verify multi-source activity events are assembled and sorted reverse-chronologically."""
    temp_dashboard_service.manifests_dir.mkdir(parents=True, exist_ok=True)
    temp_dashboard_service.reports_dir.mkdir(parents=True, exist_ok=True)

    # Event 1: older dataset ingestion
    with open(temp_dashboard_service.manifests_dir / "batch_alpha.json", "w", encoding="utf-8") as f:
        json.dump({
            "batch_id": "batch_alpha",
            "created_at": "2026-03-01T10:00:00Z",
            "total_samples": 100,
        }, f)

    # Event 2: newer assurance report
    with open(temp_dashboard_service.reports_dir / "rep_alpha.json", "w", encoding="utf-8") as f:
        json.dump({
            "report_id": "rep_alpha",
            "target_asset_id": "batch_alpha",
            "overall_verdict": AssetStatus.QUARANTINED.value,
            "risk_score": 0.9,
            "created_at": "2026-03-01T12:00:00Z",
        }, f)

    timeline = temp_dashboard_service.get_activity_timeline(limit=10)
    assert len(timeline) == 2
    assert all(isinstance(item, ActivityTimelineItem) for item in timeline)

    # Latest event first
    assert timeline[0].event_type == "TAMPER_DETECTED"
    assert timeline[0].severity == IntegritySeverity.CRITICAL
    assert timeline[0].entity_id == "rep_alpha"

    assert timeline[1].event_type == "DATASET_INGESTED"
    assert timeline[1].severity == IntegritySeverity.LOW
    assert timeline[1].entity_id == "batch_alpha"

    # Test limit clamping
    limited = temp_dashboard_service.get_activity_timeline(limit=1)
    assert len(limited) == 1
    assert limited[0].entity_id == "rep_alpha"


def test_investigate_entity_lineage(temp_dashboard_service, temp_graph_engine):
    """Verify deep-dive forensic audit resolves upstream/downstream lineage and findings."""
    # Build a complete lineage chain in graph
    temp_graph_engine.build_lineage(
        contributor_id="contrib_recon_01",
        batch_id="batch_recon_42",
        model_id="model_yolo_recon",
        inference_id="inf_rec_99",
        sample_ids=["samp_001", "samp_002"],
        findings=[
            {
                "finding_id": "finding_trojan_01",
                "target_id": "batch_recon_42",
                "severity": "CRITICAL",
                "description": "Trigger backdoor watermark detected.",
            }
        ],
    )

    # Set canonical hash on the batch node
    batch_node = temp_graph_engine.nodes["batch_recon_42"]
    batch_node.properties["sha256_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Create matching report
    temp_dashboard_service.reports_dir.mkdir(parents=True, exist_ok=True)
    with open(temp_dashboard_service.reports_dir / "rep_batch_recon.json", "w", encoding="utf-8") as f:
        json.dump({
            "report_id": "rep_batch_recon",
            "target_asset_id": "batch_recon_42",
            "overall_verdict": AssetStatus.QUARANTINED.value,
            "risk_score": 0.85,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }, f)

    investigation = temp_dashboard_service.investigate_entity(
        entity_id="batch_recon_42",
        graph_engine=temp_graph_engine,
    )

    assert isinstance(investigation, InvestigationView)
    assert investigation.entity_id == "batch_recon_42"
    assert investigation.entity_type == NodeType.DATASET_BATCH.value
    assert investigation.status == AssetStatus.QUARANTINED
    assert investigation.risk_score == 0.85
    assert investigation.canonical_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert investigation.latest_report_id == "rep_batch_recon"

    # Verify upstream lineage contains the contributor
    upstream_ids = [n["id"] for n in investigation.lineage_upstream]
    assert "contrib_recon_01" in upstream_ids

    # Verify downstream lineage contains samples and models
    downstream_ids = [n["id"] for n in investigation.lineage_downstream]
    assert "samp_001" in downstream_ids
    assert "model_yolo_recon" in downstream_ids

    # Verify associated findings
    finding_ids = [f["id"] for f in investigation.associated_findings]
    assert "finding_trojan_01" in finding_ids


def test_contributor_leaderboard(temp_dashboard_service, temp_graph_engine):
    """Verify contributors are evaluated and ranked in descending order of risk score."""
    # Contributor A: Clean batch
    temp_graph_engine.build_lineage(
        contributor_id="contrib_clean_01",
        batch_id="batch_clean_01",
        model_id="model_clean",
        inference_id="inf_clean",
        sample_ids=["s1", "s2", "s3"],
        findings=[],
    )

    # Contributor B: Flagged batch with critical finding
    temp_graph_engine.build_lineage(
        contributor_id="contrib_suspect_02",
        batch_id="batch_suspect_02",
        model_id="model_suspect",
        inference_id="inf_suspect",
        sample_ids=["s4", "s5"],
        findings=[
            {
                "finding_id": "finding_poison_99",
                "target_id": "batch_suspect_02",
                "severity": "CRITICAL",
                "description": "Backdoor poisoning detected.",
            },
            {
                "finding_id": "finding_poison_100",
                "target_id": "batch_suspect_02",
                "severity": "CRITICAL",
                "description": "Second backdoor trigger injection detected.",
            },
        ],
    )

    leaderboard = temp_dashboard_service.get_contributor_leaderboard(
        graph_engine=temp_graph_engine,
    )

    assert len(leaderboard) == 2
    assert all(isinstance(item, ContributorLeaderboardItem) for item in leaderboard)

    # Contributor B should have higher risk and be ranked first
    assert leaderboard[0].contributor_id == "contrib_suspect_02"
    assert leaderboard[0].risk_score > leaderboard[1].risk_score
    assert leaderboard[0].status == AssetStatus.QUARANTINED
    assert leaderboard[0].flagged_findings == 2

    # Contributor A should have zero risk and be accepted
    assert leaderboard[1].contributor_id == "contrib_clean_01"
    assert leaderboard[1].risk_score == 0.0
    assert leaderboard[1].status == AssetStatus.ACCEPTED


def test_api_dashboard_endpoints():
    """Test all FastAPI dashboard endpoints via TestClient."""
    client = TestClient(app)

    # 1. GET /overview
    res_overview = client.get("/api/v1/dashboard/overview")
    assert res_overview.status_code == 200
    body = res_overview.json()
    assert body["success"] is True
    data = body["data"]
    assert "total_datasets" in data
    assert "total_models" in data
    assert "total_inferences" in data
    assert "total_reports" in data
    assert "chain_head_hash" in data
    assert "system_integrity_status" in data

    # 2. GET /timeline
    res_timeline = client.get("/api/v1/dashboard/timeline?limit=5")
    assert res_timeline.status_code == 200
    body = res_timeline.json()
    assert body["success"] is True
    assert isinstance(body["data"], list)

    # 3. GET /investigate/{entity_id}
    res_inv = client.get("/api/v1/dashboard/investigate/non_existent_entity_404")
    assert res_inv.status_code == 200
    body = res_inv.json()
    assert body["success"] is True
    inv_data = body["data"]
    assert inv_data["entity_id"] == "non_existent_entity_404"
    assert inv_data["entity_type"] == "UNKNOWN"
    assert inv_data["status"] == AssetStatus.ACCEPTED.value

    # 4. GET /contributors
    res_contrib = client.get("/api/v1/dashboard/contributors")
    assert res_contrib.status_code == 200
    body = res_contrib.json()
    assert body["success"] is True
    assert isinstance(body["data"], list)
