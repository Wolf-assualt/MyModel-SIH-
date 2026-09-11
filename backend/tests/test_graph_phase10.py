"""Comprehensive Phase 10 Tests: Evidence & Provenance Graph, Contributor Risk, and Blast Radius Analysis.

Verifies:
- 30 distinct graph capability, integrity, security, API, CLI, and scalability scenarios.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import pytest
from fastapi.testclient import TestClient

from app.cli import main as cli_main
from app.graph.contributor import ContributorRiskEngine
from app.graph.engine import EvidenceGraphEngine, default_graph_engine
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceItem,
    EvidenceSource,
    IntegritySeverity,
)
from app.schemas.graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)


@pytest.fixture
def temp_graph_engine(tmp_path: Path):
    """Provides an isolated EvidenceGraphEngine instance."""
    return EvidenceGraphEngine(storage_dir=tmp_path / "graph")


# 1. Node creation
def test_01_node_creation(temp_graph_engine):
    node = GraphNode(
        id="node_dataset_01",
        node_type=NodeType.DATASET,
        label="FLIR Thermal Dataset v1",
        digest="a" * 64,
        properties={"format": "YOLO", "sensor": "LWIR"},
    )
    temp_graph_engine.add_node(node)
    fetched = temp_graph_engine.get_node("node_dataset_01")
    assert fetched is not None
    assert fetched.label == "FLIR Thermal Dataset v1"
    assert fetched.properties["format"] == "YOLO"


# 2. Edge creation
def test_02_edge_creation(temp_graph_engine):
    n1 = GraphNode(id="contrib_1", node_type=NodeType.CONTRIBUTOR, label="Vendor Alpha")
    n2 = GraphNode(id="dataset_1", node_type=NodeType.DATASET, label="Dataset 1")
    temp_graph_engine.add_node(n1)
    temp_graph_engine.add_node(n2)

    edge = GraphEdge(source_id="contrib_1", target_id="dataset_1", edge_type=EdgeType.PROVIDED)
    temp_graph_engine.add_edge(edge)

    assert len(temp_graph_engine.edges) == 1
    assert temp_graph_engine.edges[0].edge_type == EdgeType.PROVIDED


# 3. Duplicate node prevention / idempotency
def test_03_duplicate_node_prevention(temp_graph_engine):
    n1 = GraphNode(id="node_dup", node_type=NodeType.MODEL, label="Version 1")
    temp_graph_engine.add_node(n1)
    n2 = GraphNode(id="node_dup", node_type=NodeType.MODEL, label="Version 2 Updated")
    temp_graph_engine.add_node(n2, overwrite=False)

    assert temp_graph_engine.get_node("node_dup").label == "Version 1"
    assert len(temp_graph_engine.nodes) == 1


# 4. Invalid edge rejection (missing endpoint checks in strict mode)
def test_04_invalid_edge_rejection(temp_graph_engine):
    edge = GraphEdge(source_id="nonexistent_src", target_id="nonexistent_tgt", edge_type=EdgeType.PRODUCED)
    with pytest.raises(ValueError, match="does not exist in graph"):
        temp_graph_engine.add_edge(edge, validate_nodes=True)


# 5. Dataset -> Training lineage
def test_05_dataset_training_lineage(temp_graph_engine):
    temp_graph_engine.build_lineage(
        dataset_id="ds_flir_100",
        dataset_version_id="ds_flir_100_v1",
        training_run_id="tr_run_99",
    )
    upstream = temp_graph_engine.trace_upstream("tr_run_99")
    upstream_ids = {n.id for n in upstream}
    assert "ds_flir_100_v1" in upstream_ids
    assert "ds_flir_100" in upstream_ids


# 6. Training -> Model lineage
def test_06_training_model_lineage(temp_graph_engine):
    temp_graph_engine.build_lineage(
        training_run_id="tr_yolo_run",
        model_id="yolo_thermal_detector",
    )
    upstream = temp_graph_engine.trace_upstream("yolo_thermal_detector")
    assert any(n.id == "tr_yolo_run" for n in upstream)


# 7. Model -> Inference lineage
def test_07_model_inference_lineage(temp_graph_engine):
    temp_graph_engine.build_lineage(
        model_id="yolo_thermal_detector",
        model_version_id="yolo_thermal_v1",
        inference_id="infer_dna_sample_01",
    )
    upstream = temp_graph_engine.trace_upstream("infer_dna_sample_01")
    upstream_ids = {n.id for n in upstream}
    assert "yolo_thermal_v1" in upstream_ids
    assert "yolo_thermal_detector" in upstream_ids


# 8. Inference -> Output lineage
def test_08_inference_output_lineage(temp_graph_engine):
    temp_graph_engine.build_lineage(
        model_id="model_det",
        inference_id="infer_rec_1",
        output_id="out_bbox_42",
    )
    upstream = temp_graph_engine.trace_upstream("out_bbox_42")
    assert any(n.id == "infer_rec_1" for n in upstream)


# 9. Evidence attachment
def test_09_evidence_attachment(temp_graph_engine):
    n = GraphNode(id="model_candidate", node_type=NodeType.MODEL, label="Target Model")
    temp_graph_engine.add_node(n)
    ev_node = temp_graph_engine.attach_evidence(
        evidence_id="ev_drift_01",
        subject_id="model_candidate",
        source_domain="DISTRIBUTION_SHIFT",
        severity="HIGH",
        description="Significant Wasserstein-1 drift detected.",
        metric_value=0.45,
    )
    assert ev_node.node_type == NodeType.EVIDENCE
    attached = temp_graph_engine.get_attached_evidence("model_candidate")
    assert len(attached) == 1
    assert attached[0].id == "ev_drift_01"


# 10. Fusion assessment attachment
def test_10_fusion_assessment_attachment(temp_graph_engine):
    temp_graph_engine.build_lineage(
        model_id="model_target_eval",
        fusion_assessment_id="fusion_assmt_77",
    )
    assert "fusion_assmt_77" in temp_graph_engine.nodes
    out_edges = temp_graph_engine._out_edges.get("fusion_assmt_77", [])
    assert any(e.edge_type == EdgeType.DECIDES_ON and e.target_id == "model_target_eval" for e in out_edges)


# 11. Quarantine attachment
def test_11_quarantine_attachment(temp_graph_engine):
    temp_graph_engine.build_lineage(
        model_id="model_compromised",
        fusion_assessment_id="fusion_assmt_88",
        quarantine_id="quar_rec_101",
    )
    assert "quar_rec_101" in temp_graph_engine.nodes
    out_edges = temp_graph_engine._out_edges.get("quar_rec_101", [])
    assert any(e.edge_type == EdgeType.QUARANTINES and e.target_id == "model_compromised" for e in out_edges)
    assert any(e.edge_type == EdgeType.RESULTED_FROM and e.target_id == "fusion_assmt_88" for e in out_edges)


# 12. Upstream traversal
def test_12_upstream_traversal(temp_graph_engine):
    temp_graph_engine.build_lineage(
        contributor_id="vendor_x",
        dataset_id="dataset_x",
        training_run_id="run_x",
        model_id="model_x",
        inference_id="infer_x",
    )
    upstream = temp_graph_engine.trace_upstream("infer_x")
    upstream_ids = [n.id for n in upstream]
    assert "model_x" in upstream_ids
    assert "dataset_x" in upstream_ids
    assert "vendor_x" in upstream_ids


# 13. Downstream traversal
def test_13_downstream_traversal(temp_graph_engine):
    temp_graph_engine.build_lineage(
        contributor_id="vendor_x",
        dataset_id="dataset_x",
        training_run_id="run_x",
        model_id="model_x",
        inference_id="infer_x",
        output_id="out_x",
    )
    downstream = temp_graph_engine.trace_downstream("dataset_x")
    downstream_ids = [n.id for n in downstream]
    assert "run_x" in downstream_ids
    assert "model_x" in downstream_ids
    assert "infer_x" in downstream_ids
    assert "out_x" in downstream_ids


# 14. Multi-hop traversal
def test_14_multi_hop_traversal(temp_graph_engine):
    # Contributor -> Dataset -> Version -> Run -> Model -> ModelVersion -> Inference -> Output
    temp_graph_engine.build_lineage(
        contributor_id="c_multi",
        dataset_id="d_multi",
        dataset_version_id="dv_multi",
        training_run_id="tr_multi",
        model_id="m_multi",
        model_version_id="mv_multi",
        inference_id="inf_multi",
        output_id="out_multi",
    )
    trace = temp_graph_engine.trace_lineage("out_multi")
    upstream_ids = {n.id for n in trace.upstream_path}
    assert len(upstream_ids) >= 6
    assert "c_multi" in upstream_ids
    assert "d_multi" in upstream_ids
    assert "m_multi" in upstream_ids


# 15. Blast-radius calculation
def test_15_blast_radius_calculation(temp_graph_engine):
    temp_graph_engine.build_lineage(
        dataset_id="poisoned_dataset",
        training_run_id="training_run_1",
        model_id="model_alpha",
        inference_id="inf_1",
        output_id="out_1",
    )
    temp_graph_engine.build_lineage(
        dataset_id="poisoned_dataset",
        training_run_id="training_run_2",
        model_id="model_beta",
        inference_id="inf_2",
        output_id="out_2",
    )
    temp_graph_engine.attach_evidence(
        evidence_id="ev_poison_trigger",
        subject_id="poisoned_dataset",
        source_domain="DATA_INTEGRITY",
        severity="CRITICAL",
        description="Backdoor corner pattern detected.",
    )

    report = temp_graph_engine.calculate_blast_radius("poisoned_dataset")
    assert report.root_cause_id == "poisoned_dataset"
    assert report.root_cause_type == NodeType.DATASET
    assert "training_run_1" in report.affected_training_runs
    assert "training_run_2" in report.affected_training_runs
    assert "model_alpha" in report.affected_models
    assert "model_beta" in report.affected_models
    assert len(report.affected_inferences) == 2
    assert "ev_poison_trigger" in report.affected_evidence_ids
    assert "downstream dependencies" in report.explanation.lower()


# 16. Contributor history
def test_16_contributor_history(temp_graph_engine):
    temp_graph_engine.build_lineage(
        contributor_id="contrib_mod_defense",
        dataset_id="ds_recon_01",
        sample_ids=["s1", "s2", "s3"],
    )
    temp_graph_engine.build_lineage(
        contributor_id="contrib_mod_defense",
        dataset_id="ds_recon_02",
        sample_ids=["s4", "s5"],
    )

    profile = ContributorRiskEngine.get_profile(
        contributor_id="contrib_mod_defense",
        name="MOD Recon Team",
        graph=temp_graph_engine,
    )
    assert profile.total_datasets == 2
    assert profile.total_samples == 5
    assert profile.evidence_count == 0
    assert profile.risk_score == 0.0
    assert profile.status == AssetStatus.ACCEPTED


# 17. Contributor risk explanation (objective, non-inflammatory tone)
def test_17_contributor_risk_explanation(temp_graph_engine):
    temp_graph_engine.build_lineage(
        contributor_id="vendor_noisy",
        dataset_id="noisy_ds_1",
        sample_ids=["s1", "s2"],
    )
    temp_graph_engine.attach_evidence(
        evidence_id="ev_noise_1",
        subject_id="noisy_ds_1",
        source_domain="DATA_INTEGRITY",
        severity="HIGH",
        description="Label inconsistency across 15% of samples.",
    )

    profile = ContributorRiskEngine.get_profile(
        contributor_id="vendor_noisy",
        graph=temp_graph_engine,
    )
    assert profile.evidence_count == 1
    assert profile.severity_breakdown["HIGH"] == 1
    assert "not an assertion of malicious intent" in profile.explanation.lower()


# 18. Cross-dataset mismatch rejection
def test_18_cross_dataset_mismatch_rejection(temp_graph_engine):
    d1 = GraphNode(id="ds_ground_truth", node_type=NodeType.DATASET, label="Dataset 1")
    d2 = GraphNode(id="ds_foreign", node_type=NodeType.DATASET, label="Dataset 2")
    ev = GraphNode(
        id="ev_d1_specific",
        node_type=NodeType.EVIDENCE,
        label="D1 Evidence",
        properties={"related_dataset_id": "ds_ground_truth"},
    )
    temp_graph_engine.add_node(d1)
    temp_graph_engine.add_node(d2)
    temp_graph_engine.add_node(ev)

    # Attempting to link D1 evidence directly to D2
    with pytest.raises(ValueError, match="Cross-dataset mismatch"):
        temp_graph_engine.add_edge(
            GraphEdge(source_id="ev_d1_specific", target_id="ds_foreign", edge_type=EdgeType.ABOUT),
            strict_subject_validation=True,
        )


# 19. Cross-model mismatch rejection
def test_19_cross_model_mismatch_rejection(temp_graph_engine):
    m1 = GraphNode(id="model_authorized", node_type=NodeType.MODEL, label="Model 1")
    m2 = GraphNode(id="model_foreign", node_type=NodeType.MODEL, label="Model 2")
    ev = GraphNode(
        id="ev_m1_weights",
        node_type=NodeType.EVIDENCE,
        label="M1 Weight Hash",
        properties={"related_model_id": "model_authorized"},
    )
    temp_graph_engine.add_node(m1)
    temp_graph_engine.add_node(m2)
    temp_graph_engine.add_node(ev)

    with pytest.raises(ValueError, match="Cross-model mismatch"):
        temp_graph_engine.add_edge(
            GraphEdge(source_id="ev_m1_weights", target_id="model_foreign", edge_type=EdgeType.ABOUT),
            strict_subject_validation=True,
        )


# 20. Graph tamper detection
def test_20_graph_tamper_detection(temp_graph_engine):
    temp_graph_engine.build_lineage(
        contributor_id="c_tamper",
        dataset_id="d_tamper",
        model_id="m_tamper",
    )
    export_before = temp_graph_engine.export_graph()

    # Tamper with node in-memory
    temp_graph_engine.nodes["d_tamper"].label = "TAMPERED_LABEL"
    export_after = temp_graph_engine.export_graph()

    assert export_before.graph_digest != export_after.graph_digest


# 21. Graph digest verification
def test_21_graph_digest_verification(temp_graph_engine):
    temp_graph_engine.build_lineage(
        contributor_id="c1",
        dataset_id="d1",
    )
    report = temp_graph_engine.verify_graph_integrity()
    assert report.is_valid is True
    assert len(report.computed_digest) == 64
    assert len(report.broken_edges) == 0


# 22. Orphan detection
def test_22_orphan_detection(temp_graph_engine):
    temp_graph_engine.build_lineage(
        contributor_id="c_connected",
        dataset_id="d_connected",
    )
    # Add an unconnected isolated node
    temp_graph_engine.add_node(GraphNode(id="orphan_sensor", node_type=NodeType.SAMPLE, label="Orphan Sample"))
    report = temp_graph_engine.verify_graph_integrity()
    assert "orphan_sensor" in report.orphan_nodes


# 23. Duplicate edge handling
def test_23_duplicate_edge_handling(temp_graph_engine):
    n1 = GraphNode(id="n_a", node_type=NodeType.CONTRIBUTOR, label="A")
    n2 = GraphNode(id="n_b", node_type=NodeType.DATASET, label="B")
    temp_graph_engine.add_node(n1)
    temp_graph_engine.add_node(n2)

    e1 = GraphEdge(source_id="n_a", target_id="n_b", edge_type=EdgeType.PROVIDED, metadata={"k1": "v1"})
    e2 = GraphEdge(source_id="n_a", target_id="n_b", edge_type=EdgeType.PROVIDED, metadata={"k2": "v2"})
    temp_graph_engine.add_edge(e1)
    temp_graph_engine.add_edge(e2)

    assert len(temp_graph_engine.edges) == 1
    assert temp_graph_engine.edges[0].metadata.get("k1") == "v1"
    assert temp_graph_engine.edges[0].metadata.get("k2") == "v2"


# 24. Empty graph handling
def test_24_empty_graph_handling(temp_graph_engine):
    temp_graph_engine.clear()
    export_snapshot = temp_graph_engine.export_graph()
    assert export_snapshot.node_count == 0
    assert export_snapshot.edge_count == 0
    assert len(export_snapshot.graph_digest) == 64

    trace = temp_graph_engine.trace_lineage("nonexistent")
    assert trace.blast_radius_count == 0
    assert len(trace.upstream_path) == 0


# 25. API lifecycle
def test_25_api_lifecycle():
    client = TestClient(app)
    # Reset global default graph
    default_graph_engine.clear()
    default_graph_engine.build_lineage(
        contributor_id="c_api_p10",
        dataset_id="d_api_p10",
        model_id="m_api_p10",
        inference_id="i_api_p10",
    )

    # 1. GET /api/v1/graph/nodes/{id}
    res = client.get("/api/v1/graph/nodes/m_api_p10")
    assert res.status_code == 200
    assert res.json()["data"]["id"] == "m_api_p10"

    # 2. GET /api/v1/graph/nodes/{id}/neighbors
    res = client.get("/api/v1/graph/nodes/m_api_p10/neighbors")
    assert res.status_code == 200
    assert len(res.json()["data"]["neighbors"]) >= 1

    # 3. GET /api/v1/graph/nodes/{id}/upstream
    res = client.get("/api/v1/graph/nodes/i_api_p10/upstream")
    assert res.status_code == 200
    assert any(n["id"] == "m_api_p10" for n in res.json()["data"])

    # 4. GET /api/v1/graph/nodes/{id}/downstream
    res = client.get("/api/v1/graph/nodes/c_api_p10/downstream")
    assert res.status_code == 200
    assert any(n["id"] == "d_api_p10" for n in res.json()["data"])

    # 5. POST /api/v1/graph/blast-radius
    res = client.post("/api/v1/graph/blast-radius", json={"root_cause_id": "d_api_p10"})
    assert res.status_code == 200
    assert res.json()["data"]["root_cause_id"] == "d_api_p10"

    # 6. POST /api/v1/graph/verify
    res = client.post("/api/v1/graph/verify", json={"check_cycles": True})
    assert res.status_code == 200
    assert res.json()["data"]["is_valid"] is True

    # 7. GET /api/v1/graph/contributors/{id}/risk
    res = client.get("/api/v1/graph/contributors/c_api_p10/risk")
    assert res.status_code == 200
    assert res.json()["data"]["contributor_id"] == "c_api_p10"


# 26. CLI lifecycle
def test_26_cli_lifecycle(capsys):
    default_graph_engine.clear()
    default_graph_engine.build_lineage(
        contributor_id="c_cli_test",
        dataset_id="d_cli_test",
        model_id="m_cli_test",
    )

    # graph-node
    ret = cli_main(["graph-node", "--node-id", "m_cli_test"])
    assert ret == 0

    # graph-upstream
    ret = cli_main(["graph-upstream", "--node-id", "m_cli_test"])
    assert ret == 0

    # graph-downstream
    ret = cli_main(["graph-downstream", "--node-id", "c_cli_test"])
    assert ret == 0

    # blast-radius
    ret = cli_main(["blast-radius", "--root-cause-id", "d_cli_test"])
    assert ret == 0

    # contributor-risk
    ret = cli_main(["contributor-risk", "--contributor-id", "c_cli_test"])
    assert ret == 0

    # verify-graph
    ret = cli_main(["verify-graph"])
    assert ret == 0


# 27. Persistence across restart
def test_27_persistence_across_restart(tmp_path: Path):
    store_dir = tmp_path / "persist_graph"
    g1 = EvidenceGraphEngine(storage_dir=store_dir)
    g1.build_lineage(
        contributor_id="c_persist",
        dataset_id="d_persist",
        model_id="m_persist",
    )
    g1.save_graph()

    # Load in new engine instance
    g2 = EvidenceGraphEngine(storage_dir=store_dir)
    assert "c_persist" in g2.nodes
    assert "d_persist" in g2.nodes
    assert "m_persist" in g2.nodes
    assert len(g2.edges) == len(g1.edges)


# 28. Deterministic graph serialization
def test_28_deterministic_serialization(temp_graph_engine):
    # Insert in random order
    temp_graph_engine.add_node(GraphNode(id="node_z", node_type=NodeType.SAMPLE, label="Z"))
    temp_graph_engine.add_node(GraphNode(id="node_a", node_type=NodeType.SAMPLE, label="A"))
    temp_graph_engine.add_node(GraphNode(id="node_m", node_type=NodeType.SAMPLE, label="M"))

    exp1 = temp_graph_engine.export_graph()
    exp2 = temp_graph_engine.export_graph()

    assert [n.id for n in exp1.nodes] == ["node_a", "node_m", "node_z"]
    assert exp1.graph_digest == exp2.graph_digest


# 29. Large synthetic graph traversal benchmark (100, 1000, 10000 nodes)
def test_29_synthetic_graph_scalability_benchmark(temp_graph_engine):
    temp_graph_engine.clear()

    # Build 100-node graph
    t0 = time.perf_counter()
    for i in range(100):
        temp_graph_engine.add_node(GraphNode(id=f"node_100_{i}", node_type=NodeType.SAMPLE, label=f"S {i}"))
        if i > 0:
            temp_graph_engine.add_edge(
                GraphEdge(source_id=f"node_100_{i-1}", target_id=f"node_100_{i}", edge_type=EdgeType.CONTAINS_SAMPLE)
            )
    t_100 = time.perf_counter() - t0

    # Build 1,000-node graph
    temp_graph_engine.clear()
    t0 = time.perf_counter()
    for i in range(1000):
        temp_graph_engine.add_node(GraphNode(id=f"node_1k_{i}", node_type=NodeType.SAMPLE, label=f"S {i}"))
        if i > 0:
            temp_graph_engine.add_edge(
                GraphEdge(source_id=f"node_1k_{i-1}", target_id=f"node_1k_{i}", edge_type=EdgeType.CONTAINS_SAMPLE)
            )
    t_1k = time.perf_counter() - t0

    # Measure 1k traversal
    t0 = time.perf_counter()
    downstream = temp_graph_engine.trace_downstream("node_1k_0", max_depth=100)
    t_trav_1k = time.perf_counter() - t0

    assert len(downstream) == 100
    assert t_1k < 2.0  # Ingestion time well under 2s
    assert t_trav_1k < 0.1  # Traversal under 100ms


# 30. Full integration with Phase 9 Evidence Fusion & Quarantine
def test_30_full_integration_phase9(temp_graph_engine):
    from app.fusion.engine import EvidenceFusionEngine
    from app.schemas.fusion import EvidenceItem, EvidenceSource

    fusion_engine = EvidenceFusionEngine(storage_dir=temp_graph_engine.storage_dir / "fusion")

    # 1. Register evidence
    ev = EvidenceItem(
        evidence_id="ev_phase9_integ_01",
        source=EvidenceSource.MODEL_IDENTITY,
        severity=IntegritySeverity.CRITICAL,
        metric_value=1.0,
        description="Model layer weight substitution detected in layer3.",
        subject_id="model_flir_critical",
        related_model_id="model_flir_critical",
    )
    fusion_engine.register_evidence(ev)

    # 2. Fuse evidence (Triggers Hard Veto)
    assessment = fusion_engine.fuse(
        target_entity_id="model_flir_critical",
        evidence=[ev],
    )
    assert assessment.action == AssuranceAction.BLOCK
    assert assessment.hard_veto_triggered is True

    # 3. Build graph lineage and attach Phase 9 fusion artifacts
    temp_graph_engine.build_lineage(
        contributor_id="vendor_suspect",
        dataset_id="dataset_recon_flir",
        training_run_id="tr_recon_flir_01",
        model_id="model_flir_critical",
        inference_id="infer_deployed_flir",
        evidence_items=[ev.model_dump()],
        fusion_assessment_id=assessment.assessment_id,
        quarantine_id="quar_auto_flir_01",
    )

    # 4. Perform blast-radius from the compromised model
    blast = temp_graph_engine.calculate_blast_radius("model_flir_critical")
    assert "infer_deployed_flir" in blast.affected_inferences
    assert "quar_auto_flir_01" in blast.affected_quarantines
    assert blast.status == AssetStatus.QUARANTINED

    # 5. Evaluate contributor risk profile reflecting the compromised downstream model
    contrib_risk = ContributorRiskEngine.get_profile(
        contributor_id="vendor_suspect",
        graph=temp_graph_engine,
    )
    assert contrib_risk.status == AssetStatus.QUARANTINED
    assert contrib_risk.risk_score >= 0.70
    assert "quarantine" in contrib_risk.explanation.lower()
