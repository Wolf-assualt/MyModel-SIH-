"""Comprehensive End-to-End Pipeline Integration and Hardening Test Suite.

Validates:
1. Full-lifecycle clean asset acceptance across all 11 core subsystems.
2. Full-lifecycle attack interception and quarantine enforcement.
3. Hash chain tamper stress testing with broken block localization.
4. Offline air-gapped operations and telemetry benchmarking.
"""
import json
from pathlib import Path
import numpy as np
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from app.core.hardening import SystemIntegrityAuditor
from app.crypto.chain import HashChain
from app.graph.engine import default_graph_engine
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.fusion import EvidenceItem, EvidenceSource
from app.schemas.graph import GraphEdge, GraphNode, NodeType, EdgeType
from app.schemas.integrity import IntegritySeverity


@pytest.fixture
def client():
    """FastAPI TestClient for API route validation."""
    return TestClient(app)


def test_full_lifecycle_clean_asset_acceptance(tmp_path: Path, client: TestClient):
    """Verify that a clean CV asset traverses all 11 subsystems with zero defects and is ACCEPTED."""
    # -------------------------------------------------------------
    # Step 1: Create clean dataset images and ingest directory
    # -------------------------------------------------------------
    ds_dir = tmp_path / "clean_recon_dataset"
    ds_dir.mkdir(parents=True, exist_ok=True)

    for i in range(4):
        img_arr = np.zeros((64, 64, 3), dtype=np.uint8)
        img_arr[:32, :] = 120 + i * 10
        img_arr[32:, :] = 40 + i * 10
        Image.fromarray(img_arr).save(ds_dir / f"frame_{i:03d}.png")

    ingest_payload = {
        "dataset_name": "Recon_Patrol_Dataset_Alpha",
        "format": "IMAGE_FOLDER",
        "contributor_id": "vendor_lockheed_defense",
        "source_path": str(ds_dir),
    }
    res_ingest = client.post("/api/v1/datasets/ingest", json=ingest_payload)
    assert res_ingest.status_code == 200
    ingest_data = res_ingest.json()["data"]
    batch_id = ingest_data["batch_id"]
    merkle_root = ingest_data["merkle_root"]
    assert len(merkle_root) == 64
    assert ingest_data["sample_count"] == 4

    # -------------------------------------------------------------
    # Step 2: Training-Data Integrity Scan
    # -------------------------------------------------------------
    scan_payload = {
        "batch_id": batch_id,
        "duplicate_threshold": 4,
        "trigger_detection_enabled": True,
    }
    res_scan = client.post("/api/v1/integrity/scan", json=scan_payload)
    assert res_scan.status_code == 200
    scan_data = res_scan.json()["data"]
    assert scan_data["overall_health_score"] >= 0.85
    assert scan_data["recommendation"] == AssetStatus.ACCEPTED.value

    # -------------------------------------------------------------
    # Step 3: Model Ingestion and Identity Baseline Registration
    # -------------------------------------------------------------
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_bin = model_dir / "recon_detector_v1.bin"
    model_bin.write_bytes(b"MILITARY_GRADE_DETECTOR_WEIGHTS_TENSOR_GRAPH_1234567890" * 16)

    model_reg_payload = {
        "name": "recon_detector_v1",
        "version": "1.0.0",
        "model_path": str(model_bin),
        "format": "GENERIC_BINARY",
        "is_reference": True,
    }
    res_mod = client.post("/api/v1/models/register", json=model_reg_payload)
    assert res_mod.status_code == 200
    mod_data = res_mod.json()["data"]
    model_id = mod_data["model_id"]
    assert len(mod_data["binary_sha256"]) == 64

    # -------------------------------------------------------------
    # Step 4: Behavioral Fingerprinting
    # -------------------------------------------------------------
    res_fp = client.post(f"/api/v1/fingerprint/generate?model_id={model_id}&count=4&seed=42")
    assert res_fp.status_code == 200
    fp_data = res_fp.json()["data"]
    assert fp_data["model_id"] == model_id
    assert len(fp_data["aggregate_digest"]) == 64

    # -------------------------------------------------------------
    # Step 5: Provenance-Sealed Inference Execution
    # -------------------------------------------------------------
    inf_req = {
        "model_id": model_id,
        "image_sha256": "f" * 64,
        "preprocessing": {
            "target_size": [640, 640],
            "normalization_mean": [0.485, 0.456, 0.406],
            "normalization_std": [0.229, 0.224, 0.225],
            "color_space": "RGB",
        },
    }
    res_inf = client.post("/api/v1/inference/execute", json=inf_req)
    assert res_inf.status_code == 200
    inf_data = res_inf.json()["data"]
    record = inf_data["dna_record"]
    public_key_pem = inf_data["public_key_pem"]
    assert len(record["dna_hash"]) == 64
    assert len(record["signature"]) > 0

    # -------------------------------------------------------------
    # Step 6: Inference DNA Cryptographic Verification
    # -------------------------------------------------------------
    verify_dna_req = {
        "dna_record": record,
        "public_key_pem": public_key_pem,
    }
    res_ver_dna = client.post("/api/v1/inference/verify", json=verify_dna_req)
    assert res_ver_dna.status_code == 200
    dna_ver_data = res_ver_dna.json()["data"]
    assert dna_ver_data["is_valid"] is True
    assert dna_ver_data["hash_integrity_valid"] is True
    assert dna_ver_data["signature_valid"] is True

    # -------------------------------------------------------------
    # Step 7: Distribution-Shift Evaluation
    # -------------------------------------------------------------
    drift_base_req = {
        "baseline_id": f"base_{model_id}",
        "features": {
            "brightness": [0.50] * 20,
            "contrast": [0.40] * 20,
        },
    }
    res_base = client.post("/api/v1/drift/baselines/register", json=drift_base_req)
    assert res_base.status_code == 200

    drift_eval_req = {
        "baseline_id": f"base_{model_id}",
        "target_features": {
            "brightness": [0.50] * 20,
            "contrast": [0.40] * 20,
        },
        "target_batch_id": batch_id,
        "drift_threshold": 0.30,
    }
    res_drift = client.post("/api/v1/drift/evaluate", json=drift_eval_req)
    assert res_drift.status_code == 200
    drift_data = res_drift.json()["data"]
    assert drift_data["detected_drift_type"] == "NO_DRIFT"
    assert drift_data["status"] == AssetStatus.ACCEPTED.value

    # -------------------------------------------------------------
    # Step 8: Multi-Source Evidence Fusion
    # -------------------------------------------------------------
    fusion_payload = {
        "target_entity_id": model_id,
        "evidence_items": [
            {
                "evidence_id": "ev_integrity_01",
                "source": "DATA_INTEGRITY",
                "severity": "LOW",
                "metric_value": 0.05,
                "description": "Clean dataset batch verified.",
            },
            {
                "evidence_id": "ev_fp_02",
                "source": "BEHAVIOURAL_FINGERPRINT",
                "severity": "LOW",
                "metric_value": 0.02,
                "description": "Model behavior matches baseline.",
            },
            {
                "evidence_id": "ev_drift_03",
                "source": "DISTRIBUTION_SHIFT",
                "severity": "LOW",
                "metric_value": 0.01,
                "description": "Zero distribution shift detected.",
            },
        ],
    }
    res_fusion = client.post("/api/v1/fusion/evaluate", json=fusion_payload)
    assert res_fusion.status_code == 200
    fusion_data = res_fusion.json()["data"]
    assessment_id = fusion_data["assessment_id"]
    assert fusion_data["verdict"] == AssetStatus.ACCEPTED.value
    assert fusion_data["risk_score"] < 0.25

    # -------------------------------------------------------------
    # Step 9: Lineage Graph Tracing
    # -------------------------------------------------------------
    # Connect model to batch in graph engine
    default_graph_engine.add_node(GraphNode(id=batch_id, node_type=NodeType.DATASET_BATCH, label="Clean Batch"))
    default_graph_engine.add_node(GraphNode(id=model_id, node_type=NodeType.MODEL, label="Clean Model"))
    default_graph_engine.add_edge(GraphEdge(source_id=model_id, target_id=batch_id, edge_type=EdgeType.TRAINED_ON))

    res_trace = client.get(f"/api/v1/graph/trace/{model_id}")
    assert res_trace.status_code == 200
    trace_data = res_trace.json()["data"]
    assert trace_data["target_id"] == model_id

    # -------------------------------------------------------------
    # Step 10: Assurance Report Generation & Cryptographic Verification
    # -------------------------------------------------------------
    rep_gen_req = {
        "target_asset_id": model_id,
        "target_asset_type": "MODEL",
        "assessment_id": assessment_id,
        "include_limitations": True,
    }
    res_rep = client.post("/api/v1/reports/generate", json=rep_gen_req)
    assert res_rep.status_code == 200
    report_data = res_rep.json()["data"]
    assert report_data["overall_verdict"] == AssetStatus.ACCEPTED.value
    assert len(report_data["signature"]) > 0

    # Verify report integrity
    res_rep_ver = client.post("/api/v1/reports/verify", json={"report": report_data})
    assert res_rep_ver.status_code == 200
    rep_ver_data = res_rep_ver.json()["data"]
    assert rep_ver_data["is_valid"] is True
    assert rep_ver_data["digest_match"] is True
    assert rep_ver_data["signature_valid"] is True


def test_full_lifecycle_attack_interception_and_quarantine(client: TestClient):
    """Verify that a simulated backdoor trigger attack is intercepted and enforces QUARANTINED verdict."""
    # 1. Execute simulated backdoor trigger attack
    atk_req = {
        "attack_type": "BACKDOOR_TRIGGER",
        "target_entity_id": "adversarial_recon_unit_44",
        "intensity": 0.5,
        "target_label": "spoofed_target_vehicle",
    }
    res_atk = client.post("/api/v1/redteam/attack/execute", json=atk_req)
    assert res_atk.status_code == 200
    atk_data = res_atk.json()["data"]
    assert atk_data["attack_type"] == "BACKDOOR_TRIGGER"

    # 2. Verify defense detection via red-team lab
    res_atk_ver = client.post("/api/v1/redteam/attack/verify", json=atk_data)
    assert res_atk_ver.status_code == 200
    atk_ver_data = res_atk_ver.json()["data"]
    assert atk_ver_data["detected_by_engine"] is True
    assert atk_ver_data["detecting_subsystem"] == "DATA_INTEGRITY"
    assert atk_ver_data["assigned_verdict"] == AssetStatus.QUARANTINED.value

    # 3. Fuse evidence and confirm quarantine veto
    fusion_payload = {
        "target_entity_id": atk_data["modified_entity_id"],
        "evidence_items": [
            {
                "evidence_id": "ev_backdoor_crit_01",
                "source": "DATA_INTEGRITY",
                "severity": "CRITICAL",
                "metric_value": 0.98,
                "description": "Trigger backdoor checkerboard patch confirmed across target samples.",
            }
        ],
    }
    res_fusion = client.post("/api/v1/fusion/evaluate", json=fusion_payload)
    assert res_fusion.status_code == 200
    fused = res_fusion.json()["data"]
    assert fused["verdict"] == AssetStatus.QUARANTINED.value
    assert fused["risk_score"] >= 0.85

    # 4. Generate report for quarantined asset
    rep_req = {
        "target_asset_id": atk_data["modified_entity_id"],
        "target_asset_type": "DATASET_BATCH",
        "assessment_id": fused["assessment_id"],
    }
    res_rep = client.post("/api/v1/reports/generate", json=rep_req)
    assert res_rep.status_code == 200
    rep_obj = res_rep.json()["data"]
    assert rep_obj["overall_verdict"] == AssetStatus.QUARANTINED.value

    # 5. Check SOC Dashboard overview reflects alert posture
    res_ov = client.get("/api/v1/dashboard/overview")
    assert res_ov.status_code == 200
    ov_data = res_ov.json()["data"]
    assert ov_data["quarantined_assets"] >= 1
    assert ov_data["system_integrity_status"] == "CRITICAL_ALERT"


def test_hash_chain_tamper_stress(client: TestClient):
    """Verify hash chain integrity across 50 sequential blocks and exact broken block localization."""
    test_chain = HashChain()

    # 1. Append 50 blocks
    for i in range(50):
        test_chain.append(f"block_payload_data_hash_{i:03d}")

    assert len(test_chain.records) == 50

    # 2. Audit intact chain
    audit_clean = SystemIntegrityAuditor.audit_full_hash_chain(test_chain)
    assert audit_clean["valid"] is True
    assert audit_clean["total_blocks"] == 50
    assert audit_clean["broken_index"] is None

    # 3. Tamper with block 25 hash pointer
    test_chain.records[25]["current_hash"] = "0" * 64

    # 4. Re-audit and assert exact detection at index 25
    audit_tampered = SystemIntegrityAuditor.audit_full_hash_chain(test_chain)
    assert audit_tampered["valid"] is False
    assert audit_tampered["broken_index"] == 25

    # 5. Verify via REST endpoint
    res_api_chain = client.get("/api/v1/hardening/audit/chain")
    assert res_api_chain.status_code == 200
    chain_data = res_api_chain.json()["data"]
    assert "valid" in chain_data
    assert "total_blocks" in chain_data


def test_offline_air_gap_operation(client: TestClient):
    """Verify air-gapped readiness and telemetry benchmark metrics with zero external network access."""
    # 1. Audit offline air-gapped posture
    res_off = client.get("/api/v1/hardening/audit/offline")
    assert res_off.status_code == 200
    off_data = res_off.json()["data"]
    assert off_data["offline_mode_active"] is True
    assert off_data["air_gapped"] is True
    assert off_data["external_network_detected"] is False

    # 2. Benchmark throughput and signing metrics
    res_bm = client.get("/api/v1/hardening/benchmark")
    assert res_bm.status_code == 200
    bm_data = res_bm.json()["data"]
    assert bm_data["hashing_throughput_mb_s"] > 0
    assert bm_data["mean_signing_latency_ms"] > 0
    assert bm_data["mean_inference_pipeline_latency_ms"] > 0

    # 3. Validate system health operates fully offline
    res_health = client.get("/api/v1/system/health")
    assert res_health.status_code == 200
    health_data = res_health.json()["data"]
    assert health_data["status"] == "healthy"
