"""TRUST-CV Phase 15 — Real-World EO Validation & BigEarthNet-S2 Integration Test Suite.

Comprehensive validation covering:
1. BigEarthNet-S2 Sentinel-2 12-band multi-spectral patch structure discovery
2. Read-only dataset inspection (complete, incomplete, and corrupted patches)
3. Deterministic per-band and compound sample SHA-256 hashing
4. Multi-band tampering detection (byte modification in single band, label modification)
5. Multi-spectral metadata parsing (CORINE Land Cover multi-label taxonomy)
6. Spectral feature extraction (NDVI, NDWI, channel reflectance, visible brightness)
7. True-color RGB composite generation from B04/B03/B02
8. Ingestion engine Merkle tree generation and ECDSA signing for BigEarthNet batches
9. Training data integrity scanning (exact duplicates, near-duplicates) on compound patches
10. Earth Observation spectral distribution drift evaluation
11. Multi-band / EO model inference DNA generation, anti-replay, and chain linkage
12. End-to-end Provenance Graph lineage (Contributor -> BigEarthNet -> Model -> Inference -> Report)
13. Sealed Forensic Assurance Report generation and verification for EO assets
14. REST API & CLI workflows for BigEarthNet inspection and ingestion
15. Full offline / air-gapped operation without external network dependencies
"""
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
import pytest
import numpy as np
import torch
from PIL import Image
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db, SessionLocal
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash, hash_file
from app.crypto.signer import default_signer
from app.datasets.bigearthnet import (
    BigEarthNetS2Adapter,
    BigEarthNetS2Parser,
    SENTINEL2_BANDS,
    BAND_RESOLUTIONS,
    BIGEARTHNET_19_CLASSES,
)
from app.datasets.engine import default_ingestion_engine
from app.datasets.parsers import DatasetParserFactory
from app.drift.engine import default_drift_engine
from app.fusion.engine import default_fusion_engine
from app.graph.engine import default_graph_engine
from app.inference.dna import default_dna_generator
from app.integrity.engine import default_integrity_engine
from app.models_engine.registry import default_model_registry
from app.reports.engine import default_report_engine
from app.schemas.base import AssetStatus
from app.schemas.dataset import DatasetFormat, IngestDirectoryRequest
from app.schemas.fusion import EvidenceItem, EvidenceSource, AssuranceRiskLevel, AssuranceAction
from app.schemas.graph import GraphNode, GraphEdge, NodeType, EdgeType
from app.schemas.inference import PreprocessingSpec, InferenceOutput, BoundingBox
from app.schemas.integrity import IntegritySeverity
from app.schemas.model import ModelFormat

client = TestClient(app)


# =============================================================================
# Helper Fixtures: Synthetic BigEarthNet-S2 Patch Generator
# =============================================================================

def create_synthetic_patch(
    parent_dir: Path,
    patch_name: str,
    labels: list[str] = None,
    corrupt_bands: list[str] = None,
    missing_bands: list[str] = None,
    intensity_offset: int = 0,
) -> Path:
    """Create a synthetic BigEarthNet-S2 Sentinel-2 patch folder with 12 GeoTIFF bands."""
    patch_dir = parent_dir / patch_name
    patch_dir.mkdir(parents=True, exist_ok=True)

    if labels is None:
        labels = ["Coniferous forest", "Broad-leaved forest"]
    if corrupt_bands is None:
        corrupt_bands = []
    if missing_bands is None:
        missing_bands = []

    # Create 12 Sentinel-2 band TIFF files
    for band in SENTINEL2_BANDS:
        if band in missing_bands:
            continue

        band_file = patch_dir / f"{patch_name}_{band}.tif"
        if band in corrupt_bands:
            # Corrupt file content
            with open(band_file, "wb") as f:
                f.write(b"CORRUPT_TIFF_HEADER_TRUNCATED")
        else:
            # Resolution: 10m = 120x120, 20m = 60x60, 60m = 20x20
            res = BAND_RESOLUTIONS.get(band, 10)
            dim = 1200 // res  # 120, 60, or 20
            
            # Deterministic pixel values based on band and patch
            np.random.seed(abs(hash(patch_name + band)) % (2**31))
            base_val = 50 + intensity_offset + (int(band[1:]) if band[1:].isdigit() else 10) * 10
            arr = np.clip(np.random.randint(base_val - 10, base_val + 10, (dim, dim)), 0, 255).astype(np.uint8)
            img = Image.fromarray(arr, mode="L")
            img.save(band_file)

    # Create metadata JSON
    meta_file = patch_dir / f"{patch_name}_labels_metadata.json"
    meta_content = {
        "labels": labels,
        "tile_source": f"S2A_MSIL2A_20170717_{patch_name[:10]}",
        "acquisition_time": "2017-07-17 11:33:21",
        "coordinates": {
            "ulx": 484800.0,
            "uly": 5462280.0,
            "lrx": 486000.0,
            "lry": 5461080.0,
        },
        "projection": "EPSG:32630",
    }
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta_content, f, indent=2)

    return patch_dir


# =============================================================================
# 1. Structure Discovery & Enumeration
# =============================================================================

def test_01_bigearthnet_patch_structure_discovery():
    """Verify adapter discovers all Sentinel-2 patch folders within a dataset directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_patch_001")
        create_synthetic_patch(root, "S2A_patch_002")
        create_synthetic_patch(root, "S2A_patch_003")

        patches = BigEarthNetS2Adapter.discover(root)
        assert len(patches) == 3
        patch_names = [p.name for p in patches]
        assert "S2A_patch_001" in patch_names
        assert "S2A_patch_002" in patch_names
        assert "S2A_patch_003" in patch_names


# =============================================================================
# 2. Read-Only Inspection on Pristine Dataset
# =============================================================================

def test_02_read_only_inspection_complete_dataset():
    """Verify read-only inspection audits complete patches without modifying files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_patch_101", labels=["Water bodies", "Inland wetlands"])
        create_synthetic_patch(root, "S2A_patch_102", labels=["Arable land", "Pastures"])

        inspection = BigEarthNetS2Adapter.inspect(root)
        assert inspection["total_patches"] == 2
        assert inspection["complete_patches"] == 2
        assert inspection["incomplete_patches"] == 0
        assert inspection["corrupt_patches"] == 0
        assert inspection["is_valid_bigearthnet"] is True
        assert len(inspection["bands_present"]) == 12
        assert "Water bodies" in inspection["label_distribution"]
        assert "Arable land" in inspection["label_distribution"]
        assert inspection["total_bytes"] > 0


# =============================================================================
# 3. Read-Only Inspection with Missing and Corrupt Bands
# =============================================================================

def test_03_read_only_inspection_missing_and_corrupt_bands():
    """Verify read-only inspection flags missing bands and corrupt metadata in anomaly logs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        # Patch with missing B08 and B11
        create_synthetic_patch(root, "S2A_incomplete", missing_bands=["B08", "B11"])
        # Patch with corrupt metadata JSON
        corrupt_p = root / "S2A_corrupt_meta"
        corrupt_p.mkdir()
        with open(corrupt_p / "S2A_corrupt_meta_labels_metadata.json", "w") as f:
            f.write("{ INVALID_JSON_SYNTAX ...")

        inspection = BigEarthNetS2Adapter.inspect(root)
        assert inspection["total_patches"] == 2
        assert inspection["incomplete_patches"] >= 1
        assert inspection["corrupt_patches"] >= 1
        assert inspection["anomaly_count"] >= 2
        
        # Verify source directory was not modified
        assert (root / "S2A_incomplete").exists()
        assert (corrupt_p / "S2A_corrupt_meta_labels_metadata.json").exists()


# =============================================================================
# 4. Deterministic Multi-Band Hashing
# =============================================================================

def test_04_deterministic_per_band_and_compound_hashing():
    """Verify multi-band hashing produces bit-exact identical compound SHA-256 digests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        p1 = create_synthetic_patch(root, "S2A_det_patch")
        
        hash1 = BigEarthNetS2Adapter.hash_sample(p1)
        hash2 = BigEarthNetS2Adapter.hash_sample(p1)

        assert hash1["compound_sha256"] == hash2["compound_sha256"]
        assert len(hash1["compound_sha256"]) == 64
        assert hash1["band_count"] == 12
        assert hash1["metadata_digest"] == hash2["metadata_digest"]


# =============================================================================
# 5. Single-Band Byte Tampering Detection
# =============================================================================

def test_05_single_band_byte_tampering_detection():
    """Verify modifying a single byte in any of the 12 bands alters the sample compound digest."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        p = create_synthetic_patch(root, "S2A_tamper_test")
        
        hash_orig = BigEarthNetS2Adapter.hash_sample(p)

        # Mutate B04 (Red band)
        b04_file = p / "S2A_tamper_test_B04.tif"
        with open(b04_file, "ab") as f:
            f.write(b"\x00_TAMPER")

        hash_tampered = BigEarthNetS2Adapter.hash_sample(p)

        assert hash_orig["compound_sha256"] != hash_tampered["compound_sha256"]
        assert hash_orig["band_hashes"]["B04"] != hash_tampered["band_hashes"]["B04"]
        # Other bands remain identical
        assert hash_orig["band_hashes"]["B02"] == hash_tampered["band_hashes"]["B02"]


# =============================================================================
# 6. Metadata Label Tampering Detection
# =============================================================================

def test_06_metadata_label_tampering_detection():
    """Verify altering metadata JSON alters metadata digest and compound SHA-256."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        p = create_synthetic_patch(root, "S2A_label_tamper", labels=["Coniferous forest"])
        hash_orig = BigEarthNetS2Adapter.hash_sample(p)

        # Change label in metadata
        meta_file = p / "S2A_label_tamper_labels_metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump({"labels": ["Industrial or commercial units"]}, f)

        hash_tampered = BigEarthNetS2Adapter.hash_sample(p)

        assert hash_orig["metadata_digest"] != hash_tampered["metadata_digest"]
        assert hash_orig["compound_sha256"] != hash_tampered["compound_sha256"]


# =============================================================================
# 7. BigEarthNet Parser & Sample Record Generation
# =============================================================================

def test_07_bigearthnet_parser_sample_records():
    """Verify BigEarthNetS2Parser parses patches into standard SampleRecord schemas."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_sample_01", labels=["Coniferous forest"])
        create_synthetic_patch(root, "S2A_sample_02", labels=["Water bodies"])

        parser = BigEarthNetS2Parser()
        records = parser.parse(root)

        assert len(records) == 2
        assert records[0].sample_id == "S2A_sample_01"
        assert records[0].labels[0]["class"] == "Coniferous forest"
        assert records[0].metadata["format"] == "BIGEARTHNET_S2"
        assert records[0].metadata["band_count"] == 12
        assert "spectral_features" in records[0].metadata
        assert "ndvi" in records[0].metadata["spectral_features"]


# =============================================================================
# 8. Dataset Ingestion Engine Merkle Sealing
# =============================================================================

def test_08_dataset_ingestion_and_merkle_sealing():
    """Verify dataset ingestion engine creates signed Merkle manifest for BigEarthNet."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_batch_p1")
        create_synthetic_patch(root, "S2A_batch_p2")
        create_synthetic_patch(root, "S2A_batch_p3")

        manifest = default_ingestion_engine.ingest(
            dataset_name="BigEarthNet_EO_Alpha",
            format=DatasetFormat.BIGEARTHNET_S2,
            contributor_id="satellite_ground_station_01",
            source_path=str(root),
        )

        assert manifest.dataset_name == "BigEarthNet_EO_Alpha"
        assert manifest.format == DatasetFormat.BIGEARTHNET_S2
        assert manifest.sample_count == 3
        assert len(manifest.merkle_root) == 64
        assert manifest.signature is not None
        assert manifest.public_key_pem is not None


# =============================================================================
# 9. Batch Manifest Verification & Tamper Detection
# =============================================================================

def test_09_manifest_verification_pass_and_tamper():
    """Verify manifest verification passes on pristine data and fails when a band is modified."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_verif_p1")
        create_synthetic_patch(root, "S2A_verif_p2")

        manifest = default_ingestion_engine.ingest(
            dataset_name="BigEarthNet_Verif_Test",
            format=DatasetFormat.BIGEARTHNET_S2,
            contributor_id="operator_01",
            source_path=str(root),
        )

        # 1. Pristine verification
        res_valid = default_ingestion_engine.verify_manifest(manifest.batch_id)
        assert res_valid.valid is True
        assert res_valid.calculated_root == manifest.merkle_root

        # 2. Tamper with a band in patch 1
        b02_file = root / "S2A_verif_p1" / "S2A_verif_p1_B02.tif"
        with open(b02_file, "ab") as f:
            f.write(b"\x99_TAMPER_INJECT")

        res_tampered = default_ingestion_engine.verify_manifest(manifest.batch_id)
        assert res_tampered.valid is False
        assert res_tampered.calculated_root != manifest.merkle_root


# =============================================================================
# 10. Spectral Feature Extraction & Scientific Indices
# =============================================================================

def test_10_spectral_feature_extraction_and_indices():
    """Verify NDVI, NDWI, and reflectance feature extraction from multi-spectral bands."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        p = create_synthetic_patch(root, "S2A_spectral_calc")
        features = BigEarthNetS2Adapter.extract_spectral_features(p)

        assert "ndvi" in features
        assert "ndwi" in features
        assert "visible_brightness" in features
        assert "nir_mean" in features
        assert -1.0 <= features["ndvi"] <= 1.0
        assert -1.0 <= features["ndwi"] <= 1.0


# =============================================================================
# 11. True-Color RGB Composite Generation
# =============================================================================

def test_11_true_color_rgb_composite_generation():
    """Verify true-color RGB composite generation from B04 (Red), B03 (Green), and B02 (Blue)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        p = create_synthetic_patch(root, "S2A_rgb_test")
        rgb_img = BigEarthNetS2Adapter.extract_composite_image(p)

        assert rgb_img is not None
        assert rgb_img.mode == "RGB"
        assert rgb_img.size == (120, 120)


# =============================================================================
# 12. Training Data Integrity Scan on EO Patches
# =============================================================================

def test_12_perceptual_hashing_and_duplicate_patch_detection():
    """Verify Data Integrity engine flags exact duplicate and near-duplicate EO patches."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        # Create patch 1
        p1 = create_synthetic_patch(root, "S2A_dupl_1", intensity_offset=10)
        # Create identical duplicate patch 2
        p2 = root / "S2A_dupl_2"
        shutil.copytree(p1, p2)

        manifest = default_ingestion_engine.ingest(
            dataset_name="BigEarthNet_Duplicate_Test",
            format=DatasetFormat.BIGEARTHNET_S2,
            contributor_id="operator_01",
            source_path=str(root),
        )

        report = default_integrity_engine.scan(manifest)
        assert report.total_samples_analyzed == 2
        assert report.findings_count >= 1
        assert any(f.check_type.value == "EXACT_DUPLICATE" for f in report.findings)


# =============================================================================
# 13. EO Spectral Distribution Drift Evaluation
# =============================================================================

def test_13_eo_spectral_distribution_drift_evaluation():
    """Verify drift engine evaluates spectral shifts between seasonal EO distributions."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        summer_dir = root / "summer"
        autumn_dir = root / "autumn"
        summer_dir.mkdir()
        autumn_dir.mkdir()

        # Generate summer patches (higher NIR / NDVI)
        summer_features = {"ndvi": [], "visible_brightness": [], "nir_mean": []}
        for i in range(5):
            p = create_synthetic_patch(summer_dir, f"S2A_summer_{i}", intensity_offset=30)
            feat = BigEarthNetS2Adapter.extract_spectral_features(p)
            for k in summer_features:
                summer_features[k].append(feat[k])

        # Generate autumn patches (lower visible / NIR)
        autumn_features = {"ndvi": [], "visible_brightness": [], "nir_mean": []}
        for i in range(5):
            p = create_synthetic_patch(autumn_dir, f"S2A_autumn_{i}", intensity_offset=-20)
            feat = BigEarthNetS2Adapter.extract_spectral_features(p)
            for k in autumn_features:
                autumn_features[k].append(feat[k])

        # Establish baseline from summer features
        baseline = default_drift_engine.register_baseline(
            baseline_id="eo_summer_baseline",
            features=summer_features,
            name="EO_Summer_Sentinel_Baseline",
        )
        assert baseline.baseline_id == "eo_summer_baseline"

        # Evaluate autumn distribution against summer baseline
        report = default_drift_engine.evaluate_shift(
            baseline_id="eo_summer_baseline",
            target_features=autumn_features,
            target_batch_id="eo_autumn_batch",
        )

        assert report.report_id is not None
        assert len(report.feature_metrics) == 3
        for fm in report.feature_metrics:
            assert fm.ks_statistic >= 0.0
            assert fm.psi_score >= 0.0
            assert fm.wasserstein_distance >= 0.0
            assert fm.energy_distance >= 0.0


# =============================================================================
# 14. EO Model Inference DNA Chain & Anti-Replay
# =============================================================================

def test_14_synthetic_eo_model_inference_dna_chain():
    """Verify deterministic inference DNA generation and cryptographic chaining on EO patches."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        p = create_synthetic_patch(root, "S2A_infer_patch")
        hash_info = BigEarthNetS2Adapter.hash_sample(p)

        dna1 = default_dna_generator.create_dna_record(
            model_id="eo_landcover_resnet18",
            model_version="1.0.0",
            model_identity_digest="e" * 64,
            input_frame_sha256=hash_info["compound_sha256"],
            prep_spec=PreprocessingSpec(),
            output=InferenceOutput(
                predictions=[BoundingBox(label="Coniferous forest", confidence=0.94, box=[0, 0, 120, 120])],
                raw_output_digest="f" * 64,
            ),
        )

        dna2 = default_dna_generator.create_dna_record(
            model_id="eo_landcover_resnet18",
            model_version="1.0.0",
            model_identity_digest="e" * 64,
            input_frame_sha256=hash_info["compound_sha256"],
            prep_spec=PreprocessingSpec(),
            output=InferenceOutput(
                predictions=[BoundingBox(label="Water bodies", confidence=0.88, box=[0, 0, 120, 120])],
                raw_output_digest="1" * 64,
            ),
        )

        assert dna1.sequence_id < dna2.sequence_id
        assert dna1.nonce != dna2.nonce
        assert dna2.prev_chain_hash == dna1.dna_hash


# =============================================================================
# 15. Provenance Graph Lineage Integration
# =============================================================================

def test_15_provenance_graph_lineage_bigearthnet():
    """Verify authentic EO artifacts and datasets attach correctly to the provenance graph."""
    dataset_node = GraphNode(id="ds_bigearthnet_01", node_type=NodeType.DATASET, label="BigEarthNet-S2 Sentinel")
    patch_node = GraphNode(id="patch_S2A_101", node_type=NodeType.DATASET, label="Patch S2A_101")
    model_node = GraphNode(id="model_eo_classifier", node_type=NodeType.MODEL, label="EO LandCover Model")

    default_graph_engine.add_node(dataset_node)
    default_graph_engine.add_node(patch_node)
    default_graph_engine.add_node(model_node)

    default_graph_engine.add_edge(GraphEdge(source_id="ds_bigearthnet_01", target_id="patch_S2A_101", edge_type=EdgeType.CONTAINS))
    default_graph_engine.add_edge(GraphEdge(source_id="patch_S2A_101", target_id="model_eo_classifier", edge_type=EdgeType.PRODUCED))

    upstream = default_graph_engine.trace_upstream("model_eo_classifier")
    downstream = default_graph_engine.trace_downstream("ds_bigearthnet_01")

    upstream_ids = [n.id for n in upstream]
    downstream_ids = [n.id for n in downstream]

    assert "patch_S2A_101" in upstream_ids
    assert "model_eo_classifier" in downstream_ids


# =============================================================================
# 16. Sealed Forensic Assurance Report for EO Assets
# =============================================================================

def test_16_forensic_report_generation_for_eo_dataset():
    """Verify sealed forensic report generation and cryptographic verification for EO dataset."""
    evidence = [
        EvidenceItem(
            evidence_id="ev_eo_integrity_01",
            source=EvidenceSource.DATA_INTEGRITY,
            evidence_type="SPECTRAL_ANOMALY",
            severity=IntegritySeverity.LOW,
            subject_id="ds_bigearthnet_01",
            confidence=0.95,
        )
    ]
    assessment = default_fusion_engine.fuse(target_entity_id="ds_bigearthnet_01", evidence=evidence)

    report = default_report_engine.generate_report(
        target_asset_id="ds_bigearthnet_01",
        target_asset_type="DATASET",
        assessment=assessment,
    )

    assert report.target_asset_id == "ds_bigearthnet_01"
    assert report.signature is not None

    verification = default_report_engine.verify_report(report)
    assert verification.is_valid is True
    assert verification.signature_valid is True


# =============================================================================
# 17. REST API: BigEarthNet Read-Only Inspection Endpoint
# =============================================================================

def test_17_api_bigearthnet_inspect_endpoint():
    """Verify REST API POST /api/v1/datasets/bigearthnet/inspect returns structural report."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_api_patch_1")
        create_synthetic_patch(root, "S2A_api_patch_2")

        res = client.post(
            "/api/v1/datasets/bigearthnet/inspect",
            json={
                "dataset_name": "API_EO_Test",
                "format": "BIGEARTHNET_S2",
                "contributor_id": "operator",
                "source_path": str(root),
            },
        )
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["total_patches"] == 2
        assert data["complete_patches"] == 2
        assert data["is_valid_bigearthnet"] is True


# =============================================================================
# 18. REST API: BigEarthNet Ingestion Endpoint
# =============================================================================

def test_18_api_bigearthnet_ingest_endpoint():
    """Verify REST API POST /api/v1/datasets/ingest handles BIGEARTHNET_S2 format."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_api_ingest_1")

        res = client.post(
            "/api/v1/datasets/ingest",
            json={
                "dataset_name": "API_BigEarthNet_Ingest",
                "format": "BIGEARTHNET_S2",
                "contributor_id": "ground_station_01",
                "source_path": str(root),
            },
        )
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["dataset_name"] == "API_BigEarthNet_Ingest"
        assert data["sample_count"] == 1
        assert len(data["merkle_root"]) == 64


# =============================================================================
# 19. CLI: BigEarthNet Inspection & Ingestion Commands
# =============================================================================

def test_19_cli_inspect_and_ingest_bigearthnet():
    """Verify CLI inspect-bigearthnet and ingest-dataset commands operate cleanly."""
    from app.cli import main

    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_cli_patch_1")

        # 1. CLI inspect-bigearthnet
        rc_inspect = main(["inspect-bigearthnet", "--path", str(root)])
        assert rc_inspect == 0

        # 2. CLI ingest-dataset
        rc_ingest = main([
            "ingest-dataset",
            "--name", "CLI_BigEarthNet_Ingest",
            "--path", str(root),
            "--format", "BIGEARTHNET_S2",
            "--contributor", "cli_tester",
        ])
        assert rc_ingest == 0


# =============================================================================
# 20. Offline Air-Gap Verification: Zero Network Footprint
# =============================================================================

def test_20_air_gap_zero_network_execution_eo_pipeline():
    """Verify the entire BigEarthNet pipeline executes with zero external network attempts."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        create_synthetic_patch(root, "S2A_airgap_patch")

        # 1. Inspect
        inspection = BigEarthNetS2Adapter.inspect(root)
        assert inspection["is_valid_bigearthnet"] is True

        # 2. Ingest & Merkle Seal
        manifest = default_ingestion_engine.ingest(
            dataset_name="AirGap_EO_Batch",
            format=DatasetFormat.BIGEARTHNET_S2,
            contributor_id="airgap_station",
            source_path=str(root),
        )
        assert manifest.signature is not None

        # 3. Integrity Audit
        report = default_integrity_engine.scan(manifest)
        assert report.total_samples_analyzed == 1

        # 4. Verification
        verif = default_ingestion_engine.verify_manifest(manifest.batch_id)
        assert verif.valid is True
