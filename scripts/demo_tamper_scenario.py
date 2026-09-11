"""TRUST-CV Phase 16: Live Defensive Tamper & Hard-Veto Demonstration.

Demonstrates:
1. Pristine BigEarthNet-S2 EO patch batch ingestion and Merkle root sealing
2. Successful cryptographic baseline verification (PASS)
3. Controlled adversarial single-byte injection into Band 4 (Red) GeoTIFF
4. Immediate Merkle root divergence and tamper localization
5. Multi-domain evidence generation with HARD-VETO precedence
6. Automatic Gatekeeper BLOCK and QUARANTINE disposition
7. Provenance Graph lineage tracing and Blast-Radius impact calculation
8. Sealed Forensic Assurance Report generation and verification
9. Adversarial tampering of the forensic report and signature rejection
"""
import os
import sys
import tempfile
import json
from pathlib import Path
import numpy as np
from PIL import Image

backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.crypto.canonical import canonical_json_hash
from app.datasets.bigearthnet import BigEarthNetS2Adapter, SENTINEL2_BANDS, BAND_RESOLUTIONS
from app.datasets.engine import default_ingestion_engine
from app.schemas.dataset import DatasetFormat
from app.fusion.engine import default_fusion_engine
from app.schemas.fusion import EvidenceItem, EvidenceSource, AssuranceRiskLevel, AssuranceAction
from app.schemas.integrity import IntegritySeverity
from app.schemas.base import AssetStatus
from app.graph.engine import default_graph_engine
from app.schemas.graph import GraphNode, GraphEdge, NodeType, EdgeType
from app.reports.engine import default_report_engine


def create_patch(parent_dir: Path, patch_name: str) -> Path:
    patch_dir = parent_dir / patch_name
    patch_dir.mkdir(parents=True, exist_ok=True)
    for band in SENTINEL2_BANDS:
        band_file = patch_dir / f"{patch_name}_{band}.tif"
        res = BAND_RESOLUTIONS.get(band, 10)
        dim = 1200 // res
        arr = np.full((dim, dim), 100, dtype=np.uint8)
        img = Image.fromarray(arr, mode="L")
        img.save(band_file)

    meta_file = patch_dir / f"{patch_name}_labels_metadata.json"
    meta_data = {
        "labels": ["Coniferous forest"],
        "tile_source": f"S2A_MSIL2A_20170717_{patch_name}",
        "acquisition_time": "2017-07-17 11:33:21",
        "coordinates": {"ulx": 484800.0, "uly": 5462280.0, "lrx": 486000.0, "lry": 5461080.0},
        "projection": "EPSG:32630",
    }
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=2)
    return patch_dir


def run_tamper_demo() -> bool:
    print("=" * 80)
    print("  TRUST-CV: DEFENSIVE TAMPER & HARD-VETO ASSURANCE DEMONSTRATION")
    print("=" * 80)

    with tempfile.TemporaryDirectory() as tmp_root:
        root_path = Path(tmp_root)
        eo_dir = root_path / "Sentinel2_Target_Batch"
        eo_dir.mkdir()

        # Step 1: Ingest pristine EO dataset
        print("\n[*] Step 1: Ingesting & Sealing Pristine BigEarthNet-S2 Patch...")
        create_patch(eo_dir, "S2A_Patch_Alpha")
        create_patch(eo_dir, "S2A_Patch_Beta")

        manifest = default_ingestion_engine.ingest(
            dataset_name="Target_EO_Recon_Dataset",
            format=DatasetFormat.BIGEARTHNET_S2,
            contributor_id="sensor_payload_unit_04",
            source_path=str(eo_dir),
        )
        print(f"    [+] Ingested Batch ID:       {manifest.batch_id}")
        print(f"    [+] Manifest Merkle Root:    {manifest.merkle_root}")

        # Step 2: Verify pristine dataset
        print("\n[*] Step 2: Verifying Cryptographic Baseline...")
        res_initial = default_ingestion_engine.verify_manifest(manifest.batch_id)
        print(f"    [+] Calculated Root:         {res_initial.calculated_root}")
        print(f"    [+] Integrity Status:        {'PASS (Bit-Exact Match)' if res_initial.valid else 'FAIL'}")
        assert res_initial.valid is True

        # Step 3: Inject controlled byte tampering into Band 4 (Red)
        print("\n[*] Step 3: Simulating Adversarial Tampering: Mutating B04 (Red band) in S2A_Patch_Alpha...")
        tampered_band = eo_dir / "S2A_Patch_Alpha" / "S2A_Patch_Alpha_B04.tif"
        with open(tampered_band, "ab") as f:
            f.write(b"\xDE\xAD\xBE\xEF_ADVERSARIAL_INJECTION")
        print(f"    [!] Appended malicious payload to {tampered_band.name}")

        # Step 4: Re-audit dataset integrity
        print("\n[*] Step 4: Re-auditing Dataset Cryptographic Manifest...")
        res_tampered = default_ingestion_engine.verify_manifest(manifest.batch_id)
        print(f"    [!] Calculated Merkle Root:  {res_tampered.calculated_root}")
        print(f"    [!] Manifest Merkle Root:    {manifest.merkle_root}")
        print(f"    [!] Verification Status:     {'VALID' if res_tampered.valid else 'TAMPERED / FAILED'}")
        print(f"    [!] Flagged Samples:         {res_tampered.tampered_samples}")
        assert res_tampered.valid is False

        # Step 5: Multi-Domain Evidence Fusion with Hard-Veto
        print("\n[*] Step 5: Ingesting Evidence & Triggering Hard-Veto Gatekeeper...")
        evidence_list = [
            EvidenceItem(
                evidence_id="ev_tamper_alert_01",
                source=EvidenceSource.DATA_INTEGRITY,
                evidence_type="BYTE_LEVEL_TAMPERING",
                severity=IntegritySeverity.CRITICAL,
                subject_id=manifest.batch_id,
                confidence=1.0,
                metadata={"hard_veto": True, "tampered_sample": "S2A_Patch_Alpha"},
            ),
            EvidenceItem(
                evidence_id="ev_benign_sensor_01",
                source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
                evidence_type="NOMINAL_SENSOR_METRICS",
                severity=IntegritySeverity.LOW,
                subject_id=manifest.batch_id,
                confidence=0.95,
            ),
        ]
        assessment = default_fusion_engine.fuse(
            target_entity_id=manifest.batch_id,
            evidence=evidence_list,
        )
        print(f"    [!] Hard-Veto Triggered:     {assessment.hard_veto_triggered}")
        print(f"    [!] Operational Risk:        {assessment.risk_level.value}")
        print(f"    [!] Gatekeeper Action:       {assessment.action.value} (Hard Veto overrides benign scores)")
        print(f"    [!] Asset Verdict:           {assessment.verdict.value}")
        assert assessment.action == AssuranceAction.BLOCK
        assert assessment.verdict == AssetStatus.QUARANTINED

        # Step 6: Provenance Graph & Blast Radius
        print("\n[*] Step 6: Calculating Downstream Blast-Radius & Affected Dependencies...")
        default_graph_engine.build_lineage(
            contributor_id="sensor_payload_unit_04",
            dataset_id=manifest.batch_id,
            model_id="model_tactical_recon",
            inference_id="infer_mission_run_99",
        )

        blast_report = default_graph_engine.calculate_blast_radius(manifest.batch_id)
        print(f"    [+] Root Cause Investigated: {blast_report.root_cause_id}")
        print(f"    [+] Downstream Blast Count:  {blast_report.total_downstream_count} assets potentially affected")
        print(f"    [+] Affected Models:         {blast_report.affected_models}")
        print(f"    [+] Affected Inferences:     {blast_report.affected_inferences}")
        print(f"    [+] Classification Status:   POTENTIALLY AFFECTED / REQUIRES REVIEW")

        # Step 7: Sealed Forensic Assurance Report
        print("\n[*] Step 7: Generating Signed Forensic Assurance Incident Report...")
        report = default_report_engine.generate_report(
            target_asset_id=manifest.batch_id,
            target_asset_type="DATASET",
            assessment=assessment,
        )
        print(f"    [+] Sealed Report ID:        {report.report_id}")
        print(f"    [+] Canonical Digest:        {report.report_digest}")
        print(f"    [+] Digital Signature:       {report.signature[:32]}... (ECDSA SECP256R1)")

        verif_clean = default_report_engine.verify_report(report)
        print(f"    [+] Report Verification:     {'VALID' if verif_clean.is_valid else 'INVALID'}")
        assert verif_clean.is_valid is True

        # Step 8: Adversarial Report Modification Detection
        print("\n[*] Step 8: Simulating Malicious Tampering with Forensic Report (Flipping Verdict to ACCEPT)...")
        report.risk_score = 0.01
        report.overall_verdict = AssetStatus.ACCEPTED
        verif_tampered = default_report_engine.verify_report(report)
        print(f"    [!] Content Digest Match:    {'PASS' if verif_tampered.digest_match else 'FAIL (Tampering Detected)'}")
        print(f"    [!] Signature Valid:         {'PASS' if verif_tampered.signature_valid else 'FAIL (Signature Broken)'}")
        print(f"    [!] Final Report Status:     {'VALID' if verif_tampered.is_valid else 'REJECTED / TAMPERED'}")
        assert verif_tampered.is_valid is False

        print("\n" + "=" * 80)
        print("  DEFENSIVE TAMPER DEMONSTRATION COMPLETE: ALL INTEGRITY DEFENSES VERIFIED")
        print("=" * 80)
        return True


if __name__ == "__main__":
    success = run_tamper_demo()
    sys.exit(0 if success else 1)
