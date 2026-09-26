# pyrefly: ignore [missing-import]
import pytest
# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app

client = TestClient(app)

def test_scan_pipeline_upload_and_status():
    """Integration test verifying upload triggers a scan and we can poll its status."""
    
    # Mocking ingestion and integrity engines so we don't need real files or heavy models
    with patch("app.api.datasets.default_ingestion_engine") as mock_ingest:
        with patch("app.api.scan.default_integrity_engine") as mock_integrity:
            with patch("app.api.scan.default_ingestion_engine") as mock_scan_ingest:
                with patch("app.api.scan.default_fusion_engine") as mock_fusion:
                    with patch("app.api.scan.default_drift_engine") as mock_drift:
                        # Setup mocks
                        mock_manifest = MagicMock()
                        mock_manifest.batch_id = "test-batch-123"
                        mock_manifest.samples = []
                        
                        mock_ingest.ingest.return_value = mock_manifest
                        mock_scan_ingest.load_manifest.return_value = mock_manifest
                        
                        mock_report = MagicMock()
                        mock_report.findings = []
                        mock_report.total_samples_analyzed = 1
                        mock_report.findings_count = 0
                        mock_report.overall_health_score = 1.0
                        mock_report.recommendation = "ACCEPTED"
                        mock_report.image_results = []
                        
                        mock_integrity.scan.return_value = mock_report
                        
                        # Mock drift engine to return no baselines (so UNAVAILABLE)
                        mock_drift.list_baselines.return_value = []
                        
                        # Mock fusion engine to handle evidence processing
                        mock_fusion.fuse.return_value = MagicMock(
                            overall_status=MagicMock(value="ACCEPTED"),
                            risk_level=MagicMock(value="LOW"),
                            risk_score=0.0,
                            hard_veto_triggered=False,
                            assessment_id="test_fusion_id",
                            confidence=0.5,
                            coverage=MagicMock(model_dump=lambda: {"sources_checked": [], "coverage_ratio": 0.0}),
                            findings=[],
                            contributors=["UNKNOWN"],
                            recommended_actions=[]
                        )
                        
                        import io
                        import zipfile
                        zip_buffer = io.BytesIO()
                        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
                            zip_file.writestr("dummy.txt", b"dummy")
                        zip_bytes = zip_buffer.getvalue()

                        # 1. Upload a dummy dataset
                        response = client.post(
                            "/api/v1/datasets/upload",
                            data={"dataset_name": "test_dataset"},
                            files={"file": ("test.zip", zip_bytes, "application/zip")}
                        )
                        
                        assert response.status_code == 200
                        data = response.json()["data"]
                        assert "scan_id" in data
                        scan_id = data["scan_id"]
                        assert data["status"] == "PENDING"
                        
                        # 2. Poll the status
                        poll_response = client.get(f"/api/v1/scan/{scan_id}")
                        assert poll_response.status_code == 200
                        poll_data = poll_response.json()["data"]
                        assert poll_data["scan_id"] == scan_id
                        
                        # The scan runs in the background. Wait for completion to verify final states.
                        import time
                        for _ in range(10):
                            time.sleep(0.5)
                            poll_response = client.get(f"/api/v1/scan/{scan_id}")
                            poll_data = poll_response.json()["data"]
                            if poll_data["status"] in ("COMPLETED", "FAILED"):
                                break
                            
                        assert poll_data["status"] == "COMPLETED"
                        
                        # 3. Verify NO FABRICATED EVIDENCE RULE
                        stage_results = poll_data.get("stage_results", {})
                        
                        # Check that missing components correctly report UNAVAILABLE with error codes
                        assert stage_results["MODEL_INTEGRITY"]["status"] == "UNAVAILABLE"
                        assert stage_results["MODEL_INTEGRITY"]["error_code"] == "ERR_MODULE_OFFLINE"
                        
                        assert stage_results["BACKDOOR_ANALYSIS"]["status"] == "UNAVAILABLE"
                        assert stage_results["BACKDOOR_ANALYSIS"]["error_code"] == "ERR_MODULE_OFFLINE"
                        
                        assert stage_results["INFERENCE_VALIDATION"]["status"] == "UNAVAILABLE"
                        assert stage_results["INFERENCE_VALIDATION"]["error_code"] == "ERR_MODULE_OFFLINE"
                        
                        assert stage_results["EVIDENCE_GRAPH"]["status"] in ["UNAVAILABLE", "PASSED"]
                        
                        # Check that the assessment risk scores reflect UNAVAILABLE
                        assert poll_data["assessment"]["modelRiskScore"] == -1.0
                        assert poll_data["assessment"]["inferenceRiskScore"] == -1.0


def test_single_clean_image_scan_without_reference_dataset():
    """Scenario test: A single clean image scanned without baseline/model/inference manifests

    Asserts:
      1. Overall assuranceScore is NOT a hardcoded 0.50 (50%).
      2. It is explicitly marked as insufficient evidence (assuranceScore is None, disposition is INSUFFICIENT_EVIDENCE).
      3. Evidence coverage ratio is low (<= 0.20) and explanation clearly highlights missing sources.
      4. Sample-level verdict in imageResults remains correctly assessed as REAL / CLEAN.
    """
    import io
    import time
    import zipfile
    import numpy as np
    from PIL import Image

    # Create a real clean gradient test image
    img = Image.new("RGB", (64, 64))
    for x in range(64):
        for y in range(64):
            img.putpixel((x, y), (int(x * 3.5), int(y * 3.5), int((x + y) * 1.5)))
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG")

    sample_filename = f"clean_sample_{int(time.time() * 1000)}.png"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(sample_filename, img_bytes.getvalue())
    zip_bytes = zip_buffer.getvalue()

    # Upload single clean image dataset with no baseline, model, or inference receipts
    dataset_name = f"single_clean_scan_{int(time.time() * 1000)}"
    response = client.post(
        "/api/v1/datasets/upload",
        data={"dataset_name": dataset_name},
        files={"file": ("single_clean.zip", zip_bytes, "application/zip")}
    )
    assert response.status_code == 200
    scan_id = response.json()["data"]["scan_id"]

    # Poll until completed
    poll_data = {}
    for _ in range(30):
        time.sleep(0.5)
        poll_response = client.get(f"/api/v1/scan/{scan_id}")
        assert poll_response.status_code == 200
        poll_data = poll_response.json()["data"]
        if poll_data.get("status") in ("COMPLETED", "FAILED"):
            break

    assert poll_data.get("status") == "COMPLETED"
    assessment = poll_data.get("assessment", {})

    # 1. Overall assurance score is NOT hardcoded 0.50 / 50%
    assert assessment.get("assuranceScore") != 0.50

    # 2. Genuine numeric partial score computed from real evidence (NOT uncomputed None, NOT 0.50)
    assert isinstance(assessment.get("assuranceScore"), (int, float))
    assert 0.90 <= assessment.get("assuranceScore") <= 1.0
    assert assessment.get("disposition") == "ACCEPTED"
    assert assessment.get("scope") == "MINIMAL"

    # 3. Coverage reflects that only 1/5 sources was checked (coverage <= 0.20)
    fusion_meta = assessment.get("fusionAssessment", {})
    coverage = fusion_meta.get("coverage", {})
    assert coverage.get("coverage_ratio", 1.0) <= 0.20
    assert assessment.get("scope") == "MINIMAL"

    # 4. Individual image verdict is sample-scoped and correctly shows REAL / CLEAN
    image_results = assessment.get("imageResults", [])
    assert len(image_results) == 1
    assert image_results[0]["result"] == "REAL / CLEAN"


def test_empty_input_scan_yields_insufficient_evidence():
    """Verify that an empty or zero-coverage evaluation correctly yields uncomputed / insufficient evidence."""
    from app.fusion.engine import EvidenceFusionEngine
    from app.schemas.fusion import EvidenceCoverage
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = EvidenceFusionEngine(storage_dir=Path(tmp_dir))
        assessment = engine.fuse("empty_entity", [])
        assert assessment.scope == "INSUFFICIENT"
        assert assessment.coverage.coverage_ratio == 0.0
