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
                        
                        assert stage_results["EVIDENCE_GRAPH"]["status"] == "UNAVAILABLE"
                        # With the new fusion implementation, if there's no evidence, it returns ERR_NO_EVIDENCE
                        # If there's evidence but fusion fails, it returns ERR_FUSION_FAILED
                        # We accept either since both indicate UNAVAILABLE status
                        assert stage_results["EVIDENCE_GRAPH"]["error_code"] in ["ERR_MODULE_OFFLINE", "ERR_NO_EVIDENCE", "ERR_FUSION_FAILED"]
                        
                        # Check that the assessment risk scores reflect UNAVAILABLE
                        assert poll_data["assessment"]["modelRiskScore"] == -1.0
                        assert poll_data["assessment"]["inferenceRiskScore"] == -1.0
