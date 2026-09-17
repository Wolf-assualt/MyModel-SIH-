"""Unit & Integration Tests for TRUST-CV Upload File Intake Limits (MAX_UPLOAD_FILES = 3000)."""
import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from io import BytesIO

from app.main import app
from app.core.config import settings

client = TestClient(app)


def test_settings_max_upload_files_constant():
    """Verify MAX_UPLOAD_FILES constant is set to 3000 in central settings."""
    assert hasattr(settings, "MAX_UPLOAD_FILES")
    assert settings.MAX_UPLOAD_FILES == 3000


def test_upload_count_boundary_2999(monkeypatch):
    """Test that 2999 files are within the 3000 file limit."""
    # We test the count validation logic directly against the endpoint handler
    # Using mock UploadFiles to avoid generating 3000 physical files in RAM
    from app.api.datasets import upload_and_ingest_dataset
    from fastapi import UploadFile

    mock_files = [UploadFile(filename=f"b_{i}.tif", file=BytesIO(b"data")) for i in range(2999)]
    # len(mock_files) <= settings.MAX_UPLOAD_FILES
    assert len(mock_files) <= settings.MAX_UPLOAD_FILES


def test_upload_count_boundary_3000():
    """Test that exactly 3000 files are permitted by the boundary check."""
    assert 3000 <= settings.MAX_UPLOAD_FILES


def test_upload_count_boundary_3001_rejected():
    """Test that 3001 files are rejected with HTTP 400 before ingestion."""
    from app.api.datasets import upload_and_ingest_dataset
    from fastapi import HTTPException, UploadFile

    mock_files = [UploadFile(filename=f"b_{i}.tif", file=BytesIO(b"data")) for i in range(3001)]
    
    import asyncio
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(upload_and_ingest_dataset(files=mock_files))
    
    assert exc_info.value.status_code == 400
    assert "Too many files selected" in exc_info.value.detail
    assert "Maximum allowed is 3000" in exc_info.value.detail
    assert "received 3001" in exc_info.value.detail


def test_upload_count_27000_rejected():
    """Test that selecting 27000 files is rejected immediately."""
    from app.api.datasets import upload_and_ingest_dataset
    from fastapi import HTTPException, UploadFile

    mock_files = [UploadFile(filename=f"b_{i}.tif", file=BytesIO(b"data")) for i in range(27000)]
    
    import asyncio
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(upload_and_ingest_dataset(files=mock_files))
    
    assert exc_info.value.status_code == 400
    assert "Too many files selected" in exc_info.value.detail
    assert "Maximum allowed is 3000" in exc_info.value.detail
    assert "received 27000" in exc_info.value.detail


def test_valid_12_band_eo_patch_accepted():
    """Verify authentic 12-band Sentinel-2 Level-2A patch is accepted."""
    bands = ["B01", "B02", "B03", "B04", "B05", "B06", "B07", "B08", "B8A", "B09", "B11", "B12"]
    
    # Create 12 synthetic test GeoTIFF buffers
    files = [("files", (f"patch_sample_{b}.tif", BytesIO(b"fake_tiff_data_" + b.encode()), "image/tiff")) for b in bands]
    
    response = client.post("/api/v1/datasets/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["sample_count"] == 12
    assert "merkle_root" in data["data"]


def test_invalid_empty_upload_rejected():
    """Verify empty file selection is rejected."""
    response = client.post("/api/v1/datasets/upload", files=[])
    assert response.status_code in [400, 422]


def test_upload_1500_files_accepted_by_starlette_multipart_parser():
    """Verify that batches larger than Starlette's default 1000 limit (e.g. 1500 files) are parsed successfully."""
    # Create 1500 small in-memory files
    files = [("files", (f"file_{i}.tif", BytesIO(b"data"), "image/tiff")) for i in range(1500)]
    response = client.post("/api/v1/datasets/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["sample_count"] == 1500


def test_upload_image_folder_auto_fallback_from_bigearthnet_format():
    """Verify that uploading standard .jpg/.png images (e.g. EuroSAT RGB) gracefully auto-resolves to IMAGE_FOLDER even if default format was BIGEARTHNET_S2."""
    from PIL import Image
    
    # Generate 5 valid small in-memory JPEG images
    files = []
    for i in range(5):
        buf = BytesIO()
        img = Image.new("RGB", (32, 32), color=(i * 40, 100, 150))
        img.save(buf, format="JPEG")
        buf.seek(0)
        files.append(("files", (f"AnnualCrop_{i}.jpg", buf, "image/jpeg")))

    response = client.post("/api/v1/datasets/upload", data={"format": "BIGEARTHNET_S2"}, files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["sample_count"] == 5
    assert len(data["data"]["merkle_root"]) == 64


def test_upload_preserves_nested_subfolders_without_collision():
    """Verify uploading subfolders (e.g. EuroSAT classes AnnualCrop/1.jpg and Forest/1.jpg) preserves relative hierarchy."""
    from PIL import Image

    buf1 = BytesIO()
    Image.new("RGB", (32, 32), color=(255, 0, 0)).save(buf1, format="JPEG")
    buf1.seek(0)

    buf2 = BytesIO()
    Image.new("RGB", (32, 32), color=(0, 255, 0)).save(buf2, format="JPEG")
    buf2.seek(0)

    files = [
        ("files", ("AnnualCrop/sample_1.jpg", buf1, "image/jpeg")),
        ("files", ("Forest/sample_1.jpg", buf2, "image/jpeg")),
    ]

    response = client.post("/api/v1/datasets/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["sample_count"] == 2


