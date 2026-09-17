"""Tests for Dataset Ingestion Pipeline, parsers, Merkle verification, and API endpoints."""
import json
from pathlib import Path
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from app.datasets.engine import DatasetIngestionEngine
from app.datasets.parsers import COCOParser, DirectoryParser, YOLOParser
from app.main import app
from app.schemas.dataset import DatasetFormat

client = TestClient(app)


def create_dummy_image(path: Path, width: int = 64, height: int = 64, color: str = "red"):
    """Helper to create a minimal valid PNG image."""
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (width, height), color=color)
    img.save(path)


def test_directory_parser(tmp_path):
    """Verify DirectoryParser extracts classified samples and image dimensions."""
    data_dir = tmp_path / "data_dir"
    create_dummy_image(data_dir / "tanks" / "tank1.png", width=128, height=64)
    create_dummy_image(data_dir / "tanks" / "tank2.png", width=64, height=64)
    create_dummy_image(data_dir / "aircraft" / "plane1.jpg", width=100, height=80)

    parser = DirectoryParser()
    records = parser.parse(data_dir)

    assert len(records) == 3
    # Sorted deterministically
    assert records[0].sample_id == "aircraft/plane1.jpg"
    assert records[0].width == 100
    assert records[0].height == 80
    assert records[0].labels == [{"class": "aircraft"}]
    assert len(records[0].sha256_hash) == 64


def test_yolo_parser(tmp_path):
    """Verify YOLOParser parses images with normalized bounding box annotations."""
    yolo_dir = tmp_path / "yolo_data"
    img_path = yolo_dir / "frame_001.png"
    txt_path = yolo_dir / "frame_001.txt"

    create_dummy_image(img_path, width=64, height=64)
    txt_path.write_text("0 0.5 0.5 0.2 0.2\n1 0.8 0.8 0.1 0.1\n", encoding="utf-8")

    parser = YOLOParser()
    records = parser.parse(yolo_dir)

    assert len(records) == 1
    assert len(records[0].labels) == 2
    assert records[0].labels[0]["class_id"] == 0
    assert records[0].labels[0]["bbox_normalized"] == [0.5, 0.5, 0.2, 0.2]
    assert records[0].labels[1]["class_id"] == 1


def test_coco_parser(tmp_path):
    """Verify COCOParser matches image ids with annotations and category metadata."""
    coco_dir = tmp_path / "coco_data"
    create_dummy_image(coco_dir / "img_a.png", width=64, height=64)
    create_dummy_image(coco_dir / "img_b.png", width=64, height=64)

    annotation_file = coco_dir / "annotations.json"
    coco_json = {
        "images": [
            {"id": 101, "file_name": "img_a.png", "width": 64, "height": 64},
            {"id": 102, "file_name": "img_b.png", "width": 64, "height": 64},
        ],
        "categories": [
            {"id": 1, "name": "convoy"},
            {"id": 2, "name": "radar"},
        ],
        "annotations": [
            {"image_id": 101, "category_id": 1, "bbox": [5, 5, 20, 20]},
            {"image_id": 101, "category_id": 2, "bbox": [30, 30, 10, 10]},
        ],
    }
    annotation_file.write_text(json.dumps(coco_json), encoding="utf-8")

    parser = COCOParser()
    records = parser.parse(coco_dir, annotation_file)

    assert len(records) == 2
    assert records[0].sample_id == "101"
    assert len(records[0].labels) == 2
    assert records[0].labels[0]["category"] == "convoy"
    assert records[0].labels[1]["category"] == "radar"


def test_ingestion_engine_and_tamper_detection(tmp_path):
    """Verify full ingestion flow, Merkle root calculation, and tamper detection."""
    dataset_dir = tmp_path / "surveillance_feed"
    img1 = dataset_dir / "cam1.png"
    img2 = dataset_dir / "cam2.png"
    create_dummy_image(img1, width=64, height=64, color="blue")
    create_dummy_image(img2, width=64, height=64, color="green")

    manifests_dir = tmp_path / "manifests"
    engine = DatasetIngestionEngine(manifests_dir=manifests_dir)

    # 1. Ingest
    manifest = engine.ingest(
        dataset_name="Perimeter Surveillance",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="unit-7",
        source_path=str(dataset_dir),
    )

    assert manifest.sample_count == 2
    assert len(manifest.merkle_root) == 64
    assert (manifests_dir / f"{manifest.batch_id}.json").is_file()

    # 2. Verify intact manifest
    verification = engine.verify_manifest(manifest.batch_id)
    assert verification.valid is True
    assert verification.tampered_samples == []
    assert verification.calculated_root == manifest.merkle_root

    # 3. Deliberate file tampering on disk
    img1.write_bytes(b"CORRUPTED_TAMPERED_PIXEL_DATA")

    tampered_verification = engine.verify_manifest(manifest.batch_id)
    assert tampered_verification.valid is False
    assert len(tampered_verification.tampered_samples) == 1
    assert "cam1.png" in tampered_verification.tampered_samples[0]
    assert tampered_verification.calculated_root != manifest.merkle_root


def test_api_dataset_endpoints(tmp_path):
    """Verify /api/v1/datasets/ingest, manifest retrieval, and verification endpoints."""
    dataset_dir = tmp_path / "api_test_dataset"
    create_dummy_image(dataset_dir / "f1.jpg")
    create_dummy_image(dataset_dir / "f2.jpg")

    # Ingest valid directory
    ingest_payload = {
        "dataset_name": "Recon Flight 12",
        "format": "IMAGE_FOLDER",
        "contributor_id": "squadron-3",
        "source_path": str(dataset_dir),
    }
    resp = client.post("/api/v1/datasets/ingest", json=ingest_payload)
    assert resp.status_code == 200
    res_data = resp.json()["data"]
    batch_id = res_data["batch_id"]
    assert res_data["sample_count"] == 2
    assert len(res_data["merkle_root"]) == 64

    # Retrieve manifest
    manifest_resp = client.get(f"/api/v1/datasets/manifest/{batch_id}")
    assert manifest_resp.status_code == 200
    manifest_data = manifest_resp.json()["data"]
    assert manifest_data["batch_id"] == batch_id
    assert manifest_data["dataset_name"] == "Recon Flight 12"
    assert len(manifest_data["samples"]) == 2

    # Verify manifest
    verify_resp = client.get(f"/api/v1/datasets/manifest/{batch_id}/verify")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()["data"]
    assert verify_data["valid"] is True
    assert verify_data["tampered_samples"] == []

    # Invalid directory path check
    bad_resp = client.post(
        "/api/v1/datasets/ingest",
        json={
            "dataset_name": "Bad",
            "format": "IMAGE_FOLDER",
            "contributor_id": "sq",
            "source_path": "/non/existent/path/xyz",
        },
    )
    assert bad_resp.status_code == 400

    # Non-existent batch manifest check
    not_found_resp = client.get("/api/v1/datasets/manifest/non-existent-batch-id")
    assert not_found_resp.status_code == 404
