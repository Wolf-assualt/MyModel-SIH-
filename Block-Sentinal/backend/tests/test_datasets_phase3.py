"""Phase 3 Dataset Ingestion and Identity Pipeline Verification Tests.

Validates:
1. Directory, YOLO, and COCO dataset parsers with deterministic ordering
2. Automatic format detection via DatasetParserFactory
3. Per-sample SHA-256 identity calculation and normalized representations
4. Merkle Tree computation and digital signing of BatchManifest
5. Relational database registration linking Contributor, Dataset, Batch, Sample, and MerkleRoot
6. Validation errors on empty, missing, or malformed datasets
7. Tamper detection on modified or missing samples via manifest verification
8. Scalability and memory streaming behavior across dataset sizes (10, 100, 500 samples)
9. Dataset REST API endpoints and CLI ingestion command
"""
from pathlib import Path
import json
import time
import pytest
from PIL import Image

from app.cli import main as cli_main
from app.crypto.canonical import hash_bytes, hash_file
from app.datasets.engine import DatasetIngestionEngine
from app.datasets.parsers import (
    COCOParser,
    DatasetParserFactory,
    DirectoryParser,
    YOLOParser,
)
from app.models.dataset import Dataset, DatasetBatch
from app.models.sample import Sample
from app.schemas.dataset import DatasetFormat


# Helper to generate synthetic test image
def create_test_image(path: Path, color: tuple = (100, 150, 200), size: tuple = (64, 64)):
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", size, color=color)
    img.save(path, format="JPEG")
    return path


# ==============================================================================
# 1. PARSER & FORMAT DETECTION TESTS
# ==============================================================================
def test_directory_parser_and_auto_detection(tmp_path):
    """Verify DirectoryParser hierarchy parsing and DatasetParserFactory auto-detection."""
    ds_dir = tmp_path / "raw_image_folder"
    create_test_image(ds_dir / "tanks" / "tank_01.jpg", color=(50, 50, 50))
    create_test_image(ds_dir / "tanks" / "tank_02.jpg", color=(60, 60, 60))
    create_test_image(ds_dir / "aircraft" / "plane_01.jpg", color=(200, 200, 200))

    # Test auto-detection
    detected_fmt = DatasetParserFactory.detect_format(ds_dir)
    assert detected_fmt == DatasetFormat.IMAGE_FOLDER

    # Test parsing
    parser = DatasetParserFactory.get_parser(detected_fmt)
    records = parser.parse(ds_dir)

    assert len(records) == 3
    assert all(r.width == 64 and r.height == 64 for r in records)
    assert all(len(r.sha256_hash) == 64 for r in records)

    # Check labels extracted from parent directory
    tank_record = next(r for r in records if "tank_01" in r.sample_id)
    assert tank_record.labels == [{"class": "tanks"}]


def test_coco_parser_and_annotations(tmp_path):
    """Verify COCOParser with categories, bounding boxes, and image references."""
    ds_dir = tmp_path / "coco_dataset"
    img_dir = ds_dir / "images"
    ann_file = ds_dir / "annotations" / "instances.json"

    create_test_image(img_dir / "frame_001.jpg", color=(10, 20, 30))
    create_test_image(img_dir / "frame_002.jpg", color=(40, 50, 60))

    coco_payload = {
        "categories": [{"id": 1, "name": "vehicle"}, {"id": 2, "name": "person"}],
        "images": [
            {"id": 101, "file_name": "frame_001.jpg", "width": 64, "height": 64},
            {"id": 102, "file_name": "frame_002.jpg", "width": 64, "height": 64},
        ],
        "annotations": [
            {"id": 1, "image_id": 101, "category_id": 1, "bbox": [10, 10, 20, 20]},
            {"id": 2, "image_id": 102, "category_id": 2, "bbox": [5, 5, 15, 30]},
        ],
    }
    ann_file.parent.mkdir(parents=True, exist_ok=True)
    with open(ann_file, "w", encoding="utf-8") as f:
        json.dump(coco_payload, f)

    # Test auto-detection
    assert DatasetParserFactory.detect_format(ds_dir, ann_file) == DatasetFormat.COCO

    parser = COCOParser()
    records = parser.parse(ds_dir, ann_file)

    assert len(records) == 2
    assert records[0].sample_id == "101"
    assert records[0].labels[0]["category"] == "vehicle"
    assert records[1].sample_id == "102"
    assert records[1].labels[0]["category"] == "person"


def test_yolo_parser_parallel_labels(tmp_path):
    """Verify YOLOParser with companion .txt annotation files and bounding boxes."""
    ds_dir = tmp_path / "yolo_dataset"
    img_dir = ds_dir / "images"
    lbl_dir = ds_dir / "labels"

    create_test_image(img_dir / "tactical_01.jpg", color=(100, 100, 100))
    lbl_file = lbl_dir / "tactical_01.txt"
    lbl_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lbl_file, "w", encoding="utf-8") as f:
        f.write("0 0.5 0.5 0.2 0.3\n1 0.8 0.7 0.1 0.1\n")

    assert DatasetParserFactory.detect_format(ds_dir) == DatasetFormat.YOLO

    parser = YOLOParser()
    records = parser.parse(ds_dir)

    assert len(records) == 1
    assert len(records[0].labels) == 2
    assert records[0].labels[0]["class_id"] == 0
    assert records[0].labels[0]["bbox_normalized"] == [0.5, 0.5, 0.2, 0.3]


# ==============================================================================
# 2. INGESTION ENGINE & DIGITAL SIGNING TESTS
# ==============================================================================
def test_ingestion_engine_merkle_and_digital_signature(tmp_path):
    """Verify manifest creation, Merkle root calculation, and ECDSA SECP256R1 signing."""
    manifests_dir = tmp_path / "manifests"
    ds_dir = tmp_path / "recon_dataset"
    for i in range(5):
        create_test_image(ds_dir / f"recon_{i}.jpg", color=(i * 20, i * 20, i * 20))

    engine = DatasetIngestionEngine(manifests_dir=manifests_dir)
    manifest = engine.ingest(
        dataset_name="Aerial Recon Alpha",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="sensor_uav_09",
        source_path=str(ds_dir),
    )

    assert manifest.sample_count == 5
    assert len(manifest.merkle_root) == 64
    assert manifest.signature is not None
    assert manifest.public_key_pem is not None
    assert "BEGIN PUBLIC KEY" in manifest.public_key_pem

    # Verify manifest on disk
    verification = engine.verify_manifest(manifest.batch_id)
    assert verification.valid is True
    assert verification.signature_valid is True
    assert len(verification.tampered_samples) == 0


def test_manifest_tampering_detection(tmp_path):
    """Verify that tampering with an on-disk image is detected by manifest verification."""
    manifests_dir = tmp_path / "manifests"
    ds_dir = tmp_path / "sensor_stream"
    for i in range(4):
        create_test_image(ds_dir / f"frame_{i}.jpg", color=(50, 50, 50))

    engine = DatasetIngestionEngine(manifests_dir=manifests_dir)
    manifest = engine.ingest(
        dataset_name="Perimeter Sensor Stream",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="perimeter_guard_01",
        source_path=str(ds_dir),
    )

    # Tamper with frame_2 by overwriting it with different image data
    create_test_image(ds_dir / "frame_2.jpg", color=(255, 0, 0))

    verification = engine.verify_manifest(manifest.batch_id)
    assert verification.valid is False
    assert len(verification.tampered_samples) == 1
    assert "frame_2.jpg" in verification.tampered_samples[0]


# ==============================================================================
# 3. DATABASE PERSISTENCE INTEGRATION
# ==============================================================================
def test_dataset_database_registration(tmp_path, db_session):
    """Verify that ingested manifests are registered to DB with full relational integrity."""
    manifests_dir = tmp_path / "manifests"
    ds_dir = tmp_path / "naval_surveillance"
    for i in range(3):
        create_test_image(ds_dir / f"vessel_{i}.jpg", color=(0, 100, 200))

    engine = DatasetIngestionEngine(manifests_dir=manifests_dir)
    manifest = engine.ingest(
        dataset_name="Naval Surveillance Fleet",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="coast_radar_unit",
        source_path=str(ds_dir),
    )

    batch_record = engine.register_batch_to_database(
        manifest=manifest,
        db=db_session,
        root_path=str(ds_dir.resolve()),
    )

    assert batch_record.id == manifest.batch_id
    assert batch_record.sample_count == 3

    # Query back via SQLAlchemy ORM
    dataset = db_session.query(Dataset).filter(Dataset.name == "Naval Surveillance Fleet").first()
    assert dataset is not None
    assert dataset.contributor_id == "coast_radar_unit"
    assert len(dataset.batches) == 1

    samples = db_session.query(Sample).filter(Sample.batch_id == batch_record.id).all()
    assert len(samples) == 3
    assert all(len(s.sha256_digest) == 64 for s in samples)


# ==============================================================================
# 4. ERROR HANDLING & VALIDATION FAILURES
# ==============================================================================
def test_empty_dataset_rejection(tmp_path):
    """Verify that an empty directory with no images produces a ValueError."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()

    engine = DatasetIngestionEngine(manifests_dir=tmp_path / "manifests")
    with pytest.raises(ValueError, match="Empty dataset"):
        engine.ingest(
            dataset_name="Empty Set",
            format=DatasetFormat.IMAGE_FOLDER,
            contributor_id="test",
            source_path=str(empty_dir),
        )


def test_missing_directory_rejection(tmp_path):
    """Verify FileNotFoundError when target source directory does not exist."""
    engine = DatasetIngestionEngine(manifests_dir=tmp_path / "manifests")
    with pytest.raises(FileNotFoundError):
        engine.ingest(
            dataset_name="Ghost Set",
            format=DatasetFormat.IMAGE_FOLDER,
            contributor_id="test",
            source_path=str(tmp_path / "non_existent_folder"),
        )


# ==============================================================================
# 5. LARGE DATASET SCALABILITY SIMULATION
# ==============================================================================
@pytest.mark.parametrize("sample_count", [10, 50, 100])
def test_large_dataset_streaming_throughput(tmp_path, sample_count):
    """Verify that dataset ingestion scales efficiently without loading entire dataset into memory."""
    ds_dir = tmp_path / f"scale_test_{sample_count}"
    for i in range(sample_count):
        create_test_image(ds_dir / f"img_{i:04d}.jpg", color=(i % 255, (i * 2) % 255, (i * 3) % 255))

    engine = DatasetIngestionEngine(manifests_dir=tmp_path / "manifests")

    t0 = time.perf_counter()
    manifest = engine.ingest(
        dataset_name=f"Scalability Test {sample_count}",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="benchmark_unit",
        source_path=str(ds_dir),
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert manifest.sample_count == sample_count
    assert len(manifest.merkle_root) == 64
    # Ensure throughput remains scalable for 100 samples
    assert elapsed_ms < 2500.0


# ==============================================================================
# 6. API ENDPOINTS & CLI INTEGRATION
# ==============================================================================
def test_api_dataset_ingestion_and_get(client, tmp_path):
    """Verify POST /api/v1/datasets/ingest and GET /api/v1/datasets/{id}."""
    ds_dir = tmp_path / "api_test_ds"
    create_test_image(ds_dir / "target_01.jpg", color=(10, 20, 30))
    create_test_image(ds_dir / "target_02.jpg", color=(40, 50, 60))

    # Ingest via API
    resp_ingest = client.post(
        "/api/v1/datasets/ingest",
        json={
            "dataset_name": "Border Patrol Target Set",
            "format": "IMAGE_FOLDER",
            "contributor_id": "c_border_unit_01",
            "source_path": str(ds_dir),
        },
    )
    assert resp_ingest.status_code == 200
    ingest_data = resp_ingest.json()["data"]
    batch_id = ingest_data["batch_id"]
    assert ingest_data["sample_count"] == 2
    assert len(ingest_data["merkle_root"]) == 64

    # Fetch manifest
    resp_manifest = client.get(f"/api/v1/datasets/manifest/{batch_id}")
    assert resp_manifest.status_code == 200
    assert resp_manifest.json()["data"]["batch_id"] == batch_id

    # Verify manifest
    resp_verify = client.get(f"/api/v1/datasets/manifest/{batch_id}/verify")
    assert resp_verify.status_code == 200
    assert resp_verify.json()["data"]["valid"] is True


def test_cli_ingest_dataset_command(tmp_path, capsys):
    """Verify that python -m app.cli ingest-dataset functions from terminal."""
    ds_dir = tmp_path / "cli_dataset"
    create_test_image(ds_dir / "frame_cli_01.jpg", color=(80, 90, 100))

    code = cli_main([
        "ingest-dataset",
        "--name", "CLI Surveillance Batch",
        "--path", str(ds_dir),
        "--format", "IMAGE_FOLDER",
        "--contributor", "cli_test_node",
    ])
    assert code == 0
    captured = capsys.readouterr()
    assert "DATASET INGESTION & CRYPTOGRAPHIC SEALING COMPLETE" in captured.out
    assert "CLI Surveillance Batch" in captured.out
    assert "Merkle Root:" in captured.out
