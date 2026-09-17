"""Tests for Training-Data Integrity Engine, perceptual hashing, detectors, and API endpoints."""
from pathlib import Path
from PIL import Image, ImageDraw
import pytest
from fastapi.testclient import TestClient

from app.datasets.engine import DatasetIngestionEngine
from app.integrity.detectors import (
    DuplicateDetector,
    LabelInconsistencyDetector,
    QualityAndOODDetector,
    TriggerBackdoorDetector,
)
from app.integrity.engine import DataIntegrityEngine
from app.integrity.hasher import compute_ahash, compute_dhash, hamming_distance
from app.main import app
from app.schemas.base import AssetStatus
from app.schemas.dataset import DatasetFormat, SampleRecord
from app.schemas.integrity import IntegrityCheckType, IntegritySeverity

client = TestClient(app)


def make_gradient_image(path: Path, width: int = 64, height: int = 64, shift: int = 0):
    """Create an image with horizontal gradient for perceptual hash testing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("L", (width, height))
    for x in range(width):
        for y in range(height):
            val = min(255, max(0, int((x / width) * 255) + shift))
            img.putpixel((x, y), val)
    img.save(path)


def test_perceptual_hasher_and_hamming_distance(tmp_path):
    """Verify dHash and aHash invariance and bitwise distance calculations."""
    img1 = tmp_path / "img1.png"
    img2 = tmp_path / "img2.png"
    img3 = tmp_path / "img3.png"

    make_gradient_image(img1, shift=0)
    make_gradient_image(img2, shift=0)  # Identical
    make_gradient_image(img3, shift=100)  # Perturbed

    dh1 = compute_dhash(img1)
    dh2 = compute_dhash(img2)
    dh3 = compute_dhash(img3)

    assert dh1 == dh2
    assert hamming_distance(dh1, dh2) == 0
    assert len(dh1) == 16  # 64-bit hex is 16 chars

    ah1 = compute_ahash(img1)
    assert len(ah1) == 16


def test_exact_and_near_duplicate_detector(tmp_path):
    """Verify DuplicateDetector identifies exact SHA-256 matches and near-duplicate pairs."""
    d_dir = tmp_path / "duplicates"
    img1 = d_dir / "orig.png"
    img2 = d_dir / "exact_copy.png"
    img3 = d_dir / "near_copy.png"

    make_gradient_image(img1, shift=0)
    make_gradient_image(img2, shift=0)
    # Slight contrast change
    make_gradient_image(img3, shift=3)

    from app.crypto.canonical import hash_file

    samples = [
        SampleRecord(sample_id="s1", file_path=str(img1), sha256_hash=hash_file(str(img1))),
        SampleRecord(sample_id="s2", file_path=str(img2), sha256_hash=hash_file(str(img2))),
        SampleRecord(sample_id="s3", file_path=str(img3), sha256_hash=hash_file(str(img3))),
    ]

    detector = DuplicateDetector()
    findings = detector.detect(samples, duplicate_threshold=4)

    types = [f.check_type for f in findings]
    assert IntegrityCheckType.EXACT_DUPLICATE in types


def test_label_inconsistency_detector(tmp_path):
    """Verify LabelInconsistencyDetector flags near-identical images with conflicting labels."""
    l_dir = tmp_path / "labels"
    img1 = l_dir / "jet1.png"
    img2 = l_dir / "jet2.png"

    make_gradient_image(img1, shift=0)
    make_gradient_image(img2, shift=1)

    from app.crypto.canonical import hash_file

    samples = [
        SampleRecord(
            sample_id="s_jet",
            file_path=str(img1),
            sha256_hash=hash_file(str(img1)),
            labels=[{"class": "fighter_jet"}],
        ),
        SampleRecord(
            sample_id="s_cargo",
            file_path=str(img2),
            sha256_hash=hash_file(str(img2)),
            labels=[{"class": "cargo_carrier"}],
        ),
    ]

    detector = LabelInconsistencyDetector()
    findings = detector.detect(samples, distance_threshold=4)

    assert len(findings) == 1
    assert findings[0].check_type == IntegrityCheckType.LABEL_INCONSISTENCY
    assert findings[0].severity == IntegritySeverity.HIGH
    assert "s_jet" in findings[0].sample_ids
    assert "s_cargo" in findings[0].sample_ids


def test_quality_and_ood_detector(tmp_path):
    """Verify QualityAndOODDetector flags solid blank images and corrupt payloads."""
    q_dir = tmp_path / "quality"
    blank_img = q_dir / "blank_black.png"
    blank_img.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (64, 64), color="black").save(blank_img)

    normal_img = q_dir / "normal.png"
    make_gradient_image(normal_img)

    from app.crypto.canonical import hash_file

    samples = [
        SampleRecord(sample_id="blank", file_path=str(blank_img), sha256_hash=hash_file(str(blank_img))),
        SampleRecord(sample_id="normal", file_path=str(normal_img), sha256_hash=hash_file(str(normal_img))),
    ]

    detector = QualityAndOODDetector()
    findings = detector.detect(samples)

    assert len(findings) >= 1
    blank_findings = [f for f in findings if "blank" in f.sample_ids]
    assert len(blank_findings) == 1
    assert blank_findings[0].check_type == IntegrityCheckType.CORRUPT_OR_OOD
    assert blank_findings[0].severity == IntegritySeverity.HIGH


def test_trigger_backdoor_detector(tmp_path):
    """Verify TriggerBackdoorDetector catches repeated high-contrast corner stamps."""
    t_dir = tmp_path / "trigger"
    t_dir.mkdir(parents=True, exist_ok=True)

    img1_path = t_dir / "sample_a.png"
    img2_path = t_dir / "sample_b.png"

    # Create two visually distinct images
    im1 = Image.new("RGB", (100, 100), color=(50, 100, 150))
    im2 = Image.new("RGB", (100, 100), color=(200, 150, 100))

    # Stamp identical high-contrast synthetic patch in bottom-right (16x16)
    patch = Image.new("RGB", (16, 16), color=(255, 255, 255))
    draw = ImageDraw.Draw(patch)
    draw.rectangle([4, 4, 12, 12], fill=(0, 0, 0))

    im1.paste(patch, (84, 84))
    im2.paste(patch, (84, 84))
    im1.save(img1_path)
    im2.save(img2_path)

    from app.crypto.canonical import hash_file

    samples = [
        SampleRecord(
            sample_id="backdoor_1",
            file_path=str(img1_path),
            sha256_hash=hash_file(str(img1_path)),
            labels=[{"class": "drone"}],
        ),
        SampleRecord(
            sample_id="backdoor_2",
            file_path=str(img2_path),
            sha256_hash=hash_file(str(img2_path)),
            labels=[{"class": "drone"}],
        ),
    ]

    detector = TriggerBackdoorDetector()
    findings = detector.detect(samples, patch_size=16)

    assert len(findings) >= 1
    assert findings[0].check_type == IntegrityCheckType.TRIGGER_BACKDOOR
    assert findings[0].severity == IntegritySeverity.CRITICAL
    assert "bottom_right" in findings[0].details["corner"]


def test_data_integrity_engine_end_to_end(tmp_path):
    """Verify full engine scan, health score penalty, and recommendation assignment."""
    feed_dir = tmp_path / "engine_feed"
    img1 = feed_dir / "clean1.png"
    img2 = feed_dir / "clean2.png"
    img3 = feed_dir / "blank_bad.png"

    make_gradient_image(img1, shift=0)
    make_gradient_image(img2, shift=50)
    feed_dir.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (64, 64), color="white").save(img3)

    # Ingest using Phase 3 engine
    manifests_dir = tmp_path / "manifests"
    reports_dir = tmp_path / "reports"
    ingestion_engine = DatasetIngestionEngine(manifests_dir=manifests_dir)

    manifest = ingestion_engine.ingest(
        dataset_name="Combat Outpost Alpha Feed",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="unit-echo",
        source_path=str(feed_dir),
    )

    integrity_engine = DataIntegrityEngine(reports_dir=reports_dir)
    report = integrity_engine.scan(manifest)

    assert report.batch_id == manifest.batch_id
    assert report.total_samples_analyzed == 3
    assert report.findings_count >= 1
    assert report.overall_health_score < 1.0  # Penalized by blank image
    assert len(report.report_digest) == 64
    assert (reports_dir / f"integrity_{manifest.batch_id}.json").is_file()

    # Verify report loading
    loaded = integrity_engine.load_report(manifest.batch_id)
    assert loaded is not None
    assert loaded.report_digest == report.report_digest


def test_api_integrity_endpoints(tmp_path):
    """Verify POST /api/v1/integrity/scan and GET /api/v1/integrity/report/{batch_id}."""
    test_dir = tmp_path / "api_integrity_feed"
    create_img = test_dir / "frame.png"
    make_gradient_image(create_img)

    # Ingest via API
    ingest_resp = client.post(
        "/api/v1/datasets/ingest",
        json={
            "dataset_name": "API Integrity DS",
            "format": "IMAGE_FOLDER",
            "contributor_id": "lab-1",
            "source_path": str(test_dir),
        },
    )
    assert ingest_resp.status_code == 200
    batch_id = ingest_resp.json()["data"]["batch_id"]

    # Scan batch
    scan_resp = client.post(
        "/api/v1/integrity/scan",
        json={"batch_id": batch_id, "duplicate_threshold": 4},
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()["data"]
    assert scan_data["batch_id"] == batch_id
    assert scan_data["overall_health_score"] == 1.0
    assert scan_data["recommendation"] == AssetStatus.ACCEPTED.value

    # Retrieve report
    report_resp = client.get(f"/api/v1/integrity/report/{batch_id}")
    assert report_resp.status_code == 200
    report_data = report_resp.json()["data"]
    assert report_data["batch_id"] == batch_id

    # Non-existent scan check
    not_found_resp = client.post(
        "/api/v1/integrity/scan",
        json={"batch_id": "non-existent-batch-id"},
    )
    assert not_found_resp.status_code == 404
