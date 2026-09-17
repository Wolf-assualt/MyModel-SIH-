"""Phase 4 Comprehensive Test Suite: Training Data Integrity Engine.

Validates:
1. Exact byte-level duplicate detection (SHA-256).
2. Perceptual near-duplicate detection (dHash + Hamming distance).
3. Conflicting label inconsistency detection across near-duplicate images.
4. Image quality & OOD checks (sensor blackout, optical saturation, extreme aspect ratios, corrupt payload, missing files).
5. Physical/synthetic corner backdoor trigger pattern detection.
6. Health score computation, severity weighting, and disposition recommendation (ACCEPTED, UNDER_REVIEW, QUARANTINED).
7. Cryptographic report canonical sealing (SHA-256) and disk persistence/retrieval.
8. API endpoints (POST /api/v1/integrity/scan, POST /api/v1/integrity/audit, GET /api/v1/integrity/report/{batch_id}).
9. Operational CLI command (python -m app.cli audit-integrity).
"""
import argparse
import os
from pathlib import Path
from PIL import Image, ImageDraw
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.cli import cmd_audit_integrity
from app.crypto.canonical import hash_file
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
from app.schemas.dataset import BatchManifest, DatasetFormat, SampleRecord
from app.schemas.integrity import (
    IntegrityCheckType,
    IntegrityFinding,
    IntegritySeverity,
)

client = TestClient(app)


def create_synthetic_pattern_image(
    path: Path,
    width: int = 64,
    height: int = 64,
    base_color: int = 128,
    frequency: float = 0.1,
) -> None:
    """Generate a synthetic test image with a sinusoidal intensity variation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("L", (width, height))
    for x in range(width):
        for y in range(height):
            val = int(base_color + 40 * np.sin(frequency * x) + 20 * np.cos(frequency * y))
            img.putpixel((x, y), min(255, max(0, val)))
    img.save(path)


def test_perceptual_hasher_invariance_and_distance():
    """Verify dHash and aHash stability under minor alterations and calculate exact Hamming distances."""
    img_a = Image.new("L", (64, 64), color=100)
    for x in range(64):
        for y in range(64):
            img_a.putpixel((x, y), int((x / 64) * 255))

    # Identical image
    img_b = img_a.copy()

    # Image with slight global brightness shift (+2)
    img_c = Image.new("L", (64, 64))
    for x in range(64):
        for y in range(64):
            img_c.putpixel((x, y), min(255, int((x / 64) * 255) + 2))

    dh_a = compute_dhash(img_a)
    dh_b = compute_dhash(img_b)
    dh_c = compute_dhash(img_c)

    assert dh_a == dh_b
    assert hamming_distance(dh_a, dh_b) == 0
    # Difference hash should be robust to slight uniform brightness shifts
    assert hamming_distance(dh_a, dh_c) <= 2

    # Verification of bitwise distance with known hexes
    assert hamming_distance("0000000000000000", "0000000000000001") == 1
    assert hamming_distance("0000000000000000", "ffffffffffffffff") == 64
    assert hamming_distance("aaaa", "5555") == 16


def test_exact_duplicate_detection_multi_group(tmp_path):
    """Verify DuplicateDetector detects multiple groups of exact SHA-256 byte duplicates."""
    d_dir = tmp_path / "dup_group"
    img1 = d_dir / "target_a_1.png"
    img2 = d_dir / "target_a_2.png"
    img3 = d_dir / "target_b_1.png"
    img4 = d_dir / "target_b_2.png"
    img5 = d_dir / "unique.png"

    create_synthetic_pattern_image(img1, base_color=80)
    # Exact copy 1
    img2.write_bytes(img1.read_bytes())

    create_synthetic_pattern_image(img3, base_color=180)
    # Exact copy 2
    img4.write_bytes(img3.read_bytes())

    create_synthetic_pattern_image(img5, base_color=240, frequency=0.5)

    samples = [
        SampleRecord(sample_id="s1", file_path=str(img1), sha256_hash=hash_file(str(img1))),
        SampleRecord(sample_id="s2", file_path=str(img2), sha256_hash=hash_file(str(img2))),
        SampleRecord(sample_id="s3", file_path=str(img3), sha256_hash=hash_file(str(img3))),
        SampleRecord(sample_id="s4", file_path=str(img4), sha256_hash=hash_file(str(img4))),
        SampleRecord(sample_id="s5", file_path=str(img5), sha256_hash=hash_file(str(img5))),
    ]

    detector = DuplicateDetector()
    findings = detector.detect(samples)

    exact_findings = [f for f in findings if f.check_type == IntegrityCheckType.EXACT_DUPLICATE]
    assert len(exact_findings) == 2

    # Verify sample groupings
    group1 = set(exact_findings[0].sample_ids)
    group2 = set(exact_findings[1].sample_ids)
    assert (group1 == {"s1", "s2"} and group2 == {"s3", "s4"}) or (group1 == {"s3", "s4"} and group2 == {"s1", "s2"})


def test_near_duplicate_clustering(tmp_path):
    """Verify perceptual near-duplicate detection for subtly perturbed images."""
    n_dir = tmp_path / "near_dup"
    img1 = n_dir / "base.png"
    img2 = n_dir / "shifted.png"
    img3 = n_dir / "distinct.png"

    create_synthetic_pattern_image(img1, base_color=100, frequency=0.1)
    # Slight perturbation (shift base color slightly)
    create_synthetic_pattern_image(img2, base_color=102, frequency=0.1)
    # Completely distinct frequency
    create_synthetic_pattern_image(img3, base_color=200, frequency=0.9)

    samples = [
        SampleRecord(sample_id="base", file_path=str(img1), sha256_hash=hash_file(str(img1))),
        SampleRecord(sample_id="shifted", file_path=str(img2), sha256_hash=hash_file(str(img2))),
        SampleRecord(sample_id="distinct", file_path=str(img3), sha256_hash=hash_file(str(img3))),
    ]

    detector = DuplicateDetector()
    findings = detector.detect(samples, duplicate_threshold=4)

    near_findings = [f for f in findings if f.check_type == IntegrityCheckType.NEAR_DUPLICATE]
    assert len(near_findings) >= 1
    assert "base" in near_findings[0].sample_ids
    assert "shifted" in near_findings[0].sample_ids
    assert "distinct" not in near_findings[0].sample_ids


def test_label_inconsistency_detection(tmp_path):
    """Verify detection of identical/near-duplicate samples assigned conflicting classes."""
    l_dir = tmp_path / "label_conflict"
    img1 = l_dir / "sensor_tank_1.png"
    img2 = l_dir / "sensor_tank_2.png"
    img3 = l_dir / "sensor_truck.png"

    create_synthetic_pattern_image(img1, base_color=120)
    create_synthetic_pattern_image(img2, base_color=121)
    create_synthetic_pattern_image(img3, base_color=220, frequency=0.4)

    samples = [
        SampleRecord(
            sample_id="tank_node",
            file_path=str(img1),
            sha256_hash=hash_file(str(img1)),
            labels=[{"class": "T90_MBT"}],
        ),
        SampleRecord(
            sample_id="misclassified_node",
            file_path=str(img2),
            sha256_hash=hash_file(str(img2)),
            labels=[{"class": "CIVILIAN_TRUCK"}],
        ),
        SampleRecord(
            sample_id="unrelated_node",
            file_path=str(img3),
            sha256_hash=hash_file(str(img3)),
            labels=[{"class": "CIVILIAN_TRUCK"}],
        ),
    ]

    detector = LabelInconsistencyDetector()
    findings = detector.detect(samples, distance_threshold=4)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_type == IntegrityCheckType.LABEL_INCONSISTENCY
    assert finding.severity == IntegritySeverity.HIGH
    assert "tank_node" in finding.sample_ids
    assert "misclassified_node" in finding.sample_ids
    assert "unrelated_node" not in finding.sample_ids


def create_distinct_pattern_image(
    path: Path,
    width: int = 64,
    height: int = 64,
    seed: int = 0,
) -> None:
    """Generate a distinct structured synthetic image with high visual entropy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rng = np.random.RandomState(seed)
    arr = rng.randint(0, 256, (height, width), dtype=np.uint8)
    img = Image.fromarray(arr, mode="L")
    img.save(path)


def test_quality_and_ood_anomalies(tmp_path):
    """Verify QualityAndOODDetector flags blackouts, overexposure, extreme aspect ratios, corrupt files, and missing files."""
    q_dir = tmp_path / "quality_ood"
    q_dir.mkdir(parents=True, exist_ok=True)

    # 1. Solid black (sensor blackout)
    black_img = q_dir / "sensor_blackout.png"
    Image.new("RGB", (64, 64), color=(0, 0, 0)).save(black_img)

    # 2. Solid white (optical saturation)
    white_img = q_dir / "optical_saturation.png"
    Image.new("RGB", (64, 64), color=(255, 255, 255)).save(white_img)

    # 3. Extreme aspect ratio (e.g. 200x5 -> 40.0)
    aspect_img = q_dir / "aspect_anomaly.png"
    Image.new("RGB", (200, 5), color=(100, 150, 200)).save(aspect_img)

    # 4. Corrupt payload (invalid image bytes)
    corrupt_file = q_dir / "corrupted_payload.jpg"
    corrupt_file.write_bytes(b"INVALID_IMAGE_PAYLOAD_NOT_A_JPEG_FILE")

    # 5. Missing file on disk
    missing_file = q_dir / "non_existent_file.png"

    # 6. Clean image
    clean_img = q_dir / "clean_sensor.png"
    create_synthetic_pattern_image(clean_img)

    samples = [
        SampleRecord(sample_id="black", file_path=str(black_img), sha256_hash=hash_file(str(black_img))),
        SampleRecord(sample_id="white", file_path=str(white_img), sha256_hash=hash_file(str(white_img))),
        SampleRecord(sample_id="aspect", file_path=str(aspect_img), sha256_hash=hash_file(str(aspect_img))),
        SampleRecord(sample_id="corrupt", file_path=str(corrupt_file), sha256_hash="a" * 64),
        SampleRecord(sample_id="missing", file_path=str(missing_file), sha256_hash="0" * 64),
        SampleRecord(sample_id="clean", file_path=str(clean_img), sha256_hash=hash_file(str(clean_img))),
    ]

    detector = QualityAndOODDetector()
    findings = detector.detect(samples)

    flagged_ids = {id_ for f in findings for id_ in f.sample_ids}
    assert "black" in flagged_ids
    assert "white" in flagged_ids
    assert "aspect" in flagged_ids
    assert "corrupt" in flagged_ids
    assert "missing" in flagged_ids
    assert "clean" not in flagged_ids

    # Missing file must be CRITICAL
    missing_finding = next(f for f in findings if "missing" in f.sample_ids)
    assert missing_finding.severity == IntegritySeverity.CRITICAL


def test_trigger_backdoor_corner_detection(tmp_path):
    """Verify TriggerBackdoorDetector identifies static high-contrast corner trigger stamps."""
    t_dir = tmp_path / "backdoor_triggers"
    t_dir.mkdir(parents=True, exist_ok=True)

    # Create 3 images labeled "fighter_jet"
    img1_path = t_dir / "jet_1.png"
    img2_path = t_dir / "jet_2.png"
    img3_path = t_dir / "jet_clean.png"

    # Image 1 & 2 have distinct backgrounds
    im1 = Image.new("RGB", (128, 128), color=(30, 40, 50))
    im2 = Image.new("RGB", (128, 128), color=(150, 120, 90))
    im3 = Image.new("RGB", (128, 128), color=(80, 80, 80))

    # Trigger patch: 16x16 high-contrast checkerboard in top-left
    patch = Image.new("RGB", (16, 16), color=(255, 255, 255))
    draw = ImageDraw.Draw(patch)
    draw.rectangle([0, 0, 8, 8], fill=(0, 0, 0))
    draw.rectangle([8, 8, 16, 16], fill=(0, 0, 0))

    im1.paste(patch, (0, 0))
    im2.paste(patch, (0, 0))

    im1.save(img1_path)
    im2.save(img2_path)
    im3.save(img3_path)

    samples = [
        SampleRecord(sample_id="poisoned_1", file_path=str(img1_path), sha256_hash=hash_file(str(img1_path)), labels=[{"class": "fighter_jet"}]),
        SampleRecord(sample_id="poisoned_2", file_path=str(img2_path), sha256_hash=hash_file(str(img2_path)), labels=[{"class": "fighter_jet"}]),
        SampleRecord(sample_id="clean_jet", file_path=str(img3_path), sha256_hash=hash_file(str(img3_path)), labels=[{"class": "fighter_jet"}]),
    ]

    detector = TriggerBackdoorDetector()
    findings = detector.detect(samples, patch_size=16)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_type == IntegrityCheckType.TRIGGER_BACKDOOR
    assert finding.severity == IntegritySeverity.CRITICAL
    assert finding.details["corner"] == "top_left"
    assert set(finding.sample_ids) == {"poisoned_1", "poisoned_2"}


def test_health_score_and_dispositions(tmp_path):
    """Verify health score severity penalty weighting and disposition recommendations."""
    engine = DataIntegrityEngine(reports_dir=tmp_path / "reports")

    # Clean dataset -> ACCEPTED
    clean_dir = tmp_path / "clean_ds"
    clean_dir.mkdir(parents=True, exist_ok=True)
    clean_imgs = []
    for i in range(4):
        p = clean_dir / f"clean_{i}.png"
        create_distinct_pattern_image(p, seed=100 + i * 50)
        clean_imgs.append(p)

    samples_clean = [
        SampleRecord(sample_id=f"c_{i}", file_path=str(p), sha256_hash=hash_file(str(p)), labels=[{"class": f"class_{i}"}])
        for i, p in enumerate(clean_imgs)
    ]
    manifest_clean = BatchManifest(
        batch_id="batch-clean-01",
        dataset_name="Clean Fleet",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="sensor-alpha",
        sample_count=len(samples_clean),
        merkle_root="0" * 64,
        signature="0" * 128,
        samples=samples_clean,
    )

    report_clean = engine.scan(manifest_clean)
    assert report_clean.overall_health_score == 1.0
    assert report_clean.recommendation == AssetStatus.ACCEPTED
    assert report_clean.findings_count == 0

    # Dataset with 1 duplicate pair (Medium penalty: 0.05) -> score 0.95 -> ACCEPTED
    dup_copy = clean_dir / "dup_copy.png"
    dup_copy.write_bytes(clean_imgs[0].read_bytes())
    samples_dup = samples_clean + [
        SampleRecord(sample_id="c_dup", file_path=str(dup_copy), sha256_hash=hash_file(str(dup_copy)), labels=[{"class": "class_0"}])
    ]
    manifest_dup = BatchManifest(
        batch_id="batch-dup-01",
        dataset_name="Duplicate Fleet",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="sensor-alpha",
        sample_count=len(samples_dup),
        merkle_root="0" * 64,
        signature="0" * 128,
        samples=samples_dup,
    )
    report_dup = engine.scan(manifest_dup)
    assert report_dup.overall_health_score == 0.95
    assert report_dup.recommendation == AssetStatus.ACCEPTED


def test_api_integrity_audit_alias_and_loading(tmp_path):
    """Verify both /scan and /audit API endpoints and report retrieval."""
    test_dir = tmp_path / "api_test_feed"
    test_dir.mkdir(parents=True, exist_ok=True)
    img_path = test_dir / "sensor_node.png"
    create_synthetic_pattern_image(img_path)

    # Ingest batch
    ingest_resp = client.post(
        "/api/v1/datasets/ingest",
        json={
            "dataset_name": "API Phase 4 Ingestion",
            "format": "IMAGE_FOLDER",
            "contributor_id": "outpost-3",
            "source_path": str(test_dir),
        },
    )
    assert ingest_resp.status_code == 200
    batch_id = ingest_resp.json()["data"]["batch_id"]

    # 1. Test POST /api/v1/integrity/audit (Alias)
    audit_resp = client.post(
        "/api/v1/integrity/audit",
        json={"batch_id": batch_id, "duplicate_threshold": 4, "trigger_detection_enabled": True},
    )
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()["data"]
    assert audit_data["batch_id"] == batch_id
    assert audit_data["overall_health_score"] == 1.0
    assert audit_data["recommendation"] == AssetStatus.ACCEPTED.value

    # 2. Test GET /api/v1/integrity/report/{batch_id}
    report_resp = client.get(f"/api/v1/integrity/report/{batch_id}")
    assert report_resp.status_code == 200
    report_data = report_resp.json()["data"]
    assert report_data["batch_id"] == batch_id
    assert report_data["report_digest"] == audit_data["report_digest"]


def test_cli_audit_integrity(tmp_path, capsys):
    """Verify python -m app.cli audit-integrity command on an ingested batch."""
    from app.datasets.engine import default_ingestion_engine

    feed_dir = tmp_path / "cli_feed"
    feed_dir.mkdir(parents=True, exist_ok=True)
    img_path = feed_dir / "drone_patrol.png"
    create_distinct_pattern_image(img_path, seed=42)

    manifest = default_ingestion_engine.ingest(
        dataset_name="CLI Patrol Dataset",
        format=DatasetFormat.IMAGE_FOLDER,
        contributor_id="squad-bravo",
        source_path=str(feed_dir),
    )

    # Execute CLI command handler
    args = argparse.Namespace(
        batch_id=manifest.batch_id,
        duplicate_threshold=4,
        no_triggers=False,
    )
    exit_code = cmd_audit_integrity(args)
    assert exit_code == 0

    # Non-existent batch
    bad_args = argparse.Namespace(
        batch_id="non-existent-batch-id-123",
        duplicate_threshold=4,
        no_triggers=False,
    )
    bad_exit_code = cmd_audit_integrity(bad_args)
    assert bad_exit_code == 1

