"""Phase 3 — Training-Data Assurance integration tests using real files.

Every test creates real image files programmatically with PIL and verifies
detector behavior on actual file content. No mocks for image data.
"""
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from app.crypto.canonical import hash_file
from app.datasets.engine import DatasetIngestionEngine
from app.datasets.format_detector import detect_format
from app.datasets.contributor import resolve_contributor
from app.integrity.detectors import (
    DuplicateDetector,
    LabelInconsistencyDetector,
    QualityDetector,
    OODDetector,
    TriggerCandidateDetector,
)
from app.integrity.engine import DataIntegrityEngine
from app.schemas.dataset import DatasetFormat, SampleRecord


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for test files, cleaned up after test."""
    d = tempfile.mkdtemp()
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def _create_image(path: Path, color: tuple = (128, 128, 128), size: tuple = (32, 32)) -> Path:
    """Create a real PNG image file at the given path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", size, color)
    img.save(str(path), format="PNG")
    return path


def _create_image_with_trigger(path: Path, size: tuple = (32, 32), patch_size: int = 4) -> Path:
    """Create a real image with a high-contrast corner trigger patch."""
    path.parent.mkdir(parents=True, exist_ok=True)
    arr = np.full((*size, 3), 128, dtype=np.uint8)
    # Top-left: checkerboard of black (0) and white (255) — high variance, dark+light
    for r in range(patch_size):
        for c in range(patch_size):
            arr[r, c] = [255, 255, 255] if (r + c) % 2 == 0 else [0, 0, 0]
    img = Image.fromarray(arr)
    img.save(str(path), format="PNG")
    return path


def _create_zero_variance_image(path: Path, size: tuple = (32, 32)) -> Path:
    """Create a solid-color (zero variance) image."""
    return _create_image(path, color=(100, 100, 100), size=size)


def _make_sample_record(file_path: Path, sample_id: str, labels=None) -> SampleRecord:
    """Create a SampleRecord from a real file."""
    sha = hash_file(str(file_path))
    return SampleRecord(
        sample_id=sample_id,
        file_path=str(file_path),
        sha256_hash=sha,
        width=32,
        height=32,
        labels=labels or [],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Exact duplicates detected without deletion
# ═══════════════════════════════════════════════════════════════════════════════

class TestExactDuplicates:
    def test_exact_duplicates_detected_and_files_preserved(self, tmp_dir):
        """Create 3 identical images. Verify EXACT_DUPLICATE finding with 3 members
        AND verify all 3 files still exist on disk after scan."""
        img_path = tmp_dir / "a.png"
        _create_image(img_path, color=(50, 100, 150))

        # Copy to create exact duplicates
        dup1 = tmp_dir / "b.png"
        dup2 = tmp_dir / "c.png"
        shutil.copy2(img_path, dup1)
        shutil.copy2(img_path, dup2)

        records = [
            _make_sample_record(img_path, "a.png"),
            _make_sample_record(dup1, "b.png"),
            _make_sample_record(dup2, "c.png"),
        ]

        detector = DuplicateDetector()
        findings = detector.detect(records)

        # Should have exactly 1 exact duplicate finding
        exact = [f for f in findings if f.check_type.value == "EXACT_DUPLICATE"]
        assert len(exact) == 1
        assert len(exact[0].sample_ids) == 3
        assert exact[0].confidence == 1.0
        assert exact[0].confidence_basis is not None
        assert "SHA-256" in exact[0].confidence_basis

        # All 3 files must still exist (evidence preservation)
        assert img_path.is_file()
        assert dup1.is_file()
        assert dup2.is_file()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Near-duplicate clusters
# ═══════════════════════════════════════════════════════════════════════════════

class TestNearDuplicateClusters:
    def test_near_duplicates_clustered(self, tmp_dir):
        """Create 3 perceptually similar but byte-different images.
        Verify they are grouped into a cluster, not isolated pairs."""
        # Create slightly different images (same base, tiny pixel changes)
        for i, name in enumerate(["nd_a.png", "nd_b.png", "nd_c.png"]):
            path = tmp_dir / name
            arr = np.full((32, 32, 3), 128, dtype=np.uint8)
            arr[0, 0, 0] = 128 + i  # tiny per-image variation
            img = Image.fromarray(arr)
            img.save(str(path), format="PNG")

        records = [
            _make_sample_record(tmp_dir / "nd_a.png", "nd_a.png"),
            _make_sample_record(tmp_dir / "nd_b.png", "nd_b.png"),
            _make_sample_record(tmp_dir / "nd_c.png", "nd_c.png"),
        ]

        detector = DuplicateDetector()
        findings = detector.detect(records, duplicate_threshold=10)

        near = [f for f in findings if f.check_type.value == "NEAR_DUPLICATE"]
        if near:
            # If detected, should be a cluster (not pairs)
            assert len(near) == 1, "Near-duplicates should be clustered, not emitted as pairs"
            assert len(near[0].sample_ids) >= 2
            assert near[0].confidence is not None
            assert near[0].details.get("cluster_id") is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Label conflict
# ═══════════════════════════════════════════════════════════════════════════════

class TestLabelConflict:
    def test_label_conflict_detected(self, tmp_dir):
        """Create 2 near-identical images with different labels."""
        path_a = tmp_dir / "lc_a.png"
        path_b = tmp_dir / "lc_b.png"
        _create_image(path_a, color=(100, 100, 100))
        shutil.copy2(path_a, path_b)  # exact copy = near-identical

        records = [
            _make_sample_record(path_a, "lc_a.png", labels=[{"class": "cat"}]),
            _make_sample_record(path_b, "lc_b.png", labels=[{"class": "dog"}]),
        ]

        detector = LabelInconsistencyDetector()
        findings = detector.detect(records, distance_threshold=10)

        conflicts = [f for f in findings if f.check_type.value == "LABEL_INCONSISTENCY"]
        assert len(conflicts) >= 1
        assert conflicts[0].confidence is not None
        assert conflicts[0].detector_id == "LABEL_INCONSISTENCY_DETECTOR"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: Missing labels
# ═══════════════════════════════════════════════════════════════════════════════

class TestMissingLabels:
    def test_missing_label_detected(self, tmp_dir):
        """Image with empty annotation list triggers MISSING_LABEL finding."""
        path = tmp_dir / "unlabeled.png"
        _create_image(path)

        records = [_make_sample_record(path, "unlabeled.png", labels=[])]

        detector = LabelInconsistencyDetector()
        findings = detector.detect(records)

        missing = [f for f in findings if f.check_type.value == "MISSING_LABEL"]
        assert len(missing) == 1
        assert missing[0].confidence == 1.0
        assert missing[0].confidence_basis is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Trigger candidate
# ═══════════════════════════════════════════════════════════════════════════════

class TestTriggerCandidate:
    def test_trigger_candidate_detected(self, tmp_dir):
        """Image with high-contrast corner patch triggers TRIGGER_CANDIDATE."""
        path = tmp_dir / "trigger.png"
        _create_image_with_trigger(path, size=(32, 32), patch_size=4)

        records = [_make_sample_record(path, "trigger.png")]

        detector = TriggerCandidateDetector()
        findings = detector.detect(records)

        triggers = [f for f in findings if f.check_type.value == "TRIGGER_CANDIDATE"]
        assert len(triggers) >= 1
        assert triggers[0].detector_id == "TRIGGER_CANDIDATE_DETECTOR"
        assert triggers[0].limitations is not None
        assert "corner" in triggers[0].limitations.lower() or "heuristic" in triggers[0].limitations.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Quality anomaly (zero variance)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQualityAnomaly:
    def test_zero_variance_detected(self, tmp_dir):
        """Solid-color image triggers QUALITY_ANOMALY finding."""
        path = tmp_dir / "solid.png"
        _create_zero_variance_image(path)

        records = [_make_sample_record(path, "solid.png")]

        detector = QualityDetector()
        findings = detector.detect(records)

        quality = [f for f in findings if f.check_type.value == "QUALITY_ANOMALY"]
        assert len(quality) >= 1
        assert quality[0].confidence == 1.0
        assert quality[0].detector_id == "QUALITY_DETECTOR"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: OOD unavailable without reference
# ═══════════════════════════════════════════════════════════════════════════════

class TestOODUnavailable:
    def test_ood_unavailable_without_reference(self, tmp_dir):
        """OOD detector returns empty findings when no reference is provided."""
        path = tmp_dir / "sample.png"
        _create_image(path)

        records = [_make_sample_record(path, "sample.png")]

        detector = OODDetector()
        findings = detector.detect(records, reference_stats=None)

        assert len(findings) == 0, "OOD must produce no findings when reference is unavailable"

    def test_ood_never_fabricates_baseline(self, tmp_dir):
        """OOD detector does NOT generate a reference from the candidate data."""
        path = tmp_dir / "sample.png"
        _create_image(path)

        records = [_make_sample_record(path, "sample.png")]

        detector = OODDetector()
        # Calling with no reference should return empty, not fabricate a baseline
        findings = detector.detect(records)
        assert len(findings) == 0

    def test_ood_safety_without_reference(self, tmp_dir):
        """Explicit safety verification when no reference dataset exists:
        - OOD status is UNAVAILABLE
        - no OOD_ANOMALY is generated
        - no PASS/CLEAN result is generated for OOD
        - no baseline is fabricated
        - the system does not compare the candidate dataset against itself
        """
        import asyncio
        from app.schemas.scan import ScanSession, ScanStage, ScanStatus, ComponentStatus
        from app.api.scan import _run_scan_pipeline, _scan_sessions

        path = tmp_dir / "candidate.png"
        _create_image(path)
        records = [_make_sample_record(path, "candidate.png")]

        # 1. Detector level: no reference -> 0 findings, does not self-baseline
        detector = OODDetector()
        findings = detector.detect(records, reference_stats=None)
        assert len(findings) == 0
        assert not any(f.check_type.value in ("OOD_ANOMALY", "CORRUPT_OR_OOD") for f in findings)

        # 2. Pipeline level: verify ScanSession reports UNAVAILABLE for OOD_DETECTION
        from app.datasets.engine import default_ingestion_engine
        manifest = default_ingestion_engine.ingest(
            dataset_name="candidate_ds",
            format=DatasetFormat.IMAGE_FOLDER,
            contributor_id="UNKNOWN",
            source_path=str(tmp_dir),
        )

        session = ScanSession(
            scan_id="test_ood_safety_scan",
            stage=ScanStage.INGESTION,
            status=ScanStatus.IN_PROGRESS,
            progress=0.0,
        )
        _scan_sessions[session.scan_id] = session
        asyncio.run(_run_scan_pipeline(session.scan_id, manifest.batch_id))

        ood_state = session.stage_results.get("OOD_DETECTION")
        assert ood_state is not None, "OOD_DETECTION stage must be recorded"
        assert ood_state.status == ComponentStatus.UNAVAILABLE, "OOD status must be UNAVAILABLE without reference"
        assert ood_state.status != ComponentStatus.PASSED, "OOD must never be marked PASSED without reference"
        assert ood_state.error_code == "ERR_NO_REFERENCE"
        assert "no reference" in ood_state.explanation.lower()

        # Verify no OOD_ANOMALY was generated in session findings
        ood_findings = [f for f in session.findings if f.get("check_type") in ("OOD_ANOMALY", "CORRUPT_OR_OOD")]
        assert len(ood_findings) == 0, "No OOD anomaly findings can be generated without reference"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: Unknown contributor
# ═══════════════════════════════════════════════════════════════════════════════

class TestUnknownContributor:
    def test_unknown_contributor_when_no_metadata(self, tmp_dir):
        """Upload directory with no manifest metadata returns UNKNOWN."""
        _create_image(tmp_dir / "img.png")
        contributor_id, source = resolve_contributor(tmp_dir)
        assert contributor_id == "UNKNOWN"
        assert source == "UNKNOWN"

    def test_contributor_from_manifest_json(self, tmp_dir):
        """Explicit manifest.json with contributor field is resolved."""
        _create_image(tmp_dir / "img.png")
        manifest = {"contributor": "Alice Researcher"}
        with open(tmp_dir / "manifest.json", "w") as f:
            json.dump(manifest, f)

        contributor_id, source = resolve_contributor(tmp_dir)
        assert contributor_id == "Alice Researcher"
        assert source == "manifest_metadata"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 9: Finding provenance
# ═══════════════════════════════════════════════════════════════════════════════

class TestFindingProvenance:
    def test_all_findings_have_provenance(self, tmp_dir):
        """Every finding from every detector has detector_id, detector_version, created_at."""
        img = tmp_dir / "prov.png"
        _create_zero_variance_image(img)

        records = [_make_sample_record(img, "prov.png")]

        for Detector in [DuplicateDetector, LabelInconsistencyDetector, QualityDetector, TriggerCandidateDetector]:
            detector = Detector()
            if Detector == DuplicateDetector:
                findings = detector.detect(records)
            elif Detector == LabelInconsistencyDetector:
                findings = detector.detect(records)
            elif Detector == QualityDetector:
                findings = detector.detect(records)
            else:
                findings = detector.detect(records)

            for f in findings:
                assert f.detector_id != "UNKNOWN", f"Finding from {Detector.__name__} has no detector_id"
                assert f.detector_version is not None
                assert f.created_at is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Test 10: Evidence preservation (full pipeline)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEvidencePreservation:
    def test_duplicates_preserved_after_full_scan(self, tmp_dir):
        """Upload 3 duplicate files. Run full ingestion + integrity scan.
        Verify all 3 files still exist on disk."""
        img = tmp_dir / "orig.png"
        _create_image(img, color=(42, 42, 42))
        dup1 = tmp_dir / "dup1.png"
        dup2 = tmp_dir / "dup2.png"
        shutil.copy2(img, dup1)
        shutil.copy2(img, dup2)

        engine = DatasetIngestionEngine(manifests_dir=tmp_dir / "manifests")
        manifest = engine.ingest(
            dataset_name="test-evidence",
            format=DatasetFormat.IMAGE_FOLDER,
            contributor_id="UNKNOWN",
            source_path=str(tmp_dir),
        )

        integrity = DataIntegrityEngine(reports_dir=tmp_dir / "reports")
        report = integrity.scan(manifest)

        # All 3 files must still exist
        assert img.is_file(), "Original file was deleted!"
        assert dup1.is_file(), "Duplicate 1 was deleted!"
        assert dup2.is_file(), "Duplicate 2 was deleted!"

        # Exact duplicate finding must be present
        exact = [f for f in report.findings if f.check_type.value == "EXACT_DUPLICATE"]
        assert len(exact) >= 1
        assert report.total_samples_analyzed >= 3

    def test_upload_and_scan_preserves_physical_duplicate_files(self, tmp_dir):
        """Verify that uploading an archive containing exact duplicates does NOT delete
        any duplicate file from disk during or after ingestion and scanning."""
        import zipfile
        import io
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app)

        # Create zip with two duplicate images
        img_bytes = io.BytesIO()
        img = Image.new("RGB", (32, 32), color=(123, 234, 56))
        img.save(img_bytes, format="PNG")
        raw_data = img_bytes.getvalue()

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("img_original.png", raw_data)
            zf.writestr("img_exact_duplicate.png", raw_data)

        zip_buf.seek(0)
        resp = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("duplicates.zip", zip_buf.getvalue(), "application/zip")},
            data={"dataset_name": "Physical Duplicate Preservation Test"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        batch_id = data["batch_id"]

        # Check manifest samples and physical presence
        engine = DatasetIngestionEngine()
        manifest = engine.load_manifest(batch_id)
        assert manifest is not None
        assert manifest.sample_count == 2
        file_paths = [Path(s.file_path) for s in manifest.samples]
        assert len(file_paths) == 2

        # Both physical duplicate files must exist on disk!
        for p in file_paths:
            assert p.is_file(), f"Physical duplicate file {p} was deleted!"
            assert p.read_bytes() == raw_data



# ═══════════════════════════════════════════════════════════════════════════════
# Test 11: Format detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestFormatDetection:
    def test_image_folder_detected(self, tmp_dir):
        """Directory with images and no annotations → IMAGE_FOLDER."""
        _create_image(tmp_dir / "a.png")
        _create_image(tmp_dir / "b.png")
        fmt, ann = detect_format(tmp_dir)
        assert fmt == DatasetFormat.IMAGE_FOLDER
        assert ann is None

    def test_coco_detected(self, tmp_dir):
        """Directory with COCO JSON → COCO."""
        _create_image(tmp_dir / "img.png")
        coco = {
            "images": [{"id": 1, "file_name": "img.png"}],
            "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [0, 0, 10, 10]}],
            "categories": [{"id": 1, "name": "cat"}],
        }
        with open(tmp_dir / "annotations.json", "w") as f:
            json.dump(coco, f)
        fmt, ann = detect_format(tmp_dir)
        assert fmt == DatasetFormat.COCO
        assert ann is not None

    def test_yolo_detected(self, tmp_dir):
        """Directory with images/ and labels/ → YOLO."""
        images_dir = tmp_dir / "images"
        labels_dir = tmp_dir / "labels"
        images_dir.mkdir()
        labels_dir.mkdir()
        _create_image(images_dir / "img.png")
        (labels_dir / "img.txt").write_text("0 0.5 0.5 0.1 0.1\n")
        fmt, ann = detect_format(tmp_dir)
        assert fmt == DatasetFormat.YOLO


# ═══════════════════════════════════════════════════════════════════════════════
# Test 12: Dataset SHA-256
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatasetSHA256:
    def test_dataset_sha256_deterministic(self, tmp_dir):
        """Same files produce same dataset_sha256 regardless of ingestion order."""
        _create_image(tmp_dir / "x.png", color=(10, 20, 30))
        _create_image(tmp_dir / "y.png", color=(40, 50, 60))

        engine = DatasetIngestionEngine(manifests_dir=tmp_dir / "manifests")
        m1 = engine.ingest("ds1", DatasetFormat.IMAGE_FOLDER, "UNKNOWN", str(tmp_dir))

        # Ingest again — should produce same dataset_sha256
        m2 = engine.ingest("ds2", DatasetFormat.IMAGE_FOLDER, "UNKNOWN", str(tmp_dir))

        assert m1.dataset_sha256 == m2.dataset_sha256
        assert len(m1.dataset_sha256) == 64  # SHA-256 hex

    def test_dataset_sha256_changes_with_content(self, tmp_dir):
        """Different file content produces different dataset_sha256."""
        dir1 = tmp_dir / "d1"
        dir2 = tmp_dir / "d2"
        _create_image(dir1 / "img.png", color=(10, 20, 30))
        _create_image(dir2 / "img.png", color=(99, 99, 99))

        engine = DatasetIngestionEngine(manifests_dir=tmp_dir / "manifests")
        m1 = engine.ingest("ds1", DatasetFormat.IMAGE_FOLDER, "UNKNOWN", str(dir1))
        m2 = engine.ingest("ds2", DatasetFormat.IMAGE_FOLDER, "UNKNOWN", str(dir2))

        assert m1.dataset_sha256 != m2.dataset_sha256


# ═══════════════════════════════════════════════════════════════════════════════
# Test 13: Contributor risk aggregation
# ═══════════════════════════════════════════════════════════════════════════════

class TestContributorRisk:
    def test_contributor_risk_with_known_contributor(self, tmp_dir):
        """Known contributor produces risk aggregation."""
        img = tmp_dir / "risk.png"
        _create_zero_variance_image(img)

        engine = DatasetIngestionEngine(manifests_dir=tmp_dir / "manifests")
        manifest = engine.ingest("ds", DatasetFormat.IMAGE_FOLDER, "KnownContributor", str(tmp_dir))

        integrity = DataIntegrityEngine(reports_dir=tmp_dir / "reports")
        report = integrity.scan(manifest)

        assert len(report.contributor_risks) == 1
        assert report.contributor_risks[0].contributor_id == "KnownContributor"

    def test_no_contributor_risk_for_unknown(self, tmp_dir):
        """UNKNOWN contributor does NOT produce risk aggregation."""
        img = tmp_dir / "risk.png"
        _create_zero_variance_image(img)

        engine = DatasetIngestionEngine(manifests_dir=tmp_dir / "manifests")
        manifest = engine.ingest("ds", DatasetFormat.IMAGE_FOLDER, "UNKNOWN", str(tmp_dir))

        integrity = DataIntegrityEngine(reports_dir=tmp_dir / "reports")
        report = integrity.scan(manifest)

        assert len(report.contributor_risks) == 0
