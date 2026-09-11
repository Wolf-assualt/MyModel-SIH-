"""Dataset ingestion, upload, and manifest verification endpoints."""
import hashlib
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps
from app.datasets.engine import default_ingestion_engine
from app.integrity.engine import default_integrity_engine
from app.schemas.base import AssetStatus, ResponseEnvelope
from app.schemas.dataset import (
    BatchManifest,
    BatchVerificationResponse,
    IngestDirectoryRequest,
    IngestResponse,
)
from app.schemas.integrity import AuditEvent, DatasetIntegrityReport, ImageAssessment

router = APIRouter(prefix="/datasets", tags=["Dataset Ingestion"])


def _safe_extract(archive: Path, destination: Path) -> None:
    """Extract an uploaded ZIP without allowing paths outside the upload directory."""
    with zipfile.ZipFile(archive) as zipped:
        for member in zipped.infolist():
            target = (destination / member.filename).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise ValueError("Archive contains an unsafe path")
        zipped.extractall(destination)


def _remove_exact_duplicate_images(source_dir: Path) -> int:
    """Keep one copy of each identical image while preserving distinct files."""
    image_extensions = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
    seen_hashes: set[str] = set()
    removed = 0
    for image_path in sorted(source_dir.rglob("*")):
        if not image_path.is_file() or image_path.suffix.lower() not in image_extensions:
            continue
        digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
        if digest in seen_hashes:
            image_path.unlink()
            removed += 1
        else:
            seen_hashes.add(digest)
    return removed


@router.post("/upload", response_model=ResponseEnvelope[DatasetIntegrityReport])
async def upload_and_scan_dataset(
    file: UploadFile = File(...),
    dataset_name: str = Form("uploaded-dataset"),
) -> ResponseEnvelope[DatasetIntegrityReport]:
    """Persist and immediately scan an uploaded image or ZIP dataset."""
    upload_root = Path(settings.DATA_DIR) / "uploads" / str(uuid.uuid4())
    source_dir = upload_root / "samples"
    source_dir.mkdir(parents=True, exist_ok=True)
    upload_path = upload_root / (Path(file.filename or "upload").name)

    try:
        with upload_path.open("wb") as destination:
            shutil.copyfileobj(file.file, destination)

        if upload_path.suffix.lower() == ".zip":
            _safe_extract(upload_path, source_dir)
        else:
            shutil.copy2(upload_path, source_dir / upload_path.name)

        _remove_exact_duplicate_images(source_dir)
        manifest = default_ingestion_engine.ingest(
            dataset_name=dataset_name,
            format="IMAGE_FOLDER",
            contributor_id="frontend-upload",
            source_path=str(source_dir),
        )
        report = default_integrity_engine.scan(manifest)
        return ResponseEnvelope(data=report)
    except (zipfile.BadZipFile, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Dataset upload failed: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Dataset analysis failed: {exc}")


@router.post("/quarantine/{batch_id}/{sample_id:path}", response_model=ResponseEnvelope[ImageAssessment])
def quarantine_dataset_image(batch_id: str, sample_id: str) -> ResponseEnvelope[ImageAssessment]:
    """Copy a flagged sample into isolated storage and block it from trusted use."""
    manifest = default_ingestion_engine.load_manifest(batch_id)
    report = default_integrity_engine.load_report(batch_id)
    if not manifest or not report:
        raise HTTPException(status_code=404, detail=f"Dataset batch '{batch_id}' not found.")

    assessment = next((item for item in report.image_results if item.sample_id == sample_id), None)
    sample = next((item for item in manifest.samples if item.sample_id == sample_id), None)
    if not assessment or not sample:
        raise HTTPException(status_code=404, detail=f"Image '{sample_id}' not found in batch '{batch_id}'.")
    if assessment.result == "REAL / CLEAN":
        raise HTTPException(status_code=400, detail="Clean images cannot be quarantined.")

    quarantine_dir = Path(settings.DATA_DIR) / "quarantine" / "uploads" / batch_id
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    destination = quarantine_dir / Path(sample.file_path).name
    shutil.copy2(sample.file_path, destination)

    assessment.quarantined = True
    assessment.action = "BLOCKED: EXCLUDED FROM INFERENCE"
    assessment.trust_status = "REVOKED"
    event = AuditEvent(
        timestamp=datetime.now(timezone.utc),
        artifact_id=sample.sample_id,
        sha256_hash=sample.sha256_hash,
        detection_result=assessment.result,
        integrity_status=assessment.integrity_status,
        reason="Integrity/poisoning violation",
        action="QUARANTINED",
    )
    report.audit_events.append(event)
    audit_file = Path(settings.DATA_DIR) / "audit" / "image_events.jsonl"
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    with audit_file.open("a", encoding="utf-8") as stream:
        stream.write(event.model_dump_json() + "\n")
    report_file = default_integrity_engine.reports_dir / f"integrity_{batch_id}.json"
    with report_file.open("w", encoding="utf-8") as stream:
        stream.write(canonical_json_dumps(report.model_dump(mode="json")))
    return ResponseEnvelope(data=assessment)


@router.post("/ingest", response_model=ResponseEnvelope[IngestResponse])
def ingest_dataset(payload: IngestDirectoryRequest) -> ResponseEnvelope[IngestResponse]:
    """Ingest a directory of CV samples, compute Merkle inclusion root, and persist manifest."""
    source_dir = Path(payload.source_path)
    if not source_dir.exists() or not source_dir.is_dir():
        raise HTTPException(status_code=400, detail=f"Source directory does not exist or is not a directory: {payload.source_path}")

    if payload.annotation_path:
        ann_path = Path(payload.annotation_path)
        if not ann_path.exists() or not ann_path.is_file():
            raise HTTPException(status_code=400, detail=f"Annotation file does not exist: {payload.annotation_path}")

    try:
        manifest = default_ingestion_engine.ingest(
            dataset_name=payload.dataset_name,
            format=payload.format,
            contributor_id=payload.contributor_id,
            source_path=payload.source_path,
            annotation_path=payload.annotation_path,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Dataset ingestion failed: {str(exc)}")

    return ResponseEnvelope(data=IngestResponse(
        batch_id=manifest.batch_id,
        dataset_name=manifest.dataset_name,
        sample_count=manifest.sample_count,
        merkle_root=manifest.merkle_root,
        status=AssetStatus.ACCEPTED,
    ))


@router.get("/manifest/{batch_id}", response_model=ResponseEnvelope[BatchManifest])
def get_batch_manifest(batch_id: str) -> ResponseEnvelope[BatchManifest]:
    """Retrieve the cryptographic batch manifest for an ingested dataset."""
    manifest = default_ingestion_engine.load_manifest(batch_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Batch manifest {batch_id} not found.")
    return ResponseEnvelope(data=manifest)


@router.get("/manifest/{batch_id}/verify", response_model=ResponseEnvelope[BatchVerificationResponse])
def verify_batch_manifest(batch_id: str) -> ResponseEnvelope[BatchVerificationResponse]:
    """Verify on-disk sample file integrity and Merkle root against stored manifest."""
    try:
        result = default_ingestion_engine.verify_manifest(batch_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Batch manifest {batch_id} not found.")
    return ResponseEnvelope(data=result)
