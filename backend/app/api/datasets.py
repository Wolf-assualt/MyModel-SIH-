"""Dataset Ingestion and Manifest Verification Endpoints."""
import uuid
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.core.config import settings
from app.datasets.engine import default_ingestion_engine
from app.schemas.base import AssetStatus, ResponseEnvelope
from app.schemas.dataset import (
    BatchManifest,
    BatchVerificationResponse,
    DatasetFormat,
    IngestDirectoryRequest,
    IngestResponse,
)

router = APIRouter(prefix="/datasets", tags=["Dataset Ingestion"])


@router.post("/upload", response_model=ResponseEnvelope[IngestResponse])
async def upload_and_ingest_dataset(
    dataset_name: str = Form("Uploaded_EO_Patch"),
    format: DatasetFormat = Form(DatasetFormat.BIGEARTHNET_S2),
    contributor_id: str = Form("operator_ground_station"),
    files: List[UploadFile] = File(...),
) -> ResponseEnvelope[IngestResponse]:
    """Accept real browser multipart file/folder upload, save to sandbox, and execute cryptographic ingestion."""
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    if len(files) > settings.MAX_UPLOAD_FILES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many files selected. Maximum allowed is {settings.MAX_UPLOAD_FILES} files per upload (received {len(files)}).",
        )

    upload_batch_id = str(uuid.uuid4())
    upload_dir = Path(settings.DATA_DIR) / "uploads" / upload_batch_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    try:
        saved_files = []
        for upload_file in files:
            # Preserve relative filename or basename
            raw_filename = upload_file.filename or f"band_{len(saved_files)}.tif"
            filename = Path(raw_filename).name
            dest_path = upload_dir / filename
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            content = await upload_file.read()
            with open(dest_path, "wb") as f:
                f.write(content)
            saved_files.append(dest_path)

        manifest = default_ingestion_engine.ingest(
            dataset_name=dataset_name,
            format=format,
            contributor_id=contributor_id,
            source_path=str(upload_dir),
        )

        return ResponseEnvelope(
            data=IngestResponse(
                batch_id=manifest.batch_id,
                dataset_name=manifest.dataset_name,
                sample_count=manifest.sample_count,
                merkle_root=manifest.merkle_root,
                status=AssetStatus.ACCEPTED,
            )
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Dataset upload ingestion failed: {str(exc)}")


@router.post("/ingest", response_model=ResponseEnvelope[IngestResponse])
def ingest_dataset(payload: IngestDirectoryRequest) -> ResponseEnvelope[IngestResponse]:
    """Ingest a directory of CV samples, compute Merkle inclusion root, and persist manifest."""
    source_dir = Path(payload.source_path)
    if not source_dir.exists() or not source_dir.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"Source directory does not exist or is not a directory: {payload.source_path}",
        )

    if payload.annotation_path:
        ann_path = Path(payload.annotation_path)
        if not ann_path.exists() or not ann_path.is_file():
            raise HTTPException(
                status_code=400,
                detail=f"Annotation file does not exist: {payload.annotation_path}",
            )

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

    return ResponseEnvelope(
        data=IngestResponse(
            batch_id=manifest.batch_id,
            dataset_name=manifest.dataset_name,
            sample_count=manifest.sample_count,
            merkle_root=manifest.merkle_root,
            status=AssetStatus.ACCEPTED,
        )
    )


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
