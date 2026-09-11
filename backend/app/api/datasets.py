from typing import List
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.datasets.engine import default_ingestion_engine
from app.models.dataset import Dataset
from app.schemas.base import AssetStatus, ResponseEnvelope
from app.schemas.dataset import (
    BatchManifest,
    BatchVerificationResponse,
    DatasetResponse,
    IngestDirectoryRequest,
    IngestResponse,
)

router = APIRouter(prefix="/datasets", tags=["Dataset Ingestion"])


@router.get("", response_model=ResponseEnvelope[List[BatchManifest]])
def list_datasets() -> ResponseEnvelope[List[BatchManifest]]:
    """List all ingested dataset batch manifests."""
    manifests = default_ingestion_engine.list_manifests()
    return ResponseEnvelope(data=manifests)


@router.post("/ingest", response_model=ResponseEnvelope[IngestResponse])
def ingest_dataset(
    payload: IngestDirectoryRequest,
    db: Session = Depends(get_db),
) -> ResponseEnvelope[IngestResponse]:
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
        # Register batch into database
        default_ingestion_engine.register_batch_to_database(
            manifest=manifest,
            db=db,
            root_path=str(source_dir.resolve()),
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



@router.get("/{dataset_id}", response_model=ResponseEnvelope[DatasetResponse])
def get_dataset_details(
    dataset_id: str,
    db: Session = Depends(get_db),
) -> ResponseEnvelope[DatasetResponse]:
    """Retrieve ingested dataset record and associated batches from database."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail=f"Dataset with ID '{dataset_id}' not found.")

    return ResponseEnvelope(data=DatasetResponse.model_validate(dataset))


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


@router.post("/bigearthnet/inspect", response_model=ResponseEnvelope[dict])
def inspect_bigearthnet(payload: IngestDirectoryRequest) -> ResponseEnvelope[dict]:
    """Perform read-only structure inspection and audit on a local BigEarthNet-S2 directory."""
    from app.datasets.bigearthnet import BigEarthNetS2Adapter
    source_dir = Path(payload.source_path)
    if not source_dir.exists() or not source_dir.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"Source directory does not exist or is not a directory: {payload.source_path}",
        )
    try:
        inspection = BigEarthNetS2Adapter.inspect(source_dir)
        return ResponseEnvelope(data=inspection)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"BigEarthNet inspection failed: {str(exc)}")


