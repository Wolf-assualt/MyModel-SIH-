"""Training-Data Integrity Analysis API Endpoints."""
from fastapi import APIRouter, HTTPException

from app.datasets.engine import default_ingestion_engine
from app.integrity.engine import default_integrity_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.integrity import DatasetIntegrityReport, IntegrityScanRequest

router = APIRouter(prefix="/integrity", tags=["Training-Data Integrity"])


@router.post("/scan", response_model=ResponseEnvelope[DatasetIntegrityReport])
@router.post("/audit", response_model=ResponseEnvelope[DatasetIntegrityReport])
def scan_batch_integrity(payload: IntegrityScanRequest) -> ResponseEnvelope[DatasetIntegrityReport]:
    """Execute multi-detector integrity scan on an ingested dataset batch."""
    manifest = default_ingestion_engine.load_manifest(payload.batch_id)
    if not manifest:
        raise HTTPException(
            status_code=404,
            detail=f"Batch manifest '{payload.batch_id}' not found for integrity scanning.",
        )

    report = default_integrity_engine.scan(
        manifest=manifest,
        duplicate_threshold=payload.duplicate_threshold,
        trigger_detection_enabled=payload.trigger_detection_enabled,
    )
    return ResponseEnvelope(data=report)


@router.get("/report/{batch_id}", response_model=ResponseEnvelope[DatasetIntegrityReport])
def get_integrity_report(batch_id: str) -> ResponseEnvelope[DatasetIntegrityReport]:
    """Retrieve an existing cryptographic integrity report by batch ID."""
    report = default_integrity_engine.load_report(batch_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Integrity report for batch '{batch_id}' not found.",
        )

    return ResponseEnvelope(data=report)
