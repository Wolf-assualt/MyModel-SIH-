"""Model Ingestion, Cryptographic Identity, and Baseline Verification API Endpoints."""
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from app.models_engine.registry import default_model_registry
from app.schemas.base import ResponseEnvelope
from app.schemas.model import (
    ModelIdentityManifest,
    ModelIngestRequest,
    ModelVerifyResponse,
)

router = APIRouter(prefix="/models", tags=["Model Supply Chain & Identity"])


@router.post("/register", response_model=ResponseEnvelope[ModelIdentityManifest])
def register_model(payload: ModelIngestRequest) -> ResponseEnvelope[ModelIdentityManifest]:
    """Ingest a CV model, inspect internal graph structures, and issue cryptographic identity manifest."""
    model_path = Path(payload.model_path)
    if not model_path.is_file():
        raise HTTPException(
            status_code=400,
            detail=f"Model file not found at path: {payload.model_path}",
        )

    try:
        manifest = default_model_registry.register_model(
            name=payload.name,
            version=payload.version,
            model_path=model_path,
            format=payload.format,
            is_reference=payload.is_reference,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Model registration failed: {str(exc)}")

    return ResponseEnvelope(data=manifest)


@router.get("/{model_id}", response_model=ResponseEnvelope[ModelIdentityManifest])
def get_model_manifest(model_id: str) -> ResponseEnvelope[ModelIdentityManifest]:
    """Retrieve registered model identity manifest by model ID."""
    manifest = default_model_registry.get_model(model_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Model manifest '{model_id}' not found.")

    return ResponseEnvelope(data=manifest)


@router.post("/{model_id}/verify", response_model=ResponseEnvelope[ModelVerifyResponse])
def verify_model_integrity(
    model_id: str,
    baseline_id: Optional[str] = Query(None, description="Optional specific baseline manifest ID"),
) -> ResponseEnvelope[ModelVerifyResponse]:
    """Verify model binary digest and structural dimensions against an approved reference baseline."""
    try:
        result = default_model_registry.verify_against_baseline(
            model_id=model_id,
            baseline_id=baseline_id,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found in registry.")

    return ResponseEnvelope(data=result)
