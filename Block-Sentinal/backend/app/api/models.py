"""Model Ingestion, Cryptographic Identity, and Baseline Verification API Endpoints."""
from pathlib import Path
from typing import Optional
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Query
# pyrefly: ignore [missing-import]
from pydantic import BaseModel

from app.crypto.signer import KeyManager
from app.models_engine.registry import default_model_registry
from app.schemas.base import ResponseEnvelope
from app.schemas.model import (
    ModelAssuranceFinding,
    ModelIdentityManifest,
    ModelIngestRequest,
    ModelVerifyResponse,
)

router = APIRouter(prefix="/models", tags=["Model Supply Chain & Identity"])


class ModelVerifyRequest(BaseModel):
    model_id: str
    baseline_id: Optional[str] = None


@router.post("/ingest", response_model=ResponseEnvelope[ModelIdentityManifest])
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
            access_mode=payload.access_mode,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Model registration failed: {str(exc)}")

    return ResponseEnvelope(data=manifest)


@router.get("/manifest/{model_id}", response_model=ResponseEnvelope[ModelIdentityManifest])
def get_model_manifest_by_id(model_id: str) -> ResponseEnvelope[ModelIdentityManifest]:
    """Retrieve registered model identity manifest by model ID."""
    manifest = default_model_registry.get_model(model_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Model manifest '{model_id}' not found.")
    return ResponseEnvelope(data=manifest)


@router.get("/{model_id}", response_model=ResponseEnvelope[ModelIdentityManifest])
def get_model_manifest(model_id: str) -> ResponseEnvelope[ModelIdentityManifest]:
    """Retrieve registered model identity manifest by model ID."""
    manifest = default_model_registry.get_model(model_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Model manifest '{model_id}' not found.")

    return ResponseEnvelope(data=manifest)


@router.post("/verify", response_model=ResponseEnvelope[ModelVerifyResponse])
def verify_model_by_body(payload: ModelVerifyRequest) -> ResponseEnvelope[ModelVerifyResponse]:
    """Verify model binary digest and structural dimensions against an approved reference baseline (body-based)."""
    try:
        result = default_model_registry.verify_against_baseline(
            model_id=payload.model_id,
            baseline_id=payload.baseline_id,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{payload.model_id}' not found in registry.")

    # Compute signature_valid from manifest
    manifest = default_model_registry.get_model(payload.model_id)
    signature_valid = False
    if manifest and manifest.signature:
        try:
            pub_pem = default_model_registry.key_manager.export_public_key_pem()
            signature_valid = KeyManager.verify_signature(pub_pem, manifest.identity_digest, manifest.signature)
        except Exception:
            signature_valid = False

    result.signature_valid = signature_valid
    return ResponseEnvelope(data=result)


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


@router.get("/{model_id}/assurance", response_model=ResponseEnvelope[ModelAssuranceFinding])
def get_model_assurance(
    model_id: str,
    baseline_id: Optional[str] = Query(None, description="Optional specific baseline manifest ID"),
) -> ResponseEnvelope[ModelAssuranceFinding]:
    """Retrieve comprehensive standardized model assurance finding."""
    try:
        finding = default_model_registry.generate_assurance_finding(
            model_id=model_id,
            baseline_id=baseline_id,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found in registry.")

    return ResponseEnvelope(data=finding)
