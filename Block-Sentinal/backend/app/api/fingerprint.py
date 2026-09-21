"""Model Behavioural Fingerprinting and Comparative Audit API Endpoints."""
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Query

from app.fingerprint.runner import default_fingerprinter
from app.schemas.base import ResponseEnvelope
from app.schemas.fingerprint import (
    FingerprintComparisonRequest,
    FingerprintComparisonResponse,
    ModelFingerprint,
)

router = APIRouter(prefix="/fingerprint", tags=["Behavioural Fingerprinting"])


@router.post("/generate", response_model=ResponseEnvelope[ModelFingerprint])
def generate_model_fingerprint(
    model_id: str = Query(..., min_length=1, description="Registered model ID"),
    seed: int = Query(42, description="Battery randomization seed"),
    count: int = Query(8, ge=1, le=64, description="Number of probe inputs"),
) -> ResponseEnvelope[ModelFingerprint]:
    """Execute standard perturbation battery against a model and generate behavioural fingerprint."""
    try:
        fingerprint = default_fingerprinter.fingerprint_model(
            model_id=model_id,
            seed=seed,
            count=count,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Fingerprint generation failed: {str(exc)}")

    return ResponseEnvelope(data=fingerprint)


@router.get("/{model_id}", response_model=ResponseEnvelope[ModelFingerprint])
def get_model_fingerprint(
    model_id: str,
    seed: int = Query(42, description="Battery randomization seed"),
) -> ResponseEnvelope[ModelFingerprint]:
    """Retrieve an existing model behavioural fingerprint by model ID."""
    fp = default_fingerprinter.load_fingerprint(model_id, seed=seed)
    if not fp:
        try:
            fp = default_fingerprinter.fingerprint_model(model_id=model_id, seed=seed)
        except Exception:
            raise HTTPException(status_code=404, detail=f"Fingerprint for model '{model_id}' (seed: {seed}) not found.")
    return ResponseEnvelope(data=fp)


@router.post("/compare", response_model=ResponseEnvelope[FingerprintComparisonResponse])
def compare_model_fingerprints(
    payload: FingerprintComparisonRequest,
) -> ResponseEnvelope[FingerprintComparisonResponse]:
    """Compare candidate model against reference baseline across perturbation responses."""
    # Ensure both candidate and reference fingerprints are available (or generate on-demand)
    cand_fp = default_fingerprinter.load_fingerprint(payload.candidate_model_id, payload.battery_seed)
    if not cand_fp:
        cand_fp = default_fingerprinter.fingerprint_model(
            payload.candidate_model_id,
            seed=payload.battery_seed,
            count=payload.battery_size,
        )

    ref_fp = default_fingerprinter.load_fingerprint(payload.reference_model_id, payload.battery_seed)
    if not ref_fp:
        ref_fp = default_fingerprinter.fingerprint_model(
            payload.reference_model_id,
            seed=payload.battery_seed,
            count=payload.battery_size,
        )

    comparison = default_fingerprinter.compare_fingerprints(cand_fp, ref_fp)
    return ResponseEnvelope(data=comparison)
