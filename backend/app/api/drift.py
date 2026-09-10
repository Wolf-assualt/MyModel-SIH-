"""Distribution-Shift and Out-of-Distribution (OOD) Analysis API Endpoints."""
from typing import Any, Dict
from fastapi import APIRouter, HTTPException

from app.drift.engine import default_drift_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.drift import (
    DistributionShiftReport,
    DistributionShiftRequest,
    RegisterBaselineRequest,
)

router = APIRouter(prefix="/drift", tags=["Distribution-Shift Engine"])


@router.post("/baselines/register", response_model=ResponseEnvelope[Dict[str, Any]])
def register_baseline_features(
    payload: RegisterBaselineRequest,
) -> ResponseEnvelope[Dict[str, Any]]:
    """Register reference image feature distributions for subsequent drift evaluations."""
    try:
        default_drift_engine.register_baseline(
            baseline_id=payload.baseline_id,
            features=payload.features,
            metadata=payload.metadata,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return ResponseEnvelope(
        data={
            "baseline_id": payload.baseline_id,
            "features_registered": list(payload.features.keys()),
            "status": "REGISTERED",
        }
    )


@router.post("/evaluate", response_model=ResponseEnvelope[DistributionShiftReport])
def evaluate_distribution_shift(
    payload: DistributionShiftRequest,
) -> ResponseEnvelope[DistributionShiftReport]:
    """Quantify distribution divergence between a candidate batch and a registered baseline."""
    # Resolve target features: from payload if provided, or synthetic fallback based on batch ID
    target_features = payload.target_features
    if not target_features:
        # If not supplied explicitly, attempt to load baseline to match keys or return error
        try:
            base_feats = default_drift_engine.load_baseline(payload.baseline_id)
            # Duplicate baseline features as a neutral comparison if none supplied
            target_features = base_feats
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Cannot resolve target features: {str(exc)}")

    try:
        report = default_drift_engine.evaluate_shift(
            baseline_id=payload.baseline_id,
            target_features=target_features,
            target_batch_id=payload.target_batch_id,
            threshold=payload.drift_threshold,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return ResponseEnvelope(data=report)


@router.get("/reports/{report_id}", response_model=ResponseEnvelope[DistributionShiftReport])
def get_distribution_shift_report(
    report_id: str,
) -> ResponseEnvelope[DistributionShiftReport]:
    """Retrieve an existing distribution shift report by its report ID."""
    report = default_drift_engine.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return ResponseEnvelope(data=report)
