"""Distribution-Shift and Out-of-Distribution (OOD) Analysis API Endpoints."""
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException

from app.drift.engine import default_drift_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.drift import (
    BaselineProfile,
    DistributionShiftReport,
    DistributionShiftRequest,
    RegisterBaselineRequest,
)

router = APIRouter(prefix="/drift", tags=["Distribution-Shift Engine"])


@router.post("/baselines/register", response_model=ResponseEnvelope[BaselineProfile])
def register_baseline_features(
    payload: RegisterBaselineRequest,
) -> ResponseEnvelope[BaselineProfile]:
    """Register reference image feature distributions for subsequent drift evaluations."""
    try:
        profile = default_drift_engine.register_baseline(
            baseline_id=payload.baseline_id,
            name=payload.name,
            features=payload.features,
            metadata=payload.metadata,
            sign=payload.sign_baseline,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return ResponseEnvelope(data=profile)


@router.get("/baselines", response_model=ResponseEnvelope[List[BaselineProfile]])
def list_registered_baselines() -> ResponseEnvelope[List[BaselineProfile]]:
    """List all registered baseline distribution profiles."""
    profiles = default_drift_engine.list_baselines()
    return ResponseEnvelope(data=profiles)


@router.get("/baselines/{baseline_id}", response_model=ResponseEnvelope[BaselineProfile])
def get_registered_baseline(baseline_id: str) -> ResponseEnvelope[BaselineProfile]:
    """Retrieve a specific registered baseline distribution profile."""
    profile = default_drift_engine.load_baseline_profile(baseline_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Baseline '{baseline_id}' not found.")
    return ResponseEnvelope(data=profile)


@router.post("/evaluate", response_model=ResponseEnvelope[DistributionShiftReport])
def evaluate_distribution_shift(
    payload: DistributionShiftRequest,
) -> ResponseEnvelope[DistributionShiftReport]:
    """Quantify distribution divergence between a candidate batch and a registered baseline."""
    target_features = payload.target_features
    if not target_features:
        try:
            base_feats = default_drift_engine.load_baseline(payload.baseline_id)
            target_features = base_feats
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Cannot resolve target features: {str(exc)}")

    try:
        report = default_drift_engine.evaluate_shift(
            baseline_id=payload.baseline_id,
            target_features=target_features,
            target_batch_id=payload.target_batch_id,
            threshold=payload.drift_threshold,
            expected_baseline_digest=payload.expected_baseline_digest,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return ResponseEnvelope(data=report)


@router.get("/reports", response_model=ResponseEnvelope[List[DistributionShiftReport]])
def list_distribution_shift_reports() -> ResponseEnvelope[List[DistributionShiftReport]]:
    """List all stored distribution shift reports."""
    reports = default_drift_engine.list_reports()
    return ResponseEnvelope(data=reports)


@router.get("/reports/{report_id}", response_model=ResponseEnvelope[DistributionShiftReport])
def get_distribution_shift_report(
    report_id: str,
) -> ResponseEnvelope[DistributionShiftReport]:
    """Retrieve an existing distribution shift report by its report ID."""
    report = default_drift_engine.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return ResponseEnvelope(data=report)
