"""Distribution-Shift and Out-of-Distribution (OOD) Analysis API Endpoints."""
from typing import Any, Dict, List
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Query

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
    """Register and cryptographically seal reference image feature distributions."""
    try:
        profile = default_drift_engine.register_baseline(
            baseline_id=payload.baseline_id,
            name=payload.name,
            features=payload.features,
            metadata=payload.metadata,
            sign_baseline=payload.sign_baseline,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return ResponseEnvelope(data=profile)


@router.get("/baselines", response_model=ResponseEnvelope[List[Dict[str, Any]]])
def list_registered_baselines() -> ResponseEnvelope[List[Dict[str, Any]]]:
    """List all registered reference baseline profiles."""
    baselines = default_drift_engine.list_baselines()
    return ResponseEnvelope(data=baselines)


@router.get("/baselines/{baseline_id}", response_model=ResponseEnvelope[BaselineProfile])
def get_registered_baseline(
    baseline_id: str,
) -> ResponseEnvelope[BaselineProfile]:
    """Retrieve full details of a registered baseline profile by baseline_id."""
    try:
        profile = default_drift_engine.load_baseline_profile(baseline_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Baseline '{baseline_id}' not found.")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return ResponseEnvelope(data=profile)


@router.post("/evaluate", response_model=ResponseEnvelope[DistributionShiftReport])
def evaluate_distribution_shift(
    payload: DistributionShiftRequest,
) -> ResponseEnvelope[DistributionShiftReport]:
    """Quantify distribution divergence between a candidate batch and a registered reference baseline."""
    # Enforce invariant: Never copy the target dataset as its own baseline
    target_features = payload.target_features
    if not target_features:
        raise HTTPException(
            status_code=400,
            detail="target_features is required. Cannot evaluate drift without candidate distribution.",
        )

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
def list_distribution_shift_reports(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of reports to return"),
) -> ResponseEnvelope[List[DistributionShiftReport]]:
    """List stored distribution shift reports up to limit."""
    reports: List[DistributionShiftReport] = []
    if default_drift_engine.reports_dir.exists():
        for rf in sorted(default_drift_engine.reports_dir.glob("*.json"), reverse=True):
            rep = default_drift_engine.get_report(rf.stem)
            if rep:
                reports.append(rep)
            if len(reports) >= limit:
                break
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

