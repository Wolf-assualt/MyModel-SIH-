"""Pydantic schemas for Distribution-Shift and Out-of-Distribution (OOD) Analysis."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class DriftType(str, Enum):
    """Classification of distribution shift in computer vision pipelines."""
    NO_DRIFT = "NO_DRIFT"
    OPERATIONAL_ENVIRONMENTAL = "OPERATIONAL_ENVIRONMENTAL"  # e.g., low light, fog, seasonal terrain
    SENSOR_DEGRADATION = "SENSOR_DEGRADATION"  # e.g., blur, noise, lens obstruction
    ADVERSARIAL_ANOMALY = "ADVERSARIAL_ANOMALY"  # sudden confidence collapse, unnatural histogram shifts


class FeatureDriftMetric(BaseModel):
    """Statistical drift metric for a specific extracted image feature."""
    feature_name: str
    baseline_mean: float
    target_mean: float
    drift_score: float = Field(..., ge=0.0)  # PSI or KS distance [0.0, 1.0+]
    is_drifted: bool


class DistributionShiftReport(BaseModel):
    """Cryptographically sealed report summarizing distribution shift analysis."""
    report_id: str
    baseline_id: str
    target_batch_id: str
    sample_count: int = Field(..., ge=0)
    overall_drift_score: float = Field(..., ge=0.0)  # 0.0 (identical) to 1.0 (extreme shift)
    detected_drift_type: DriftType
    feature_metrics: List[FeatureDriftMetric]
    status: AssetStatus
    report_digest: str = Field(..., min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DistributionShiftRequest(BaseModel):
    """Request payload to evaluate distribution shift of a candidate batch against a baseline."""
    baseline_id: str = Field(..., min_length=1)
    target_batch_id: str = Field(..., min_length=1)
    drift_threshold: float = Field(0.25, ge=0.0, le=1.0)
    target_features: Optional[Dict[str, List[float]]] = None


class RegisterBaselineRequest(BaseModel):
    """Request payload to store baseline distribution features."""
    baseline_id: str = Field(..., min_length=1)
    features: Dict[str, List[float]] = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)
