"""Pydantic schemas for Distribution-Shift and Out-of-Distribution (OOD) Analysis."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class DriftSeverity(str, Enum):
    """Calibrated four-tier severity classification for distribution shift."""
    NO_DRIFT = "NO_DRIFT"              # Score < 0.10: normal statistical variance
    MILD_DRIFT = "MILD_DRIFT"          # 0.10 <= Score < 0.25: slight environmental changes
    SIGNIFICANT_DRIFT = "SIGNIFICANT_DRIFT"  # 0.25 <= Score < 0.50: noticeable domain change
    CRITICAL_SHIFT = "CRITICAL_SHIFT"  # Score >= 0.50: severe anomaly / OOD failure


class DriftType(str, Enum):
    """Categorization of distribution shift root causes in computer vision pipelines."""
    NO_DRIFT = "NO_DRIFT"
    OPERATIONAL_ENVIRONMENTAL = "OPERATIONAL_ENVIRONMENTAL"  # e.g., low light, fog, seasonal terrain
    SENSOR_DEGRADATION = "SENSOR_DEGRADATION"                # e.g., blur, noise, lens obstruction
    ADVERSARIAL_ANOMALY = "ADVERSARIAL_ANOMALY"              # sudden confidence collapse, entropy collapse


class FeatureSummary(BaseModel):
    """Statistical summary moments for a single distribution feature."""
    count: int = 0
    mean: float = 0.0
    std: float = 0.0
    min: float = 0.0
    max: float = 0.0
    median: float = 0.0
    p25: float = 0.0
    p75: float = 0.0


class FeatureDriftMetric(BaseModel):
    """Statistical drift metric for a specific extracted image feature."""
    feature_name: str
    baseline_mean: float
    baseline_std: float = 0.0
    target_mean: float
    target_std: float = 0.0
    drift_score: float = Field(..., ge=0.0)  # Primary normalized distance [0.0, 1.0+]
    wasserstein_distance: float = 0.0
    ks_statistic: float = 0.0
    ks_p_value: float = 1.0
    psi_score: float = 0.0
    energy_distance: float = 0.0
    severity: DriftSeverity = DriftSeverity.NO_DRIFT
    is_drifted: bool = False
    explanation: str = ""


class BaselineProfile(BaseModel):
    """Cryptographically signed reference baseline distribution profile."""
    baseline_id: str
    name: str = "baseline"
    sample_count: int = Field(..., ge=0)
    features: Dict[str, List[float]] = Field(default_factory=dict)
    feature_summaries: Dict[str, FeatureSummary] = Field(default_factory=dict)
    baseline_digest: str = Field(..., min_length=64, max_length=64)
    signature: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DistributionShiftReport(BaseModel):
    """Cryptographically sealed report summarizing distribution shift analysis."""
    report_id: str
    baseline_id: str
    baseline_digest: str = Field(..., min_length=64, max_length=64)
    target_batch_id: str
    sample_count: int = Field(..., ge=0)
    overall_drift_score: float = Field(..., ge=0.0)
    severity: DriftSeverity = DriftSeverity.NO_DRIFT
    detected_drift_type: DriftType
    feature_metrics: List[FeatureDriftMetric]
    affected_features: List[str] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)
    status: AssetStatus
    report_digest: str = Field(..., min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DistributionShiftRequest(BaseModel):
    """Request payload to evaluate distribution shift of a candidate batch against a baseline."""
    baseline_id: str = Field(..., min_length=1)
    target_batch_id: str = Field("batch_target", min_length=1)
    drift_threshold: float = Field(0.25, ge=0.0, le=1.0)
    expected_baseline_digest: Optional[str] = None
    target_features: Optional[Dict[str, List[float]]] = None


class RegisterBaselineRequest(BaseModel):
    """Request payload to store baseline distribution features."""
    baseline_id: str = Field(..., min_length=1)
    name: str = "approved_baseline"
    features: Dict[str, List[float]] = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    sign_baseline: bool = True
