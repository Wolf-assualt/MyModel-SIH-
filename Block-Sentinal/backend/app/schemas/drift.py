"""Pydantic schemas for Distribution-Shift, OOD, and Drift Assurance."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class DriftType(str, Enum):
    """Classification of distribution shift in computer vision pipelines."""
    NO_DRIFT = "NO_DRIFT"
    OPERATIONAL_ENVIRONMENTAL = "OPERATIONAL_ENVIRONMENTAL"
    ENVIRONMENTAL_SHIFT = "OPERATIONAL_ENVIRONMENTAL"
    ILLUMINATION_SHIFT = "OPERATIONAL_ENVIRONMENTAL"
    SENSOR_DEGRADATION = "SENSOR_DEGRADATION"
    SENSOR_SHIFT = "SENSOR_DEGRADATION"
    DATASET_DRIFT = "DATASET_DRIFT"
    ADVERSARIAL_ANOMALY = "ADVERSARIAL_ANOMALY"
    SUSPICIOUS_SHIFT = "ADVERSARIAL_ANOMALY"
    UNKNOWN = "UNKNOWN"


class DriftSeverity(str, Enum):
    """Severity classification for observed distribution divergence."""
    NO_DRIFT = "NO_DRIFT"
    NONE = "NONE"
    MILD = "MILD"
    MILD_DRIFT = "MILD_DRIFT"
    MODERATE = "MODERATE"
    MODERATE_DRIFT = "MODERATE_DRIFT"
    SIGNIFICANT = "SIGNIFICANT"
    SIGNIFICANT_DRIFT = "SIGNIFICANT_DRIFT"
    CRITICAL = "CRITICAL"
    CRITICAL_SHIFT = "CRITICAL_SHIFT"


class BaselineReferenceType(str, Enum):
    """Supported reference baseline formats."""
    REFERENCE_DATASET = "REFERENCE_DATASET"
    FEATURE_PROFILE = "FEATURE_PROFILE"
    CANONICAL_MANIFEST = "CANONICAL_MANIFEST"


class FeatureSummary(BaseModel):
    """Summary descriptive moments for an individual feature distribution."""
    count: int = 0
    mean: float = 0.0
    std: float = 0.0
    min: float = 0.0
    max: float = 0.0
    median: float = 0.0


class BaselineProfile(BaseModel):
    """Cryptographically signed reference baseline feature profile."""
    baseline_id: str
    name: str = "Reference Baseline"
    reference_type: BaselineReferenceType = BaselineReferenceType.FEATURE_PROFILE
    features: Dict[str, List[float]] = Field(default_factory=dict)
    feature_summaries: Dict[str, FeatureSummary] = Field(default_factory=dict)
    sample_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    baseline_digest: str = Field(..., min_length=64, max_length=64)
    signature: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FeatureDriftMetric(BaseModel):
    """Statistical drift metric for a specific extracted image feature."""
    feature_name: str
    baseline_mean: float
    target_mean: float
    drift_score: float = Field(..., ge=0.0)  # Primary normalized drift score [0.0, 1.0+]
    ks_distance: Optional[float] = None
    ks_statistic: Optional[float] = None
    ks_p_value: Optional[float] = None
    psi: Optional[float] = None
    psi_score: Optional[float] = None
    wasserstein: Optional[float] = None
    wasserstein_distance: Optional[float] = None
    energy_distance: Optional[float] = None
    is_drifted: bool
    explanation: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if self.psi is not None and self.psi_score is None:
            self.psi_score = self.psi
        elif self.psi_score is not None and self.psi is None:
            self.psi = self.psi_score

        if self.ks_distance is not None and self.ks_statistic is None:
            self.ks_statistic = self.ks_distance
        elif self.ks_statistic is not None and self.ks_distance is None:
            self.ks_distance = self.ks_statistic

        if self.wasserstein is not None and self.wasserstein_distance is None:
            self.wasserstein_distance = self.wasserstein
        elif self.wasserstein_distance is not None and self.wasserstein is None:
            self.wasserstein = self.wasserstein_distance


class DistributionShiftReport(BaseModel):
    """Cryptographically sealed report summarizing distribution shift analysis."""
    report_id: str
    baseline_id: str
    target_batch_id: str
    sample_count: int = Field(..., ge=0)
    overall_drift_score: float = Field(..., ge=0.0)  # 0.0 (identical) to 1.0 (extreme shift)
    detected_drift_type: DriftType
    severity: DriftSeverity = DriftSeverity.NO_DRIFT
    feature_metrics: List[FeatureDriftMetric] = Field(default_factory=list)
    affected_features: List[str] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)
    status: AssetStatus
    report_digest: str = Field(..., min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DistributionShiftRequest(BaseModel):
    """Request payload to evaluate distribution shift of a candidate batch against a baseline."""
    baseline_id: str = Field(..., min_length=1)
    target_batch_id: str = Field(..., min_length=1)
    drift_threshold: float = Field(0.25, ge=0.0, le=1.0)
    target_features: Optional[Dict[str, List[float]]] = None
    expected_baseline_digest: Optional[str] = None


class RegisterBaselineRequest(BaseModel):
    """Request payload to store baseline distribution features."""
    baseline_id: str = Field(..., min_length=1)
    name: Optional[str] = None
    features: Dict[str, List[float]] = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    sign_baseline: bool = True
