"""Pydantic schemas for Model Behavioural Fingerprinting & Sensitivity Analysis."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class PerturbationType(str, Enum):
    IDENTITY = "IDENTITY"
    GAUSSIAN_NOISE = "GAUSSIAN_NOISE"
    GAUSSIAN_BLUR = "GAUSSIAN_BLUR"
    CONTRAST_SHIFT = "CONTRAST_SHIFT"
    BRIGHTNESS_SHIFT = "BRIGHTNESS_SHIFT"
    ROTATION = "ROTATION"
    OCCLUSION_PATCH = "OCCLUSION_PATCH"


class PerturbationResult(BaseModel):
    perturbation: PerturbationType
    output_digest: str = Field(..., min_length=64, max_length=64)
    mean_confidence: float = Field(..., ge=0.0, le=1.0)
    top_class_id: int = Field(..., ge=0)
    output_l2_norm: Optional[float] = None
    output_mean: Optional[float] = None
    output_std: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ModelFingerprint(BaseModel):
    fingerprint_id: str
    model_id: str
    battery_seed: int
    battery_size: int
    results: List[PerturbationResult]
    activation_stats: Dict[str, Any] = Field(default_factory=dict)
    aggregate_digest: str = Field(..., min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FingerprintComparisonRequest(BaseModel):
    candidate_model_id: str = Field(..., min_length=1)
    reference_model_id: str = Field(..., min_length=1)
    battery_seed: int = 42
    battery_size: int = 8
    divergence_threshold: float = 0.95


class FingerprintComparisonResponse(BaseModel):
    candidate_model_id: str
    reference_model_id: str
    cosine_similarity: float = Field(..., ge=0.0, le=1.0)
    mean_squared_error: float = Field(..., ge=0.0)
    max_absolute_error: float = Field(default=0.0, ge=0.0)
    is_divergent: bool
    divergent_probes: List[str] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)
    status: AssetStatus
    details: List[Dict[str, Any]] = Field(default_factory=list)
