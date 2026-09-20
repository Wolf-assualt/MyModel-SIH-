"""Pydantic schemas for Model Behavioural Fingerprinting."""
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
    ROTATION = "ROTATION"


class ProbeRecord(BaseModel):
    probe_id: str
    input_hash: str = Field(..., min_length=64, max_length=64)
    output_hash: str = Field(..., min_length=64, max_length=64)
    canonical_output: List[float] = Field(default_factory=list)
    model_hash: str = Field(..., min_length=64, max_length=64)


class PerturbationResult(BaseModel):
    perturbation: PerturbationType
    output_digest: str = Field(..., min_length=64, max_length=64)
    mean_confidence: float = Field(..., ge=0.0, le=1.0)
    top_class_id: int = Field(..., ge=0)


class ModelFingerprint(BaseModel):
    fingerprint_id: str
    model_id: str
    model_hash: Optional[str] = None
    battery_seed: int
    battery_size: int
    probe_records: List[ProbeRecord] = Field(default_factory=list)
    results: List[PerturbationResult]
    aggregate_digest: str = Field(..., min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FingerprintComparisonRequest(BaseModel):
    candidate_model_id: str = Field(..., min_length=1)
    reference_model_id: str = Field(..., min_length=1)
    battery_seed: int = 42
    battery_size: int = 8


class FingerprintComparisonResponse(BaseModel):
    candidate_model_id: str
    reference_model_id: str
    cosine_similarity: float = Field(..., ge=0.0, le=1.0)
    mean_squared_error: float = Field(..., ge=0.0)
    is_divergent: bool
    status: AssetStatus
    details: List[Dict[str, Any]] = Field(default_factory=list)
