"""Schemas for Model Runtime Lifecycle, State Machine, Preprocessing, and Execution Audit."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.model import ModelFormat, ModelInputSpec, ModelOutputSpec


class ModelRuntimeState(str, Enum):
    """Authoritative states for model validation, runtime loading, and execution lifecycle."""
    DISCOVERED = "DISCOVERED"
    VALIDATING = "VALIDATING"
    VALID = "VALID"
    INVALID = "INVALID"
    RUNTIME_LOADING = "RUNTIME_LOADING"
    RUNTIME_READY = "RUNTIME_READY"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class StateTransitionEvent(BaseModel):
    """Audit event recording an explicit state transition in the runtime lifecycle."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    from_state: ModelRuntimeState
    to_state: ModelRuntimeState
    reason: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ModelValidationReport(BaseModel):
    """Structural and cryptographic validation audit performed before model execution."""
    model_id: str
    model_path: str
    model_sha256: str = Field(..., min_length=64, max_length=64)
    format: ModelFormat
    is_valid: bool
    state: ModelRuntimeState
    parameter_count: int = 0
    node_count: int = 0
    layer_count: int = 0
    input_specs: List[ModelInputSpec] = Field(default_factory=list)
    output_specs: List[ModelOutputSpec] = Field(default_factory=list)
    architecture_metadata: Dict[str, Any] = Field(default_factory=dict)
    validation_errors: List[str] = Field(default_factory=list)
    validated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeterministicPreprocessingRecord(BaseModel):
    """Deterministic preprocessing configuration adhering strictly to the model input contract."""
    preprocessing_id: str = Field(..., min_length=1)
    resize: Tuple[int, int]
    normalization_mean: List[float]
    normalization_std: List[float]
    channel_order: str = "NCHW"  # "NCHW" or "NHWC"
    dtype: str = "float32"
    color_space: str = "RGB"
    input_shape: List[Optional[int]]
    preprocessing_hash: str = Field(..., min_length=64, max_length=64)


class OutputValidationStatus(str, Enum):
    """Status of actual runtime output validation."""
    PASSED = "PASSED"
    FAILED = "FAILED"


class OutputValidationReport(BaseModel):
    """Integrity audit on actual tensor outputs from runtime forward pass."""
    output_exists: bool
    dtype_valid: bool
    shape_matches_schema: bool
    all_values_finite: bool
    serializable: bool
    output_sha256: str = Field(..., min_length=64, max_length=64)
    validation_status: OutputValidationStatus
    discrepancies: List[str] = Field(default_factory=list)


class RuntimeExecutionRecord(BaseModel):
    """Authoritative provenance record capturing actual local runtime inference execution."""
    inference_id: str
    model_id: str
    model_sha256: str = Field(..., min_length=64, max_length=64)
    fingerprint_id: Optional[str] = None
    runtime: str = "onnxruntime"
    runtime_version: str
    architecture: str
    input_signature: List[Dict[str, Any]]
    output_signature: List[Dict[str, Any]]
    preprocessing_config: Dict[str, Any]
    input_sha256: str = Field(..., min_length=64, max_length=64)
    output_sha256: str = Field(..., min_length=64, max_length=64)
    started_at: datetime
    completed_at: datetime
    latency_ms: float = Field(..., ge=0.0)
    output_shape: List[int]
    output_dtype: str
    output_summary: Dict[str, float] = Field(default_factory=dict)  # min, max, mean, std
    validation_report: OutputValidationReport
    lifecycle_history: List[StateTransitionEvent] = Field(default_factory=list)
