"""Model and Model Identity validation schemas."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.base import AssetStatus
from app.schemas.common import ModelFramework


class ModelFormat(str, Enum):
    ONNX = "ONNX"
    TORCHSCRIPT = "TORCHSCRIPT"
    PYTORCH_WEIGHTS = "PYTORCH_WEIGHTS"
    GENERIC_BINARY = "GENERIC_BINARY"
    BLACK_BOX = "BLACK_BOX"
    UNSUPPORTED = "UNSUPPORTED"


class AccessMode(str, Enum):
    WHITE_BOX = "WHITE_BOX"
    BLACK_BOX = "BLACK_BOX"
    PARTIAL = "PARTIAL"


class VerificationStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"


class TriggerStatus(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS_TRIGGER_SENSITIVITY = "SUSPICIOUS_TRIGGER_SENSITIVITY"
    UNAVAILABLE = "UNAVAILABLE"


class ModelInputSpec(BaseModel):
    name: str
    shape: List[Optional[int]]
    data_type: str = "float32"


class ModelOutputSpec(BaseModel):
    name: str
    shape: List[Optional[int]]
    data_type: str = "float32"


class ModelIdentityManifest(BaseModel):
    model_id: str
    name: str
    version: str
    format: ModelFormat
    artifact_hash: str = Field(..., min_length=64, max_length=64)
    binary_sha256: str = Field(..., min_length=64, max_length=64)
    access_mode: AccessMode = AccessMode.WHITE_BOX
    architecture_info: Dict[str, Any] = Field(default_factory=dict)
    parameter_count: int = Field(default=0, ge=0)
    node_count: int = Field(default=0, ge=0)
    layer_count: int = Field(default=0, ge=0)
    inputs: List[ModelInputSpec] = Field(default_factory=list)
    outputs: List[ModelOutputSpec] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scanner_version: str = "1.0.0"
    identity_digest: str = Field(..., min_length=64, max_length=64)
    status: AssetStatus = AssetStatus.ACCEPTED
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelIngestRequest(BaseModel):
    name: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    model_path: str = Field(..., min_length=1)
    format: ModelFormat
    is_reference: bool = False
    access_mode: Optional[AccessMode] = None


class ModelVerifyResponse(BaseModel):
    model_id: str
    is_valid: bool
    binary_match: bool
    structural_match: bool
    binary_identity: VerificationStatus = VerificationStatus.UNAVAILABLE
    structural_identity: VerificationStatus = VerificationStatus.UNAVAILABLE
    behavioural_identity: VerificationStatus = VerificationStatus.UNAVAILABLE
    trigger_status: TriggerStatus = TriggerStatus.UNAVAILABLE
    discrepancies: List[str] = Field(default_factory=list)


class ModelAssuranceFinding(BaseModel):
    model_id: str
    artifact_hash: str
    format: str
    access_mode: AccessMode
    identity_status: VerificationStatus
    structural_status: VerificationStatus
    behavioural_status: VerificationStatus
    trigger_status: TriggerStatus
    confidence: Optional[float] = None
    confidence_basis: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Retained for ORM entity compatibility
class ModelFingerprintBase(BaseModel):
    weights_sha256: str = Field(..., min_length=64, max_length=64)
    parameter_stats_json: Optional[str] = None
    activation_stats_json: Optional[str] = None
    behavioral_vector_json: Optional[str] = None
    benchmark_digest: Optional[str] = None


class ModelFingerprintCreate(ModelFingerprintBase):
    model_id: str


class ModelFingerprintResponse(ModelFingerprintBase):
    id: str
    model_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ModelBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    framework: ModelFramework
    format: str = Field(..., max_length=50)
    version: str = Field(default="1.0.0", max_length=50)
    file_path: str = Field(..., max_length=1024)
    sha256_digest: str = Field(..., min_length=64, max_length=64)
    parameters_count: Optional[int] = None
    size_bytes: int = Field(..., ge=0)
    metadata_json: Optional[str] = None


class ModelCreate(ModelBase):
    pass


class ModelResponse(ModelBase):
    id: str
    created_at: datetime
    updated_at: datetime
    fingerprints: List[ModelFingerprintResponse] = []

    model_config = ConfigDict(from_attributes=True)
