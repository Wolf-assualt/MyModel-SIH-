"""Inference DNA schemas and cryptographic verification payload types."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field


# --- Phase 7 Core Inference DNA & Execution Schemas ---

class BoundingBox(BaseModel):
    """Normalized or absolute object bounding box detection [x1, y1, x2, y2]."""
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    box: List[float] = Field(..., min_length=4, max_length=4)


class InferenceOutput(BaseModel):
    """Raw predictions and its canonical SHA-256 digest."""
    predictions: List[BoundingBox] = Field(default_factory=list)
    raw_output_digest: str = Field(..., min_length=64, max_length=64)
    raw_output: List[float] = Field(default_factory=list)


class PreprocessingSpec(BaseModel):
    """Preprocessing parameters applied to the input frame before model execution."""
    target_size: Any = (640, 640)
    normalization_mean: List[float] = Field(default_factory=lambda: [0.485, 0.456, 0.406])
    normalize_mean: Optional[List[float]] = None
    normalization_std: List[float] = Field(default_factory=lambda: [0.229, 0.224, 0.225])
    normalize_std: Optional[List[float]] = None
    color_space: str = "RGB"
    interpolation: str = "BILINEAR"

    def model_post_init(self, __context: Any) -> None:
        if isinstance(self.target_size, list):
            self.target_size = tuple(self.target_size)
        if self.normalize_mean is not None:
            self.normalization_mean = self.normalize_mean
        if self.normalize_std is not None:
            self.normalization_std = self.normalize_std


class InferenceConfigSpec(BaseModel):
    """Inference execution configuration options."""
    device: str = "cpu"
    batch_size: int = 1
    confidence_threshold: float = 0.5
    execution_provider: str = "CPUExecutionProvider"
    extra_params: Dict[str, Any] = Field(default_factory=dict)


class InputMetadataSpec(BaseModel):
    """Input frame metadata specification."""
    input_frame_sha256: str = Field(..., min_length=64, max_length=64)
    dimensions: List[int] = Field(default_factory=lambda: [3, 640, 640])
    data_type: str = "float32"
    source_filename: Optional[str] = None


class ModelBindingSpec(BaseModel):
    """Model identity binding specification."""
    model_id: str
    artifact_hash: str = Field(..., min_length=64, max_length=64)
    format: str = "ONNX"
    version: str = "1.0.0"


class InferenceDNARecord(BaseModel):
    """Complete cryptographically signed inference DNA record with provenance binding."""
    record_id: str
    sequence_number: int = Field(default=0, ge=0)
    sequence_id: int = Field(default=0, ge=0)
    timestamp: str  # ISO-8601 UTC string
    nonce: str = Field(..., min_length=16, max_length=64)
    model_id: str
    model_version: Optional[str] = "1.0.0"
    model_hash: str = Field(default="", min_length=0, max_length=64)
    model_identity_digest: str = Field(default="", min_length=0, max_length=64)
    input_hash: str = Field(default="", min_length=0, max_length=64)
    input_frame_sha256: str = Field(default="", min_length=0, max_length=64)
    preprocessing_hash: str = Field(default="", min_length=0, max_length=64)
    preprocessing_digest: str = Field(default="", min_length=0, max_length=64)
    inference_config_hash: str = Field(default="", min_length=0, max_length=64)
    output_hash: str = Field(default="", min_length=0, max_length=64)
    output_digest: str = Field(default="", min_length=0, max_length=64)
    dna_hash: str = Field(..., min_length=64, max_length=64)
    signature: str
    prev_chain_hash: str = Field(..., min_length=64, max_length=64)

    def model_post_init(self, __context: Any) -> None:
        if not self.sequence_number and self.sequence_id:
            self.sequence_number = self.sequence_id
        elif not self.sequence_id and self.sequence_number:
            self.sequence_id = self.sequence_number

        if not self.model_hash and self.model_identity_digest:
            self.model_hash = self.model_identity_digest
        elif not self.model_identity_digest and self.model_hash:
            self.model_identity_digest = self.model_hash

        if not self.input_hash and self.input_frame_sha256:
            self.input_hash = self.input_frame_sha256
        elif not self.input_frame_sha256 and self.input_hash:
            self.input_frame_sha256 = self.input_hash

        if not self.preprocessing_hash and self.preprocessing_digest:
            self.preprocessing_hash = self.preprocessing_digest
        elif not self.preprocessing_digest and self.preprocessing_hash:
            self.preprocessing_digest = self.preprocessing_hash

        if not self.output_hash and self.output_digest:
            self.output_hash = self.output_digest
        elif not self.output_digest and self.output_hash:
            self.output_digest = self.output_hash

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name == "sequence_number":
            super().__setattr__("sequence_id", value)
        elif name == "sequence_id":
            super().__setattr__("sequence_number", value)
        elif name == "model_hash":
            super().__setattr__("model_identity_digest", value)
        elif name == "model_identity_digest":
            super().__setattr__("model_hash", value)
        elif name == "input_hash":
            super().__setattr__("input_frame_sha256", value)
        elif name == "input_frame_sha256":
            super().__setattr__("input_hash", value)
        elif name == "preprocessing_hash":
            super().__setattr__("preprocessing_digest", value)
        elif name == "preprocessing_digest":
            super().__setattr__("preprocessing_hash", value)
        elif name == "output_hash":
            super().__setattr__("output_digest", value)
        elif name == "output_digest":
            super().__setattr__("output_hash", value)


class InferenceRequest(BaseModel):
    """Request payload to execute inference under provenance tracking."""
    model_id: str = Field(..., min_length=1)
    image_bytes_b64: Optional[str] = None
    image_sha256: Optional[str] = None
    preprocessing: Optional[PreprocessingSpec] = None
    inference_config: Optional[InferenceConfigSpec] = None


class InferenceReceipt(BaseModel):
    """Proof receipt returned to client upon authenticated inference execution."""
    dna_record: InferenceDNARecord
    output: InferenceOutput
    public_key_pem: str


class VerifyDNARequest(BaseModel):
    """Payload to audit an inference DNA record against a public key."""
    dna_record: InferenceDNARecord
    public_key_pem: str


class VerifyDNAResponse(BaseModel):
    """Detailed audit verdict for an inference DNA verification request."""
    is_valid: bool
    signature_valid: bool
    hash_integrity_valid: bool
    chain_pointer_valid: bool
    replay_detected: bool = False
    discrepancies: List[str] = Field(default_factory=list)


class VerifyChainRequest(BaseModel):
    """Payload to audit an entire hash chain sequence."""
    records: List[InferenceDNARecord] = Field(default_factory=list)
    chain_records: List[Dict[str, Any]] = Field(default_factory=list)
    public_key_pem: Optional[str] = None


class ChainVerificationResponse(BaseModel):
    """Detailed audit verdict for hash chain sequence and anti-replay audit."""
    is_valid: bool
    total_records: int = 0
    broken_sequence_id: Optional[int] = None
    broken_index: Optional[int] = None
    replay_detected: bool = False
    reason: Optional[str] = None
    discrepancies: List[str] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)


# --- Relational & Legacy Compatibility Schemas ---

class InferenceDNATuple(BaseModel):
    """The core cryptographic tuple constituting Inference DNA."""
    input_sha256: str = Field(..., min_length=64, max_length=64)
    model_sha256: str = Field(..., min_length=64, max_length=64)
    preprocessing_sha256: str = Field(..., min_length=64, max_length=64)
    config_sha256: str = Field(..., min_length=64, max_length=64)
    output_sha256: str = Field(..., min_length=64, max_length=64)
    nonce: str = Field(..., min_length=16, max_length=64)
    timestamp: datetime
    sequence_number: int = Field(..., ge=0)
    prev_record_hash: str = Field(..., min_length=64, max_length=64)


class InferenceCreate(BaseModel):
    model_id: str
    sample_id: Optional[str] = None
    input_sha256: str = Field(..., min_length=64, max_length=64)
    model_sha256: str = Field(..., min_length=64, max_length=64)
    preprocessing_sha256: str = Field(..., min_length=64, max_length=64)
    config_sha256: str = Field(..., min_length=64, max_length=64)
    output_sha256: str = Field(..., min_length=64, max_length=64)
    prediction_json: str
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    nonce: str = Field(..., min_length=16, max_length=64)
    sequence_number: int = Field(..., ge=0)
    prev_record_hash: str = Field(..., min_length=64, max_length=64)
    record_hash: str = Field(..., min_length=64, max_length=64)
    signature: Optional[str] = None


class InferenceResponse(InferenceCreate):
    id: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class InferenceVerificationResult(BaseModel):
    inference_id: str
    is_valid: bool
    dna_digest_valid: bool
    sequence_valid: bool
    replay_detected: bool
    signature_valid: Optional[bool] = None
    reason: Optional[str] = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
