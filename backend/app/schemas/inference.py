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
    predictions: List[BoundingBox]
    raw_output_digest: str = Field(..., min_length=64, max_length=64)


class PreprocessingSpec(BaseModel):
    """Preprocessing parameters applied to the input frame before model execution."""
    target_size: Tuple[int, int] = (640, 640)
    normalization_mean: List[float] = Field(default_factory=lambda: [0.485, 0.456, 0.406])
    normalization_std: List[float] = Field(default_factory=lambda: [0.229, 0.224, 0.225])
    color_space: str = "RGB"


class InferenceDNARecord(BaseModel):
    """Complete cryptographically signed inference DNA record with provenance binding."""
    record_id: str
    sequence_id: int = Field(..., ge=0)
    timestamp: str  # ISO-8601 UTC string
    nonce: str = Field(..., min_length=16, max_length=64)
    model_id: str
    model_identity_digest: str = Field(..., min_length=64, max_length=64)
    input_frame_sha256: str = Field(..., min_length=64, max_length=64)
    preprocessing_digest: str = Field(..., min_length=64, max_length=64)
    output_digest: str = Field(..., min_length=64, max_length=64)
    dna_hash: str = Field(..., min_length=64, max_length=64)
    signature: str
    prev_chain_hash: str = Field(..., min_length=64, max_length=64)


class InferenceRequest(BaseModel):
    """Request payload to execute inference under provenance tracking."""
    model_id: str = Field(..., min_length=1)
    image_bytes_b64: Optional[str] = None
    image_sha256: Optional[str] = None
    preprocessing: Optional[PreprocessingSpec] = None


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
    discrepancies: List[str] = Field(default_factory=list)


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
