"""AuditEvent and MerkleRoot validation schemas."""
from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class AuditEventCreate(BaseModel):
    sequence_number: int = Field(..., ge=0)
    event_type: str = Field(..., max_length=100)
    entity_type: str = Field(..., max_length=50)
    entity_id: str = Field(..., max_length=64)
    actor: str = Field(default="SYSTEM", max_length=100)
    payload_sha256: str = Field(..., min_length=64, max_length=64)
    prev_event_hash: str = Field(..., min_length=64, max_length=64)
    event_hash: str = Field(..., min_length=64, max_length=64)
    signature: Optional[str] = None


class AuditEventResponse(AuditEventCreate):
    id: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class MerkleRootResponse(BaseModel):
    id: str
    batch_id: Optional[str] = None
    root_hash: str
    leaf_count: int
    block_height: int
    finalized_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ChainVerificationResult(BaseModel):
    is_valid: bool
    total_events_checked: int
    last_verified_sequence: int
    broken_link_sequence: Optional[int] = None
    tampered_event_id: Optional[str] = None
    message: str
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
