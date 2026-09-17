"""Pydantic schemas for the Red-Team Adversarial Attack Lab."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class AttackType(str, Enum):
    """Supported red-team adversarial attack vectors."""
    LABEL_FLIPPING = "LABEL_FLIPPING"
    BACKDOOR_TRIGGER = "BACKDOOR_TRIGGER"
    DATASET_CORRUPTION = "DATASET_CORRUPTION"
    MODEL_WEIGHT_TAMPERING = "MODEL_WEIGHT_TAMPERING"
    INFERENCE_TAMPERING = "INFERENCE_TAMPERING"
    INFERENCE_REPLAY = "INFERENCE_REPLAY"


class AttackExecutionRequest(BaseModel):
    """Request payload to simulate an adversarial attack."""
    attack_type: AttackType
    target_entity_id: str = Field(..., description="batch_id, model_id, or inference_record_id")
    intensity: float = Field(default=0.5, ge=0.0, le=1.0, description="Scale of attack (e.g., % of samples poisoned, noise level)")
    target_label: Optional[str] = Field(default="poisoned_class", description="Target label for flipping or backdoor associations")


class AttackExecutionResult(BaseModel):
    """Result of an executed adversarial attack simulation."""
    attack_id: str
    attack_type: AttackType
    target_entity_id: str
    modified_entity_id: str
    samples_modified_count: int = Field(default=0, ge=0)
    attack_signature: str
    description: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackVerificationReport(BaseModel):
    """Verification audit confirming if TRUST-CV defensive engines caught the attack."""
    attack_id: str
    attack_type: AttackType
    detected_by_engine: bool
    detecting_subsystem: str  # "DATA_INTEGRITY", "MODEL_IDENTITY", "BEHAVIOURAL_FINGERPRINT", "INFERENCE_DNA"
    assigned_verdict: AssetStatus  # QUARANTINED, UNDER_REVIEW, ACCEPTED
    confidence: float = Field(..., ge=0.0, le=1.0)
    details: Dict[str, Any] = Field(default_factory=dict)
