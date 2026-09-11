"""Common enums, types, and base response schemas for TRUST-CV."""
from enum import Enum
from datetime import datetime, timezone
from typing import Generic, TypeVar, Optional, List, Any
from pydantic import BaseModel, Field, ConfigDict


class RiskLevel(str, Enum):
    NORMAL = "Normal"
    LOW_RISK = "Low Risk"
    REVIEW = "Review"
    HIGH_INTEGRITY_RISK = "High Integrity Risk"
    QUARANTINE_RECOMMENDED = "Quarantine Recommended"


class Disposition(str, Enum):
    ACCEPT = "ACCEPT"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingType(str, Enum):
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    NEAR_DUPLICATE = "NEAR_DUPLICATE"
    LABEL_ANOMALY = "LABEL_ANOMALY"
    OOD_SAMPLE = "OOD_SAMPLE"
    POISONING_INDICATOR = "POISONING_INDICATOR"
    TRIGGER_INDICATOR = "TRIGGER_INDICATOR"
    MODEL_SUBSTITUTION = "MODEL_SUBSTITUTION"
    PARAMETER_TAMPERING = "PARAMETER_TAMPERING"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"
    INFERENCE_TAMPERING = "INFERENCE_TAMPERING"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    HASH_MISMATCH = "HASH_MISMATCH"
    SEQUENCE_ANOMALY = "SEQUENCE_ANOMALY"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"


class ModelFramework(str, Enum):
    ONNX = "ONNX"
    PYTORCH = "PyTorch"
    TORCHSCRIPT = "TorchScript"


class DatasetFormat(str, Enum):
    COCO = "COCO"
    YOLO = "YOLO"
    IMAGE_FOLDER = "ImageFolder"
    BIGEARTHNET_S2 = "BIGEARTHNET_S2"


class AttackClass(str, Enum):
    LABEL_FLIPPING = "LABEL_FLIPPING"
    SYSTEMATIC_MISLABELING = "SYSTEMATIC_MISLABELING"
    NEAR_DUPLICATE_FLOODING = "NEAR_DUPLICATE_FLOODING"
    OOD_INSERTION = "OOD_INSERTION"
    TRIGGER_INJECTION = "TRIGGER_INJECTION"
    MODEL_SUBSTITUTION = "MODEL_SUBSTITUTION"
    MODEL_MODIFICATION = "MODEL_MODIFICATION"
    INFERENCE_TAMPERING = "INFERENCE_TAMPERING"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"


class DetectionStatus(str, Enum):
    PENDING = "PENDING"
    DETECTED = "DETECTED"
    EVADED = "EVADED"
    INCONCLUSIVE = "INCONCLUSIVE"


T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Standardized top-level API response envelope."""
    success: bool = True
    message: str = "Operation completed successfully"
    data: Optional[T] = None
    errors: Optional[List[str]] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)
