from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field

class ScanStage(str, Enum):
    INGESTION = "INGESTION"
    HASHING = "HASHING"
    DATA_INTEGRITY = "DATA_INTEGRITY"
    MODEL_ASSURANCE = "MODEL_ASSURANCE"
    INFERENCE_ASSURANCE = "INFERENCE_ASSURANCE"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    EVIDENCE_FUSION = "EVIDENCE_FUSION"
    AUDIT = "AUDIT"
    REPORT = "REPORT"
    COMPLETED = "COMPLETED"

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ComponentStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"

class ComponentState(BaseModel):
    status: ComponentStatus = ComponentStatus.PENDING
    error_code: Optional[str] = None
    explanation: Optional[str] = None

class ScanSession(BaseModel):
    scan_id: str
    batch_id: Optional[str] = None
    sample_count: Optional[int] = None
    merkle_root: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: ScanStatus = ScanStatus.PENDING
    stage: ScanStage = ScanStage.INGESTION
    progress: float = 0.0
    stage_results: Dict[str, ComponentState] = Field(default_factory=dict)
    input_artifacts: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    assessment: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
