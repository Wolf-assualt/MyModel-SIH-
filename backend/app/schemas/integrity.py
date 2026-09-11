"""Pydantic schemas for Training-Data Integrity Engine."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class IntegrityCheckType(str, Enum):
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    NEAR_DUPLICATE = "NEAR_DUPLICATE"
    LABEL_INCONSISTENCY = "LABEL_INCONSISTENCY"
    CORRUPT_OR_OOD = "CORRUPT_OR_OOD"
    TRIGGER_BACKDOOR = "TRIGGER_BACKDOOR"


class IntegritySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IntegrityFinding(BaseModel):
    finding_id: str
    check_type: IntegrityCheckType
    severity: IntegritySeverity
    sample_ids: List[str]
    description: str
    metric_score: float  # e.g. hamming distance, similarity ratio, confidence
    details: Dict[str, Any] = Field(default_factory=dict)


class ImageAssessment(BaseModel):
    sample_id: str
    file_name: str
    sha256_hash: str
    result: str
    integrity_status: str
    trust_status: str
    anomaly_score: Optional[float] = None
    evidence: List[str] = Field(default_factory=list)
    action: str
    preview_data_url: Optional[str] = None
    quarantined: bool = False


class AuditEvent(BaseModel):
    timestamp: datetime
    artifact_id: str
    sha256_hash: str
    detection_result: str
    integrity_status: str
    reason: str
    action: str


class DatasetIntegrityReport(BaseModel):
    batch_id: str
    total_samples_analyzed: int
    findings_count: int
    findings: List[IntegrityFinding]
    overall_health_score: float  # 0.0 (severely compromised) to 1.0 (clean)
    recommendation: AssetStatus  # ACCEPTED, UNDER_REVIEW, or QUARANTINED
    report_digest: str  # SHA-256 canonical hash of this report
    image_results: List[ImageAssessment] = Field(default_factory=list)
    audit_events: List[AuditEvent] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntegrityScanRequest(BaseModel):
    batch_id: str
    duplicate_threshold: int = 4  # Max Hamming distance for near duplicates
    trigger_detection_enabled: bool = True
