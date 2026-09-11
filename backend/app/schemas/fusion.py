"""Pydantic schemas for Multi-Source Evidence Fusion, Threat Assessment, and Automatic Quarantine."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.integrity import IntegritySeverity


class EvidenceSourceDomain(str, Enum):
    """Supported evidence domains across the full assurance lifecycle."""
    DATASET = "DATASET"
    MODEL = "MODEL"
    BEHAVIOR = "BEHAVIOR"
    INFERENCE = "INFERENCE"
    DRIFT = "DRIFT"
    CRYPTO = "CRYPTO"
    SYSTEM = "SYSTEM"


class EvidenceSource(str, Enum):
    """Supported evidence categories across the assurance pipeline (backward compatibility)."""
    DATA_INTEGRITY = "DATA_INTEGRITY"
    MODEL_IDENTITY = "MODEL_IDENTITY"
    BEHAVIOURAL_FINGERPRINT = "BEHAVIOURAL_FINGERPRINT"
    INFERENCE_DNA = "INFERENCE_DNA"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    CRYPTO_VERIFICATION = "CRYPTO_VERIFICATION"
    SYSTEM_INTEGRITY = "SYSTEM_INTEGRITY"


class AssuranceRiskLevel(str, Enum):
    """Calibrated four-tier risk classification for synthesized assurance decisions."""
    LOW = "LOW"            # 0.00 <= Risk < 0.25: safe, normal operational variance
    MEDIUM = "MEDIUM"      # 0.25 <= Risk < 0.50: elevated risk / operational drift
    HIGH = "HIGH"          # 0.50 <= Risk < 0.70: significant concern / behavioral mismatch
    CRITICAL = "CRITICAL"  # 0.70 <= Risk <= 1.00: confirmed integrity violation / hard veto


class AssuranceAction(str, Enum):
    """Operational disposition action emitted for automated SOC gatekeepers."""
    ALLOW = "ALLOW"        # Clear to proceed to next pipeline stage
    REVIEW = "REVIEW"      # Flag for human forensic inspection
    BLOCK = "BLOCK"        # Automatic quarantine, block execution immediately


class EvidenceItem(BaseModel):
    """An individual piece of verification evidence from an assurance engine."""
    evidence_id: str
    source: EvidenceSource = EvidenceSource.DATA_INTEGRITY
    source_domain: Optional[EvidenceSourceDomain] = None
    source_component: str = "sentinel_engine"
    evidence_type: str = "INTEGRITY_CHECK"
    severity: IntegritySeverity = IntegritySeverity.LOW
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    subject_id: Optional[str] = None
    related_dataset_id: Optional[str] = None
    related_model_id: Optional[str] = None
    related_inference_id: Optional[str] = None
    metric_value: float = 0.0
    description: str = ""
    metrics: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    provenance_references: List[str] = Field(default_factory=list)


class EvidenceCoverage(BaseModel):
    """Audit coverage analysis reporting which sources were verified."""
    sources_checked: List[EvidenceSource]
    coverage_ratio: float = Field(..., ge=0.0, le=1.0)
    missing_sources: List[EvidenceSource]


class QuarantineRecord(BaseModel):
    """Durable record of an entity quarantined by hard veto or critical assurance decision."""
    quarantine_id: str
    subject_id: str
    subject_type: str = "MODEL"  # MODEL, DATASET, INFERENCE, PIPELINE_RUN
    reason: str
    evidence_ids: List[str] = Field(default_factory=list)
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None


class FusedAssessment(BaseModel):
    """Synthesized holistic risk assessment aggregating all cross-layer evidence."""
    assessment_id: str
    target_entity_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0)  # 0.0 (safe) to 1.0 (compromised)
    risk_level: AssuranceRiskLevel = AssuranceRiskLevel.LOW
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    verdict: AssetStatus  # ACCEPTED, UNDER_REVIEW, or QUARANTINED
    action: AssuranceAction = AssuranceAction.ALLOW
    hard_veto_triggered: bool = False
    veto_reasons: List[str] = Field(default_factory=list)
    coverage: EvidenceCoverage
    correlated_findings: List[str] = Field(default_factory=list)
    contributing_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    decisive_evidence: List[str] = Field(default_factory=list)
    raw_evidence: List[EvidenceItem]
    explanation: str = ""
    assessment_digest: str = Field(..., min_length=64, max_length=64)
    signature: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provenance_references: List[str] = Field(default_factory=list)


class EvidenceFusionRequest(BaseModel):
    """Request payload to fuse evidence for a specific entity."""
    target_entity_id: str = Field(..., min_length=1)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    evidence_ids: Optional[List[str]] = None
    strict_subject_binding: bool = True


class QuarantineRequest(BaseModel):
    """Request payload to manually place an entity in quarantine."""
    subject_id: str = Field(..., min_length=1)
    subject_type: str = "MODEL"
    reason: str = Field(..., min_length=1)
    evidence_ids: List[str] = Field(default_factory=list)


class ResolveQuarantineRequest(BaseModel):
    """Request payload to resolve/un-quarantine an entity with forensic justification."""
    resolved_by: str = Field(..., min_length=1)
    resolution_notes: str = Field(..., min_length=1)
