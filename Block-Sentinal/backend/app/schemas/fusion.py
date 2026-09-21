"""Pydantic schemas for Multi-Source Evidence Fusion and Authoritative Risk Assessment."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.integrity import IntegritySeverity


class AssuranceRiskLevel(str, Enum):
    """Categorical risk tiers for authoritative assurance decisions."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssuranceAction(str, Enum):
    """Authoritative gatekeeper enforcement action."""
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class EvidenceSource(str, Enum):
    """Supported evidence categories across the assurance pipeline."""
    DATA_INTEGRITY = "DATA_INTEGRITY"
    MODEL_IDENTITY = "MODEL_IDENTITY"
    BEHAVIOURAL_FINGERPRINT = "BEHAVIOURAL_FINGERPRINT"
    INFERENCE_DNA = "INFERENCE_DNA"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    CONTRIBUTOR_RISK = "CONTRIBUTOR_RISK"
    CRYPTO_VERIFICATION = "CRYPTO_VERIFICATION"
    SYSTEM_INTEGRITY = "SYSTEM_INTEGRITY"


class EvidenceSourceDomain(str, Enum):
    """High-level architectural domain generating evidence."""
    DATASET = "DATASET"
    MODEL = "MODEL"
    INFERENCE = "INFERENCE"
    DRIFT = "DRIFT"
    CONTRIBUTOR = "CONTRIBUTOR"
    SYSTEM = "SYSTEM"


class EvidenceItem(BaseModel):
    """An individual piece of verification evidence with provenance and cryptographic grounding."""
    evidence_id: str = Field(..., min_length=1, description="Mandatory real unique evidence identifier")
    source: EvidenceSource
    domain: Optional[EvidenceSourceDomain] = None
    severity: IntegritySeverity = IntegritySeverity.LOW
    metric_value: float = 0.0
    description: str = ""
    subject_id: Optional[str] = None
    related_model_id: Optional[str] = None
    related_dataset_id: Optional[str] = None
    evidence_digest: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceCoverage(BaseModel):
    """Audit coverage analysis reporting which sources were verified."""
    sources_checked: List[EvidenceSource]
    coverage_ratio: float = Field(..., ge=0.0, le=1.0)
    missing_sources: List[EvidenceSource]


class QuarantineRecord(BaseModel):
    """Audit record of a quarantined asset or pipeline stage."""
    quarantine_id: str
    subject_id: str
    subject_type: str = "ASSET"
    reason: str
    evidence_ids: List[str] = Field(default_factory=list)
    is_active: bool = True
    quarantined_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if self.created_at is None:
            self.created_at = self.quarantined_at


class FusedAssessment(BaseModel):
    """Authoritative holistic risk assessment aggregating all cross-layer evidence."""
    assessment_id: str
    target_entity_id: str
    overall_status: AssetStatus = AssetStatus.ACCEPTED
    verdict: Optional[AssetStatus] = None
    risk_level: AssuranceRiskLevel = AssuranceRiskLevel.LOW
    risk_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    confidence_score: Optional[float] = None
    action: AssuranceAction = AssuranceAction.ALLOW
    coverage: EvidenceCoverage
    findings: List[str] = Field(default_factory=list)
    correlated_findings: Optional[List[str]] = None
    contributors: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None
    raw_evidence: List[EvidenceItem] = Field(default_factory=list)
    decisive_evidence: List[str] = Field(default_factory=list)
    hard_veto_triggered: bool = False
    veto_reasons: List[str] = Field(default_factory=list)
    signature: Optional[str] = None
    assessment_digest: str = Field(..., min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: Any) -> None:
        # Sync verdict and overall_status
        if self.verdict is not None and self.overall_status == AssetStatus.ACCEPTED and self.verdict != AssetStatus.ACCEPTED:
            self.overall_status = self.verdict
        elif self.overall_status is not None and self.verdict is None:
            self.verdict = self.overall_status

        # Sync confidence and confidence_score
        if self.confidence_score is not None and self.confidence == 0.0:
            self.confidence = self.confidence_score
        elif self.confidence is not None and self.confidence_score is None:
            self.confidence_score = self.confidence

        # Sync findings and correlated_findings
        if self.correlated_findings is not None and not self.findings:
            self.findings = list(self.correlated_findings)
        elif self.findings and self.correlated_findings is None:
            self.correlated_findings = list(self.findings)

        # Default explanation if missing
        if self.explanation is None:
            if self.veto_reasons:
                self.explanation = "HARD VETO: " + "; ".join(self.veto_reasons)
            elif self.findings:
                self.explanation = "CORRELATED: " + "; ".join(self.findings)
            else:
                self.explanation = f"Assessment completed with status {self.overall_status.value} and risk level {self.risk_level.value}."


class EvidenceFusionRequest(BaseModel):
    """Request payload to fuse evidence for a specific entity."""
    target_entity_id: str = Field(..., min_length=1)
    evidence_items: Optional[List[EvidenceItem]] = None
    evidence_ids: Optional[List[str]] = None


class QuarantineResolveRequest(BaseModel):
    """Request payload to resolve an active quarantine."""
    resolved_by: str = Field(..., min_length=1)
    resolution_notes: str = Field(..., min_length=1)
