"""Pydantic schemas for Multi-Source Evidence Fusion and Threat Assessment."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.integrity import IntegritySeverity


class EvidenceSource(str, Enum):
    """Supported evidence categories across the assurance pipeline."""
    DATA_INTEGRITY = "DATA_INTEGRITY"
    MODEL_IDENTITY = "MODEL_IDENTITY"
    BEHAVIOURAL_FINGERPRINT = "BEHAVIOURAL_FINGERPRINT"
    INFERENCE_DNA = "INFERENCE_DNA"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"


class EvidenceItem(BaseModel):
    """An individual piece of verification evidence from an assurance engine."""
    evidence_id: str
    source: EvidenceSource
    severity: IntegritySeverity
    metric_value: float
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceCoverage(BaseModel):
    """Audit coverage analysis reporting which sources were verified."""
    sources_checked: List[EvidenceSource]
    coverage_ratio: float = Field(..., ge=0.0, le=1.0)
    missing_sources: List[EvidenceSource]


class FusedAssessment(BaseModel):
    """Synthesized holistic risk assessment aggregating all cross-layer evidence."""
    assessment_id: str
    target_entity_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0)  # 0.0 (safe) to 1.0 (compromised)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    verdict: AssetStatus  # ACCEPTED, UNDER_REVIEW, or QUARANTINED
    coverage: EvidenceCoverage
    correlated_findings: List[str]
    raw_evidence: List[EvidenceItem]
    assessment_digest: str = Field(..., min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceFusionRequest(BaseModel):
    """Request payload to fuse evidence for a specific entity."""
    target_entity_id: str = Field(..., min_length=1)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
