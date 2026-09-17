"""Pydantic schemas for the Analyst SOC Dashboard and Investigation Workbench."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.integrity import IntegritySeverity


class SystemHealthOverview(BaseModel):
    """Real-time inventory of assets, status distributions, and hash chain tip."""
    total_datasets: int = Field(..., ge=0)
    total_models: int = Field(..., ge=0)
    total_inferences: int = Field(..., ge=0)
    total_reports: int = Field(..., ge=0)
    quarantined_assets: int = Field(..., ge=0)
    under_review_assets: int = Field(..., ge=0)
    accepted_assets: int = Field(..., ge=0)
    active_threats_count: int = Field(..., ge=0)
    chain_head_hash: str = Field(..., min_length=64, max_length=64)
    system_integrity_status: str  # "OPERATIONAL", "ELEVATED_RISK", "CRITICAL_ALERT"


class ActivityTimelineItem(BaseModel):
    """An operational event in the reverse-chronological activity log."""
    event_id: str
    timestamp: str
    event_type: str  # "MODEL_REGISTERED", "DATASET_INGESTED", "INFERENCE_VERIFIED", "ASSESSMENT_GENERATED", "TAMPER_DETECTED"
    severity: IntegritySeverity
    entity_id: str
    description: str


class InvestigationView(BaseModel):
    """Deep-dive forensic analysis view for a specific asset or contributor."""
    entity_id: str
    entity_type: str  # "DATASET", "MODEL", "INFERENCE", "CONTRIBUTOR"
    status: AssetStatus
    risk_score: float = Field(..., ge=0.0, le=1.0)
    canonical_hash: Optional[str] = None
    lineage_upstream: List[Dict[str, Any]] = Field(default_factory=list)
    lineage_downstream: List[Dict[str, Any]] = Field(default_factory=list)
    associated_findings: List[Dict[str, Any]] = Field(default_factory=list)
    latest_report_id: Optional[str] = None


class ContributorLeaderboardItem(BaseModel):
    """Contributor trust scorecard item for dashboard leaderboard ranking."""
    contributor_id: str
    name: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    status: AssetStatus
    total_batches: int = Field(..., ge=0)
    total_samples: int = Field(..., ge=0)
    flagged_findings: int = Field(..., ge=0)
