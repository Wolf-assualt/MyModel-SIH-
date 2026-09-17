"""Pydantic schemas for Defense-Grade Security Assurance Reports."""
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class ReportFormat(str, Enum):
    """Output formats for assurance reports."""
    JSON_MANIFEST = "JSON_MANIFEST"
    MARKDOWN = "MARKDOWN"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"


class AssuranceReport(BaseModel):
    """Cryptographically sealed defense security assurance report."""
    report_id: str
    target_asset_id: str
    target_asset_type: str  # "MODEL", "DATASET_BATCH", "INFERENCE_PIPELINE"
    assessment_id: str
    overall_verdict: AssetStatus
    risk_score: float = Field(..., ge=0.0, le=1.0)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    coverage_ratio: float = Field(..., ge=0.0, le=1.0)
    findings_summary: Dict[str, int] = Field(default_factory=dict)
    threat_narratives: List[str] = Field(default_factory=list)
    limitations_and_disclaimers: List[str] = Field(default_factory=list)
    report_digest: str = Field(..., min_length=64, max_length=64)
    signature: str
    signer_public_key_pem: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GenerateReportRequest(BaseModel):
    """Request payload to generate a signed assurance report from a fused assessment."""
    target_asset_id: str = Field(..., min_length=1)
    target_asset_type: str = Field("MODEL", min_length=1)
    assessment_id: str = Field(..., min_length=1)
    include_limitations: bool = True


class VerifyReportRequest(BaseModel):
    """Request payload to cryptographically audit an assurance report."""
    report: AssuranceReport


class VerifyReportResponse(BaseModel):
    """Audit verdict on report authenticity and tamper status."""
    is_valid: bool
    digest_match: bool
    signature_valid: bool
    discrepancies: List[str] = Field(default_factory=list)
