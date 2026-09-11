"""Pydantic schemas for Defense-Grade Forensic Assurance Reports and Export.

Phase 12: Comprehensive, multi-layer forensic assurance reporting,
cross-domain evidence synthesis, export formatting, and cryptographic proof sealing.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.fusion import AssuranceAction, AssuranceRiskLevel, EvidenceItem, FusedAssessment, QuarantineRecord
from app.schemas.graph import BlastRadiusReport, GraphNode


class ReportFormat(str, Enum):
    """Output presentation formats for forensic assurance reports."""
    JSON_MANIFEST = "JSON_MANIFEST"
    MARKDOWN = "MARKDOWN"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    HTML = "HTML"


class ReportSectionOverview(BaseModel):
    """Structured breakdown of individual assurance layer findings."""
    layer_name: str
    status: AssetStatus
    risk_contribution: float = Field(0.0, ge=0.0, le=1.0)
    findings_count: int = 0
    key_observations: List[str] = Field(default_factory=list)


class ForensicCryptographicProofs(BaseModel):
    """Cryptographic proofs and digital signatures sealing the assurance report."""
    canonical_report_digest: str = Field(..., min_length=64, max_length=64, description="RFC 8785 SHA-256 hash")
    ecdsa_signature: str = Field(..., description="ECDSA SECP256R1 digital signature")
    signer_public_key_pem: str = Field(..., description="SubjectPublicKeyInfo PEM")
    assessment_digest: Optional[str] = None
    dataset_merkle_root: Optional[str] = None
    model_binary_sha256: Optional[str] = None
    inference_dna_hash: Optional[str] = None
    graph_digest: Optional[str] = None


class AssuranceReport(BaseModel):
    """Comprehensive, cryptographically sealed defense forensic assurance report."""
    report_id: str = Field(..., description="Unique report identifier")
    title: str = Field(default="TRUST-CV Defense Forensic Assurance Report")
    classification: str = Field(default="RESTRICTED // MINISTRY OF DEFENCE")
    target_asset_id: str
    target_asset_type: str = "MODEL"  # MODEL, DATASET, INFERENCE, PIPELINE_RUN
    assessment_id: str
    overall_verdict: AssetStatus
    gatekeeper_action: AssuranceAction = AssuranceAction.ALLOW
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: AssuranceRiskLevel = AssuranceRiskLevel.LOW
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    coverage_ratio: float = Field(..., ge=0.0, le=1.0)
    hard_veto_triggered: bool = False
    veto_reasons: List[str] = Field(default_factory=list)
    findings_summary: Dict[str, int] = Field(default_factory=dict)
    threat_narratives: List[str] = Field(default_factory=list)
    section_overviews: List[ReportSectionOverview] = Field(default_factory=list)
    dataset_findings: List[Dict[str, Any]] = Field(default_factory=list)
    model_findings: List[Dict[str, Any]] = Field(default_factory=list)
    behavioral_findings: List[Dict[str, Any]] = Field(default_factory=list)
    inference_findings: List[Dict[str, Any]] = Field(default_factory=list)
    drift_findings: List[Dict[str, Any]] = Field(default_factory=list)
    quarantine_records: List[QuarantineRecord] = Field(default_factory=list)
    upstream_lineage: List[GraphNode] = Field(default_factory=list)
    downstream_blast_radius: Optional[BlastRadiusReport] = None
    redteam_summary: Optional[Dict[str, Any]] = None
    limitations_and_disclaimers: List[str] = Field(default_factory=list)
    cryptographic_proofs: Optional[ForensicCryptographicProofs] = None
    report_digest: str = Field(..., min_length=64, max_length=64)
    signature: str
    signer_public_key_pem: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GenerateReportRequest(BaseModel):
    """Request payload to generate a signed forensic assurance report."""
    target_asset_id: str = Field(..., min_length=1)
    target_asset_type: str = Field("MODEL", min_length=1)
    assessment_id: Optional[str] = None
    include_lineage: bool = True
    include_blast_radius: bool = True
    include_limitations: bool = True


class VerifyReportRequest(BaseModel):
    """Request payload to cryptographically audit an assurance report."""
    report: AssuranceReport


class VerifyReportResponse(BaseModel):
    """Audit verdict on report authenticity, digest integrity, and signature validity."""
    is_valid: bool
    digest_match: bool
    signature_valid: bool
    discrepancies: List[str] = Field(default_factory=list)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExportReportResponse(BaseModel):
    """Outcome of exporting a report to disk."""
    report_id: str
    format: ReportFormat
    export_path: str
    file_size_bytes: int
    export_digest: str
