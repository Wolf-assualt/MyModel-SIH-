"""Defense-Grade Security Assurance Reports API Endpoints."""
from typing import Any, List
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Query

from app.fusion.engine import default_fusion_engine
from app.reports.engine import default_report_engine
from app.reports.formatter import ReportFormatter
from app.schemas.base import ResponseEnvelope
from app.schemas.report import (
    AssuranceReport,
    GenerateReportRequest,
    ReportFormat,
    VerifyReportRequest,
    VerifyReportResponse,
)

router = APIRouter(prefix="/reports", tags=["Assurance Reports Engine"])


@router.post("/generate", response_model=ResponseEnvelope[AssuranceReport])
def generate_assurance_report(
    payload: GenerateReportRequest,
) -> ResponseEnvelope[AssuranceReport]:
    """Generate and cryptographically seal an assurance report from a fused security assessment."""
    assessment = default_fusion_engine.get_assessment(payload.assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=404,
            detail=f"Fused assessment '{payload.assessment_id}' not found.",
        )

    try:
        report = default_report_engine.generate_report(
            target_asset_id=payload.target_asset_id,
            target_asset_type=payload.target_asset_type,
            assessment=assessment,
            include_limitations=payload.include_limitations,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Report generation failed: {str(exc)}")

    return ResponseEnvelope(data=report)


@router.get("/{report_id}", response_model=ResponseEnvelope[Any])
def get_assurance_report(
    report_id: str,
    format: ReportFormat = Query(ReportFormat.JSON_MANIFEST, description="Desired report presentation format"),
) -> ResponseEnvelope[Any]:
    """Retrieve an existing assurance report in JSON manifest, Markdown, or Executive Summary format."""
    report = default_report_engine.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Assurance report '{report_id}' not found.")

    if format == ReportFormat.MARKDOWN:
        rendered = ReportFormatter.format_markdown(report)
        return ResponseEnvelope(
            data={"report_id": report_id, "format": "MARKDOWN", "content": rendered}
        )
    elif format == ReportFormat.EXECUTIVE_SUMMARY:
        rendered = ReportFormatter.format_executive_summary(report)
        return ResponseEnvelope(
            data={"report_id": report_id, "format": "EXECUTIVE_SUMMARY", "content": rendered}
        )
    elif format == ReportFormat.HTML:
        rendered = ReportFormatter.format_html(report)
        return ResponseEnvelope(
            data={"report_id": report_id, "format": "HTML", "content": rendered}
        )

    return ResponseEnvelope(data=report)


@router.get("/", response_model=ResponseEnvelope[List[AssuranceReport]])
def list_assurance_reports() -> ResponseEnvelope[List[AssuranceReport]]:
    """List all stored forensic assurance reports."""
    reports = default_report_engine.list_reports()
    return ResponseEnvelope(data=reports)


@router.post("/{report_id}/export", response_model=ResponseEnvelope[Any])
def export_assurance_report(
    report_id: str,
    format: ReportFormat = Query(ReportFormat.JSON_MANIFEST, description="Desired export format"),
) -> ResponseEnvelope[Any]:
    """Export a stored assurance report to disk in the specified format."""
    try:
        result = default_report_engine.export_report_to_file(
            report_id=report_id,
            export_format=format,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return ResponseEnvelope(data={
        "report_id": result.report_id,
        "format": result.format.value,
        "export_path": result.export_path,
        "file_size_bytes": result.file_size_bytes,
        "export_digest": result.export_digest,
    })


@router.post("/verify", response_model=ResponseEnvelope[VerifyReportResponse])
def verify_assurance_report(
    payload: VerifyReportRequest,
) -> ResponseEnvelope[VerifyReportResponse]:
    """Cryptographically audit an assurance report for tamper status and signature validity."""
    result = default_report_engine.verify_report(payload.report)
    return ResponseEnvelope(data=result)
