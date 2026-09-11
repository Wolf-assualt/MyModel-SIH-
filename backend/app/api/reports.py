from typing import Any, List, Optional
from fastapi import APIRouter, HTTPException, Query

from app.fusion.engine import default_fusion_engine
from app.reports.engine import default_report_engine
from app.reports.formatter import ReportFormatter
from app.schemas.base import ResponseEnvelope
from app.schemas.report import (
    AssuranceReport,
    ExportReportResponse,
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


@router.get("", response_model=ResponseEnvelope[List[AssuranceReport]])
def list_assurance_reports() -> ResponseEnvelope[List[AssuranceReport]]:
    """List all stored forensic assurance reports."""
    reports = default_report_engine.list_reports()
    return ResponseEnvelope(data=reports)


@router.get("/{report_id}", response_model=ResponseEnvelope[Any])
def get_assurance_report(
    report_id: str,
    format: ReportFormat = Query(ReportFormat.JSON_MANIFEST, description="Desired report presentation format"),
) -> ResponseEnvelope[Any]:
    """Retrieve an existing assurance report in JSON manifest, Markdown, Executive Summary, or HTML format."""
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


@router.post("/{report_id}/export", response_model=ResponseEnvelope[ExportReportResponse])
def export_assurance_report(
    report_id: str,
    format: ReportFormat = Query(ReportFormat.JSON_MANIFEST, description="Desired report export format"),
) -> ResponseEnvelope[ExportReportResponse]:
    """Export an assurance report to disk in the specified format."""
    try:
        export_res = default_report_engine.export_report_to_file(report_id=report_id, export_format=format)
        return ResponseEnvelope(data=export_res)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Assurance report '{report_id}' not found.")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Export failed: {str(exc)}")


@router.post("/verify", response_model=ResponseEnvelope[VerifyReportResponse])
def verify_assurance_report(
    payload: VerifyReportRequest,
) -> ResponseEnvelope[VerifyReportResponse]:
    """Cryptographically audit an assurance report for tamper status and signature validity."""
    result = default_report_engine.verify_report(payload.report)
    return ResponseEnvelope(data=result)

