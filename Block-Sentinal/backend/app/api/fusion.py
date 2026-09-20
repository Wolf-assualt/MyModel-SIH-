"""Evidence Fusion, Composite Risk Assessment, and Quarantine API Endpoints."""
from typing import List, Optional
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Query

from app.fusion.engine import default_fusion_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.fusion import (
    EvidenceFusionRequest,
    EvidenceItem,
    FusedAssessment,
    QuarantineRecord,
    QuarantineResolveRequest,
)

router = APIRouter(prefix="/fusion", tags=["Evidence Fusion Engine"])


@router.post("/evidence", response_model=ResponseEnvelope[EvidenceItem])
def submit_evidence(item: EvidenceItem) -> ResponseEnvelope[EvidenceItem]:
    """Register an individual verified evidence item into the central assurance store."""
    try:
        registered = default_fusion_engine.register_evidence(item)
        return ResponseEnvelope(data=registered)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Evidence registration failed: {str(exc)}")


@router.get("/evidence/{evidence_id}", response_model=ResponseEnvelope[EvidenceItem])
def get_evidence(evidence_id: str) -> ResponseEnvelope[EvidenceItem]:
    """Retrieve an evidence item by its evidence ID."""
    item = default_fusion_engine.get_evidence(evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Evidence item '{evidence_id}' not found.")
    return ResponseEnvelope(data=item)


@router.post("/evaluate", response_model=ResponseEnvelope[FusedAssessment])
def evaluate_evidence_fusion(
    payload: EvidenceFusionRequest,
) -> ResponseEnvelope[FusedAssessment]:
    """Fuse multi-source verification evidence and calculate holistic threat assessment."""
    try:
        evidence_items: List[EvidenceItem] = []
        if payload.evidence_items:
            evidence_items.extend(payload.evidence_items)
        if payload.evidence_ids:
            for eid in payload.evidence_ids:
                it = default_fusion_engine.get_evidence(eid)
                if not it:
                    raise HTTPException(status_code=404, detail=f"Evidence ID '{eid}' not found.")
                evidence_items.append(it)

        assessment = default_fusion_engine.fuse(
            target_entity_id=payload.target_entity_id,
            evidence=evidence_items,
        )
        return ResponseEnvelope(data=assessment)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Evidence fusion failed: {str(exc)}")


@router.get("/assessment/{assessment_id}", response_model=ResponseEnvelope[FusedAssessment])
def get_fused_assessment(
    assessment_id: str,
) -> ResponseEnvelope[FusedAssessment]:
    """Retrieve a persisted fused assurance assessment by its assessment ID."""
    assessment = default_fusion_engine.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")
    return ResponseEnvelope(data=assessment)


@router.get("/quarantine", response_model=ResponseEnvelope[List[QuarantineRecord]])
def list_quarantines(
    active_only: bool = Query(True, description="Filter to active quarantines only"),
) -> ResponseEnvelope[List[QuarantineRecord]]:
    """List quarantine records from the audit ledger."""
    records = default_fusion_engine.list_quarantines(active_only=active_only)
    return ResponseEnvelope(data=records)


@router.post("/quarantine/{quarantine_id}/resolve", response_model=ResponseEnvelope[QuarantineRecord])
def resolve_quarantine(
    quarantine_id: str,
    payload: QuarantineResolveRequest,
) -> ResponseEnvelope[QuarantineRecord]:
    """Resolve an active quarantine with forensic rationale."""
    record = default_fusion_engine.resolve_quarantine(
        quarantine_id=quarantine_id,
        resolved_by=payload.resolved_by,
        resolution_notes=payload.resolution_notes,
    )
    if not record:
        raise HTTPException(status_code=404, detail=f"Quarantine record '{quarantine_id}' not found.")
    return ResponseEnvelope(data=record)
