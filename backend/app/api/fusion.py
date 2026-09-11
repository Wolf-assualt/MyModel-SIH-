"""Evidence Fusion, Composite Threat Assessment, and Quarantine API Endpoints."""
from typing import List
from fastapi import APIRouter, HTTPException

from app.fusion.engine import default_fusion_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.fusion import (
    EvidenceFusionRequest,
    EvidenceItem,
    FusedAssessment,
    QuarantineRecord,
    QuarantineRequest,
    ResolveQuarantineRequest,
)

router = APIRouter(prefix="/fusion", tags=["Evidence Fusion Engine"])


@router.post("/evaluate", response_model=ResponseEnvelope[FusedAssessment])
def evaluate_evidence_fusion(
    payload: EvidenceFusionRequest,
) -> ResponseEnvelope[FusedAssessment]:
    """Fuse multi-source verification evidence, apply hard-veto rules, and calculate assurance verdict."""
    evidence_items = list(payload.evidence_items)

    # If evidence_ids are provided, resolve from storage
    if payload.evidence_ids:
        for eid in payload.evidence_ids:
            item = default_fusion_engine.get_evidence(eid)
            if item and not any(e.evidence_id == eid for e in evidence_items):
                evidence_items.append(item)

    try:
        assessment = default_fusion_engine.fuse(
            target_entity_id=payload.target_entity_id,
            evidence=evidence_items,
            strict_subject_binding=payload.strict_subject_binding,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evidence fusion failed: {str(exc)}")

    return ResponseEnvelope(data=assessment)


@router.get("/assessment/{assessment_id}", response_model=ResponseEnvelope[FusedAssessment])
def get_fused_assessment(
    assessment_id: str,
) -> ResponseEnvelope[FusedAssessment]:
    """Retrieve a persisted fused assurance assessment by its assessment ID."""
    assessment = default_fusion_engine.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")
    return ResponseEnvelope(data=assessment)


@router.get("/assessments", response_model=ResponseEnvelope[List[FusedAssessment]])
def list_fused_assessments() -> ResponseEnvelope[List[FusedAssessment]]:
    """List all persisted fused assurance assessments."""
    assessments = default_fusion_engine.list_assessments()
    return ResponseEnvelope(data=assessments)


# -------------------------------------------------------------------------
# Evidence Management Endpoints
# -------------------------------------------------------------------------

@router.post("/evidence", response_model=ResponseEnvelope[EvidenceItem])
def submit_evidence_item(
    payload: EvidenceItem,
) -> ResponseEnvelope[EvidenceItem]:
    """Persist an individual verified EvidenceItem to the central assurance store."""
    try:
        item = default_fusion_engine.register_evidence(payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ResponseEnvelope(data=item)


@router.get("/evidence/{evidence_id}", response_model=ResponseEnvelope[EvidenceItem])
def get_evidence_item(
    evidence_id: str,
) -> ResponseEnvelope[EvidenceItem]:
    """Retrieve an individual EvidenceItem by evidence_id."""
    item = default_fusion_engine.get_evidence(evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")
    return ResponseEnvelope(data=item)


@router.get("/evidence", response_model=ResponseEnvelope[List[EvidenceItem]])
def list_evidence_items() -> ResponseEnvelope[List[EvidenceItem]]:
    """List all registered EvidenceItems in the central assurance store."""
    items = default_fusion_engine.list_evidence()
    return ResponseEnvelope(data=items)


# -------------------------------------------------------------------------
# Quarantine Management Endpoints
# -------------------------------------------------------------------------

@router.post("/quarantine", response_model=ResponseEnvelope[QuarantineRecord])
def create_quarantine_record(
    payload: QuarantineRequest,
) -> ResponseEnvelope[QuarantineRecord]:
    """Manually place an entity in quarantine with reason and evidence bindings."""
    try:
        rec = default_fusion_engine.quarantine_entity(
            subject_id=payload.subject_id,
            subject_type=payload.subject_type,
            reason=payload.reason,
            evidence_ids=payload.evidence_ids,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ResponseEnvelope(data=rec)


@router.get("/quarantine", response_model=ResponseEnvelope[List[QuarantineRecord]])
def list_quarantine_records(
    active_only: bool = False,
) -> ResponseEnvelope[List[QuarantineRecord]]:
    """List all quarantine records."""
    records = default_fusion_engine.list_quarantines(active_only=active_only)
    return ResponseEnvelope(data=records)


@router.get("/quarantine/{quarantine_id}", response_model=ResponseEnvelope[QuarantineRecord])
def get_quarantine_record(
    quarantine_id: str,
) -> ResponseEnvelope[QuarantineRecord]:
    """Retrieve a specific quarantine record."""
    rec = default_fusion_engine.get_quarantine(quarantine_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Quarantine record '{quarantine_id}' not found.")
    return ResponseEnvelope(data=rec)


@router.post("/quarantine/{quarantine_id}/resolve", response_model=ResponseEnvelope[QuarantineRecord])
def resolve_quarantine_record(
    quarantine_id: str,
    payload: ResolveQuarantineRequest,
) -> ResponseEnvelope[QuarantineRecord]:
    """Resolve and clear an active quarantine record with required forensic justification."""
    try:
        rec = default_fusion_engine.resolve_quarantine(
            quarantine_id=quarantine_id,
            resolved_by=payload.resolved_by,
            resolution_notes=payload.resolution_notes,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ResponseEnvelope(data=rec)
