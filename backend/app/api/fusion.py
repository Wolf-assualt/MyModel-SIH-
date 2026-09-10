"""Evidence Fusion and Composite Risk Assessment API Endpoints."""
from fastapi import APIRouter, HTTPException

from app.fusion.engine import default_fusion_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.fusion import EvidenceFusionRequest, FusedAssessment

router = APIRouter(prefix="/fusion", tags=["Evidence Fusion Engine"])


@router.post("/evaluate", response_model=ResponseEnvelope[FusedAssessment])
def evaluate_evidence_fusion(
    payload: EvidenceFusionRequest,
) -> ResponseEnvelope[FusedAssessment]:
    """Fuse multi-source verification evidence and calculate holistic threat assessment."""
    try:
        assessment = default_fusion_engine.fuse(
            target_entity_id=payload.target_entity_id,
            evidence=payload.evidence_items,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Evidence fusion failed: {str(exc)}")

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
