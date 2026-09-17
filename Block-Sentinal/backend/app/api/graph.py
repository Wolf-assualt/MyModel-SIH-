"""Evidence Graph, Lineage Tracing, and Contributor Risk API Endpoints."""
from fastapi import APIRouter, HTTPException, Query

from app.graph.contributor import ContributorRiskEngine
from app.graph.engine import default_graph_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.graph import (
    ContributorRiskProfile,
    GraphExport,
    LineageTraceResponse,
)

router = APIRouter(prefix="/graph", tags=["Evidence & Lineage Graph"])


@router.get("/export", response_model=ResponseEnvelope[GraphExport])
def export_evidence_graph() -> ResponseEnvelope[GraphExport]:
    """Export the complete directed property graph sealed with a canonical SHA-256 digest."""
    export_data = default_graph_engine.export_graph()
    return ResponseEnvelope(data=export_data)


@router.get("/trace/{entity_id}", response_model=ResponseEnvelope[LineageTraceResponse])
def trace_entity_lineage(
    entity_id: str,
) -> ResponseEnvelope[LineageTraceResponse]:
    """Traverse upstream dependencies and downstream blast-radius consumers for an entity."""
    trace_result = default_graph_engine.trace_lineage(entity_id)
    return ResponseEnvelope(data=trace_result)


@router.get("/contributor/{contributor_id}/risk", response_model=ResponseEnvelope[ContributorRiskProfile])
def get_contributor_risk_scorecard(
    contributor_id: str,
    name: str = Query("Unknown", description="Display name for contributor"),
) -> ResponseEnvelope[ContributorRiskProfile]:
    """Calculate and return a dynamic risk scorecard for a contributor based on historical evidence."""
    profile = ContributorRiskEngine.get_profile(
        contributor_id=contributor_id,
        name=name,
        graph=default_graph_engine,
    )
    return ResponseEnvelope(data=profile)
