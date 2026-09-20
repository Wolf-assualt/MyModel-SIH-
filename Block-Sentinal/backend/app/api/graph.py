"""Evidence Graph, Lineage Tracing, Blast Radius, and Contributor Risk API Endpoints."""
from typing import List, Optional
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Query

from app.graph.contributor import ContributorRiskEngine
from app.graph.engine import default_graph_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.graph import (
    BlastRadiusReport,
    BlastRadiusRequest,
    ContributorRiskProfile,
    GraphExport,
    GraphIntegrityReport,
    GraphNeighborsResponse,
    GraphNode,
    GraphVerifyRequest,
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


@router.get("/nodes/{node_id}", response_model=ResponseEnvelope[GraphNode])
def get_graph_node(node_id: str) -> ResponseEnvelope[GraphNode]:
    """Retrieve details for a specific graph vertex."""
    node = default_graph_engine.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found.")
    return ResponseEnvelope(data=node)


@router.get("/nodes/{node_id}/neighbors", response_model=ResponseEnvelope[GraphNeighborsResponse])
def get_node_neighbors(node_id: str) -> ResponseEnvelope[GraphNeighborsResponse]:
    """Retrieve connected neighbors and edges for a given vertex."""
    neighbors = default_graph_engine.get_neighbors(node_id)
    if not neighbors:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found.")
    return ResponseEnvelope(data=neighbors)


@router.get("/nodes/{node_id}/upstream", response_model=ResponseEnvelope[List[GraphNode]])
def get_node_upstream(
    node_id: str,
    max_depth: int = Query(10, ge=1, le=50),
) -> ResponseEnvelope[List[GraphNode]]:
    """Trace upstream dependencies for an entity."""
    upstream = default_graph_engine.trace_upstream(node_id, max_depth=max_depth)
    return ResponseEnvelope(data=upstream)


@router.get("/nodes/{node_id}/downstream", response_model=ResponseEnvelope[List[GraphNode]])
def get_node_downstream(
    node_id: str,
    max_depth: int = Query(10, ge=1, le=50),
) -> ResponseEnvelope[List[GraphNode]]:
    """Trace downstream consumers for an entity."""
    downstream = default_graph_engine.trace_downstream(node_id, max_depth=max_depth)
    return ResponseEnvelope(data=downstream)


@router.post("/blast-radius", response_model=ResponseEnvelope[BlastRadiusReport])
def calculate_blast_radius(
    payload: BlastRadiusRequest,
) -> ResponseEnvelope[BlastRadiusReport]:
    """Calculate forensic downstream blast radius of a compromised entity."""
    try:
        report = default_graph_engine.calculate_blast_radius(payload.root_cause_id)
        return ResponseEnvelope(data=report)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/verify", response_model=ResponseEnvelope[GraphIntegrityReport])
def verify_graph_integrity(
    payload: Optional[GraphVerifyRequest] = None,
) -> ResponseEnvelope[GraphIntegrityReport]:
    """Audit graph cryptographic and topological integrity."""
    check_cycles = payload.check_cycles if payload else False
    report = default_graph_engine.verify_graph_integrity(check_cycles=check_cycles)
    return ResponseEnvelope(data=report)


@router.get("/contributor/{contributor_id}/risk", response_model=ResponseEnvelope[ContributorRiskProfile])
@router.get("/contributors/{contributor_id}/risk", response_model=ResponseEnvelope[ContributorRiskProfile])
def get_contributor_risk_scorecard(
    contributor_id: str,
    name: Optional[str] = Query(None, description="Display name for contributor"),
) -> ResponseEnvelope[ContributorRiskProfile]:
    """Calculate and return a dynamic risk scorecard for a contributor based on historical evidence."""
    profile = ContributorRiskEngine.get_profile(
        contributor_id=contributor_id,
        name=name,
        graph=default_graph_engine,
    )
    return ResponseEnvelope(data=profile)
