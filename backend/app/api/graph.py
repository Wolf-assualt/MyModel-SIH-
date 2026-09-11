"""Evidence & Provenance Graph, Blast-Radius, and Contributor Risk API Endpoints.

Phase 10: Multi-layer provenance graph queries, blast-radius calculation,
upstream/downstream lineage traversals, and cryptographic graph audits.
"""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.graph.contributor import ContributorRiskEngine
from app.graph.engine import default_graph_engine
from app.schemas.base import ResponseEnvelope
from app.schemas.graph import (
    BlastRadiusReport,
    ContributorRiskProfile,
    GraphExport,
    GraphIntegrityReport,
    GraphNeighborsResponse,
    GraphNode,
    LineageTraceResponse,
)

router = APIRouter(prefix="/graph", tags=["Evidence & Lineage Graph"])


class BlastRadiusRequest(BaseModel):
    """Request payload for downstream blast-radius analysis."""
    root_cause_id: str = Field(..., description="ID of the root cause entity to investigate")


class GraphVerifyRequest(BaseModel):
    """Optional parameters for on-demand graph verification."""
    check_cycles: bool = Field(default=True, description="Whether to check for DAG cycles")


@router.get("/export", response_model=ResponseEnvelope[GraphExport])
def export_evidence_graph(
    sign: bool = Query(True, description="Whether to sign the graph digest with ECDSA"),
) -> ResponseEnvelope[GraphExport]:
    """Export the complete directed property graph sealed with a canonical SHA-256 digest and ECDSA signature."""
    export_data = default_graph_engine.export_graph(sign=sign)
    return ResponseEnvelope(data=export_data)


@router.get("/nodes/{node_id}", response_model=ResponseEnvelope[GraphNode])
def get_graph_node(node_id: str) -> ResponseEnvelope[GraphNode]:
    """Retrieve a single node by its identifier."""
    node = default_graph_engine.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in graph.")
    return ResponseEnvelope(data=node)


@router.get("/nodes/{node_id}/neighbors", response_model=ResponseEnvelope[GraphNeighborsResponse])
def get_node_neighbors(node_id: str) -> ResponseEnvelope[GraphNeighborsResponse]:
    """Retrieve all direct incoming/outgoing edges and neighbor nodes for a given entity."""
    neighbors_resp = default_graph_engine.get_neighbors(node_id)
    if not neighbors_resp:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in graph.")
    return ResponseEnvelope(data=neighbors_resp)


@router.get("/nodes/{node_id}/upstream", response_model=ResponseEnvelope[List[GraphNode]])
def get_upstream_lineage(
    node_id: str,
    max_depth: int = Query(20, ge=1, le=100, description="Maximum traversal depth"),
) -> ResponseEnvelope[List[GraphNode]]:
    """Traverse and return all upstream dependencies for an entity."""
    if node_id not in default_graph_engine.nodes:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in graph.")
    upstream = default_graph_engine.trace_upstream(node_id, max_depth=max_depth)
    return ResponseEnvelope(data=upstream)


@router.get("/nodes/{node_id}/downstream", response_model=ResponseEnvelope[List[GraphNode]])
def get_downstream_lineage(
    node_id: str,
    max_depth: int = Query(20, ge=1, le=100, description="Maximum traversal depth"),
) -> ResponseEnvelope[List[GraphNode]]:
    """Traverse and return all downstream consumers for an entity."""
    if node_id not in default_graph_engine.nodes:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in graph.")
    downstream = default_graph_engine.trace_downstream(node_id, max_depth=max_depth)
    return ResponseEnvelope(data=downstream)


@router.get("/nodes/{node_id}/evidence", response_model=ResponseEnvelope[List[GraphNode]])
def get_node_evidence(node_id: str) -> ResponseEnvelope[List[GraphNode]]:
    """Retrieve all evidence items and findings attached directly or contextually to a node."""
    if node_id not in default_graph_engine.nodes:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in graph.")
    evidence_nodes = default_graph_engine.get_attached_evidence(node_id)
    return ResponseEnvelope(data=evidence_nodes)


@router.get("/contributors/{contributor_id}/risk", response_model=ResponseEnvelope[ContributorRiskProfile])
def get_contributor_risk_profile(
    contributor_id: str,
    name: Optional[str] = Query(None, description="Display name for contributor"),
) -> ResponseEnvelope[ContributorRiskProfile]:
    """Calculate and return an explainable, evidence-grounded risk profile for a contributor."""
    profile = ContributorRiskEngine.get_profile(
        contributor_id=contributor_id,
        name=name,
        graph=default_graph_engine,
    )
    return ResponseEnvelope(data=profile)


@router.post("/blast-radius", response_model=ResponseEnvelope[BlastRadiusReport])
def calculate_blast_radius(request: BlastRadiusRequest) -> ResponseEnvelope[BlastRadiusReport]:
    """Calculate downstream blast-radius impact and affected dependencies for a root cause entity."""
    try:
        report = default_graph_engine.calculate_blast_radius(request.root_cause_id)
        return ResponseEnvelope(data=report)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/verify", response_model=ResponseEnvelope[GraphIntegrityReport])
def verify_graph_integrity(
    request: Optional[GraphVerifyRequest] = None,
) -> ResponseEnvelope[GraphIntegrityReport]:
    """Audit graph topology, reference consistency, and cryptographic digests."""
    report = default_graph_engine.verify_graph_integrity()
    return ResponseEnvelope(data=report)


# Backward Compatibility Endpoints
@router.get("/trace/{entity_id}", response_model=ResponseEnvelope[LineageTraceResponse])
def trace_entity_lineage(
    entity_id: str,
) -> ResponseEnvelope[LineageTraceResponse]:
    """Traverse upstream dependencies and downstream blast-radius consumers for an entity (legacy)."""
    trace_result = default_graph_engine.trace_lineage(entity_id)
    return ResponseEnvelope(data=trace_result)


@router.get("/contributor/{contributor_id}/risk", response_model=ResponseEnvelope[ContributorRiskProfile])
def get_contributor_risk_scorecard_legacy(
    contributor_id: str,
    name: str = Query("Unknown", description="Display name for contributor"),
) -> ResponseEnvelope[ContributorRiskProfile]:
    """Legacy alias for contributor risk scorecard endpoint."""
    profile = ContributorRiskEngine.get_profile(
        contributor_id=contributor_id,
        name=name,
        graph=default_graph_engine,
    )
    return ResponseEnvelope(data=profile)
