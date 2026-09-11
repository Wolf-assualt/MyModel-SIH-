"""Pydantic schemas for the Directed Evidence & Lineage Property Graph."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class NodeType(str, Enum):
    """Categorical node types in the evidence graph."""
    CONTRIBUTOR = "CONTRIBUTOR"
    DATASET_BATCH = "DATASET_BATCH"
    SAMPLE = "SAMPLE"
    MODEL = "MODEL"
    INFERENCE_RECORD = "INFERENCE_RECORD"
    FINDING = "FINDING"


class EdgeType(str, Enum):
    """Directed edge relationships connecting entities."""
    AUTHORED_BY = "AUTHORED_BY"
    CONTAINS_SAMPLE = "CONTAINS_SAMPLE"
    TRAINED_ON = "TRAINED_ON"
    GENERATED_BY = "GENERATED_BY"
    FLAGGED_WITH = "FLAGGED_WITH"


class GraphNode(BaseModel):
    """A vertex in the directed property graph representing an asset, contributor, or finding."""
    id: str
    node_type: NodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """A directed edge representing provenance, containment, training, or integrity flagging."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphExport(BaseModel):
    """Complete serialized graph snapshot sealed with a canonical SHA-256 digest."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    graph_digest: str = Field(..., min_length=64, max_length=64)


class ContributorRiskProfile(BaseModel):
    """Dynamic risk scorecard assessing an individual contributor across historical activity."""
    contributor_id: str
    name: str
    total_batches: int = Field(..., ge=0)
    total_samples: int = Field(..., ge=0)
    flagged_findings_count: int = Field(..., ge=0)
    risk_score: float = Field(..., ge=0.0, le=1.0)  # 0.0 (trusted) to 1.0 (high risk)
    status: AssetStatus  # ACCEPTED, UNDER_REVIEW, QUARANTINED
    last_active: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LineageTraceResponse(BaseModel):
    """Upstream provenance and downstream blast-radius traversal result for an entity."""
    target_id: str
    upstream_path: List[GraphNode]
    downstream_path: List[GraphNode]
    associated_findings: List[GraphNode]
    blast_radius_count: int = Field(..., ge=0)
