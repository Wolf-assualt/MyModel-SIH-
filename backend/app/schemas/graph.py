"""Pydantic schemas for the Directed Evidence & Lineage Property Graph.

Phase 10: Traceable Provenance Graph, Contributor Risk Profiles, and Blast-Radius Analysis.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.fusion import AssuranceRiskLevel


class NodeType(str, Enum):
    """Categorical node types in the evidence & provenance graph."""
    CONTRIBUTOR = "CONTRIBUTOR"
    DATASET = "DATASET"
    DATASET_VERSION = "DATASET_VERSION"
    DATASET_BATCH = "DATASET_BATCH"  # Backward compatibility alias
    SAMPLE = "SAMPLE"
    TRAINING_RUN = "TRAINING_RUN"
    MODEL = "MODEL"
    MODEL_VERSION = "MODEL_VERSION"
    INFERENCE = "INFERENCE"
    INFERENCE_RECORD = "INFERENCE_RECORD"  # Backward compatibility alias
    OUTPUT = "OUTPUT"
    EVIDENCE = "EVIDENCE"
    FINDING = "FINDING"  # Backward compatibility alias
    DRIFT_BASELINE = "DRIFT_BASELINE"
    DRIFT_REPORT = "DRIFT_REPORT"
    FUSION_ASSESSMENT = "FUSION_ASSESSMENT"
    QUARANTINE = "QUARANTINE"


class EdgeType(str, Enum):
    """Directed edge relationships connecting entities in the provenance graph."""
    PROVIDED = "PROVIDED"
    AUTHORED_BY = "AUTHORED_BY"  # Backward compatibility alias
    HAS_VERSION = "HAS_VERSION"
    CONTAINS = "CONTAINS"
    CONTAINS_SAMPLE = "CONTAINS_SAMPLE"  # Backward compatibility alias
    USED_IN = "USED_IN"
    PRODUCED = "PRODUCED"
    TRAINED_ON = "TRAINED_ON"
    USED_FOR = "USED_FOR"
    GENERATED_BY = "GENERATED_BY"
    ABOUT = "ABOUT"
    FLAGGED_WITH = "FLAGGED_WITH"
    USES = "USES"
    DECIDES_ON = "DECIDES_ON"
    COMPARED_WITH = "COMPARED_WITH"
    QUARANTINES = "QUARANTINES"
    JUSTIFIED_BY = "JUSTIFIED_BY"
    RESULTED_FROM = "RESULTED_FROM"


class GraphNode(BaseModel):
    """A vertex in the directed property graph representing an asset, contributor, or assurance event."""
    id: str = Field(..., description="Stable, unique identifier for the graph node")
    node_type: NodeType = Field(..., description="Categorical entity type")
    label: str = Field(..., description="Human-readable node label or description")
    digest: Optional[str] = Field(default=None, description="SHA-256 cryptographic digest of the node asset")
    canonical_identity: Optional[str] = Field(default=None, description="Canonical identity string (e.g. format:type:id)")
    signature_ref: Optional[str] = Field(default=None, description="Reference ID or substring of ECDSA signature")
    source_record_id: Optional[str] = Field(default=None, description="Primary key or record ID in source subsystem")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Node registration timestamp")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata and attributes")


class GraphEdge(BaseModel):
    """A directed relationship connecting two vertices in the property graph."""
    source_id: str = Field(..., description="Source node identifier")
    target_id: str = Field(..., description="Target node identifier")
    edge_type: EdgeType = Field(..., description="Directed relationship type")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Edge creation timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Relationship metadata and contextual evidence")


class GraphExport(BaseModel):
    """Complete serialized graph snapshot sealed with a canonical SHA-256 digest and ECDSA signature."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    graph_digest: str = Field(..., min_length=64, max_length=64, description="RFC 8785 canonical SHA-256 hash")
    node_count: int = Field(default=0, ge=0)
    edge_count: int = Field(default=0, ge=0)
    signature: Optional[str] = Field(default=None, description="ECDSA SECP256R1 signature over graph_digest")
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ContributorRiskProfile(BaseModel):
    """Explainable risk profile assessing an individual contributor across historical evidence."""
    contributor_id: str
    name: str
    total_datasets: int = Field(default=0, ge=0)
    total_batches: int = Field(default=0, ge=0)  # Backward compatibility
    total_samples: int = Field(default=0, ge=0)
    evidence_count: int = Field(default=0, ge=0)
    flagged_findings_count: int = Field(default=0, ge=0)  # Backward compatibility
    severity_breakdown: Dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    )
    historical_incidents: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Normalized risk score [0.0 - 1.0]")
    risk_level: AssuranceRiskLevel = Field(default=AssuranceRiskLevel.LOW)
    status: AssetStatus = Field(default=AssetStatus.ACCEPTED)
    explanation: str = Field(..., description="Explainable narrative based on observable evidence")
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    last_active: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BlastRadiusReport(BaseModel):
    """Downstream blast-radius impact analysis for a compromised or investigated entity."""
    root_cause_id: str = Field(..., description="Investigated root entity ID")
    root_cause_type: NodeType
    status: AssetStatus = Field(default=AssetStatus.UNDER_REVIEW)
    directly_affected_count: int = Field(..., ge=0)
    total_downstream_count: int = Field(..., ge=0)
    affected_training_runs: List[str] = Field(default_factory=list)
    affected_models: List[str] = Field(default_factory=list)
    affected_model_versions: List[str] = Field(default_factory=list)
    affected_inferences: List[str] = Field(default_factory=list)
    affected_outputs: List[str] = Field(default_factory=list)
    affected_evidence_ids: List[str] = Field(default_factory=list)
    affected_quarantines: List[str] = Field(default_factory=list)
    downstream_nodes: List[GraphNode] = Field(default_factory=list)
    associated_evidence: List[GraphNode] = Field(default_factory=list)
    explanation: str = Field(..., description="Forensic dependency narrative (non-inflammatory)")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LineageTraceResponse(BaseModel):
    """Upstream provenance and downstream blast-radius traversal result for an entity."""
    target_id: str
    upstream_path: List[GraphNode]
    downstream_path: List[GraphNode]
    associated_findings: List[GraphNode] = Field(default_factory=list)
    associated_evidence: List[GraphNode] = Field(default_factory=list)
    blast_radius_count: int = Field(..., ge=0)


class GraphNeighborsResponse(BaseModel):
    """Neighbors connected directly to a node."""
    node: GraphNode
    incoming_edges: List[GraphEdge] = Field(default_factory=list)
    outgoing_edges: List[GraphEdge] = Field(default_factory=list)
    neighbors: List[GraphNode] = Field(default_factory=list)


class GraphIntegrityReport(BaseModel):
    """Integrity audit report for the provenance graph."""
    is_valid: bool
    total_nodes: int
    total_edges: int
    computed_digest: str
    stored_digest: Optional[str] = None
    tampered_nodes: List[str] = Field(default_factory=list)
    broken_edges: List[Dict[str, str]] = Field(default_factory=list)
    orphan_nodes: List[str] = Field(default_factory=list)
    cycles_detected: List[List[str]] = Field(default_factory=list)
    details: str
