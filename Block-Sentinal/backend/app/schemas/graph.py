"""Pydantic schemas for Directed Evidence & Provenance Lineage Property Graph."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class NodeType(str, Enum):
    """Categorical node types in the evidence and provenance graph."""
    CONTRIBUTOR = "CONTRIBUTOR"
    DATASET = "DATASET"
    DATASET_BATCH = "DATASET_BATCH"
    DATASET_VERSION = "DATASET_VERSION"
    SAMPLE = "SAMPLE"
    FINDING = "FINDING"
    EVIDENCE = "EVIDENCE"
    MODEL = "MODEL"
    MODEL_VERSION = "MODEL_VERSION"
    TRAINING_RUN = "TRAINING_RUN"
    PREPROCESSING_CONFIG = "PREPROCESSING_CONFIG"
    INFERENCE = "INFERENCE"
    INFERENCE_RECORD = "INFERENCE_RECORD"
    OUTPUT = "OUTPUT"
    DRIFT_ASSESSMENT = "DRIFT_ASSESSMENT"
    CONTRIBUTOR_ASSESSMENT = "CONTRIBUTOR_ASSESSMENT"
    FUSION_ASSESSMENT = "FUSION_ASSESSMENT"
    QUARANTINE_RECORD = "QUARANTINE_RECORD"
    ANALYST_DECISION = "ANALYST_DECISION"
    AUDIT_EVENT = "AUDIT_EVENT"
    REPORT = "REPORT"


class EdgeType(str, Enum):
    """Directed edge relationships connecting assurance entities."""
    PROVIDED = "PROVIDED"
    PRODUCED = "PRODUCED"
    AUTHORED_BY = "AUTHORED_BY"
    CONTAINS_SAMPLE = "CONTAINS_SAMPLE"
    TRAINED_ON = "TRAINED_ON"
    USED_PREPROCESSING = "USED_PREPROCESSING"
    GENERATED_BY = "GENERATED_BY"
    FLAGGED_WITH = "FLAGGED_WITH"
    EVALUATED_BY = "EVALUATED_BY"
    DECIDES_ON = "DECIDES_ON"
    QUARANTINES = "QUARANTINES"
    RESULTED_FROM = "RESULTED_FROM"
    VERSION_OF = "VERSION_OF"
    HAS_OUTPUT = "HAS_OUTPUT"
    ASSESSED_IN = "ASSESSED_IN"
    REFERENCES = "REFERENCES"
    ATTACHED_TO = "ATTACHED_TO"
    ABOUT = "ABOUT"


class GraphNode(BaseModel):
    """A vertex in the directed property graph representing an entity or assurance artifact."""
    id: str
    node_type: NodeType
    label: str
    digest: Optional[str] = None
    canonical_identity: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GraphEdge(BaseModel):
    """A directed edge representing provenance, dependency, containment, or integrity flagging."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    evidence_id: Optional[str] = Field(default=None, description="Cryptographic evidence or reference ID for this relationship")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: Any) -> None:
        if not self.evidence_id:
            # Invariant: Every edge must have an evidence/reference ID
            self.evidence_id = f"ref_{self.edge_type.value.lower()}_{self.source_id[:16]}_{self.target_id[:16]}"


class GraphNeighborsResponse(BaseModel):
    """Connected direct incoming and outgoing neighbors for a given vertex."""
    node_id: str
    incoming_edges: List[GraphEdge] = Field(default_factory=list)
    outgoing_edges: List[GraphEdge] = Field(default_factory=list)
    neighbors: List[GraphNode] = Field(default_factory=list)


class GraphExport(BaseModel):
    """Complete serialized graph snapshot sealed with a canonical SHA-256 digest."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    node_count: int = 0
    edge_count: int = 0
    graph_digest: str = Field(..., min_length=64, max_length=64)

    def model_post_init(self, __context: Any) -> None:
        if self.node_count == 0 and self.nodes:
            self.node_count = len(self.nodes)
        if self.edge_count == 0 and self.edges:
            self.edge_count = len(self.edges)


class GraphIntegrityReport(BaseModel):
    """Cryptographic integrity audit report of the in-memory graph structure."""
    is_valid: bool
    computed_digest: str
    broken_edges: List[str] = Field(default_factory=list)
    orphan_nodes: List[str] = Field(default_factory=list)
    cycles_detected: List[List[str]] = Field(default_factory=list)
    details: str = "Integrity check completed successfully."
    total_nodes: int = 0
    total_edges: int = 0


class BlastRadiusReport(BaseModel):
    """Forensic downstream impact report identifying all affected models, runs, and inferences."""
    root_cause_id: str
    root_cause_type: NodeType
    status: AssetStatus = AssetStatus.ACCEPTED
    directly_affected_count: int = 0
    total_downstream_count: int = 0
    affected_training_runs: List[str] = Field(default_factory=list)
    affected_models: List[str] = Field(default_factory=list)
    affected_inferences: List[str] = Field(default_factory=list)
    affected_evidence_ids: List[str] = Field(default_factory=list)
    affected_quarantines: List[str] = Field(default_factory=list)
    total_affected_entities: int = 0
    explanation: str = ""


class ContributorRiskProfile(BaseModel):
    """Dynamic explainable risk scorecard assessing an individual contributor."""
    contributor_id: str
    name: str = "Unknown"
    total_batches: int = Field(default=0, ge=0)
    total_datasets: int = Field(default=0, ge=0)
    total_samples: int = Field(default=0, ge=0)
    flagged_findings_count: int = Field(default=0, ge=0)
    evidence_count: int = Field(default=0, ge=0)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_level: Optional[Any] = None
    status: AssetStatus = AssetStatus.ACCEPTED
    explanation: str = ""
    historical_findings: List[Dict[str, Any]] = Field(default_factory=list)
    last_active: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: Any) -> None:
        from app.schemas.fusion import AssuranceRiskLevel

        if self.total_datasets == 0 and self.total_batches > 0:
            self.total_datasets = self.total_batches
        elif self.total_batches == 0 and self.total_datasets > 0:
            self.total_batches = self.total_datasets

        if self.evidence_count == 0 and self.flagged_findings_count > 0:
            self.evidence_count = self.flagged_findings_count
        elif self.flagged_findings_count == 0 and self.evidence_count > 0:
            self.flagged_findings_count = self.evidence_count

        if self.risk_level is None:
            if self.risk_score >= 0.70:
                self.risk_level = AssuranceRiskLevel.CRITICAL
            elif self.risk_score >= 0.40:
                self.risk_level = AssuranceRiskLevel.HIGH
            elif self.risk_score >= 0.20:
                self.risk_level = AssuranceRiskLevel.MEDIUM
            else:
                self.risk_level = AssuranceRiskLevel.LOW


class LineageTraceResponse(BaseModel):
    """Upstream provenance and downstream blast-radius traversal result for an entity."""
    target_id: str
    upstream_path: List[GraphNode] = Field(default_factory=list)
    downstream_path: List[GraphNode] = Field(default_factory=list)
    associated_findings: List[GraphNode] = Field(default_factory=list)
    blast_radius_count: int = Field(default=0, ge=0)


class BlastRadiusRequest(BaseModel):
    """Request payload to calculate downstream blast radius."""
    root_cause_id: str = Field(..., min_length=1)


class GraphVerifyRequest(BaseModel):
    """Request payload to verify graph integrity."""
    check_cycles: bool = False
