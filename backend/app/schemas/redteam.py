"""Pydantic schemas for the Red-Team Adversarial Attack & Tamper Simulation Lab.

Phase 11: Controlled Defensive Validation Laboratory for TRUST-CV.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus
from app.schemas.fusion import AssuranceAction, AssuranceRiskLevel, EvidenceItem, FusedAssessment, QuarantineRecord
from app.schemas.graph import BlastRadiusReport, GraphEdge, GraphNode


class AttackType(str, Enum):
    """Supported red-team adversarial attack categories and vectors."""
    LABEL_FLIPPING = "LABEL_FLIPPING"
    BACKDOOR_TRIGGER = "BACKDOOR_TRIGGER"
    DATASET_CORRUPTION = "DATASET_CORRUPTION"
    DATASET_BYTE_TAMPER = "DATASET_BYTE_TAMPER"
    DATASET_SAMPLE_DELETION = "DATASET_SAMPLE_DELETION"
    DATASET_DUPLICATE_INJECTION = "DATASET_DUPLICATE_INJECTION"
    MODEL_WEIGHT_TAMPERING = "MODEL_WEIGHT_TAMPERING"
    MODEL_SUBSTITUTION = "MODEL_SUBSTITUTION"
    MODEL_SIGNATURE_TAMPER = "MODEL_SIGNATURE_TAMPER"
    BEHAVIORAL_DIVERGENCE = "BEHAVIORAL_DIVERGENCE"
    INFERENCE_TAMPERING = "INFERENCE_TAMPERING"
    INFERENCE_REPLAY = "INFERENCE_REPLAY"
    INFERENCE_HASH_CHAIN_TAMPER = "INFERENCE_HASH_CHAIN_TAMPER"
    DRIFT_BENIGN_SHIFT = "DRIFT_BENIGN_SHIFT"
    DRIFT_BASELINE_TAMPER = "DRIFT_BASELINE_TAMPER"
    DRIFT_CORROBORATING_ATTACK = "DRIFT_CORROBORATING_ATTACK"
    EVIDENCE_TAMPERING = "EVIDENCE_TAMPERING"
    FUSION_TAMPERING = "FUSION_TAMPERING"
    GRAPH_TAMPERING = "GRAPH_TAMPERING"
    MULTI_STAGE_CHAIN = "MULTI_STAGE_CHAIN"
    BENIGN_NORMAL_BASELINE = "BENIGN_NORMAL_BASELINE"


class ScenarioCategory(str, Enum):
    """Broad category for red-team simulation scenarios."""
    DATASET = "DATASET"
    MODEL = "MODEL"
    BEHAVIOR = "BEHAVIOR"
    INFERENCE = "INFERENCE"
    DRIFT = "DRIFT"
    EVIDENCE_FUSION = "EVIDENCE_FUSION"
    GRAPH = "GRAPH"
    COMPOUND_CHAIN = "COMPOUND_CHAIN"
    BENIGN_BASELINE = "BENIGN_BASELINE"


class RedTeamScenario(BaseModel):
    """Specification of a controlled defensive adversarial scenario."""
    scenario_id: str = Field(..., description="Stable unique scenario identifier")
    scenario_name: str = Field(..., description="Human-readable title")
    category: ScenarioCategory
    target_domain: str = Field(..., description="Targeted subsystem domain (e.g. DATA_INTEGRITY, MODEL_IDENTITY)")
    target_artifact: str = Field(..., description="Target asset identifier or synthetic fixture type")
    attack_description: str = Field(..., description="Detailed description of the simulated mutation")
    preconditions: str = Field(default="Synthetic fixture initialized in sandbox", description="Prerequisites")
    mutation_method: str = Field(..., description="Specific algorithmic mutation applied")
    expected_detection: bool = Field(default=True, description="Whether the detector is expected to catch the mutation")
    expected_severity: str = Field(default="CRITICAL", description="Expected finding severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)")
    expected_disposition: AssuranceAction = Field(default=AssuranceAction.BLOCK, description="Expected gatekeeper action")
    expected_evidence_types: List[str] = Field(default_factory=list, description="Expected evidence source domains")
    expected_graph_impact: str = Field(default="Quarantine and blast-radius propagated", description="Graph expectation")
    expected_blast_radius: str = Field(default="Downstream dependencies flagged", description="Blast-radius impact summary")


class ScenarioExecutionResult(BaseModel):
    """Comprehensive outcome of executing a controlled red-team validation scenario."""
    execution_id: str
    scenario_id: str
    scenario_name: str
    category: ScenarioCategory
    is_detected: bool
    detecting_subsystems: List[str] = Field(default_factory=list)
    evidence_generated: List[EvidenceItem] = Field(default_factory=list)
    fused_assessment: Optional[FusedAssessment] = None
    hard_veto_triggered: bool = False
    quarantine_record: Optional[QuarantineRecord] = None
    graph_lineage_nodes: List[GraphNode] = Field(default_factory=list)
    graph_lineage_edges: List[GraphEdge] = Field(default_factory=list)
    blast_radius_report: Optional[BlastRadiusReport] = None
    execution_time_ms: float = Field(..., ge=0.0)
    forensic_summary: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CoverageMatrixItem(BaseModel):
    """Single entry in the defensive detection coverage matrix."""
    scenario_id: str
    scenario_name: str
    category: str
    target_artifact: str
    detector: str
    evidence_generated: str
    fusion_result: str
    quarantine_result: str
    graph_impact: str
    blast_radius_impact: str
    detection_status: str  # "DETECTED", "BENIGN_PASS", "MISSED"


class DetectionCoverageMatrix(BaseModel):
    """Machine-readable matrix summarizing defense coverage across all scenarios."""
    total_scenarios: int
    covered_scenarios: int
    items: List[CoverageMatrixItem] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionScorecard(BaseModel):
    """Statistical evaluation of defensive detection performance and false-positive rates."""
    total_scenarios: int
    detected: int
    missed: int
    false_positives: int
    hard_veto_detections: int
    review_detections: int
    quarantine_detections: int
    accuracy_rate: float = Field(..., ge=0.0, le=1.0)
    category_breakdown: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    missed_explanations: List[Dict[str, str]] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Backward Compatibility Schemas
class AttackExecutionRequest(BaseModel):
    """Request payload to simulate an adversarial attack (legacy)."""
    attack_type: AttackType
    target_entity_id: str = Field(..., description="batch_id, model_id, or inference_record_id")
    intensity: float = Field(default=0.5, ge=0.0, le=1.0, description="Scale of attack")
    target_label: Optional[str] = Field(default="poisoned_class", description="Target label")


class AttackExecutionResult(BaseModel):
    """Result of an executed adversarial attack simulation (legacy)."""
    attack_id: str
    attack_type: AttackType
    target_entity_id: str
    modified_entity_id: str
    samples_modified_count: int = Field(default=0, ge=0)
    attack_signature: str
    description: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackVerificationReport(BaseModel):
    """Verification audit confirming if TRUST-CV defensive engines caught the attack (legacy)."""
    attack_id: str
    attack_type: AttackType
    detected_by_engine: bool
    detecting_subsystem: str
    assigned_verdict: AssetStatus
    confidence: float = Field(..., ge=0.0, le=1.0)
    details: Dict[str, Any] = Field(default_factory=dict)
