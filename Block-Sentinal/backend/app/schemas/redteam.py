"""Pydantic schemas for the Red-Team Adversarial Attack Lab."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.base import AssetStatus


class AttackType(str, Enum):
    """Supported red-team adversarial attack vectors."""
    LABEL_FLIPPING = "LABEL_FLIPPING"
    BACKDOOR_TRIGGER = "BACKDOOR_TRIGGER"
    DATASET_CORRUPTION = "DATASET_CORRUPTION"
    MODEL_WEIGHT_TAMPERING = "MODEL_WEIGHT_TAMPERING"
    INFERENCE_TAMPERING = "INFERENCE_TAMPERING"
    INFERENCE_REPLAY = "INFERENCE_REPLAY"


class AttackExecutionRequest(BaseModel):
    """Request payload to simulate an adversarial attack."""
    attack_type: AttackType
    target_entity_id: str = Field(..., description="batch_id, model_id, or inference_record_id")
    intensity: float = Field(default=0.5, ge=0.0, le=1.0, description="Scale of attack (e.g., % of samples poisoned, noise level)")
    target_label: Optional[str] = Field(default="poisoned_class", description="Target label for flipping or backdoor associations")


class AttackExecutionResult(BaseModel):
    """Result of an executed adversarial attack simulation."""
    attack_id: str
    attack_type: AttackType
    target_entity_id: str
    modified_entity_id: str
    samples_modified_count: int = Field(default=0, ge=0)
    attack_signature: str
    description: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackVerificationReport(BaseModel):
    """Verification audit confirming if TRUST-CV defensive engines caught the attack."""
    attack_id: str
    attack_type: AttackType
    detected_by_engine: bool
    detecting_subsystem: str  # "DATA_INTEGRITY", "MODEL_IDENTITY", "BEHAVIOURAL_FINGERPRINT", "INFERENCE_DNA"
    assigned_verdict: AssetStatus  # QUARANTINED, UNDER_REVIEW, ACCEPTED
    confidence: float = Field(..., ge=0.0, le=1.0)
    details: Dict[str, Any] = Field(default_factory=dict)


class ScenarioCategory(str, Enum):
    """Categories of red-team validation scenarios."""
    DATASET = "DATASET"
    MODEL = "MODEL"
    INFERENCE = "INFERENCE"
    BACKDOOR = "BACKDOOR"
    DRIFT = "DRIFT"
    BEHAVIOR = "BEHAVIOR"
    EVIDENCE_FUSION = "EVIDENCE_FUSION"
    GRAPH = "GRAPH"
    COMPOUND_CHAIN = "COMPOUND_CHAIN"
    BENIGN_BASELINE = "BENIGN_BASELINE"
    DATA_POISONING = "DATA_POISONING"
    MODEL_TAMPERING = "MODEL_TAMPERING"
    INFERENCE_ATTACK = "INFERENCE_ATTACK"
    DRIFT_MANIPULATION = "DRIFT_MANIPULATION"


class RedTeamScenario(BaseModel):
    """Definition of a red-team validation scenario."""
    scenario_id: str
    scenario_name: str
    category: ScenarioCategory
    target_domain: str
    target_artifact: str
    attack_description: str
    mutation_method: str
    expected_detection: bool
    expected_severity: str = "HIGH"
    expected_disposition: Any = "BLOCK"
    expected_evidence_types: List[str] = Field(default_factory=list)
    expected_graph_impact: str = ""
    expected_blast_radius: str = ""


class ScenarioExecutionResult(BaseModel):
    """Result of executing a red-team scenario."""
    execution_id: str = ""
    scenario_id: str
    scenario_name: str = ""
    category: Optional[Any] = None
    attack_id: str = ""
    is_detected: bool = False
    execution_success: bool = True
    detected: bool = False
    detecting_subsystems: List[str] = Field(default_factory=list)
    evidence_generated: List[Any] = Field(default_factory=list)
    fused_assessment: Optional[Any] = None
    hard_veto_triggered: bool = False
    quarantine_record: Optional[Any] = None
    graph_lineage_nodes: List[Any] = Field(default_factory=list)
    graph_lineage_edges: List[Any] = Field(default_factory=list)
    blast_radius_report: Optional[Any] = None
    execution_time_ms: float = 0.0
    execution_time_seconds: float = 0.0
    forensic_summary: str = ""
    assigned_verdict: str = "QUARANTINED"
    details: Dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: Any) -> None:
        if self.is_detected and not self.detected:
            self.detected = True
        elif self.detected and not self.is_detected:
            self.is_detected = True


class DetectionScorecard(BaseModel):
    """Scorecard tracking detection coverage across attack types."""
    attack_type: Optional[AttackType] = None
    total_scenarios: int = 0
    detected_count: int = 0
    detected: int = 0
    missed: int = 0
    false_positives: int = 0
    hard_veto_detections: int = 0
    review_detections: int = 0
    quarantine_detections: int = 0
    detection_rate: float = 0.0
    accuracy_rate: float = 1.0
    category_breakdown: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    missed_scenarios: List[str] = Field(default_factory=list)
    missed_explanations: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: Any) -> None:
        if self.detected and not self.detected_count:
            self.detected_count = self.detected
        elif self.detected_count and not self.detected:
            self.detected = self.detected_count


class CoverageMatrixItem(BaseModel):
    """Individual item in the detection coverage matrix."""
    scenario_id: str
    scenario_name: str = ""
    category: str = ""
    target_artifact: str = ""
    detector: str = ""
    evidence_generated: str = ""
    fusion_result: str = ""
    quarantine_result: str = ""
    graph_impact: str = ""
    blast_radius_impact: str = ""
    detection_status: str = ""
    attack_type: Optional[AttackType] = None
    detected: bool = True
    detecting_subsystem: Optional[str] = None
    confidence: float = 1.0


class DetectionCoverageMatrix(BaseModel):
    """Matrix showing detection coverage across all attack types and scenarios."""
    total_scenarios: int = 0
    covered_scenarios: int = 0
    matrix: List[CoverageMatrixItem] = Field(default_factory=list)
    items: List[CoverageMatrixItem] = Field(default_factory=list)
    overall_detection_rate: float = 1.0
    scorecards: List[DetectionScorecard] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: Any) -> None:
        if self.items and not self.matrix:
            self.matrix = self.items
        elif self.matrix and not self.items:
            self.items = self.matrix
        if not self.total_scenarios and self.items:
            self.total_scenarios = len(self.items)
            self.covered_scenarios = len(self.items)
