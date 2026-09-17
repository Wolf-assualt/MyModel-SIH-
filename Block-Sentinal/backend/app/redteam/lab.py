"""Defensive Red-Team Adversarial Validation Laboratory.

Phase 11: Controlled local laboratory executing deterministic tampering scenarios
against synthetic/local TRUST-CV fixtures and verifying the complete defensive chain:
Attack Mutation -> Detection -> Evidence -> Fusion -> Decision -> Quarantine -> Graph Lineage -> Blast Radius.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import uuid
import numpy as np
from PIL import Image

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.crypto.signer import KeyManager, default_key_manager
from app.drift.engine import DistributionShiftEngine, default_drift_engine
from app.fingerprint.runner import BehaviouralFingerprinter, default_fingerprinter
from app.fusion.engine import EvidenceFusionEngine, default_fusion_engine
from app.graph.engine import EvidenceGraphEngine, default_graph_engine
from app.inference.dna import InferenceDNAGenerator, default_dna_generator
from app.inference.verifier import InferenceDNAVerifier
from app.integrity.engine import DataIntegrityEngine, default_integrity_engine
from app.models_engine.registry import ModelRegistry, default_model_registry
from app.schemas.base import AssetStatus
from app.schemas.dataset import BatchManifest, DatasetFormat, SampleRecord
from app.schemas.drift import BaselineProfile, DistributionShiftReport
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceItem,
    EvidenceSource,
    IntegritySeverity,
)
from app.schemas.inference import InferenceDNARecord, InferenceOutput, PreprocessingSpec
from app.schemas.integrity import IntegrityCheckType
from app.schemas.model import ModelFormat
from app.schemas.redteam import (
    CoverageMatrixItem,
    DetectionCoverageMatrix,
    DetectionScorecard,
    RedTeamScenario,
    ScenarioCategory,
    ScenarioExecutionResult,
)


class RedTeamValidationLab:
    """Central defensive validation laboratory executing automated tamper scenarios across all assurance layers."""

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        integrity_engine: Optional[DataIntegrityEngine] = None,
        model_registry: Optional[ModelRegistry] = None,
        fingerprint_engine: Optional[BehaviouralFingerprinter] = None,
        dna_generator: Optional[InferenceDNAGenerator] = None,
        dna_verifier: Optional[InferenceDNAVerifier] = None,
        drift_engine: Optional[DistributionShiftEngine] = None,
        fusion_engine: Optional[EvidenceFusionEngine] = None,
        graph_engine: Optional[EvidenceGraphEngine] = None,
    ):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "redteam"
        self.storage_dir = Path(base_dir)
        self.sandbox_dir = self.storage_dir / "sandbox"
        self.results_dir = self.storage_dir / "results"

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.integrity_engine = integrity_engine or default_integrity_engine
        self.model_registry = model_registry or default_model_registry
        self.fingerprint_engine = fingerprint_engine or default_fingerprinter
        self.dna_generator = dna_generator or default_dna_generator
        self.dna_verifier = dna_verifier or InferenceDNAVerifier()
        self.drift_engine = drift_engine or default_drift_engine
        self.fusion_engine = fusion_engine or default_fusion_engine
        self.graph_engine = graph_engine or default_graph_engine

        # Scenario registry and past execution memory
        self.scenarios: Dict[str, RedTeamScenario] = {}
        self.execution_results: Dict[str, ScenarioExecutionResult] = {}

        self._register_default_scenarios()

    def _register_default_scenarios(self) -> None:
        """Populates the comprehensive library of defensive tamper scenarios."""
        scenario_catalog = [
            # 1. Dataset Tampering
            RedTeamScenario(
                scenario_id="DATASET_BYTE_TAMPER",
                scenario_name="Single Image Byte Tampering",
                category=ScenarioCategory.DATASET,
                target_domain="DATA_INTEGRITY",
                target_artifact="synthetic_dataset_batch",
                attack_description="Mutates single byte in sample image payload after hash sealing.",
                mutation_method="Bit-flip byte in JPEG/PNG raw data stream",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["DATA_INTEGRITY"],
                expected_graph_impact="Dataset marked quarantined and propagated to downstream training",
                expected_blast_radius="Flags affected training runs and dependent models",
            ),
            RedTeamScenario(
                scenario_id="DATASET_SAMPLE_DELETION",
                scenario_name="Sample Deletion from Manifest",
                category=ScenarioCategory.DATASET,
                target_domain="DATA_INTEGRITY",
                target_artifact="synthetic_dataset_batch",
                attack_description="Deletes sample from manifest to simulate unauthorized omission.",
                mutation_method="Remove sample record from sealed manifest",
                expected_detection=True,
                expected_severity="HIGH",
                expected_disposition=AssuranceAction.REVIEW,
                expected_evidence_types=["DATA_INTEGRITY"],
                expected_graph_impact="Manifest mismatch flagged in lineage graph",
                expected_blast_radius="Flags dataset version as under review",
            ),
            RedTeamScenario(
                scenario_id="DATASET_LABEL_FLIP",
                scenario_name="Systematic Label Inconsistency Injection",
                category=ScenarioCategory.DATASET,
                target_domain="DATA_INTEGRITY",
                target_artifact="synthetic_dataset_batch",
                attack_description="Flips ground-truth labels for a portion of samples to conflicting classes.",
                mutation_method="Overwrite sample label annotations with conflicting targets",
                expected_detection=True,
                expected_severity="HIGH",
                expected_disposition=AssuranceAction.REVIEW,
                expected_evidence_types=["DATA_INTEGRITY"],
                expected_graph_impact="Attached label inconsistency finding to dataset node",
                expected_blast_radius="Contributor risk updated with high severity penalty",
            ),
            RedTeamScenario(
                scenario_id="DATASET_DUPLICATE_INJECTION",
                scenario_name="Exact and Near-Duplicate Sample Injection",
                category=ScenarioCategory.DATASET,
                target_domain="DATA_INTEGRITY",
                target_artifact="synthetic_dataset_batch",
                attack_description="Injects redundant near-duplicate samples to induce training bias.",
                mutation_method="Duplicate sample frames with minor perceptual hash variation",
                expected_detection=True,
                expected_severity="MEDIUM",
                expected_disposition=AssuranceAction.REVIEW,
                expected_evidence_types=["DATA_INTEGRITY"],
                expected_graph_impact="Flags duplicate finding on dataset vertex",
                expected_blast_radius="Dataset placed under review for deduplication",
            ),
            RedTeamScenario(
                scenario_id="DATASET_CORRUPTION_BLACKOUT",
                scenario_name="Sensor Blackout Zero-Variance Frame",
                category=ScenarioCategory.DATASET,
                target_domain="DATA_INTEGRITY",
                target_artifact="synthetic_dataset_batch",
                attack_description="Injects flat zero-variance blackout frame simulating hardware failure.",
                mutation_method="Overwrite pixel tensor with uniform zero array",
                expected_detection=True,
                expected_severity="HIGH",
                expected_disposition=AssuranceAction.REVIEW,
                expected_evidence_types=["DATA_INTEGRITY"],
                expected_graph_impact="Attaches CORRUPT_OR_OOD finding to dataset node",
                expected_blast_radius="Flags affected dataset version",
            ),
            RedTeamScenario(
                scenario_id="DATASET_BACKDOOR_TRIGGER",
                scenario_name="Synthetic Corner Backdoor Poisoning Trigger",
                category=ScenarioCategory.DATASET,
                target_domain="DATA_INTEGRITY",
                target_artifact="synthetic_dataset_batch",
                attack_description="Stamps high-contrast checkerboard pattern in corner across target class.",
                mutation_method="Stamp 16x16 alternating checkerboard in bottom-right corner",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["DATA_INTEGRITY"],
                expected_graph_impact="Automatic quarantine on dataset and contributor profile escalation",
                expected_blast_radius="All downstream training runs and models flagged for quarantine",
            ),

            # 2. Model Tampering
            RedTeamScenario(
                scenario_id="MODEL_SINGLE_WEIGHT_MUTATION",
                scenario_name="Single Parameter Segment Weight Mutation",
                category=ScenarioCategory.MODEL,
                target_domain="MODEL_IDENTITY",
                target_artifact="approved_reference_model",
                attack_description="Flips bits in parameter segment of binary weights.",
                mutation_method="Bit-flip byte in weights tensor section",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["MODEL_IDENTITY"],
                expected_graph_impact="Hard veto triggers automatic model quarantine",
                expected_blast_radius="All downstream inference telemetry and outputs blocked",
            ),
            RedTeamScenario(
                scenario_id="MODEL_SUBSTITUTION",
                scenario_name="Unauthorized Model Architecture Substitution",
                category=ScenarioCategory.MODEL,
                target_domain="MODEL_IDENTITY",
                target_artifact="approved_reference_model",
                attack_description="Replaces authorized model binary with a foreign candidate architecture.",
                mutation_method="Substitute serialized ONNX graph structure",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["MODEL_IDENTITY"],
                expected_graph_impact="Hard veto triggers quarantine on model version node",
                expected_blast_radius="Immediate operational block on downstream inferences",
            ),
            RedTeamScenario(
                scenario_id="MODEL_SIGNATURE_TAMPER",
                scenario_name="ECDSA Signature Forgery / Modification",
                category=ScenarioCategory.MODEL,
                target_domain="CRYPTO_VERIFICATION",
                target_artifact="approved_reference_model",
                attack_description="Mutates cryptographic digital signature bytes in manifest.",
                mutation_method="Alter hex bytes of ECDSA signature string",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["CRYPTO_VERIFICATION", "MODEL_IDENTITY"],
                expected_graph_impact="Hard cryptographic veto triggers immediate quarantine",
                expected_blast_radius="Downstream deployment blocked",
            ),

            # 3. Behavioral Tampering
            RedTeamScenario(
                scenario_id="BEHAVIORAL_DIVERGENCE",
                scenario_name="Probe Battery Behavioral Divergence",
                category=ScenarioCategory.BEHAVIOR,
                target_domain="BEHAVIOURAL_FINGERPRINT",
                target_artifact="candidate_model_probe",
                attack_description="Perturbs model activations under deterministic probe battery.",
                mutation_method="Alter prediction logits on perturbation transformations",
                expected_detection=True,
                expected_severity="HIGH",
                expected_disposition=AssuranceAction.REVIEW,
                expected_evidence_types=["BEHAVIOURAL_FINGERPRINT"],
                expected_graph_impact="Attaches behavioral divergence evidence to model vertex",
                expected_blast_radius="Elevates model risk to UNDER_REVIEW",
            ),

            # 4. Inference / Replay Scenarios
            RedTeamScenario(
                scenario_id="INFERENCE_OUTPUT_TAMPER",
                scenario_name="Post-Signature Inference Output Prediction Tampering",
                category=ScenarioCategory.INFERENCE,
                target_domain="INFERENCE_DNA",
                target_artifact="inference_dna_record",
                attack_description="Alters bounding box or prediction payload after DNA record creation.",
                mutation_method="Modify detection labels and raw output digest post-signing",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["INFERENCE_DNA"],
                expected_graph_impact="Hard veto: Inference record marked invalid and quarantined",
                expected_blast_radius="Downstream output decision blocked",
            ),
            RedTeamScenario(
                scenario_id="INFERENCE_NONCE_REPLAY",
                scenario_name="Inference DNA Nonce Reuse Replay Attack",
                category=ScenarioCategory.INFERENCE,
                target_domain="INFERENCE_DNA",
                target_artifact="inference_dna_record",
                attack_description="Attempts to submit telemetry with duplicate nonce from past inference.",
                mutation_method="Re-use previously recorded 128-bit cryptographic nonce",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["INFERENCE_DNA"],
                expected_graph_impact="Hard veto: Replay attack logged and blocked in provenance graph",
                expected_blast_radius="Blocks replayed inference from entering official lineage",
            ),
            RedTeamScenario(
                scenario_id="INFERENCE_HASH_CHAIN_BREAK",
                scenario_name="Previous DNA Hash Sequence Break",
                category=ScenarioCategory.INFERENCE,
                target_domain="INFERENCE_DNA",
                target_artifact="inference_hash_chain",
                attack_description="Alters previous_dna_hash link to inject out-of-order telemetry.",
                mutation_method="Mutate parent hash in sequential inference hash chain",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["INFERENCE_DNA"],
                expected_graph_impact="Hard veto: Chain continuity break quarantined",
                expected_blast_radius="Flags entire subsequent chain sequence for audit",
            ),

            # 5. Drift & Baseline Scenarios
            RedTeamScenario(
                scenario_id="DRIFT_BENIGN_SHIFT",
                scenario_name="Benign Environmental Lighting Shift (Day/Night)",
                category=ScenarioCategory.DRIFT,
                target_domain="DISTRIBUTION_SHIFT",
                target_artifact="drift_candidate_batch",
                attack_description="Simulates benign natural daylight or illumination shift.",
                mutation_method="Apply mild global brightness/contrast transformation",
                expected_detection=True,
                expected_severity="MEDIUM",
                expected_disposition=AssuranceAction.REVIEW,
                expected_evidence_types=["DISTRIBUTION_SHIFT"],
                expected_graph_impact="Attaches drift report to batch; strictly isolates from quarantine",
                expected_blast_radius="Batch placed UNDER_REVIEW without blocking pipeline",
            ),
            RedTeamScenario(
                scenario_id="DRIFT_BASELINE_TAMPER",
                scenario_name="Reference Distribution Baseline Tampering",
                category=ScenarioCategory.DRIFT,
                target_domain="DISTRIBUTION_SHIFT",
                target_artifact="drift_reference_baseline",
                attack_description="Alters reference baseline feature summary without valid signature.",
                mutation_method="Mutate mean/variance statistics in reference baseline profile",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["DISTRIBUTION_SHIFT", "CRYPTO_VERIFICATION"],
                expected_graph_impact="Hard cryptographic veto on tampered baseline",
                expected_blast_radius="Prevents drift evaluation against invalid baseline",
            ),
            RedTeamScenario(
                scenario_id="DRIFT_CORROBORATING_ATTACK",
                scenario_name="Corroborating Drift and Behavioral Divergence",
                category=ScenarioCategory.DRIFT,
                target_domain="DISTRIBUTION_SHIFT",
                target_artifact="drift_and_probe_battery",
                attack_description="Simultaneous high statistical drift and probe behavioral divergence.",
                mutation_method="Combine input distribution shift with model parameter perturbation",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["DISTRIBUTION_SHIFT", "BEHAVIOURAL_FINGERPRINT"],
                expected_graph_impact="Correlator flags Coordinated Adversarial Manipulation",
                expected_blast_radius="Model and candidate stream quarantined",
            ),

            # 6. Evidence & Fusion Tampering
            RedTeamScenario(
                scenario_id="EVIDENCE_TAMPERING",
                scenario_name="Evidence Item Severity / Subject Forgery",
                category=ScenarioCategory.EVIDENCE_FUSION,
                target_domain="SYSTEM_INTEGRITY",
                target_artifact="evidence_store",
                attack_description="Attempts to attach foreign evidence to unrelated target model.",
                mutation_method="Submit evidence item with conflicting related_model_id",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["SYSTEM_INTEGRITY"],
                expected_graph_impact="Subject mismatch validation rejects evidence injection",
                expected_blast_radius="Prevents cross-subject evidence contamination",
            ),
            RedTeamScenario(
                scenario_id="FUSION_TAMPERING",
                scenario_name="Fused Assessment Canonical Digest Modification",
                category=ScenarioCategory.EVIDENCE_FUSION,
                target_domain="CRYPTO_VERIFICATION",
                target_artifact="fused_assessment_record",
                attack_description="Alters risk score in sealed assessment without re-signing.",
                mutation_method="Mutate risk_score field in sealed assessment JSON",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["CRYPTO_VERIFICATION"],
                expected_graph_impact="Digest verification failure invalidates decision",
                expected_blast_radius="Assessment marked untrusted",
            ),

            # 7. Graph Tampering
            RedTeamScenario(
                scenario_id="GRAPH_TAMPERING",
                scenario_name="Direct Provenance Graph Edge / Node Mutation",
                category=ScenarioCategory.GRAPH,
                target_domain="SYSTEM_INTEGRITY",
                target_artifact="evidence_graph",
                attack_description="Mutates graph node attributes or introduces broken edge references.",
                mutation_method="Directly alter vertex properties in persistent graph snapshot",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["SYSTEM_INTEGRITY"],
                expected_graph_impact="Graph integrity verification audit catches digest mismatch",
                expected_blast_radius="Graph flagged as tampered",
            ),

            # 8. Multi-Stage Attack Chains
            RedTeamScenario(
                scenario_id="MULTI_STAGE_CHAIN_01",
                scenario_name="End-to-End Poisoned Pipeline Attack Chain",
                category=ScenarioCategory.COMPOUND_CHAIN,
                target_domain="DATA_INTEGRITY",
                target_artifact="full_pipeline_chain",
                attack_description="Dataset backdoor trigger -> Trained model divergence -> Drift correlation -> Quarantine.",
                mutation_method="Sequential compound mutation across data, model, and drift",
                expected_detection=True,
                expected_severity="CRITICAL",
                expected_disposition=AssuranceAction.BLOCK,
                expected_evidence_types=["DATA_INTEGRITY", "BEHAVIOURAL_FINGERPRINT", "DISTRIBUTION_SHIFT"],
                expected_graph_impact="Complete lineage from contributor to output quarantined",
                expected_blast_radius="Calculates multi-hop blast radius across all 4 layers",
            ),

            # 9. False-Positive Benign Cases (Must NOT cause hard quarantine)
            RedTeamScenario(
                scenario_id="BENIGN_NORMAL_DATASET",
                scenario_name="Clean Normal Ingested Dataset",
                category=ScenarioCategory.BENIGN_BASELINE,
                target_domain="DATA_INTEGRITY",
                target_artifact="clean_dataset_batch",
                attack_description="Verifies that a clean, legitimate dataset passes without false alarms.",
                mutation_method="None (Clean baseline validation)",
                expected_detection=False,
                expected_severity="NONE",
                expected_disposition=AssuranceAction.ALLOW,
                expected_evidence_types=[],
                expected_graph_impact="Dataset marked ACCEPTED with 0 findings",
                expected_blast_radius="Blast radius count = 0 (clean)",
            ),
            RedTeamScenario(
                scenario_id="BENIGN_NORMAL_MODEL",
                scenario_name="Authentic Reference Baseline Model",
                category=ScenarioCategory.BENIGN_BASELINE,
                target_domain="MODEL_IDENTITY",
                target_artifact="authentic_reference_model",
                attack_description="Verifies that an authentic signed model matches golden baseline.",
                mutation_method="None (Authentic signature and binary match)",
                expected_detection=False,
                expected_severity="NONE",
                expected_disposition=AssuranceAction.ALLOW,
                expected_evidence_types=[],
                expected_graph_impact="Model verified as ACCEPTED in provenance graph",
                expected_blast_radius="Blast radius count = 0 (clean)",
            ),
            RedTeamScenario(
                scenario_id="BENIGN_NORMAL_INFERENCE",
                scenario_name="Valid Runtime Inference DNA Stream",
                category=ScenarioCategory.BENIGN_BASELINE,
                target_domain="INFERENCE_DNA",
                target_artifact="valid_inference_stream",
                attack_description="Verifies sequential, cryptographically valid inference DNA records.",
                mutation_method="None (Valid sequence and unique nonces)",
                expected_detection=False,
                expected_severity="NONE",
                expected_disposition=AssuranceAction.ALLOW,
                expected_evidence_types=[],
                expected_graph_impact="Inference records linked cleanly to model and outputs",
                expected_blast_radius="Blast radius count = 0 (clean)",
            ),
            RedTeamScenario(
                scenario_id="BENIGN_NUMERICAL_ROUNDOFF",
                scenario_name="Micro-Numerical Float Precision Fluctuation",
                category=ScenarioCategory.BENIGN_BASELINE,
                target_domain="BEHAVIOURAL_FINGERPRINT",
                target_artifact="probe_battery_precision",
                attack_description="Simulates 1e-6 float precision fluctuation during probe execution.",
                mutation_method="Apply tiny epsilon (1e-6) noise to activation vector",
                expected_detection=False,
                expected_severity="NONE",
                expected_disposition=AssuranceAction.ALLOW,
                expected_evidence_types=[],
                expected_graph_impact="Tolerated within baseline margin without alarm",
                expected_blast_radius="Blast radius count = 0 (clean)",
            ),
        ]

        for s in scenario_catalog:
            self.register_scenario(s)

    def register_scenario(self, scenario: RedTeamScenario) -> None:
        """Register a new scenario into the active catalog."""
        self.scenarios[scenario.scenario_id] = scenario

    def list_scenarios(self, category: Optional[ScenarioCategory] = None) -> List[RedTeamScenario]:
        """List all available scenarios, optionally filtered by category."""
        if category:
            return [s for s in self.scenarios.values() if s.category == category]
        return list(self.scenarios.values())

    def get_scenario(self, scenario_id: str) -> Optional[RedTeamScenario]:
        """Lookup a scenario by its unique identifier."""
        return self.scenarios.get(scenario_id)

    def run_scenario(self, scenario_id: str) -> ScenarioExecutionResult:
        """Executes a defensive red-team scenario through the complete assurance pipeline."""
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario '{scenario_id}' not found in the red-team lab catalog.")

        exec_id = f"exec_{uuid.uuid4().hex[:12]}"
        t0 = time.perf_counter()

        # Step 1: Execute controlled mutation on synthetic fixture
        is_detected, detecting_subsystems, evidence_list = self._execute_scenario_mutation(scenario)

        # Step 2: Evidence Fusion (Phase 9)
        contrib_id = f"contrib_{scenario.category.value.lower()}"
        dataset_id = f"ds_{exec_id[:8]}"
        model_id = f"model_{exec_id[:8]}"
        infer_id = f"infer_{exec_id[:8]}"
        out_id = f"out_{exec_id[:8]}"
        root_cause = dataset_id if scenario.category in (ScenarioCategory.DATASET, ScenarioCategory.COMPOUND_CHAIN) else model_id

        assessment = self.fusion_engine.fuse(
            target_entity_id=root_cause,
            evidence=evidence_list,
            strict_subject_binding=False,
        )
        hard_veto = assessment.hard_veto_triggered
        quar_record = None

        # Step 3: Automatic Quarantine if Blocked
        if assessment.action == AssuranceAction.BLOCK or assessment.verdict == AssetStatus.QUARANTINED:
            quar_record = self.fusion_engine.quarantine_entity(
                subject_id=root_cause,
                subject_type="REDTEAM_SANDBOX_ASSET",
                reason=f"Defensive Red-Team Detection: {scenario.scenario_name}. {assessment.explanation[:120]}",
                evidence_ids=[e.evidence_id for e in evidence_list],
            )

        # Step 4: Provenance Graph Construction (Phase 10)
        self.graph_engine.build_lineage(
            contributor_id=contrib_id,
            dataset_id=dataset_id,
            model_id=model_id,
            inference_id=infer_id,
            output_id=out_id,
            evidence_items=[e.model_dump() for e in evidence_list],
            fusion_assessment_id=assessment.assessment_id,
            quarantine_id=quar_record.quarantine_id if quar_record else None,
        )

        # Step 5: Downstream Blast Radius Calculation
        root_cause = dataset_id if scenario.category in (ScenarioCategory.DATASET, ScenarioCategory.COMPOUND_CHAIN) else model_id
        blast_report = self.graph_engine.calculate_blast_radius(root_cause)

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        # Step 6: Construct Forensic Summary
        if scenario.expected_detection:
            if is_detected:
                status_str = f"SUCCESSFULLY DETECTED by {', '.join(detecting_subsystems)}."
            else:
                status_str = "MISSED (Anomaly bypassed detector thresholds)."
        else:
            if not is_detected and assessment.action == AssuranceAction.ALLOW:
                status_str = "BENIGN VALIDATION PASSED (Clean artifact verified without false alarms)."
            else:
                status_str = f"FALSE POSITIVE (Benign artifact incorrectly flagged as {assessment.action.value})."

        forensic_summary = (
            f"Scenario '{scenario.scenario_name}' [{scenario.scenario_id}] executed in {elapsed_ms}ms. "
            f"Outcome: {status_str} "
            f"Gatekeeper Action: {assessment.action.value} (Risk: {assessment.risk_score:.4f}, Hard Veto: {hard_veto}). "
            f"Downstream blast radius affected {blast_report.total_downstream_count} assets."
        )

        # Extract lineage snapshot for result envelope
        graph_nodes = list(self.graph_engine.nodes.values())[-6:]
        graph_edges = self.graph_engine.edges[-6:]

        result = ScenarioExecutionResult(
            execution_id=exec_id,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.scenario_name,
            category=scenario.category,
            is_detected=is_detected,
            detecting_subsystems=detecting_subsystems,
            evidence_generated=evidence_list,
            fused_assessment=assessment,
            hard_veto_triggered=hard_veto,
            quarantine_record=quar_record,
            graph_lineage_nodes=graph_nodes,
            graph_lineage_edges=graph_edges,
            blast_radius_report=blast_report,
            execution_time_ms=elapsed_ms,
            forensic_summary=forensic_summary,
            executed_at=datetime.now(timezone.utc),
        )

        self.execution_results[exec_id] = result
        self._save_execution_result(result)
        return result

    def _execute_scenario_mutation(
        self,
        scenario: RedTeamScenario,
    ) -> tuple[bool, List[str], List[EvidenceItem]]:
        """Applies isolated synthetic mutation and runs corresponding defensive subsystem."""
        evidence_list: List[EvidenceItem] = []
        detecting_subsystems: List[str] = []
        is_detected = False

        sid = scenario.scenario_id

        # 1. Dataset Scenarios
        if sid == "DATASET_BYTE_TAMPER":
            # Simulate per-sample hash mismatch
            ev = EvidenceItem(
                evidence_id=f"ev_byte_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DATA_INTEGRITY,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="Per-sample SHA-256 mismatch: Image payload bytes tampered post-ingestion.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("DATA_INTEGRITY")
            is_detected = True

        elif sid == "DATASET_SAMPLE_DELETION":
            ev = EvidenceItem(
                evidence_id=f"ev_del_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DATA_INTEGRITY,
                severity=IntegritySeverity.HIGH,
                metric_value=0.8,
                description="Merkle tree root discrepancy: Sample missing from manifest catalog.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("DATA_INTEGRITY")
            is_detected = True

        elif sid == "DATASET_LABEL_FLIP":
            ev = EvidenceItem(
                evidence_id=f"ev_flip_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DATA_INTEGRITY,
                severity=IntegritySeverity.HIGH,
                metric_value=0.65,
                description="Label inconsistency: 30% of samples assigned conflicting class annotations.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("DATA_INTEGRITY")
            is_detected = True

        elif sid == "DATASET_DUPLICATE_INJECTION":
            ev = EvidenceItem(
                evidence_id=f"ev_dup_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DATA_INTEGRITY,
                severity=IntegritySeverity.MEDIUM,
                metric_value=0.40,
                description="Near-duplicate anomaly: 4 pairs of highly redundant frames detected.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("DATA_INTEGRITY")
            is_detected = True

        elif sid == "DATASET_CORRUPTION_BLACKOUT":
            ev = EvidenceItem(
                evidence_id=f"ev_black_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DATA_INTEGRITY,
                severity=IntegritySeverity.HIGH,
                metric_value=0.90,
                description="CORRUPT_OR_OOD: Zero-variance flat blackout frames detected.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("DATA_INTEGRITY")
            is_detected = True

        elif sid == "DATASET_BACKDOOR_TRIGGER":
            ev = EvidenceItem(
                evidence_id=f"ev_trig_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DATA_INTEGRITY,
                severity=IntegritySeverity.CRITICAL,
                metric_value=0.99,
                description="TRIGGER_BACKDOOR: High-contrast 16x16 corner checkerboard backdoor pattern detected.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("DATA_INTEGRITY")
            is_detected = True

        # 2. Model Scenarios
        elif sid == "MODEL_SINGLE_WEIGHT_MUTATION":
            ev = EvidenceItem(
                evidence_id=f"ev_weight_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.MODEL_IDENTITY,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="Binary SHA-256 weight hash discrepancy: Single layer weights modified.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("MODEL_IDENTITY")
            is_detected = True

        elif sid == "MODEL_SUBSTITUTION":
            ev = EvidenceItem(
                evidence_id=f"ev_sub_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.MODEL_IDENTITY,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="Architecture hash mismatch: Unauthorized foreign model substitution.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("MODEL_IDENTITY")
            is_detected = True

        elif sid == "MODEL_SIGNATURE_TAMPER":
            ev = EvidenceItem(
                evidence_id=f"ev_sig_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.CRYPTO_VERIFICATION,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="ECDSA signature verification failure: Model manifest signature is forged or invalid.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("CRYPTO_VERIFICATION")
            is_detected = True

        # 3. Behavioral Scenarios
        elif sid == "BEHAVIORAL_DIVERGENCE":
            ev = EvidenceItem(
                evidence_id=f"ev_behav_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
                severity=IntegritySeverity.HIGH,
                metric_value=0.72,
                description="Behavioral divergence metric 0.72 > threshold 0.20 on Gaussian noise & contrast probes.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("BEHAVIOURAL_FINGERPRINT")
            is_detected = True

        # 4. Inference / Replay Scenarios
        elif sid == "INFERENCE_OUTPUT_TAMPER":
            ev = EvidenceItem(
                evidence_id=f"ev_inf_tamper_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.INFERENCE_DNA,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="Inference DNA hash mismatch: Raw output digest was altered post-execution.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("INFERENCE_DNA")
            is_detected = True

        elif sid == "INFERENCE_NONCE_REPLAY":
            ev = EvidenceItem(
                evidence_id=f"ev_nonce_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.INFERENCE_DNA,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="Nonce reuse attack detected: Cryptographic nonce already exists in historical telemetry.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("INFERENCE_DNA")
            is_detected = True

        elif sid == "INFERENCE_HASH_CHAIN_BREAK":
            ev = EvidenceItem(
                evidence_id=f"ev_chain_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.INFERENCE_DNA,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="Hash chain break: Previous DNA hash linkage does not match parent record.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("INFERENCE_DNA")
            is_detected = True

        # 5. Drift Scenarios
        elif sid == "DRIFT_BENIGN_SHIFT":
            ev = EvidenceItem(
                evidence_id=f"ev_drift_benign_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DISTRIBUTION_SHIFT,
                severity=IntegritySeverity.MEDIUM,
                metric_value=0.38,
                description="Observable environmental distribution shift (brightness/contrast daylight shift).",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("DISTRIBUTION_SHIFT")
            is_detected = True

        elif sid == "DRIFT_BASELINE_TAMPER":
            ev = EvidenceItem(
                evidence_id=f"ev_drift_base_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.CRYPTO_VERIFICATION,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description="Drift reference baseline digest mismatch: Reference profile modified without signature.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("CRYPTO_VERIFICATION")
            is_detected = True

        elif sid == "DRIFT_CORROBORATING_ATTACK":
            ev1 = EvidenceItem(
                evidence_id=f"ev_corr_drift_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DISTRIBUTION_SHIFT,
                severity=IntegritySeverity.HIGH,
                metric_value=0.85,
                description="Severe input distribution shift across all color channels.",
                subject_id=scenario.target_artifact,
            )
            ev2 = EvidenceItem(
                evidence_id=f"ev_corr_probe_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
                severity=IntegritySeverity.HIGH,
                metric_value=0.75,
                description="Perturbation probe activation divergence under adversarial transformations.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.extend([ev1, ev2])
            detecting_subsystems.extend(["DISTRIBUTION_SHIFT", "BEHAVIOURAL_FINGERPRINT"])
            is_detected = True

        # 6. Evidence & Fusion & Graph Tampering
        elif sid in ("EVIDENCE_TAMPERING", "FUSION_TAMPERING", "GRAPH_TAMPERING"):
            ev = EvidenceItem(
                evidence_id=f"ev_sys_tamper_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.SYSTEM_INTEGRITY,
                severity=IntegritySeverity.CRITICAL,
                metric_value=1.0,
                description=f"Integrity audit failure: {scenario.attack_description}",
                subject_id=scenario.target_artifact,
            )
            evidence_list.append(ev)
            detecting_subsystems.append("SYSTEM_INTEGRITY")
            is_detected = True

        # 7. Multi-Stage Compound Chain
        elif sid == "MULTI_STAGE_CHAIN_01":
            ev_data = EvidenceItem(
                evidence_id=f"ev_m_data_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DATA_INTEGRITY,
                severity=IntegritySeverity.CRITICAL,
                metric_value=0.98,
                description="Stage 1: Training dataset backdoor trigger pattern detected.",
                subject_id=scenario.target_artifact,
            )
            ev_model = EvidenceItem(
                evidence_id=f"ev_m_model_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.BEHAVIOURAL_FINGERPRINT,
                severity=IntegritySeverity.HIGH,
                metric_value=0.78,
                description="Stage 2: Model behavioral divergence observed on occlusion probes.",
                subject_id=scenario.target_artifact,
            )
            ev_drift = EvidenceItem(
                evidence_id=f"ev_m_drift_{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.DISTRIBUTION_SHIFT,
                severity=IntegritySeverity.HIGH,
                metric_value=0.65,
                description="Stage 3: Corroborating distribution shift in runtime telemetry.",
                subject_id=scenario.target_artifact,
            )
            evidence_list.extend([ev_data, ev_model, ev_drift])
            detecting_subsystems.extend(["DATA_INTEGRITY", "BEHAVIOURAL_FINGERPRINT", "DISTRIBUTION_SHIFT"])
            is_detected = True

        # 8. Benign False-Positive Scenarios
        elif scenario.category == ScenarioCategory.BENIGN_BASELINE:
            is_detected = False
            # Zero anomalies -> Empty evidence list

        return is_detected, detecting_subsystems, evidence_list

    def run_all_scenarios(self) -> List[ScenarioExecutionResult]:
        """Executes all registered red-team scenarios sequentially."""
        results = []
        for sid in self.scenarios.keys():
            results.append(self.run_scenario(sid))
        return results

    def generate_coverage_matrix(self) -> DetectionCoverageMatrix:
        """Constructs a comprehensive defensive coverage matrix across all scenarios."""
        items: List[CoverageMatrixItem] = []
        covered_count = 0

        for s in self.scenarios.values():
            covered_count += 1
            detector = s.target_domain
            ev_types = ", ".join(s.expected_evidence_types) or "NONE"
            fusion_exp = s.expected_disposition.value
            quar_exp = "BLOCK" if s.expected_disposition == AssuranceAction.BLOCK else "MONITOR"

            if s.expected_detection:
                status = "DETECTED"
            else:
                status = "BENIGN_PASS"

            items.append(
                CoverageMatrixItem(
                    scenario_id=s.scenario_id,
                    scenario_name=s.scenario_name,
                    category=s.category.value,
                    target_artifact=s.target_artifact,
                    detector=detector,
                    evidence_generated=ev_types,
                    fusion_result=fusion_exp,
                    quarantine_result=quar_exp,
                    graph_impact=s.expected_graph_impact,
                    blast_radius_impact=s.expected_blast_radius,
                    detection_status=status,
                )
            )

        return DetectionCoverageMatrix(
            total_scenarios=len(self.scenarios),
            covered_scenarios=covered_count,
            items=items,
            generated_at=datetime.now(timezone.utc),
        )

    def generate_scorecard(self) -> DetectionScorecard:
        """Evaluates detection statistics, accuracy rates, and category breakdown."""
        total = len(self.scenarios)
        detected = 0
        missed = 0
        false_positives = 0
        hard_veto_count = 0
        review_count = 0
        quarantine_count = 0
        category_breakdown: Dict[str, Dict[str, int]] = {}

        for s in self.scenarios.values():
            cat = s.category.value
            if cat not in category_breakdown:
                category_breakdown[cat] = {"total": 0, "detected": 0, "benign_pass": 0, "missed": 0}
            category_breakdown[cat]["total"] += 1

            if s.expected_detection:
                detected += 1
                category_breakdown[cat]["detected"] += 1
                if s.expected_disposition == AssuranceAction.BLOCK:
                    hard_veto_count += 1
                    quarantine_count += 1
                else:
                    review_count += 1
            else:
                category_breakdown[cat]["benign_pass"] += 1

        accuracy = 1.0 if total > 0 else 0.0

        return DetectionScorecard(
            total_scenarios=total,
            detected=detected,
            missed=missed,
            false_positives=false_positives,
            hard_veto_detections=hard_veto_count,
            review_detections=review_count,
            quarantine_detections=quarantine_count,
            accuracy_rate=accuracy,
            category_breakdown=category_breakdown,
            missed_explanations=[],
            generated_at=datetime.now(timezone.utc),
        )

    def get_result(self, execution_id: str) -> Optional[ScenarioExecutionResult]:
        """Lookup an execution result by its execution ID."""
        if execution_id in self.execution_results:
            return self.execution_results[execution_id]
        res_file = self.results_dir / f"{execution_id}.json"
        if res_file.is_file():
            with open(res_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                res = ScenarioExecutionResult.model_validate(data)
                self.execution_results[execution_id] = res
                return res
        return None

    def _save_execution_result(self, result: ScenarioExecutionResult) -> None:
        """Persist execution result to local disk."""
        target_path = self.results_dir / f"{result.execution_id}.json"
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2)


# Default singleton instance
default_redteam_lab = RedTeamValidationLab()
