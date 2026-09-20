"""Dynamic Contributor Risk Scorecard Engine and Provenance Profiling."""
from datetime import datetime, timezone
import math
from typing import Dict, List, Optional, Set

from app.graph.engine import EvidenceGraphEngine, default_graph_engine
from app.schemas.base import AssetStatus
from app.schemas.graph import ContributorRiskProfile, EdgeType, NodeType

SEVERITY_PENALTIES: Dict[str, float] = {
    "CRITICAL": 0.35,
    "HIGH": 0.20,
    "MEDIUM": 0.08,
    "LOW": 0.02,
}


class ContributorRiskEngine:
    """Evaluates historical assurance evidence to calculate explainable contributor trust scores."""

    @classmethod
    def get_profile(
        cls,
        contributor_id: str,
        name: Optional[str] = None,
        graph: Optional[EvidenceGraphEngine] = None,
    ) -> ContributorRiskProfile:
        """Compute holistic risk profile for a contributor based on real graph provenance."""
        engine = graph or default_graph_engine

        # Rule 8: Contributor Aggregation - Real contributor identities only, unknown remains UNKNOWN
        clean_contrib = str(contributor_id).strip()
        if not clean_contrib or clean_contrib.lower() in ("unknown", "anonymous", "none", "null"):
            clean_contrib = "UNKNOWN"
            display_name = "Unknown Contributor"
        else:
            display_name = name or clean_contrib

        # 1. Identify all datasets authored or provided by this contributor
        authored_dataset_ids: Set[str] = set()
        for edge in engine._in_edges.get(clean_contrib, []):
            if edge.edge_type in (EdgeType.AUTHORED_BY, EdgeType.PROVIDED):
                authored_dataset_ids.add(edge.source_id)

        for edge in engine._out_edges.get(clean_contrib, []):
            if edge.edge_type == EdgeType.PROVIDED:
                authored_dataset_ids.add(edge.target_id)

        for node in engine.nodes.values():
            if node.node_type in (NodeType.DATASET, NodeType.DATASET_BATCH):
                if node.properties.get("contributor_id") == clean_contrib:
                    authored_dataset_ids.add(node.id)

        total_datasets = len(authored_dataset_ids)

        # 2. Count total samples associated with these datasets
        total_samples = 0
        sample_ids: Set[str] = set()
        for d_id in authored_dataset_ids:
            d_node = engine.nodes.get(d_id)
            if d_node:
                prop_samples = d_node.properties.get("sample_count", 0)
                edge_samples = sum(
                    1 for e in engine._out_edges.get(d_id, [])
                    if e.edge_type == EdgeType.CONTAINS_SAMPLE
                )
                total_samples += max(prop_samples, edge_samples)

            for e in engine._out_edges.get(d_id, []):
                if e.edge_type == EdgeType.CONTAINS_SAMPLE:
                    sample_ids.add(e.target_id)

        # 3. Identify models trained on these datasets (directly or via training runs)
        model_ids: Set[str] = set()
        training_run_ids: Set[str] = set()
        for d_id in authored_dataset_ids:
            for n in engine.trace_downstream(d_id):
                if n.node_type in (NodeType.MODEL, NodeType.MODEL_VERSION):
                    model_ids.add(n.id)
                elif n.node_type == NodeType.TRAINING_RUN:
                    training_run_ids.add(n.id)

            for edge in engine._in_edges.get(d_id, []):
                if edge.edge_type == EdgeType.TRAINED_ON:
                    model_ids.add(edge.source_id)

        # 4. Collect all findings and evidence linked to contributor, datasets, samples, or models
        contributor_cluster = {clean_contrib} | authored_dataset_ids | sample_ids | model_ids | training_run_ids
        linked_evidence: List[Dict] = []
        seen_finding_ids: Set[str] = set()

        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        has_active_quarantine = False
        for entity_id in contributor_cluster:
            for e in engine._in_edges.get(entity_id, []):
                if e.edge_type == EdgeType.QUARANTINES:
                    has_active_quarantine = True
            for e in engine._out_edges.get(entity_id, []):
                if e.edge_type == EdgeType.QUARANTINES:
                    has_active_quarantine = True

            for ev_node in engine.get_attached_evidence(entity_id):
                if ev_node.id not in seen_finding_ids:
                    seen_finding_ids.add(ev_node.id)
                    linked_evidence.append(ev_node.properties)
                    sev = str(ev_node.properties.get("severity", "LOW")).upper()
                    if sev in severity_breakdown:
                        severity_breakdown[sev] += 1
                    else:
                        severity_breakdown["LOW"] += 1

            for edge in engine._out_edges.get(entity_id, []):
                if edge.edge_type == EdgeType.FLAGGED_WITH:
                    f_node = engine.nodes.get(edge.target_id)
                    if f_node and f_node.id not in seen_finding_ids:
                        seen_finding_ids.add(f_node.id)
                        linked_evidence.append(f_node.properties)
                        sev = str(f_node.properties.get("severity", "LOW")).upper()
                        if sev in severity_breakdown:
                            severity_breakdown[sev] += 1
                        else:
                            severity_breakdown["LOW"] += 1

            for edge in engine._in_edges.get(entity_id, []):
                if edge.edge_type in (EdgeType.FLAGGED_WITH, EdgeType.ABOUT):
                    f_node = engine.nodes.get(edge.source_id)
                    if f_node and f_node.id not in seen_finding_ids:
                        seen_finding_ids.add(f_node.id)
                        linked_evidence.append(f_node.properties)
                        sev = str(f_node.properties.get("severity", "LOW")).upper()
                        if sev in severity_breakdown:
                            severity_breakdown[sev] += 1
                        else:
                            severity_breakdown["LOW"] += 1

        evidence_count = len(linked_evidence)

        # 5. Compute penalties
        raw_penalties = 0.0
        critical_count = severity_breakdown.get("CRITICAL", 0)
        for sev, count in severity_breakdown.items():
            raw_penalties += SEVERITY_PENALTIES.get(sev, 0.02) * count

        # 6. Logarithmic volume dampener
        dampener = max(1.0, math.log1p(total_samples))
        raw_risk = raw_penalties / dampener if total_samples > 0 else raw_penalties

        if has_active_quarantine:
            raw_risk = max(raw_risk, 0.85)
        elif critical_count >= 2:
            raw_risk = max(raw_risk, 0.75)
        elif critical_count == 1:
            raw_risk = max(raw_risk, 0.40)

        risk_score = round(float(min(1.0, max(0.0, raw_risk))), 4)

        # 7. Render status verdict
        if risk_score >= 0.70:
            status = AssetStatus.QUARANTINED
        elif risk_score >= 0.30:
            status = AssetStatus.UNDER_REVIEW
        else:
            status = AssetStatus.ACCEPTED

        # 8. Forensic explanation (objective, non-inflammatory tone)
        quarantine_note = "Active quarantine order linked to downstream lineage artifacts. " if has_active_quarantine else ""
        if clean_contrib == "UNKNOWN":
            explanation = (
                f"Unauthenticated provenance cluster: Aggregates artifacts with missing or unknown contributor metadata "
                f"({total_datasets} datasets, {total_samples} samples). {quarantine_note}"
                f"Observed {evidence_count} attached verification findings (CRITICAL: {severity_breakdown['CRITICAL']}, "
                f"HIGH: {severity_breakdown['HIGH']}, MEDIUM: {severity_breakdown['MEDIUM']}, LOW: {severity_breakdown['LOW']}). "
                f"Risk score reflects collective unauthenticated artifact assurance and does not attribute findings to an identified entity."
            )
        else:
            explanation = (
                f"Contributor risk scorecard computed from {total_datasets} datasets and {total_samples} samples. {quarantine_note}"
                f"Observed {evidence_count} attached verification findings (CRITICAL: {severity_breakdown['CRITICAL']}, "
                f"HIGH: {severity_breakdown['HIGH']}, MEDIUM: {severity_breakdown['MEDIUM']}, LOW: {severity_breakdown['LOW']}). "
                f"This statistical evaluation reflects historical artifact verification and is not an assertion of malicious intent."
            )

        return ContributorRiskProfile(
            contributor_id=clean_contrib,
            name=display_name,
            total_batches=total_datasets,
            total_datasets=total_datasets,
            total_samples=total_samples,
            flagged_findings_count=evidence_count,
            evidence_count=evidence_count,
            severity_breakdown=severity_breakdown,
            risk_score=risk_score,
            status=status,
            explanation=explanation,
            historical_findings=linked_evidence,
            last_active=datetime.now(timezone.utc),
        )
