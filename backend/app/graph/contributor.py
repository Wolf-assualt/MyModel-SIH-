"""Dynamic Contributor Risk Profiling and Provenance Engine.

Phase 10: Explainable, evidence-grounded risk profiling for data contributors.
Adheres strictly to the principle that risk scores reflect observable empirical findings
without making unproven claims of adversary intent.
"""
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Set

from app.graph.engine import EvidenceGraphEngine
from app.schemas.base import AssetStatus
from app.schemas.fusion import AssuranceRiskLevel
from app.schemas.graph import ContributorRiskProfile, EdgeType, NodeType

SEVERITY_PENALTIES: Dict[str, float] = {
    "CRITICAL": 0.35,
    "HIGH": 0.20,
    "MEDIUM": 0.08,
    "LOW": 0.02,
}


class ContributorRiskEngine:
    """Evaluates historical integrity findings across datasets, models, and evidence to calculate explainable contributor risk profiles."""

    @classmethod
    def get_profile(
        cls,
        contributor_id: str,
        name: Optional[str] = None,
        graph: Optional[EvidenceGraphEngine] = None,
    ) -> ContributorRiskProfile:
        """Compute holistic risk profile for a contributor based on graph provenance and historical evidence."""
        from app.graph.engine import default_graph_engine

        g = graph or default_graph_engine
        display_name = name or f"Contributor {contributor_id}"

        # 1. Identify all datasets / batches authored / provided by this contributor
        authored_dataset_ids: Set[str] = set()

        # Inbound AUTHORED_BY edges (Dataset -> AUTHORED_BY -> Contributor)
        for edge in g._in_edges.get(contributor_id, []):
            if edge.edge_type in (EdgeType.AUTHORED_BY, EdgeType.PROVIDED):
                authored_dataset_ids.add(edge.source_id)

        # Outbound PROVIDED edges (Contributor -> PROVIDED -> Dataset)
        for edge in g._out_edges.get(contributor_id, []):
            if edge.edge_type in (EdgeType.PROVIDED, EdgeType.AUTHORED_BY):
                authored_dataset_ids.add(edge.target_id)

        # Direct node properties fallback
        for node in g.nodes.values():
            if node.node_type in (NodeType.DATASET, NodeType.DATASET_BATCH) and node.properties.get("contributor_id") == contributor_id:
                authored_dataset_ids.add(node.id)

        total_datasets = len(authored_dataset_ids)

        # 2. Count total samples associated with these datasets
        total_samples = 0
        sample_ids: Set[str] = set()
        for d_id in authored_dataset_ids:
            d_node = g.nodes.get(d_id)
            if d_node:
                prop_samples = d_node.properties.get("sample_count", 0)
                edge_samples = sum(
                    1 for e in g._out_edges.get(d_id, [])
                    if e.edge_type in (EdgeType.CONTAINS_SAMPLE, EdgeType.CONTAINS)
                )
                total_samples += max(prop_samples, edge_samples)

            for e in g._out_edges.get(d_id, []):
                if e.edge_type in (EdgeType.CONTAINS_SAMPLE, EdgeType.CONTAINS):
                    sample_ids.add(e.target_id)

        # 3. Identify models trained on these datasets
        model_ids: Set[str] = set()
        for d_id in authored_dataset_ids:
            for edge in g._in_edges.get(d_id, []):
                if edge.edge_type == EdgeType.TRAINED_ON:
                    model_ids.add(edge.source_id)
            for edge in g._out_edges.get(d_id, []):
                if edge.edge_type == EdgeType.USED_IN:
                    training_run_id = edge.target_id
                    for tr_edge in g._out_edges.get(training_run_id, []):
                        if tr_edge.edge_type == EdgeType.PRODUCED:
                            model_ids.add(tr_edge.target_id)

        # 4. Collect all evidence items & findings linked to contributor or their assets
        contributor_cluster = {contributor_id} | authored_dataset_ids | sample_ids | model_ids
        linked_evidence_nodes: List[Dict[str, Any]] = []
        seen_evidence_ids: Set[str] = set()
        supporting_evidence_ids: List[str] = []

        for entity_id in contributor_cluster:
            # Outbound FLAGGED_WITH / ABOUT
            for edge in g._out_edges.get(entity_id, []):
                if edge.edge_type in (EdgeType.FLAGGED_WITH, EdgeType.ABOUT):
                    f_node = g.nodes.get(edge.target_id)
                    if f_node and f_node.id not in seen_evidence_ids:
                        seen_evidence_ids.add(f_node.id)
                        supporting_evidence_ids.append(f_node.id)
                        linked_evidence_nodes.append(f_node.properties or {"id": f_node.id, "description": f_node.label})

            # Inbound FLAGGED_WITH / ABOUT
            for edge in g._in_edges.get(entity_id, []):
                if edge.edge_type in (EdgeType.FLAGGED_WITH, EdgeType.ABOUT):
                    f_node = g.nodes.get(edge.source_id)
                    if f_node and f_node.id not in seen_evidence_ids:
                        seen_evidence_ids.add(f_node.id)
                        supporting_evidence_ids.append(f_node.id)
                        linked_evidence_nodes.append(f_node.properties or {"id": f_node.id, "description": f_node.label})

        # 5. Check if any associated asset is currently quarantined
        has_quarantine = False
        for entity_id in contributor_cluster:
            for edge in g._in_edges.get(entity_id, []):
                if edge.edge_type == EdgeType.QUARANTINES:
                    has_quarantine = True
                    break

        evidence_count = len(linked_evidence_nodes)

        # 6. Compute severity breakdown and penalties
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        raw_penalties = 0.0

        for f_prop in linked_evidence_nodes:
            sev = str(f_prop.get("severity", "LOW")).upper()
            if sev not in severity_breakdown:
                sev = "LOW"
            severity_breakdown[sev] += 1
            raw_penalties += SEVERITY_PENALTIES.get(sev, 0.02)

        # 7. Apply volume dampener
        dampener = max(1.0, math.log1p(total_samples))
        raw_risk = raw_penalties / dampener

        # Guarantee escalation if multiple critical findings or active quarantine present
        if severity_breakdown["CRITICAL"] >= 2 or has_quarantine:
            raw_risk = max(raw_risk, 0.75)
        elif severity_breakdown["CRITICAL"] == 1:
            raw_risk = max(raw_risk, 0.45)

        risk_score = round(float(min(1.0, max(0.0, raw_risk))), 4)

        # 8. Determine Risk Level and Asset Status
        if risk_score >= 0.70:
            risk_level = AssuranceRiskLevel.CRITICAL
            status = AssetStatus.QUARANTINED
        elif risk_score >= 0.50:
            risk_level = AssuranceRiskLevel.HIGH
            status = AssetStatus.UNDER_REVIEW
        elif risk_score >= 0.25:
            risk_level = AssuranceRiskLevel.MEDIUM
            status = AssetStatus.UNDER_REVIEW
        else:
            risk_level = AssuranceRiskLevel.LOW
            status = AssetStatus.ACCEPTED

        # 9. Formulate explainable, non-inflammatory forensic narrative
        narrative_parts = []
        if evidence_count == 0:
            narrative_parts.append(
                f"Historical baseline review for contributor '{contributor_id}' indicates clean provenance with 0 recorded integrity anomalies across {total_datasets} dataset(s)."
            )
        else:
            narrative_parts.append(
                f"Contributor '{contributor_id}' has {evidence_count} recorded evidence item(s) across {total_datasets} dataset(s) ({total_samples} samples)."
            )
            narrative_parts.append(
                f"Severity profile: {severity_breakdown['CRITICAL']} Critical, {severity_breakdown['HIGH']} High, {severity_breakdown['MEDIUM']} Medium, {severity_breakdown['LOW']} Low."
            )
            if severity_breakdown["CRITICAL"] > 0:
                narrative_parts.append("Elevated risk driven by critical integrity findings (e.g. potential trigger backdoors or structural discrepancies).")
            elif severity_breakdown["HIGH"] > 0:
                narrative_parts.append("Moderate risk driven by high-severity integrity observations (e.g. significant label inconsistencies).")

        if has_quarantine:
            narrative_parts.append("Contributor is associated with one or more assets currently subject to operational quarantine.")

        narrative_parts.append(
            "Note: Contributor risk score reflects empirical audit history and downstream asset integrity; it is not an assertion of malicious intent."
        )

        explanation = " ".join(narrative_parts)

        return ContributorRiskProfile(
            contributor_id=contributor_id,
            name=display_name,
            total_datasets=total_datasets,
            total_batches=total_datasets,
            total_samples=total_samples,
            evidence_count=evidence_count,
            flagged_findings_count=evidence_count,
            severity_breakdown=severity_breakdown,
            historical_incidents=linked_evidence_nodes,
            risk_score=risk_score,
            risk_level=risk_level,
            status=status,
            explanation=explanation,
            supporting_evidence_ids=supporting_evidence_ids,
            last_active=datetime.now(timezone.utc),
        )
