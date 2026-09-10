"""Dynamic Contributor Risk Scorecard Engine and Provenance Profiling."""
from datetime import datetime, timezone
import math
from typing import Dict, List, Set

from app.graph.engine import EvidenceGraphEngine
from app.schemas.base import AssetStatus
from app.schemas.graph import ContributorRiskProfile, EdgeType, NodeType

SEVERITY_PENALTIES: Dict[str, float] = {
    "CRITICAL": 0.35,
    "HIGH": 0.20,
    "MEDIUM": 0.08,
    "LOW": 0.02,
}


class ContributorRiskEngine:
    """Evaluates historical integrity findings to calculate dynamic contributor trust scores."""

    @classmethod
    def get_profile(
        cls,
        contributor_id: str,
        name: str,
        graph: EvidenceGraphEngine,
    ) -> ContributorRiskProfile:
        """Compute holistic risk profile for a contributor based on graph provenance and findings."""
        # 1. Identify all dataset batches authored by this contributor
        authored_batch_ids: Set[str] = set()
        for edge in graph._in_edges.get(contributor_id, []):
            if edge.edge_type == EdgeType.AUTHORED_BY:
                authored_batch_ids.add(edge.source_id)

        for node in graph.nodes.values():
            if node.node_type == NodeType.DATASET_BATCH and node.properties.get("contributor_id") == contributor_id:
                authored_batch_ids.add(node.id)

        total_batches = len(authored_batch_ids)

        # 2. Count total samples associated with these batches
        total_samples = 0
        sample_ids: Set[str] = set()
        for b_id in authored_batch_ids:
            b_node = graph.nodes.get(b_id)
            if b_node:
                prop_samples = b_node.properties.get("sample_count", 0)
                edge_samples = sum(
                    1 for e in graph._out_edges.get(b_id, [])
                    if e.edge_type == EdgeType.CONTAINS_SAMPLE
                )
                total_samples += max(prop_samples, edge_samples)

            for e in graph._out_edges.get(b_id, []):
                if e.edge_type == EdgeType.CONTAINS_SAMPLE:
                    sample_ids.add(e.target_id)

        # 3. Identify models trained on these batches
        model_ids: Set[str] = set()
        for b_id in authored_batch_ids:
            for edge in graph._in_edges.get(b_id, []):
                if edge.edge_type == EdgeType.TRAINED_ON:
                    model_ids.add(edge.source_id)

        # 4. Collect all findings linked to contributor, batches, samples, or dependent models
        contributor_cluster = {contributor_id} | authored_batch_ids | sample_ids | model_ids
        linked_findings: List[Dict] = []
        seen_finding_ids: Set[str] = set()

        for entity_id in contributor_cluster:
            for edge in graph._out_edges.get(entity_id, []):
                if edge.edge_type == EdgeType.FLAGGED_WITH:
                    f_node = graph.nodes.get(edge.target_id)
                    if f_node and f_node.id not in seen_finding_ids:
                        seen_finding_ids.add(f_node.id)
                        linked_findings.append(f_node.properties)

            for edge in graph._in_edges.get(entity_id, []):
                if edge.edge_type == EdgeType.FLAGGED_WITH:
                    f_node = graph.nodes.get(edge.source_id)
                    if f_node and f_node.id not in seen_finding_ids:
                        seen_finding_ids.add(f_node.id)
                        linked_findings.append(f_node.properties)

        flagged_findings_count = len(linked_findings)

        # 5. Compute raw penalties
        raw_penalties = 0.0
        critical_count = 0
        for f_prop in linked_findings:
            sev = str(f_prop.get("severity", "LOW")).upper()
            if sev == "CRITICAL":
                critical_count += 1
            raw_penalties += SEVERITY_PENALTIES.get(sev, 0.02)

        # 6. Apply logarithmic volume dampener
        dampener = max(1.0, math.log1p(total_samples))
        raw_risk = raw_penalties / dampener

        # Guarantee escalation: multiple critical findings mandate quarantine
        if critical_count >= 2:
            raw_risk = max(raw_risk, 0.75)

        risk_score = round(float(min(1.0, max(0.0, raw_risk))), 4)

        # 7. Render asset status verdict
        if risk_score >= 0.70:
            status = AssetStatus.QUARANTINED
        elif risk_score >= 0.30:
            status = AssetStatus.UNDER_REVIEW
        else:
            status = AssetStatus.ACCEPTED

        return ContributorRiskProfile(
            contributor_id=contributor_id,
            name=name,
            total_batches=total_batches,
            total_samples=total_samples,
            flagged_findings_count=flagged_findings_count,
            risk_score=risk_score,
            status=status,
            last_active=datetime.now(timezone.utc),
        )
