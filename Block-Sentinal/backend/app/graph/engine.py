"""In-engine Directed Evidence & Lineage Property Graph."""
from collections import defaultdict, deque
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.schemas.graph import (
    EdgeType,
    GraphEdge,
    GraphExport,
    GraphNode,
    LineageTraceResponse,
    NodeType,
)


class EvidenceGraphEngine:
    """Manages an in-memory directed property graph tracking data, models, inferences, and findings."""

    def __init__(self, storage_dir: Optional[Path] = None):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "graph"
        self.storage_dir = base_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.graph_file = self.storage_dir / "evidence_graph.json"

        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._out_edges: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._in_edges: Dict[str, List[GraphEdge]] = defaultdict(list)

        # Load existing graph if available
        if self.graph_file.exists():
            self.load_graph()

    def add_node(self, node: GraphNode) -> None:
        """Insert or update a graph node."""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Insert a directed edge, preventing duplicate entries."""
        for existing in self._out_edges[edge.source_id]:
            if existing.target_id == edge.target_id and existing.edge_type == edge.edge_type:
                return  # Duplicate edge already exists

        self.edges.append(edge)
        self._out_edges[edge.source_id].append(edge)
        self._in_edges[edge.target_id].append(edge)

    def build_lineage(
        self,
        contributor_id: str,
        batch_id: str,
        model_id: Optional[str] = None,
        inference_id: Optional[str] = None,
        sample_ids: Optional[List[str]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Construct multi-layer lineage connecting contributors, datasets, models, inferences, and findings."""
        # 1. Contributor Node
        if contributor_id not in self.nodes:
            self.add_node(
                GraphNode(
                    id=contributor_id,
                    node_type=NodeType.CONTRIBUTOR,
                    label=f"Contributor {contributor_id}",
                )
            )

        # 2. Dataset Batch Node
        sample_count = len(sample_ids) if sample_ids else 0
        if batch_id not in self.nodes:
            self.add_node(
                GraphNode(
                    id=batch_id,
                    node_type=NodeType.DATASET_BATCH,
                    label=f"Dataset Batch {batch_id}",
                    properties={"contributor_id": contributor_id, "sample_count": sample_count},
                )
            )
        self.add_edge(
            GraphEdge(
                source_id=batch_id,
                target_id=contributor_id,
                edge_type=EdgeType.AUTHORED_BY,
            )
        )

        # 3. Individual Samples
        if sample_ids:
            for s_id in sample_ids:
                if s_id not in self.nodes:
                    self.add_node(
                        GraphNode(
                            id=s_id,
                            node_type=NodeType.SAMPLE,
                            label=f"Sample {s_id}",
                            properties={"batch_id": batch_id},
                        )
                    )
                self.add_edge(
                    GraphEdge(
                        source_id=batch_id,
                        target_id=s_id,
                        edge_type=EdgeType.CONTAINS_SAMPLE,
                    )
                )

        # 4. Model Node
        if model_id:
            if model_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=model_id,
                        node_type=NodeType.MODEL,
                        label=f"Model {model_id}",
                    )
                )
            self.add_edge(
                GraphEdge(
                    source_id=model_id,
                    target_id=batch_id,
                    edge_type=EdgeType.TRAINED_ON,
                )
            )

        # 5. Inference Record Node
        if inference_id and model_id:
            if inference_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=inference_id,
                        node_type=NodeType.INFERENCE_RECORD,
                        label=f"Inference {inference_id}",
                    )
                )
            self.add_edge(
                GraphEdge(
                    source_id=inference_id,
                    target_id=model_id,
                    edge_type=EdgeType.GENERATED_BY,
                )
            )

        # 6. Attached Findings
        if findings:
            for f in findings:
                f_id = f.get("finding_id") or f.get("id", f"finding_{len(self.nodes)}")
                target_entity = f.get("target_id") or f.get("affected_asset_id", batch_id)
                if f_id not in self.nodes:
                    self.add_node(
                        GraphNode(
                            id=f_id,
                            node_type=NodeType.FINDING,
                            label=f.get("description", f"Finding {f_id}"),
                            properties=f,
                        )
                    )
                self.add_edge(
                    GraphEdge(
                        source_id=target_entity,
                        target_id=f_id,
                        edge_type=EdgeType.FLAGGED_WITH,
                    )
                )

    def trace_lineage(self, entity_id: str) -> LineageTraceResponse:
        """Traverse upstream dependencies and downstream consumers from a given node using BFS."""
        if entity_id not in self.nodes:
            return LineageTraceResponse(
                target_id=entity_id,
                upstream_path=[],
                downstream_path=[],
                associated_findings=[],
                blast_radius_count=0,
            )

        # 1. BFS Upstream: Follow dependency edges backwards
        # - InferenceRecord -> GENERATED_BY -> Model
        # - Model -> TRAINED_ON -> DatasetBatch
        # - DatasetBatch -> AUTHORED_BY -> Contributor
        # - Sample <- CONTAINS_SAMPLE - DatasetBatch
        upstream_nodes: List[GraphNode] = []
        visited_up: Set[str] = {entity_id}
        queue_up: deque[str] = deque([entity_id])

        while queue_up:
            curr_id = queue_up.popleft()

            # Outbound dependency edges
            for edge in self._out_edges.get(curr_id, []):
                if edge.edge_type in (EdgeType.GENERATED_BY, EdgeType.TRAINED_ON, EdgeType.AUTHORED_BY):
                    tgt = edge.target_id
                    if tgt not in visited_up and tgt in self.nodes:
                        visited_up.add(tgt)
                        upstream_nodes.append(self.nodes[tgt])
                        queue_up.append(tgt)

            # Inbound sample containment (Sample points up to Batch)
            for edge in self._in_edges.get(curr_id, []):
                if edge.edge_type == EdgeType.CONTAINS_SAMPLE:
                    src = edge.source_id
                    if src not in visited_up and src in self.nodes:
                        visited_up.add(src)
                        upstream_nodes.append(self.nodes[src])
                        queue_up.append(src)

        # 2. BFS Downstream: Follow consumer edges forward
        # - Contributor <- AUTHORED_BY - DatasetBatch
        # - DatasetBatch <- TRAINED_ON - Model
        # - Model <- GENERATED_BY - InferenceRecord
        # - DatasetBatch -> CONTAINS_SAMPLE -> Sample
        downstream_nodes: List[GraphNode] = []
        visited_down: Set[str] = {entity_id}
        queue_down: deque[str] = deque([entity_id])

        while queue_down:
            curr_id = queue_down.popleft()

            # Inbound dependencies are downstream consumers
            for edge in self._in_edges.get(curr_id, []):
                if edge.edge_type in (EdgeType.GENERATED_BY, EdgeType.TRAINED_ON, EdgeType.AUTHORED_BY):
                    src = edge.source_id
                    if src not in visited_down and src in self.nodes:
                        visited_down.add(src)
                        downstream_nodes.append(self.nodes[src])
                        queue_down.append(src)

            # Outbound sample containment
            for edge in self._out_edges.get(curr_id, []):
                if edge.edge_type == EdgeType.CONTAINS_SAMPLE:
                    tgt = edge.target_id
                    if tgt not in visited_down and tgt in self.nodes:
                        visited_down.add(tgt)
                        downstream_nodes.append(self.nodes[tgt])
                        queue_down.append(tgt)

        # 3. Collect Associated Findings across the entire lineage cluster
        lineage_cluster = {entity_id} | {n.id for n in upstream_nodes} | {n.id for n in downstream_nodes}
        associated_findings: List[GraphNode] = []
        seen_findings: Set[str] = set()

        for member_id in lineage_cluster:
            # Outbound FLAGGED_WITH edges
            for edge in self._out_edges.get(member_id, []):
                if edge.edge_type == EdgeType.FLAGGED_WITH:
                    f_id = edge.target_id
                    if f_id not in seen_findings and f_id in self.nodes:
                        seen_findings.add(f_id)
                        associated_findings.append(self.nodes[f_id])

            # Inbound FLAGGED_WITH edges
            for edge in self._in_edges.get(member_id, []):
                if edge.edge_type == EdgeType.FLAGGED_WITH:
                    f_id = edge.source_id
                    if f_id not in seen_findings and f_id in self.nodes:
                        seen_findings.add(f_id)
                        associated_findings.append(self.nodes[f_id])

        blast_radius_count = len(downstream_nodes) + len(associated_findings)

        return LineageTraceResponse(
            target_id=entity_id,
            upstream_path=upstream_nodes,
            downstream_path=downstream_nodes,
            associated_findings=associated_findings,
            blast_radius_count=blast_radius_count,
        )

    def export_graph(self) -> GraphExport:
        """Export sorted, deterministic graph snapshot sealed with canonical SHA-256 digest."""
        sorted_nodes = sorted(self.nodes.values(), key=lambda n: n.id)
        sorted_edges = sorted(
            self.edges,
            key=lambda e: (e.source_id, e.target_id, e.edge_type.value),
        )

        payload = {
            "nodes": [n.model_dump() for n in sorted_nodes],
            "edges": [e.model_dump() for e in sorted_edges],
        }
        graph_digest = canonical_json_hash(payload)

        return GraphExport(
            nodes=sorted_nodes,
            edges=sorted_edges,
            graph_digest=graph_digest,
        )

    def save_graph(self, filepath: Optional[Path] = None) -> None:
        """Save graph data to JSON file."""
        target_path = filepath or self.graph_file
        export_data = self.export_graph()
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(export_data.model_dump(mode="json"), f, indent=2)

    def load_graph(self, filepath: Optional[Path] = None) -> None:
        """Load graph data from JSON file."""
        target_path = filepath or self.graph_file
        if not target_path.exists():
            return

        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.nodes = {n["id"]: GraphNode.model_validate(n) for n in data.get("nodes", [])}
        self.edges = []
        self._out_edges.clear()
        self._in_edges.clear()

        for e_dict in data.get("edges", []):
            edge = GraphEdge.model_validate(e_dict)
            self.add_edge(edge)


# Default singleton instance
default_graph_engine = EvidenceGraphEngine()
