"""In-engine Directed Evidence & Lineage Property Graph.

Phase 10: Multi-layer traceable provenance graph, blast-radius analysis,
temporal lineage queries, and cryptographic graph integrity verification.
"""
from collections import defaultdict, deque
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.crypto.signer import default_key_manager
from app.schemas.base import AssetStatus
from app.schemas.graph import (
    BlastRadiusReport,
    EdgeType,
    GraphEdge,
    GraphExport,
    GraphIntegrityReport,
    GraphNeighborsResponse,
    GraphNode,
    LineageTraceResponse,
    NodeType,
)


class EvidenceGraphEngine:
    """Manages a locally persistent, directed property graph tracking data, models, inferences, evidence, and quarantines."""

    def __init__(self, storage_dir: Optional[Path] = None):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "graph"
        self.storage_dir = Path(base_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.graph_file = self.storage_dir / "evidence_graph.json"

        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._out_edges: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._in_edges: Dict[str, List[GraphEdge]] = defaultdict(list)

        # Load existing graph if available
        if self.graph_file.exists():
            try:
                self.load_graph()
            except Exception:
                pass

    def add_node(self, node: GraphNode, overwrite: bool = True) -> GraphNode:
        """Insert or update a graph node with deterministic identifier."""
        if not node.id or not isinstance(node.id, str):
            raise ValueError("Graph node must possess a valid, non-empty string ID.")

        if node.id in self.nodes and not overwrite:
            return self.nodes[node.id]

        self.nodes[node.id] = node
        return node

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node by its unique identifier."""
        return self.nodes.get(node_id)

    def add_edge(
        self,
        edge: GraphEdge,
        validate_nodes: bool = False,
        strict_subject_validation: bool = True,
    ) -> None:
        """Insert a directed edge with de-duplication, endpoint checks, and mismatch validation."""
        if not edge.source_id or not edge.target_id:
            raise ValueError("Graph edge must specify non-empty source_id and target_id.")

        if validate_nodes:
            if edge.source_id not in self.nodes:
                raise ValueError(f"Source node '{edge.source_id}' does not exist in graph.")
            if edge.target_id not in self.nodes:
                raise ValueError(f"Target node '{edge.target_id}' does not exist in graph.")

        # Cross-subject mismatch validation
        if strict_subject_validation:
            src_node = self.nodes.get(edge.source_id)
            tgt_node = self.nodes.get(edge.target_id)
            if src_node and tgt_node:
                self._validate_edge_compatibility(src_node, tgt_node, edge.edge_type)

        # De-duplicate: check if exact edge already exists
        for existing in self._out_edges[edge.source_id]:
            if existing.target_id == edge.target_id and existing.edge_type == edge.edge_type:
                # Update metadata if new keys provided
                if edge.metadata:
                    existing.metadata.update(edge.metadata)
                return

        self.edges.append(edge)
        self._out_edges[edge.source_id].append(edge)
        self._in_edges[edge.target_id].append(edge)

    def _validate_edge_compatibility(
        self,
        source: GraphNode,
        target: GraphNode,
        edge_type: EdgeType,
    ) -> None:
        """Enforce domain relationship consistency across node types."""
        # Evidence subject validation
        if edge_type == EdgeType.ABOUT or edge_type == EdgeType.FLAGGED_WITH:
            if source.node_type in (NodeType.EVIDENCE, NodeType.FINDING):
                # An evidence item must match the subject in its properties if explicitly specified
                expected_subj = source.properties.get("subject_id")
                if expected_subj and expected_subj != target.id:
                    raise ValueError(
                        f"Cross-subject mismatch: Evidence '{source.id}' has subject '{expected_subj}', cannot attach to '{target.id}'."
                    )
                expected_model = source.properties.get("related_model_id")
                if expected_model and target.node_type in (NodeType.MODEL, NodeType.MODEL_VERSION) and target.id != expected_model:
                    raise ValueError(
                        f"Cross-model mismatch: Evidence '{source.id}' is bound to model '{expected_model}', cannot attach to '{target.id}'."
                    )
                expected_dataset = source.properties.get("related_dataset_id")
                if expected_dataset and target.node_type in (NodeType.DATASET, NodeType.DATASET_VERSION, NodeType.DATASET_BATCH) and target.id != expected_dataset:
                    raise ValueError(
                        f"Cross-dataset mismatch: Evidence '{source.id}' is bound to dataset '{expected_dataset}', cannot attach to '{target.id}'."
                    )

        # Training lineage validation
        if edge_type in (EdgeType.TRAINED_ON, EdgeType.USED_IN):
            if source.node_type not in (NodeType.MODEL, NodeType.MODEL_VERSION, NodeType.TRAINING_RUN, NodeType.DATASET_VERSION, NodeType.DATASET, NodeType.DATASET_BATCH):
                pass

        # Inference generation validation
        if edge_type in (EdgeType.GENERATED_BY, EdgeType.USED_FOR):
            if source.node_type in (NodeType.INFERENCE, NodeType.INFERENCE_RECORD):
                expected_model = source.properties.get("model_id")
                if expected_model and target.id != expected_model:
                    raise ValueError(
                        f"Cross-model inference mismatch: Inference '{source.id}' was generated by '{expected_model}', cannot link to '{target.id}'."
                    )

    def build_lineage(
        self,
        contributor_id: Optional[str] = None,
        dataset_id: Optional[str] = None,
        batch_id: Optional[str] = None,
        dataset_version_id: Optional[str] = None,
        sample_ids: Optional[List[str]] = None,
        training_run_id: Optional[str] = None,
        model_id: Optional[str] = None,
        model_version_id: Optional[str] = None,
        inference_id: Optional[str] = None,
        output_id: Optional[str] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        evidence_items: Optional[List[Dict[str, Any]]] = None,
        drift_baseline_id: Optional[str] = None,
        drift_report_id: Optional[str] = None,
        quarantine_id: Optional[str] = None,
        fusion_assessment_id: Optional[str] = None,
    ) -> None:
        """Construct multi-layer lineage connecting contributors, datasets, models, inferences, evidence, and quarantines."""
        # 1. Contributor Node
        if contributor_id:
            if contributor_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=contributor_id,
                        node_type=NodeType.CONTRIBUTOR,
                        label=f"Contributor {contributor_id}",
                    )
                )

        # 2. Dataset / Dataset Batch / Dataset Version
        effective_dataset_id = dataset_id or batch_id
        if effective_dataset_id:
            if effective_dataset_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=effective_dataset_id,
                        node_type=NodeType.DATASET if dataset_id else NodeType.DATASET_BATCH,
                        label=f"Dataset {effective_dataset_id}",
                        properties={"contributor_id": contributor_id, "sample_count": len(sample_ids or [])},
                    )
                )
            if contributor_id:
                self.add_edge(
                    GraphEdge(
                        source_id=effective_dataset_id,
                        target_id=contributor_id,
                        edge_type=EdgeType.AUTHORED_BY,
                    )
                )

        if dataset_version_id and effective_dataset_id:
            if dataset_version_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=dataset_version_id,
                        node_type=NodeType.DATASET_VERSION,
                        label=f"Dataset Version {dataset_version_id}",
                        properties={"dataset_id": effective_dataset_id},
                    )
                )
            self.add_edge(
                GraphEdge(
                    source_id=effective_dataset_id,
                    target_id=dataset_version_id,
                    edge_type=EdgeType.HAS_VERSION,
                )
            )

        # 3. Individual Samples
        sample_parent_id = dataset_version_id or effective_dataset_id
        if sample_ids and sample_parent_id:
            for s_id in sample_ids:
                if s_id not in self.nodes:
                    self.add_node(
                        GraphNode(
                            id=s_id,
                            node_type=NodeType.SAMPLE,
                            label=f"Sample {s_id}",
                            properties={"parent_dataset_id": sample_parent_id},
                        )
                    )
                self.add_edge(
                    GraphEdge(
                        source_id=sample_parent_id,
                        target_id=s_id,
                        edge_type=EdgeType.CONTAINS_SAMPLE,
                    )
                )

        # 4. Training Run Node
        if training_run_id:
            if training_run_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=training_run_id,
                        node_type=NodeType.TRAINING_RUN,
                        label=f"Training Run {training_run_id}",
                    )
                )
            if sample_parent_id:
                self.add_edge(
                    GraphEdge(
                        source_id=sample_parent_id,
                        target_id=training_run_id,
                        edge_type=EdgeType.USED_IN,
                    )
                )

        # 5. Model & Model Version Nodes
        if model_id:
            if model_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=model_id,
                        node_type=NodeType.MODEL,
                        label=f"Model {model_id}",
                    )
                )
            if training_run_id:
                self.add_edge(
                    GraphEdge(
                        source_id=training_run_id,
                        target_id=model_id,
                        edge_type=EdgeType.PRODUCED,
                    )
                )
            elif effective_dataset_id:
                self.add_edge(
                    GraphEdge(
                        source_id=model_id,
                        target_id=effective_dataset_id,
                        edge_type=EdgeType.TRAINED_ON,
                    )
                )

        if model_version_id and model_id:
            if model_version_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=model_version_id,
                        node_type=NodeType.MODEL_VERSION,
                        label=f"Model Version {model_version_id}",
                        properties={"model_id": model_id},
                    )
                )
            self.add_edge(
                GraphEdge(
                    source_id=model_id,
                    target_id=model_version_id,
                    edge_type=EdgeType.HAS_VERSION,
                )
            )

        # 6. Inference Node & Output
        effective_model_id = model_version_id or model_id
        if inference_id:
            if inference_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=inference_id,
                        node_type=NodeType.INFERENCE,
                        label=f"Inference {inference_id}",
                        properties={"model_id": effective_model_id} if effective_model_id else {},
                    )
                )
            if effective_model_id:
                self.add_edge(
                    GraphEdge(
                        source_id=inference_id,
                        target_id=effective_model_id,
                        edge_type=EdgeType.GENERATED_BY,
                    )
                )
                self.add_edge(
                    GraphEdge(
                        source_id=effective_model_id,
                        target_id=inference_id,
                        edge_type=EdgeType.USED_FOR,
                    )
                )

        if output_id and inference_id:
            if output_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=output_id,
                        node_type=NodeType.OUTPUT,
                        label=f"Output {output_id}",
                        properties={"inference_id": inference_id},
                    )
                )
            self.add_edge(
                GraphEdge(
                    source_id=inference_id,
                    target_id=output_id,
                    edge_type=EdgeType.PRODUCED,
                )
            )

        # 7. Findings & Evidence Attachment
        if findings:
            for f in findings:
                f_id = f.get("finding_id") or f.get("id", f"finding_{len(self.nodes)}")
                target_entity = f.get("target_id") or f.get("affected_asset_id", effective_dataset_id or model_id)
                if f_id not in self.nodes:
                    self.add_node(
                        GraphNode(
                            id=f_id,
                            node_type=NodeType.FINDING,
                            label=f.get("description", f"Finding {f_id}"),
                            properties=f,
                        )
                    )
                if target_entity:
                    self.add_edge(
                        GraphEdge(
                            source_id=target_entity,
                            target_id=f_id,
                            edge_type=EdgeType.FLAGGED_WITH,
                        )
                    )

        if evidence_items:
            for ev in evidence_items:
                ev_id = ev.get("evidence_id") or ev.get("id", f"ev_{len(self.nodes)}")
                target_entity = ev.get("subject_id") or ev.get("target_id", effective_dataset_id or model_id or inference_id)
                if ev_id not in self.nodes:
                    self.add_node(
                        GraphNode(
                            id=ev_id,
                            node_type=NodeType.EVIDENCE,
                            label=ev.get("description", f"Evidence {ev_id}"),
                            properties=ev,
                        )
                    )
                if target_entity:
                    self.add_edge(
                        GraphEdge(
                            source_id=ev_id,
                            target_id=target_entity,
                            edge_type=EdgeType.ABOUT,
                        )
                    )

        # 8. Drift Baselines & Reports
        if drift_baseline_id:
            if drift_baseline_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=drift_baseline_id,
                        node_type=NodeType.DRIFT_BASELINE,
                        label=f"Drift Baseline {drift_baseline_id}",
                    )
                )
        if drift_report_id:
            if drift_report_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=drift_report_id,
                        node_type=NodeType.DRIFT_REPORT,
                        label=f"Drift Report {drift_report_id}",
                    )
                )
            if drift_baseline_id:
                self.add_edge(
                    GraphEdge(
                        source_id=drift_baseline_id,
                        target_id=drift_report_id,
                        edge_type=EdgeType.COMPARED_WITH,
                    )
                )
            if effective_dataset_id:
                self.add_edge(
                    GraphEdge(
                        source_id=drift_report_id,
                        target_id=effective_dataset_id,
                        edge_type=EdgeType.ABOUT,
                    )
                )

        # 9. Fusion Assessment
        if fusion_assessment_id:
            if fusion_assessment_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=fusion_assessment_id,
                        node_type=NodeType.FUSION_ASSESSMENT,
                        label=f"Fusion Assessment {fusion_assessment_id}",
                    )
                )
            subj = effective_model_id or effective_dataset_id or inference_id
            if subj:
                self.add_edge(
                    GraphEdge(
                        source_id=fusion_assessment_id,
                        target_id=subj,
                        edge_type=EdgeType.DECIDES_ON,
                    )
                )

        # 10. Quarantine
        if quarantine_id:
            if quarantine_id not in self.nodes:
                self.add_node(
                    GraphNode(
                        id=quarantine_id,
                        node_type=NodeType.QUARANTINE,
                        label=f"Quarantine {quarantine_id}",
                    )
                )
            subj = effective_model_id or effective_dataset_id or inference_id
            if subj:
                self.add_edge(
                    GraphEdge(
                        source_id=quarantine_id,
                        target_id=subj,
                        edge_type=EdgeType.QUARANTINES,
                    )
                )
            if fusion_assessment_id:
                self.add_edge(
                    GraphEdge(
                        source_id=quarantine_id,
                        target_id=fusion_assessment_id,
                        edge_type=EdgeType.RESULTED_FROM,
                    )
                )

    def attach_evidence(
        self,
        evidence_id: str,
        subject_id: str,
        source_domain: str,
        severity: str,
        description: str,
        metric_value: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Attach a verified evidence item to a specific graph asset."""
        if subject_id not in self.nodes:
            raise ValueError(f"Target subject '{subject_id}' does not exist in the graph.")

        ev_props = {
            "source_domain": source_domain,
            "severity": severity,
            "metric_value": metric_value,
            "subject_id": subject_id,
        }
        if metadata:
            ev_props.update(metadata)

        ev_node = GraphNode(
            id=evidence_id,
            node_type=NodeType.EVIDENCE,
            label=description,
            properties=ev_props,
        )
        self.add_node(ev_node)
        self.add_edge(
            GraphEdge(
                source_id=evidence_id,
                target_id=subject_id,
                edge_type=EdgeType.ABOUT,
            )
        )
        return ev_node

    def get_neighbors(self, node_id: str) -> Optional[GraphNeighborsResponse]:
        """Retrieve direct incoming/outgoing edges and neighbor nodes."""
        node = self.nodes.get(node_id)
        if not node:
            return None

        out_edges = self._out_edges.get(node_id, [])
        in_edges = self._in_edges.get(node_id, [])

        neighbor_ids = {e.target_id for e in out_edges} | {e.source_id for e in in_edges}
        neighbor_nodes = [self.nodes[n_id] for n_id in neighbor_ids if n_id in self.nodes]

        return GraphNeighborsResponse(
            node=node,
            incoming_edges=in_edges,
            outgoing_edges=out_edges,
            neighbors=neighbor_nodes,
        )

    def get_attached_evidence(self, node_id: str) -> List[GraphNode]:
        """Retrieve all evidence items and findings directly or contextually attached to a node."""
        evidence_nodes: List[GraphNode] = []
        seen: Set[str] = set()

        # Inbound ABOUT / FLAGGED_WITH edges (e.g. Evidence -> ABOUT -> Model)
        for edge in self._in_edges.get(node_id, []):
            if edge.edge_type in (EdgeType.ABOUT, EdgeType.FLAGGED_WITH):
                src = edge.source_id
                if src in self.nodes and src not in seen:
                    seen.add(src)
                    evidence_nodes.append(self.nodes[src])

        # Outbound FLAGGED_WITH / ABOUT edges
        for edge in self._out_edges.get(node_id, []):
            if edge.edge_type in (EdgeType.FLAGGED_WITH, EdgeType.ABOUT):
                tgt = edge.target_id
                if tgt in self.nodes and tgt not in seen:
                    seen.add(tgt)
                    evidence_nodes.append(self.nodes[tgt])

        return evidence_nodes

    def trace_upstream(
        self,
        entity_id: str,
        max_depth: int = 20,
        before_timestamp: Optional[datetime] = None,
        after_timestamp: Optional[datetime] = None,
    ) -> List[GraphNode]:
        """Traverse upstream dependencies backwards from an entity (Inference -> Model -> Training -> Dataset -> Contributor)."""
        if entity_id not in self.nodes:
            return []

        upstream_nodes: List[GraphNode] = []
        visited: Set[str] = {entity_id}
        queue: deque[Tuple[str, int]] = deque([(entity_id, 0)])

        while queue:
            curr_id, depth = queue.popleft()
            if depth >= max_depth:
                continue

            curr_node = self.nodes.get(curr_id)
            if not curr_node:
                continue

            # Check timestamp constraints
            if before_timestamp and curr_node.created_at > before_timestamp:
                continue
            if after_timestamp and curr_node.created_at < after_timestamp:
                continue

            # Follow outbound dependency edges backwards:
            # - Inference -> GENERATED_BY -> Model
            # - Model -> TRAINED_ON -> Dataset
            # - TrainingRun -> PRODUCED -> Model (inbound on Model)
            # - DatasetBatch -> AUTHORED_BY -> Contributor
            # - DatasetVersion -> HAS_VERSION -> Dataset (inbound)
            for edge in self._out_edges.get(curr_id, []):
                if edge.edge_type in (
                    EdgeType.GENERATED_BY,
                    EdgeType.TRAINED_ON,
                    EdgeType.AUTHORED_BY,
                    EdgeType.USED_IN,
                    EdgeType.USED_FOR,
                ):
                    tgt = edge.target_id
                    if tgt not in visited and tgt in self.nodes:
                        visited.add(tgt)
                        upstream_nodes.append(self.nodes[tgt])
                        queue.append((tgt, depth + 1))

            # Follow inbound dependency sources:
            # - TrainingRun -> PRODUCED -> Model  (curr_id = Model => src = TrainingRun)
            # - Dataset -> HAS_VERSION -> DatasetVersion (curr_id = DatasetVersion => src = Dataset)
            # - Dataset -> CONTAINS_SAMPLE -> Sample (curr_id = Sample => src = Dataset)
            # - Contributor -> PROVIDED -> Dataset (curr_id = Dataset => src = Contributor)
            for edge in self._in_edges.get(curr_id, []):
                if edge.edge_type in (
                    EdgeType.PRODUCED,
                    EdgeType.HAS_VERSION,
                    EdgeType.CONTAINS_SAMPLE,
                    EdgeType.CONTAINS,
                    EdgeType.PROVIDED,
                    EdgeType.USED_IN,
                ):
                    src = edge.source_id
                    if src not in visited and src in self.nodes:
                        visited.add(src)
                        upstream_nodes.append(self.nodes[src])
                        queue.append((src, depth + 1))

        return upstream_nodes

    def trace_downstream(
        self,
        entity_id: str,
        max_depth: int = 20,
        before_timestamp: Optional[datetime] = None,
        after_timestamp: Optional[datetime] = None,
    ) -> List[GraphNode]:
        """Traverse downstream consumers forward from an entity (Contributor -> Dataset -> Training -> Model -> Inference -> Output)."""
        if entity_id not in self.nodes:
            return []

        downstream_nodes: List[GraphNode] = []
        visited: Set[str] = {entity_id}
        queue: deque[Tuple[str, int]] = deque([(entity_id, 0)])

        while queue:
            curr_id, depth = queue.popleft()
            if depth >= max_depth:
                continue

            curr_node = self.nodes.get(curr_id)
            if not curr_node:
                continue

            # Check timestamp constraints
            if before_timestamp and curr_node.created_at > before_timestamp:
                continue
            if after_timestamp and curr_node.created_at < after_timestamp:
                continue

            # Follow inbound consumer edges:
            # - Contributor <- AUTHORED_BY - Dataset (curr_id = Contributor => src = Dataset)
            # - Dataset <- TRAINED_ON - Model (curr_id = Dataset => src = Model)
            # - Model <- GENERATED_BY - Inference (curr_id = Model => src = Inference)
            for edge in self._in_edges.get(curr_id, []):
                if edge.edge_type in (
                    EdgeType.AUTHORED_BY,
                    EdgeType.TRAINED_ON,
                    EdgeType.GENERATED_BY,
                    EdgeType.USED_FOR,
                ):
                    src = edge.source_id
                    if src not in visited and src in self.nodes:
                        visited.add(src)
                        downstream_nodes.append(self.nodes[src])
                        queue.append((src, depth + 1))

            # Follow outbound forward edges:
            # - Contributor -> PROVIDED -> Dataset
            # - Dataset -> HAS_VERSION -> DatasetVersion
            # - Dataset -> CONTAINS_SAMPLE -> Sample
            # - Dataset / DatasetVersion -> USED_IN -> TrainingRun
            # - TrainingRun -> PRODUCED -> Model
            # - Model -> HAS_VERSION -> ModelVersion
            # - Model / ModelVersion -> USED_FOR -> Inference
            # - Inference -> PRODUCED -> Output
            for edge in self._out_edges.get(curr_id, []):
                if edge.edge_type in (
                    EdgeType.PROVIDED,
                    EdgeType.HAS_VERSION,
                    EdgeType.CONTAINS_SAMPLE,
                    EdgeType.CONTAINS,
                    EdgeType.USED_IN,
                    EdgeType.PRODUCED,
                    EdgeType.USED_FOR,
                ):
                    tgt = edge.target_id
                    if tgt not in visited and tgt in self.nodes:
                        visited.add(tgt)
                        downstream_nodes.append(self.nodes[tgt])
                        queue.append((tgt, depth + 1))

        return downstream_nodes

    def trace_lineage(self, entity_id: str) -> LineageTraceResponse:
        """Traverse upstream dependencies and downstream consumers from a given node using BFS (backward-compatible)."""
        if entity_id not in self.nodes:
            return LineageTraceResponse(
                target_id=entity_id,
                upstream_path=[],
                downstream_path=[],
                associated_findings=[],
                associated_evidence=[],
                blast_radius_count=0,
            )

        upstream_nodes = self.trace_upstream(entity_id)
        downstream_nodes = self.trace_downstream(entity_id)

        # Collect associated findings/evidence across the entire lineage cluster
        lineage_cluster = {entity_id} | {n.id for n in upstream_nodes} | {n.id for n in downstream_nodes}
        associated_evidence: List[GraphNode] = []
        seen_evidence: Set[str] = set()

        for member_id in lineage_cluster:
            for ev_node in self.get_attached_evidence(member_id):
                if ev_node.id not in seen_evidence:
                    seen_evidence.add(ev_node.id)
                    associated_evidence.append(ev_node)

        blast_radius_count = len(downstream_nodes) + len(associated_evidence)

        return LineageTraceResponse(
            target_id=entity_id,
            upstream_path=upstream_nodes,
            downstream_path=downstream_nodes,
            associated_findings=associated_evidence,
            associated_evidence=associated_evidence,
            blast_radius_count=blast_radius_count,
        )

    def calculate_blast_radius(self, root_cause_id: str) -> BlastRadiusReport:
        """Perform comprehensive downstream blast-radius analysis starting from a compromised or suspect root entity."""
        root_node = self.nodes.get(root_cause_id)
        if not root_node:
            raise ValueError(f"Root cause entity '{root_cause_id}' not found in the evidence graph.")

        downstream_nodes = self.trace_downstream(root_cause_id)
        affected_cluster = {root_cause_id} | {n.id for n in downstream_nodes}

        # Collect directly affected entities (distance = 1)
        directly_affected: Set[str] = set()
        for e in self._out_edges.get(root_cause_id, []):
            if e.target_id in self.nodes and e.edge_type not in (EdgeType.ABOUT, EdgeType.FLAGGED_WITH):
                directly_affected.add(e.target_id)
        for e in self._in_edges.get(root_cause_id, []):
            if e.source_id in self.nodes and e.edge_type in (EdgeType.AUTHORED_BY, EdgeType.TRAINED_ON, EdgeType.GENERATED_BY):
                directly_affected.add(e.source_id)

        # Categorize affected artifacts
        affected_training_runs: List[str] = []
        affected_models: List[str] = []
        affected_model_versions: List[str] = []
        affected_inferences: List[str] = []
        affected_outputs: List[str] = []
        affected_evidence_ids: List[str] = []
        affected_quarantines: List[str] = []
        associated_evidence: List[GraphNode] = []
        seen_ev: Set[str] = set()

        for n in downstream_nodes:
            if n.node_type == NodeType.TRAINING_RUN:
                affected_training_runs.append(n.id)
            elif n.node_type == NodeType.MODEL:
                affected_models.append(n.id)
            elif n.node_type == NodeType.MODEL_VERSION:
                affected_model_versions.append(n.id)
            elif n.node_type in (NodeType.INFERENCE, NodeType.INFERENCE_RECORD):
                affected_inferences.append(n.id)
            elif n.node_type == NodeType.OUTPUT:
                affected_outputs.append(n.id)

        # Collect evidence and quarantines tied to this blast radius
        for member_id in affected_cluster:
            for ev_node in self.get_attached_evidence(member_id):
                if ev_node.id not in seen_ev:
                    seen_ev.add(ev_node.id)
                    affected_evidence_ids.append(ev_node.id)
                    associated_evidence.append(ev_node)

            for e in self._in_edges.get(member_id, []):
                if e.edge_type == EdgeType.QUARANTINES:
                    q_id = e.source_id
                    if q_id not in affected_quarantines:
                        affected_quarantines.append(q_id)

        # Construct objective, non-inflammatory forensic explanation
        explanation_parts = [
            f"Downstream blast-radius analysis for root entity '{root_cause_id}' ({root_node.node_type.value}).",
            f"Identified {len(downstream_nodes)} potentially affected downstream dependencies ({len(directly_affected)} direct).",
        ]
        if affected_models:
            explanation_parts.append(f"Potentially affected models ({len(affected_models)}): {', '.join(affected_models[:5])}{'...' if len(affected_models) > 5 else ''}.")
        if affected_inferences:
            explanation_parts.append(f"Operational impact encompasses {len(affected_inferences)} downstream inference events.")
        if affected_evidence_ids:
            explanation_parts.append(f"Associated with {len(affected_evidence_ids)} corroborating evidence/finding records.")
        if affected_quarantines:
            explanation_parts.append(f"Associated active/historical quarantine records: {', '.join(affected_quarantines)}.")
        explanation_parts.append("Note: Downstream dependencies indicate potential operational exposure and warrant assurance review; they do not guarantee active malicious compromise.")

        return BlastRadiusReport(
            root_cause_id=root_cause_id,
            root_cause_type=root_node.node_type,
            status=AssetStatus.QUARANTINED if affected_quarantines else AssetStatus.UNDER_REVIEW,
            directly_affected_count=len(directly_affected),
            total_downstream_count=len(downstream_nodes),
            affected_training_runs=affected_training_runs,
            affected_models=affected_models,
            affected_model_versions=affected_model_versions,
            affected_inferences=affected_inferences,
            affected_outputs=affected_outputs,
            affected_evidence_ids=affected_evidence_ids,
            affected_quarantines=affected_quarantines,
            downstream_nodes=downstream_nodes,
            associated_evidence=associated_evidence,
            explanation=" ".join(explanation_parts),
            generated_at=datetime.now(timezone.utc),
        )

    def verify_graph_integrity(self) -> GraphIntegrityReport:
        """Audit graph topology, reference consistency, orphan nodes, cycles, and cryptographic digests."""
        tampered_nodes: List[str] = []
        broken_edges: List[Dict[str, str]] = []
        orphan_nodes: List[str] = []

        # 1. Check edge endpoints integrity
        for e in self.edges:
            if e.source_id not in self.nodes:
                broken_edges.append({"source_id": e.source_id, "target_id": e.target_id, "reason": "Missing source node"})
            if e.target_id not in self.nodes:
                broken_edges.append({"source_id": e.source_id, "target_id": e.target_id, "reason": "Missing target node"})

        # 2. Check orphan nodes (nodes with zero edges, except standalone contributors or single-node graphs)
        for n_id, n in self.nodes.items():
            in_count = len(self._in_edges.get(n_id, []))
            out_count = len(self._out_edges.get(n_id, []))
            if in_count == 0 and out_count == 0 and len(self.nodes) > 1:
                orphan_nodes.append(n_id)

        # 3. Detect cycles in strict derivation DAGs (Training -> Model -> Inference -> Output)
        cycles = self._detect_derivation_cycles()

        # 4. Compute canonical snapshot hash
        export_snapshot = self.export_graph(sign=False)
        computed_digest = export_snapshot.graph_digest

        is_valid = len(broken_edges) == 0 and len(tampered_nodes) == 0 and len(cycles) == 0

        details = (
            "Graph integrity verified successfully: All edges valid, no broken references, no topological cycles."
            if is_valid
            else f"Graph integrity issues detected: {len(broken_edges)} broken edges, {len(orphan_nodes)} orphan nodes, {len(cycles)} cycles."
        )

        return GraphIntegrityReport(
            is_valid=is_valid,
            total_nodes=len(self.nodes),
            total_edges=len(self.edges),
            computed_digest=computed_digest,
            stored_digest=None,
            tampered_nodes=tampered_nodes,
            broken_edges=broken_edges,
            orphan_nodes=orphan_nodes,
            cycles_detected=cycles,
            details=details,
        )

    def _detect_derivation_cycles(self) -> List[List[str]]:
        """Detect any circular dependency loops within the asset derivation graph."""
        cycles: List[List[str]] = []
        visited: Dict[str, int] = {}  # 0 = unvisited, 1 = visiting (on stack), 2 = visited
        parent_map: Dict[str, str] = {}

        def dfs(node_id: str, path: List[str]):
            visited[node_id] = 1
            for edge in self._out_edges.get(node_id, []):
                # Only check forward dependency edges
                if edge.edge_type in (
                    EdgeType.PRODUCED,
                    EdgeType.HAS_VERSION,
                    EdgeType.CONTAINS,
                    EdgeType.CONTAINS_SAMPLE,
                    EdgeType.USED_IN,
                    EdgeType.USED_FOR,
                ):
                    nxt = edge.target_id
                    if visited.get(nxt, 0) == 1:
                        # Cycle detected
                        cycle_path = path + [nxt]
                        cycles.append(cycle_path)
                    elif visited.get(nxt, 0) == 0:
                        dfs(nxt, path + [nxt])
            visited[node_id] = 2

        for n_id in list(self.nodes.keys()):
            if visited.get(n_id, 0) == 0:
                dfs(n_id, [n_id])

        return cycles

    def export_graph(self, sign: bool = True) -> GraphExport:
        """Export sorted, deterministic graph snapshot sealed with canonical SHA-256 digest and ECDSA signature."""
        sorted_nodes = sorted(self.nodes.values(), key=lambda n: n.id)
        sorted_edges = sorted(
            self.edges,
            key=lambda e: (e.source_id, e.target_id, e.edge_type.value),
        )

        payload = {
            "nodes": [n.model_dump(mode="json") for n in sorted_nodes],
            "edges": [e.model_dump(mode="json") for e in sorted_edges],
        }
        graph_digest = canonical_json_hash(payload)

        signature = None
        if sign:
            try:
                signature = default_key_manager.sign_hash(graph_digest)
            except Exception:
                pass

        return GraphExport(
            nodes=sorted_nodes,
            edges=sorted_edges,
            graph_digest=graph_digest,
            node_count=len(sorted_nodes),
            edge_count=len(sorted_edges),
            signature=signature,
            exported_at=datetime.now(timezone.utc),
        )

    def save_graph(self, filepath: Optional[Path] = None) -> None:
        """Save graph data and cryptographic seal to JSON file."""
        target_path = filepath or self.graph_file
        export_data = self.export_graph(sign=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(export_data.model_dump(mode="json"), f, indent=2)

    def load_graph(self, filepath: Optional[Path] = None) -> None:
        """Load graph data from JSON file and populate indices."""
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
            self.add_edge(edge, validate_nodes=False, strict_subject_validation=False)

    def clear(self) -> None:
        """Reset all in-memory graph structures."""
        self.nodes.clear()
        self.edges.clear()
        self._out_edges.clear()
        self._in_edges.clear()


# Default singleton instance for global operational graph
default_graph_engine = EvidenceGraphEngine()
