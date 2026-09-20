# Directed Evidence & Provenance Graph Specification

## 1. Architectural Overview

The Evidence and Provenance Graph in TRUST-CV models the multi-layer lifecycle of computer vision assets as an in-memory, cryptographically grounded directed property graph.

The graph interconnects data contributors, dataset batches, physical samples, verification findings, neural network models, preprocessing configurations, runtime inference receipts, output predictions, drift reports, and gatekeeper decisions into an unbroken provenance fabric.

---

## 2. 14-Entity Assurance Ontology

TRUST-CV formally connects 14 primary entity types across the assurance lifecycle:

```
[ Contributor ]
      | (AUTHORED_BY / PROVIDED)
      v
  [ Dataset ] <---------------- (VERSION_OF) -- [ Dataset Version ]
      |
      +-- (CONTAINS_SAMPLE) ----> [ Sample ]
      |
      +-- (TRAINED_ON) ---------> [ Training Run ]
                                        | (PRODUCED)
                                        v
                                    [ Model ] <--- (VERSION_OF) -- [ Model Version ]
                                        |                                |
                      (USED_PREPROCESSING)                               | (GENERATED_BY)
                                        v                                v
                          [ Preprocessing Config ]                 [ Inference ]
                                                                         | (HAS_OUTPUT)
                                                                         v
                                                                     [ Output ]

   Associated Governance & Assurance Nodes:
   - [ Finding ]                 : Integrity and vulnerability discoveries (attached via FLAGGED_WITH)
   - [ Drift Assessment ]        : Distribution shift reports (attached via ASSESSED_IN)
   - [ Contributor Assessment ]  : Contributor risk scorecards (attached via DECIDES_ON)
   - [ Analyst Decision ]        : Human SOC gatekeeper determinations (attached via DECIDES_ON)
   - [ Audit Event ]             : Cryptographic hash chain log events
   - [ Report ]                  : Sealed mission-readiness and compliance documents
```

| Entity Type | Enum Value (`NodeType`) | Description & Metadata |
| :--- | :--- | :--- |
| **Contributor** | `CONTRIBUTOR` | Real authenticated vendor, sensor station, or operator identity. Unverified contributors remain strictly `UNKNOWN`. |
| **Dataset** | `DATASET` | Ingested image collection, COCO, YOLO, or satellite partition with canonical manifest. |
| **Sample** | `SAMPLE` | Individual image file with SHA-256 digest, dimensions, and perceptual hash. |
| **Finding** | `FINDING` / `EVIDENCE` | Deterministic verification result (backdoor trigger, duplicate, weight tamper, drift anomaly). |
| **Model** | `MODEL` | Trained computer vision neural network architecture (ONNX, PyTorch, TorchScript). |
| **Model Version** | `MODEL_VERSION` | Specific immutable checkpoint version sealed with weight SHA-256 digest. |
| **Preprocessing Config** | `PREPROCESSING_CONFIG` | Deterministic transformation parameters (resizing, normalization mean/std, color space). |
| **Inference** | `INFERENCE` | Runtime execution event sealed in an immutable Inference DNA receipt. |
| **Output** | `OUTPUT` | Bounding box, class logits, segmentation mask, or prediction digest. |
| **Drift Assessment** | `DRIFT_ASSESSMENT` | Statistical distribution comparison report against reference baseline. |
| **Contributor Assessment** | `CONTRIBUTOR_ASSESSMENT` | Dynamic historical risk scorecard evaluating contributor track record. |
| **Analyst Decision** | `ANALYST_DECISION` | Human review verdict, sign-off, or quarantine override record. |
| **Audit Event** | `AUDIT_EVENT` | Immutable event block in the append-only cryptographic audit chain. |
| **Report** | `REPORT` | Sealed mission assurance report or regulatory compliance export. |

---

## 3. Mandatory Edge Evidence Invariant

> **Critical Invariant**: Every directed edge in the graph **must** possess a non-empty `evidence_id`.
> Floating, ungrounded, or unverifiable relationships are strictly prohibited.

When edges are created, an explicit cryptographic evidence ID or reference ID is attached:
```python
edge = GraphEdge(
    source_id="batch_flir_101",
    target_id="vendor_alpha",
    edge_type=EdgeType.AUTHORED_BY,
    evidence_id="auth_batch_flir_101_vendor_alpha",
    metadata={"ingest_timestamp": "2026-09-20T12:00:00Z"},
)
```

---

## 4. Graph Traversals & Blast Radius Analysis

### 4.1 Upstream Provenance (`trace_upstream`)
Traverses backwards from any downstream artifact (e.g. an erroneous detection or compromised inference) to identify its exact origin:
$$\text{Output} \longrightarrow \text{Inference} \longrightarrow \text{Model Checkpoint} \longrightarrow \text{Training Run} \longrightarrow \text{Dataset} \longrightarrow \text{Contributor}$$

### 4.2 Downstream Blast-Radius Analysis (`calculate_blast_radius`)
When a training batch is found poisoned or a model checkpoint is tampered, the engine conducts a forward BFS traversal to quantify the blast radius:
- Affected downstream training runs
- Affected deployed model versions
- Affected inference executions and telemetry streams
- Active quarantine orders generated

### 4.3 Bidirectional Lineage (`trace_lineage`)
Combines upstream provenance, downstream blast radius, and all associated verification findings into a unified `LineageTraceResponse`.

---

## 5. Contributor Risk Aggregation

The `ContributorRiskEngine` calculates explainable, objective risk profiles from historical graph provenance:

### Invariants:
1. **Real Identities Only**: The engine aggregates only real, verified contributor identities. No synthetic, demo, or guessed identities are fabricated.
2. **Unverified Contributor Rule**: If a contributor ID is missing, empty, or unverified, it is strictly normalized to `"UNKNOWN"` (`name = "Unknown Contributor"`).
3. **Objective Forensic Tone**: Risk narratives explicitly state that statistical evaluations reflect artifact verification findings and do not constitute an assertion of malicious intent.
4. **Quarantine Escalation**: If active quarantines are attached to a contributor's downstream assets, or if multiple CRITICAL findings are discovered, the contributor profile escalates to `QUARANTINED`.

---

## 6. Cryptographic Graph Integrity & Export

The entire graph state is deterministically serialized and sealed:
1. Nodes and edges are sorted by primary keys (`node.id`, `(source_id, target_id, edge_type)`).
2. The sorted structure is hashed using Canonical JSON SHA-256 (`graph_digest`).
3. `verify_graph_integrity` checks for broken edges (endpoints not in graph), detects orphan vertices, and ensures digest continuity across air-gapped system restarts.
