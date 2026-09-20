# Model Assurance Architecture

## 1. Overview & Objectives

Phase 4 of TRUST-CV establishes an authoritative, air-gapped, model-aware assurance layer. It replaces all legacy surrogate analysis (previously simulated via random projection matrices in `ModelExecutor` and fabricated layer heuristics in `_binary_fallback`) with **actual local model inspection and real runtime inference**.

The system operates strictly offline, computing all cryptographic digests and behavioural probe responses directly from current model artifacts on disk.

```
+-----------------------------------------------------------------------------------+
|                            TRUST-CV Model Assurance Pipeline                      |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
                              [ Model Artifact on Disk ]
                                          |
                        +-----------------+-----------------+
                        |                                   |
                        v                                   v
             [ SHA-256 File Rehash ]             [ Format Auto-Detection ]
                        |                                   |
                        |                    +--------------+--------------+
                        |                    |              |              |
                        |                    v              v              v
                        |                 [ ONNX ]    [TorchScript]   [Safe PyTorch]
                        |                    |              |              |
                        |                    v              v              v
                        |              (ONNX Runtime)  (torch.jit)  (weights_only)
                        |                    |              |              |
                        +--------------------+--------------+--------------+
                                          |
                                          v
                            +---------------------------+
                            | BaseModelAdapter Lifecycle|
                            |   - load()                |
                            |   - metadata()            |
                            |   - input_schema()        |
                            |   - output_schema()       |
                            |   - predict()             |
                            |   - fingerprint()         |
                            |   - close()               |
                            +---------------------------+
                                          |
         +--------------------------------+--------------------------------+
         |                                |                                |
         v                                v                                v
[ 1. Binary Tier ]               [ 2. Structural Tier ]          [ 3. Behavioural Tier ]
  - Disk SHA-256 vs Baseline       - Node & param counts           - Deterministic probe battery
  - MATCH / MISMATCH / UNAVAIL     - Input / output tensor specs   - ProbeRecord per sample
                                   - MATCH / MISMATCH / UNAVAIL    - MATCH / MISMATCH / UNAVAIL
         |                                |                                |
         +--------------------------------+--------------------------------+
                                          |
                                          v
                            +---------------------------+
                            |     Trigger Sensitivity   |
                            | - Patch vs. Noise shift   |
                            | - Class collapse check    |
                            | - CLEAN / SUSPICIOUS /    |
                            |   UNAVAILABLE             |
                            +---------------------------+
                                          |
                                          v
                            [ ModelAssuranceFinding ]
```

---

## 2. Model Adapter Architecture

All model formats are integrated via the common abstract interface `BaseModelAdapter` in [`backend/app/models_engine/adapters/base.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/models_engine/adapters/base.py):

| Method / Property | Description |
|---|---|
| `artifact_hash` | SHA-256 computed directly from current file on disk via `hash_file()`. Never cached blindly. |
| `rehash()` | Forces immediate re-read of artifact bytes from disk to detect local modifications. |
| `format` | Returns `ModelFormat` (`ONNX`, `TORCHSCRIPT`, `PYTORCH_WEIGHTS`, `BLACK_BOX`). |
| `access_mode` | Returns `AccessMode` (`WHITE_BOX`, `BLACK_BOX`, `PARTIAL`). |
| `load()` | Initializes runtime session / parses proto structures safely into memory. |
| `metadata()` | Returns real node counts, parameter statistics, opset versions, and framework metadata. |
| `input_schema()` | Returns formal tensor input specifications (`name`, `shape`, `data_type`). |
| `output_schema()` | Returns formal tensor output specifications (`name`, `shape`, `data_type`). |
| `predict(inputs)` | Performs actual forward pass inference returning numpy logits / probabilities. |
| `fingerprint()` | Computes deterministic structural digest of nodes and parameter initializers. |
| `close()` | Frees allocated inference sessions, CPU handles, and memory. |

---

## 3. Cryptographic Model Identity

Every registered model receives a tamper-evident `ModelIdentityManifest`:
- **`artifact_hash`**: Direct 64-character SHA-256 digest of the model file on disk.
- **`binary_sha256`**: Exact match to `artifact_hash`.
- **`format`**: Formal enum identifying the detected format.
- **`access_mode`**: Declares whether internal architecture is inspectable (`WHITE_BOX`), opaque (`BLACK_BOX`), or restricted (`PARTIAL`).
- **`architecture_info`**: Graph details including node types, opsets, IR versions, and parameter statistics.
- **`inputs` & `outputs`**: Exact tensor dimensions and data types extracted from the graph.
- **`identity_digest`**: Canonical JSON SHA-256 digest of canonical structural properties (`name`, `version`, `format`, `parameter_count`, `node_count`, `inputs`, `outputs`).
- **`scanner_version`**: Fixed version string `"1.0.0"`.

---

## 4. Three-Tier Reference Verification

Model verification against reference baselines explicitly distinguishes three independent tiers, returning `MATCH`, `MISMATCH`, or `UNAVAILABLE`:

1. **Binary Identity**:
   - `MATCH`: Current file SHA-256 equals reference baseline SHA-256.
   - `MISMATCH`: Artifact bytes differ.
   - `UNAVAILABLE`: No registered reference baseline exists.

2. **Structural Identity**:
   - `MATCH`: Canonical graph digest, node count, layer count, parameter count, input specs, and output specs match reference baseline.
   - `MISMATCH`: Any architectural discrepancy detected.
   - `UNAVAILABLE`: Model has `BLACK_BOX` access mode or structural inspection is unsupported.

3. **Behavioural Identity**:
   - `MATCH`: Cosine similarity between candidate and reference probe outputs >= 0.999 (or matching canonical digests).
   - `MISMATCH`: Output divergence exceeds threshold or prediction flips occur on identical inputs.
   - `UNAVAILABLE`: Model runtime cannot execute forward passes (e.g. `PYTORCH_RUNTIME_UNAVAILABLE` for raw weights).

---

## 5. Real Behavioural Fingerprinting

Surrogate matrix projection (`ModelExecutor`) has been **completely removed from production**.

Behavioural fingerprints are generated by feeding deterministic probe images (from `TestBatteryGenerator`) through the actual model runtime:
- Probes are perturbed using standard operations: `IDENTITY`, `GAUSSIAN_NOISE`, `GAUSSIAN_BLUR`, `CONTRAST_SHIFT`, `ROTATION`.
- For every individual probe, a `ProbeRecord` is persisted containing:
  - `probe_id`: Unique probe identifier (e.g. `IDENTITY_probe_0`).
  - `input_hash`: SHA-256 digest of the raw input image bytes.
  - `output_hash`: SHA-256 digest of the raw output tensor bytes.
  - `canonical_output`: Rounded floating-point vector of the actual output activations.
  - `model_hash`: SHA-256 digest of the tested model artifact.
- The `aggregate_digest` is computed as a canonical JSON SHA-256 hash across all probe records and perturbation results.

---

## 6. Standardized Model Assurance Finding

Findings emitted by the model assurance stage adhere to the `ModelAssuranceFinding` schema:
```json
{
  "model_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "artifact_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "format": "ONNX",
  "access_mode": "WHITE_BOX",
  "identity_status": "MATCH",
  "structural_status": "MATCH",
  "behavioural_status": "MATCH",
  "trigger_status": "CLEAN",
  "confidence": 1.0,
  "confidence_basis": "Deterministic cryptographic file SHA-256 hash direct from disk.",
  "evidence": {
    "name": "TargetClassifier",
    "version": "1.0.0",
    "parameter_count": 30730,
    "node_count": 3,
    "binary_match": true,
    "structural_match": true
  },
  "limitations": [
    "Assurance is verified using local offline runtimes (ONNX Runtime, TorchScript).",
    "Pickle-based arbitrary PyTorch code execution is disabled to prevent code injection."
  ],
  "created_at": "2026-09-20T16:04:00Z"
}
```
