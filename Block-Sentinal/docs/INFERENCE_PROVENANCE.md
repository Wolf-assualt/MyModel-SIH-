# Real Inference Provenance and Cryptographic Binding

This document details the architecture, mathematical specifications, and cryptographic guarantees of the **Inference Provenance and Cryptographic Binding Subsystem** implemented in TRUST-CV.

---

## 1. Architectural Overview

In safety-critical, air-gapped, and mission-critical computer vision deployments, inference results cannot be accepted on faith. TRUST-CV cryptographically binds every inference execution across five foundational pillars into an immutable, verifiable **Inference DNA Record**:

```
+---------------------------------------------------------------------------------------+
|                                    INFERENCE TUPLE                                    |
+-------------------+--------------------+--------------------+--------------------+----+
|       INPUT       |       MODEL        |   PREPROCESSING    |     EXECUTION      |    OUTPUT    |
|   Metadata/Bytes  |   Artifact on Disk |   Transforms/Specs |   Config/Params    | Detections/   |
|   (input_hash)    |    (model_hash)    | (preprocessing_hash| (inference_config_ | Logits       |
|                   |                    |                    |       hash)        | (output_hash)|
+-------------------+--------------------+--------------------+--------------------+----+
                                              |
                                     CANONICAL SERIALIZATION
                                              v
                              +-------------------------------+
                              |    Deterministic DNA Hash     |
                              |    (Canonical SHA-256)        |
                              +-------------------------------+
                                              |
                                     REAL DIGITAL SIGNATURE
                                              v
                              +-------------------------------+
                              |     ECDSA SECP256R1 Seal      |
                              +-------------------------------+
                                              |
                                    APPEND-ONLY AUDIT CHAIN
                                              v
                              +-------------------------------+
                              |  Persistent State & Nonce Log |
                              +-------------------------------+
```

---

## 2. Five-Pillar Canonical Representation

Each component of the inference pipeline produces an independent canonical representation. Serialization utilizes RFC 8785 canonical JSON formatting (sorted keys, strict whitespace elimination, UTC ISO-8601 timestamps, and UTF-8 byte encoding) ensuring that identical configurations produce bit-for-bit identical bytes.

### 2.1. Input Hash (`input_hash`)
- **Direct Frame Input**: Raw frame byte array hashed via SHA-256:
  $$\text{input\_hash} = \text{SHA-256}(\text{frame\_bytes})$$
- **Input Metadata Specification**: Canonical hash of `InputMetadataSpec`:
  ```json
  {
    "data_type": "float32",
    "dimensions": [3, 640, 640],
    "input_frame_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "source_filename": "satellite_pass_042.png"
  }
  ```

### 2.2. Model Identity Hash (`model_hash`)
- Direct streaming SHA-256 hash of the model artifact binary on disk (`.onnx`, `.pt`, `.ts`), verified against `ModelIdentityManifest`.

### 2.3. Preprocessing Hash (`preprocessing_hash`)
- Canonical JSON digest of `PreprocessingSpec`:
  ```json
  {
    "color_space": "RGB",
    "interpolation": "BILINEAR",
    "normalization_mean": [0.485, 0.456, 0.406],
    "normalization_std": [0.229, 0.224, 0.225],
    "target_size": [640, 640]
  }
  ```

### 2.4. Inference Configuration Hash (`inference_config_hash`)
- Canonical JSON digest of `InferenceConfigSpec`:
  ```json
  {
    "batch_size": 1,
    "confidence_threshold": 0.5,
    "device": "cpu",
    "execution_provider": "CPUExecutionProvider",
    "extra_params": {}
  }
  ```

### 2.5. Output Hash (`output_hash`)
- Deterministic SHA-256 digest of raw inference tensor bytes returned by the model adapter runtime:
  $$\text{output\_hash} = \text{SHA-256}(\text{raw\_output\_array.tobytes()})$$
- All predictions (bounding boxes, classifications) are computed directly from this output array. Hardcoded or simulated predictions are strictly prohibited.

---

## 3. Inference DNA Record Specification

The canonical tuple binds all five hashes alongside sequence state and cryptographic provenance:

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `record_id` | `str` | Globally unique record identifier (`dna_<hex16>`) |
| `sequence_number` | `int` | Strictly monotonic sequence index ($s_i = s_{i-1} + 1$) |
| `timestamp` | `str` | UTC ISO-8601 generation timestamp |
| `nonce` | `str` | High-entropy random nonce (minimum 16 bytes hex) |
| `input_hash` | `str` | SHA-256 digest of input frame / metadata |
| `model_hash` | `str` | SHA-256 digest of model artifact on disk |
| `preprocessing_hash` | `str` | Canonical SHA-256 digest of preprocessing configuration |
| `inference_config_hash` | `str` | Canonical SHA-256 digest of inference configuration |
| `output_hash` | `str` | SHA-256 digest of model adapter output |
| `prev_chain_hash` | `str` | Cryptographic tip of preceding block (or $64 \times \text{'0'}$ for genesis) |
| `dna_hash` | `str` | Canonical SHA-256 of the complete bound payload |
| `signature` | `str` | Real ECDSA SECP256R1 signature over `dna_hash` |

---

## 4. Real Model Adapter Execution

Inference execution is driven exclusively by real model adapters (`ONNXAdapter`, `TorchScriptAdapter`):
1. Input frames are preprocessed according to `PreprocessingSpec`.
2. The model binary is loaded directly into an isolated runtime execution session.
3. The real forward pass `adapter.predict(inputs)` executes.
4. Output probabilities/logits are harvested directly from runtime memory.
5. Detection bounding boxes and labels are dynamically derived from top classification scores.

---

## 5. Persistent State & Anti-Replay Defense

To guarantee security across backend reboots, the generator maintains persistent state in `data/inference_dna/state.json`:
- `last_sequence_number`: Ensures monotonic sequencing ($seq_i > seq_{i-1}$) across system restarts. Rollbacks ($seq \le seq_{last}$) are explicitly rejected.
- `seen_nonces`: In-memory and persistent set of all nonces registered. Reused nonces trigger immediate rejection.
- `seen_records`: Record IDs already registered are tracked and blocked from being re-submitted.
- `seen_identities`: Tracks $(model\_id, input, prep, config, output)$ identities.

Every record is atomically stored to `data/inference_dna/{record_id}.json` and verified prior to journal commitment.
