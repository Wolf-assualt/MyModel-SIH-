# Phase 7: Real Model Runtime & Inference Execution

## 1. Overview & Objective

Phase 7 of TRUST-CV (`Block-Sentinal`) eliminates the `MODEL_RUNTIME = UNAVAILABLE` barrier by providing a backend-authoritative, local ONNX model execution pipeline. It provides deterministic input preprocessing, structural and tensor contract validation, runtime execution via `onnxruntime`, strict output validation, and cryptographic provenance binding into immutable **Inference DNA** records.

### Non-Negotiable Invariants:
1. **No Fabricated Evidence Rule**: The system never generates fake bounding boxes, mock confidence percentages, synthetic labels, or demo output hashes. If a model cannot be loaded or an input is missing, the status is explicitly reported as `UNAVAILABLE` or `FAILED`.
2. **Local Air-Gapped Execution**: Execution operates fully offline on local CPU hardware using `onnxruntime` (v1.30.0) without external API dependencies.
3. **Cryptographic Grounding**: Every execution record cryptographically binds the model artifact SHA-256, input SHA-256, preprocessing configuration hash, runtime output SHA-256, timestamp, sequence number, and nonce into an ECDSA-signed Inference DNA record.

---

## 2. 10-Stage Lifecycle State Machine

The runtime engine ([`app/runtime/engine.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/runtime/engine.py)) manages models through an auditable state machine with event logging:

```
[DISCOVERED]
     ↓
[VALIDATING] ──(Validation Error)──> [INVALID]
     ↓ (Success)
  [VALID]
     ↓
[RUNTIME_LOADING] ──(Load Error)───> [FAILED]
     ↓ (Session Ready)
[RUNTIME_READY]
     ↓
  [EXECUTING] ──(Non-finite / Shape Error)──> [FAILED]
     ↓ (Output Validated)
 [COMPLETED]
```

### State Definitions ([`app/schemas/runtime.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/schemas/runtime.py)):
* **`DISCOVERED`**: Model artifact path located on filesystem or referenced in manifest.
* **`VALIDATING`**: Inspecting ONNX proto headers, operator sets, initializers, and tensor contracts.
* **`VALID`**: Model structure conforms to ONNX specifications and is verified intact.
* **`INVALID`**: Model proto corrupted, malformed, or fails ONNX proto checks.
* **`RUNTIME_LOADING`**: Instantiating `ort.InferenceSession` with CPU execution provider.
* **`RUNTIME_READY`**: Session instantiated, cached, and ready for tensor feeds.
* **`EXECUTING`**: Preprocessed input array passed to forward pass; latency measured.
* **`COMPLETED`**: Forward pass finished, output validated (all finite, matches schema), and output SHA-256 sealed.
* **`UNAVAILABLE`**: Model binary missing from disk or input image data missing.
* **`FAILED`**: Runtime execution error, non-finite outputs (NaN / Inf), or output schema mismatch.

---

## 3. Deterministic Preprocessing Contract

The preprocessor ([`app/runtime/preprocessor.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/runtime/preprocessor.py)) resolves the exact input tensor contract from the model's ONNX input metadata:

1. **Rank & Layout Detection**:
   - Analyzes shape rank (3 or 4 dimensions).
   - Identifies layout: `NCHW` (`[1, C, H, W]`) or `NHWC` (`[1, H, W, C]`).
2. **Spatial Dimension Resolution**:
   - If fixed dimensions exist in the model graph (e.g. $32 \times 32$ or $640 \times 640$), they are enforced.
   - If spatial dimensions are dynamic (`None`) and no caller override is provided, the preprocessor raises:
     ```python
     RuntimeError("INFERENCE = UNAVAILABLE: Model input contract has dynamic spatial dimensions and no deterministic target_size was specified.")
     ```
3. **Resizing & Normalization**:
   - Bilinear interpolation with PIL (`Image.Resampling.BILINEAR`).
   - Standard channel normalization: $x_{\text{norm}} = \frac{x - \mu}{\sigma}$.
4. **Canonical Preprocessing Hash**:
   - Generates a deterministic SHA-256 hash of all preprocessing parameters (`target_size`, `mean`, `std`, `channel_order`, `dtype`, `color_space`).

---

## 4. Real ONNX Execution & Output Validation

Model execution is powered by `onnxruntime`:

```python
# app/runtime/engine.py
session = ort.InferenceSession(str(path), sess_options=opts, providers=["CPUExecutionProvider"])
raw_outputs = session.run(None, {input_meta.name: tensor_arr})
```

### Strict Output Validation:
Before accepting inference outputs, the engine enforces:
1. **Existence**: Non-null, non-empty output list.
2. **Data Type**: Valid tensor dtype (`float32`, `float64`, `int32`, `int64`, `uint8`).
3. **Finiteness**: Validated via `np.all(np.isfinite(output_arr))`. If any `NaN` or `Inf` values are observed, the engine raises:
   ```text
   INFERENCE_VALIDATION = FAILED: Output tensor contains non-finite values (NaN or Inf).
   ```
4. **Shape Match**: Tensor rank and fixed dimension sizes match output schema.
5. **Raw Output Hash**: Deterministically computed from the contiguous raw bytes:
   ```python
   output_sha256 = hash_bytes(output_arr.tobytes())
   ```

---

## 5. Inference DNA & Cryptographic Binding

Upon output validation, `ModelRuntimeEngine` invokes `InferenceDNAGenerator` ([`app/inference/dna.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/inference/dna.py)) to create an immutable cryptographic proof:

$$\text{DNA} = \text{SHA-256}(\text{CanonicalJSON}(\text{seq}, \text{timestamp}, \text{nonce}, \text{input\_hash}, \text{model\_hash}, \text{prep\_hash}, \text{cfg\_hash}, \text{output\_hash}, \text{prev\_chain\_hash}))$$

The DNA record is signed with ECDSA SECP256R1 and chained to the monotonic audit ledger.

---

## 6. Pipeline & ScanSession Integration

### REST Endpoints ([`app/api/inference.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/api/inference.py)):
* `POST /api/v1/inference/execute`:
  - Requires authentic base64 image data and registered model.
  - Returns `InferenceReceipt` containing signed `dna_record`, raw output statistics, and public key.
  - Never returns fabricated bounding boxes or demo labels.
  - If model is missing: HTTP 404 (`INFERENCE = UNAVAILABLE`).
  - If image data is missing: HTTP 400 (`INFERENCE = UNAVAILABLE`).

### Scan Pipeline ([`app/api/scan.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/api/scan.py)):
* When a dataset scan batch specifies a valid `model_id` and contains image samples, the pipeline executes real forward passes on the samples, verifies output finiteness, and records:
  - `stage_results["INFERENCE_VALIDATION"] = PASSED`
  - `stage_results["BACKDOOR_ANALYSIS"] = PASSED`
* When no model is specified, it strictly preserves the **No Fabricated Evidence Rule**:
  - `stage_results["INFERENCE_VALIDATION"] = UNAVAILABLE` (`ERR_MODULE_OFFLINE`)
  - `stage_results["BACKDOOR_ANALYSIS"] = UNAVAILABLE` (`ERR_MODULE_OFFLINE`)
  - `assessment["inferenceRiskScore"] = -1.0`
