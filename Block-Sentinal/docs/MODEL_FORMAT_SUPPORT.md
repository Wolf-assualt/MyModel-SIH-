# Model Format Support Matrix

## 1. Supported Formats Overview

TRUST-CV enforces strict security boundaries to prevent remote code execution (RCE) via untrusted serialized objects (such as arbitrary Python `pickle` payloads). Only formats that can be safely loaded and executed locally in an air-gapped environment are supported.

| Model Format | Safe Loading Method | Real Inference Runtime | Access Mode | Structural Graph Inspection | Security Posture |
|---|---|---|---|---|---|
| **ONNX** (`.onnx`) | `onnx.load(load_external_data=False)` | `onnxruntime.InferenceSession` (`CPUExecutionProvider`) | `WHITE_BOX` | ✅ Complete (nodes, opsets, initializers, parameter counts) | Safe protobuf schema; no arbitrary code execution. |
| **TorchScript** (`.pt`, `.ts`) | `torch.jit.load(map_location="cpu")` | PyTorch JIT execution engine (`module.eval()`) | `WHITE_BOX` | ✅ Modules, buffers, parameters, JIT schema | Static intermediate representation; sandboxed from arbitrary Python code execution. |
| **PyTorch Weights** (`.pt`, `.pth`, `.bin`) | `torch.load(weights_only=True, map_location="cpu")` | ❌ `PYTORCH_RUNTIME_UNAVAILABLE` | `PARTIAL` | ⚠️ State dictionary tensor names and parameter counts only | Safe weights inspection only. Forward execution is disallowed because raw weights lack executable graphs without arbitrary unpickling. |
| **Black-Box API / Callable** | Opaque wrapper | Custom executable callable / inference function | `BLACK_BOX` | ❌ `UNAVAILABLE` (marked explicitly) | Unobservable graph internals; evaluated solely on behavioural probe outputs. |
| **Unsupported Formats** (arbitrary `.pkl`, non-model binaries) | ❌ Rejected | ❌ Rejected | `UNAVAILABLE` | ❌ Rejected | System raises `UNSUPPORTED_FORMAT` immediately. |

---

## 2. Format Details & Capabilities

### 2.1 ONNX (`ONNXAdapter`)
- **Runtime**: ONNX Runtime CPU (`onnxruntime` v1.30.0).
- **Inspection**:
  - Node count and operator breakdown (`Gemm`, `Conv`, `Relu`, `Softmax`, etc.).
  - Initializer counts and exact parameter sum.
  - IR version, producer metadata, and opset domain imports.
  - Input tensor names, shapes, and elemental data types.
  - Output tensor names and shapes.
- **Inference**:
  - Real input normalization and shape alignment.
  - Passes feeds to `ort.InferenceSession.run()`.
  - Extracts real activation probabilities.

### 2.2 TorchScript (`TorchScriptAdapter`)
- **Runtime**: PyTorch JIT (`torch.jit`).
- **Inspection**:
  - Safe local loading via `torch.jit.load(map_location="cpu")`.
  - Introspects submodules, parameter tensor elements, and buffer shapes.
  - Extracts input/output type annotations from JIT forward schema.
- **Inference**:
  - Real tensor conversion on CPU (`torch.from_numpy`).
  - Executes forward pass under `torch.no_grad()`.

### 2.3 PyTorch Weights-Only (`PyTorchAdapter`)
- **Security Rule**: Arbitrary unpickling is **strictly forbidden**.
- **Inspection**:
  - Employs `weights_only=True` to reject any payload containing arbitrary class constructors, globals, or executable Python bytecode.
  - Calculates parameter counts and layer names directly from the state dictionary.
- **Inference Limitation**:
  - Raw `state_dict` checkpoints contain only tensor weights without computational graph wiring.
  - Executing forward passes requires instantiating user-defined Python classes.
  - To prevent unsafe code execution, `PyTorchAdapter.predict()` raises:
    `RuntimeError("PYTORCH_RUNTIME_UNAVAILABLE: Execution of raw PyTorch state_dict requires external model class definition. Arbitrary Python-dependent execution is forbidden for security.")`
  - The system reports `behavioural_identity == UNAVAILABLE` and never fabricates surrogate outputs.

### 2.4 Black-Box Models (`BlackBoxAdapter`)
- For models accessed through inference callables or remote air-gapped endpoints where the internal network graph is unobservable.
- Exposes `AccessMode.BLACK_BOX`.
- Explicitly marks `structural_status = UNAVAILABLE`.
- Executes actual inferences on deterministic probe batteries without fabricating fake layer counts or parameter estimates.

---

## 3. Handling Unsupported Formats

When an unrecognized, corrupted, or unsafe model artifact is ingested:
1. `ModelAdapterFactory.get_adapter()` raises `ValueError(f"UNSUPPORTED_FORMAT: Model format {fmt} is not safely supported locally.")`.
2. The registration API returns `HTTP 400 Bad Request` with machine-readable error details.
3. No fake identity manifest, no simulated parameters, and no fake PASS status are generated.
