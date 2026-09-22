# TRUST-CV Deployment Guide — ARM64 (aarch64 Linux / Apple Silicon)

Platform target: 64-bit ARM devices — AWS Graviton / Ampere servers, Raspberry Pi 5 (8 GB), Apple Silicon (M1/M2/M3, via Rosetta-free native Python), and other aarch64 Linux SBCs.

---

## 1. Prerequisites

| Requirement | Details |
| :--- | :--- |
| **Python** | 3.10 – 3.12 recommended. Check with `python3 --version`. On Apple Silicon use a native arm64 Python build (not x86_64-under-Rosetta). |
| **OS** | Ubuntu 20.04+/22.04/24.04 (arm64), Debian 12 (arm64), or macOS 13+ (Apple Silicon). |
| **Network** | Internet access only for the initial `pip install`; TRUST-CV itself is 100% air-gapped at runtime. |
| **RAM** | ≥ 4 GB minimum; 8 GB recommended (torch wheel extraction and model fingerprinting are memory-hungry). |
| **Disk** | ~6 GB free. |
| **Build tools** | Usually none — but see the wheel-availability notes in §6; a C compiler and headers are the fallback if a package has no ARM64 wheel for your Python version. |

### System packages (Linux)

```bash
sudo apt-get update && sudo apt-get install -y \
    python3-venv python3-pip python3-dev build-essential libgomp1 libopenblas-dev
```

`libopenblas-dev` significantly improves NumPy/scipy performance on ARM where MKL is unavailable.

---

## 2. Step-by-Step Setup (Virtual Environment)

From the repository root (`MyModel-SIH-/`), all paths are relative to `MyModel-SIH-/Block-Sentinal/`.

### Step 1 — Enter the project root

```bash
cd Block-Sentinal
```

### Step 2 — Create the virtual environment

```bash
python3 -m venv .venv
```

### Step 3 — Activate it

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
```

---

## 3. Install Dependencies

```bash
pip install -r backend/requirements.txt
```

Sanity check:

```bash
python -c "import fastapi, uvicorn, pydantic, sqlalchemy, cryptography, PIL, numpy, onnx, onnxruntime; print('OK')"
```

If the import check fails on `torch` or `onnxruntime`, read §6 — those two packages are the usual ARM64 friction points.

---

## 4. Launch TRUST-CV

### Option A — Project launcher (Linux / macOS)

```bash
chmod +x run_trust_cv.sh   # first time only
./run_trust_cv.sh
```

The launcher verifies dependencies, creates the `data/` storage tree, runs smoke tests, and starts the server on port 8000. Activate your `.venv` first so the dependency check resolves against the venv.

### Option B — Manual launch (venv active, from `Block-Sentinal/`)

```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Then open:

- **SOC Command Center UI:** http://localhost:8000
- **OpenAPI docs:** http://localhost:8000/docs

### Windows-on-ARM note

The `run_trust_cv.bat` launcher works on Windows-on-ARM64, but Python package availability is thinner there (see §6). The aarch64 Linux path is the better-tested route.

---

## 5. Verify the Deployment

```bash
cd backend
python tests/benchmark_latency.py --runs 100
cd ..
python -m pytest backend/tests/ -q
```

---

## 6. Platform-Specific Notes (ARM64)

### Pre-built ARM64 wheels required for `onnxruntime` and `torch`

These two packages are the heavy native dependencies and **must resolve as pre-built aarch64 wheels** — building them from source on-device is impractical (hours of compile time, huge RAM):

- **`torch`**: official PyPI publishes `aarch64` (manylinux) and `macosx_arm64` wheels for CPython 3.10–3.12. On aarch64 Linux they install directly with `pip install torch`. For CPython 3.13+ on some distros, availability can lag — prefer Python 3.10–3.12 on ARM.
- **`onnxruntime`**: official PyPI publishes `aarch64` manylinux wheels for CPython 3.10–3.12 (and newer in recent releases). If `pip` tries to build from source or errors with "no matching distribution":
  1. Confirm you're on 64-bit ARM (`uname -m` → `aarch64`), not 32-bit ARM (`armv7l` — **not supported**; 32-bit ARM has no wheels for this stack).
  2. Downgrade to Python 3.10–3.12, where wheel coverage is complete.
  3. As a last resort, use the pre-release channel: `pip install --pre onnxruntime`.

### Known package-availability issues

| Package | aarch64 Linux status | Apple Silicon (arm64 macOS) status |
| :--- | :--- | :--- |
| `numpy`, `scipy`, `scikit-learn` | ✅ manylinux aarch64 wheels | ✅ universal2/arm64 wheels |
| `torch` | ✅ aarch64 wheels (PyTorch 2.x); older versions may need the PyTorch index | ✅ native arm64 wheels |
| `onnx` | ✅ aarch64 wheels (pure protobuf + small native ext) | ✅ arm64 wheels |
| `onnxruntime` | ⚠️ aarch64 wheels exist for recent versions; verify your Python minor version is covered | ⚠️ arm64 wheels published since 1.16; use latest |
| `opencv-python-headless` | ✅ aarch64 wheels (since v4.x) | ✅ arm64 wheels |
| `cryptography` | ✅ (ships abi3 wheels covering aarch64) | ✅ |

Additional gotchas:

- **Raspberry Pi OS (32-bit)** is not supported — install the 64-bit Raspberry Pi OS (aarch64) variant.
- **Old pip = broken resolution.** Some aarch64 wheels only upload newer-manylinux tags; `pip install --upgrade pip` inside the venv fixes most "no matching distribution" errors.
- **Jetson devices:** do **not** follow this guide — Jetson needs NVIDIA's L4T-specific wheels. Use [`deployment/nvidia_jetson/`](../nvidia_jetson/README.md) instead.
- **Air-gap tip:** on a connected aarch64 machine with the same OS and Python version, run `pip download -r backend/requirements.txt -d wheels/ --platform manylinux2014_aarch64 --only-binary=:all:` and carry the wheels folder to the target.
