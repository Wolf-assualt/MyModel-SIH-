# TRUST-CV Deployment Guide — x86_64 (Default Development Target)

Platform target: standard 64-bit x86 PCs, workstations, and servers (Windows 10/11, Ubuntu 20.04+, RHEL 8+, macOS).

This is the **default development target**: every package in `backend/requirements.txt` publishes standard pre-built x86_64 wheels, so no special wheel indexes, cross-compilation, or GPU-specific builds are required.

---

## 1. Prerequisites

| Requirement | Details |
| :--- | :--- |
| **Python** | 3.10 – 3.13 (3.14 also verified working with this stack). Check with `python --version`. |
| **OS** | Windows 10/11, Ubuntu 20.04+, RHEL 8+, or macOS. |
| **Network** | Internet access **only** for the initial `pip install`. TRUST-CV itself is 100% air-gapped at runtime. |
| **Disk** | ~6 GB free (PyTorch CPU wheels are the largest component at ~120–800 MB depending on platform). |
| **Build tools** | None required — no compilers, no Node.js, no npm. |

### System packages (Linux only)

On minimal server images you may need basic runtime libraries before installing wheels:

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y python3-venv python3-pip libgomp1

# RHEL/Rocky/Alma
sudo dnf install -y python3-pip python3-devel
```

Windows and macOS need no extra system packages.

---

## 2. Step-by-Step Setup (Virtual Environment)

From the repository root (`MyModel-SIH-/`), all paths below are relative to `MyModel-SIH-/Block-Sentinal/`.

### Step 1 — Enter the project root

```bash
cd Block-Sentinal
```

### Step 2 — Create the virtual environment

```bash
# Linux / macOS
python3 -m venv .venv

# Windows (PowerShell / CMD)
python -m venv .venv
```

### Step 3 — Activate it

```bash
# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (CMD)
.venv\Scripts\activate.bat
```

### Step 4 — Upgrade pip (recommended)

```bash
python -m pip install --upgrade pip
```

---

## 3. Install Dependencies

From `Block-Sentinal/` with the venv active:

```bash
pip install -r backend/requirements.txt
```

This installs the full TRUST-CV stack: FastAPI, Uvicorn, Pydantic v2, SQLAlchemy, cryptography, Pillow, NumPy, **onnx**, **onnxruntime**, torch (CPU), scikit-learn, scipy, and more. All resolve from standard PyPI x86_64 wheels.

Quick sanity check that the core imports resolve:

```bash
python -c "import fastapi, uvicorn, pydantic, sqlalchemy, cryptography, PIL, numpy, onnx, onnxruntime; print('OK')"
```

---

## 4. Launch TRUST-CV

### Option A — Use the project launcher (recommended)

- **Windows:** double-click `run_trust_cv.bat` (repo root) or run `run_trust_cv.bat` from a terminal. It verifies dependencies, creates the `data/` storage tree, runs smoke tests, and starts the server on port 8000.
- **Linux / macOS:** run the equivalent shell launcher:

```bash
chmod +x run_trust_cv.sh   # first time only
./run_trust_cv.sh
```

> Note: the launchers install into whatever Python is active. Activate your `.venv` first so dependencies land inside it.

### Option B — Manual launch (venv active, from `Block-Sentinal/`)

```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Add `--reload` during development.

Then open:

- **SOC Command Center UI:** http://localhost:8000
- **OpenAPI docs:** http://localhost:8000/docs
- **System status:** http://localhost:8000/api/v1/system/status

---

## 5. Verify the Deployment (Optional but Recommended)

Run the latency benchmark to confirm the assurance flow meets the p95 < 42 ms target from the SIH presentation:

```bash
cd backend
python tests/benchmark_latency.py --runs 100
```

Run the automated test suite:

```bash
cd Block-Sentinal
python -m pytest backend/tests/ -q
```

---

## 6. Platform-Specific Notes (x86_64)

- **Standard wheels apply.** Every dependency — including `torch`, `onnx`, and `onnxruntime` — installs from PyPI's pre-built x86_64 wheels. No source builds.
- **This is the default development target.** All project documentation, tests, and benchmarks are validated here first; treat other platforms as ports of this baseline.
- **GPU optional.** The stack runs CPU-only by default. If you have an NVIDIA GPU and want CUDA-accelerated `torch`/`onnxruntime`, install the CUDA variants manually (e.g. `onnxruntime-gpu` and the CUDA-enabled torch index) — TRUST-CV's own pipelines are pure NumPy/ONNX-CPU and do not require it.
- **Performance reference:** on a typical x86_64 dev machine, the end-to-end assurance flow benchmarks at ~25 ms mean / ~29 ms p95 (target < 42 ms).
- **Air-gap tip:** to deploy on an offline machine, run `pip download -r backend/requirements.txt -d wheels/` on a connected x86_64 machine with the same OS/Python version, copy the `wheels/` folder over, then `pip install --no-index --find-links wheels/ -r backend/requirements.txt` on the target.
