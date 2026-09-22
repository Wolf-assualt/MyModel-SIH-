# TRUST-CV Deployment Guide — NVIDIA Jetson (L4T, aarch64 + GPU)

Platform target: NVIDIA Jetson modules — Orin (AGX Orin / Orin NX / Orin Nano) and Xavier — running **JetPack 5.x / 6.x** (Linux for Tegra, L4T r34.x–r36.x).

Jetson is aarch64, but it is **not** a standard ARM64 target: PyPI's generic aarch64 `torch` / `onnxruntime` wheels are not built against L4T's CUDA stack. GPU-enabled wheels must come from NVIDIA's Jetson wheel indexes — or skip native setup entirely and use the Docker container (§7), which is the recommended path.

---

## 1. Prerequisites

| Requirement | Details |
| :--- | :--- |
| **Hardware** | Jetson Orin / Orin NX / Orin Nano / Xavier (8 GB RAM minimum recommended) |
| **JetPack / L4T** | JetPack 5.x (L4T r35.x) or JetPack 6.x (L4T r36.x) with NVIDIA drivers + CUDA runtime. Check with `cat /etc/nv_tegra_release` and `nvcc --version` or `jetson_release`. |
| **Python** | The L4T system Python (3.8 on JetPack 5, 3.10 on JetPack 6). **Do not replace the system Python** — the NVIDIA stack is built against it. Use a venv (§2). |
| **pip / venv** | `sudo apt-get install -y python3-pip python3-venv` |
| **Storage** | ≥ 16 GB free (Jetson eMMC fills fast; NVMe is strongly preferred). |
| **Swap** | Recommended: 8 GB swap file — `torch` wheel installation and model fingerprinting can OOM a small-RAM module without it. See NVIDIA's `setnvzram` or a plain swapfile. |
| **Network** | Internet only for setup; TRUST-CV itself is 100% air-gapped at runtime. |

---

## 2. Step-by-Step Setup (Virtual Environment)

All paths are relative to the repository root (`MyModel-SIH-/Block-Sentinal/`).

```bash
cd Block-Sentinal

# Create and activate the venv (use the L4T system Python)
python3 -m venv .venv --system-site-packages
source .venv/bin/activate
python -m pip install --upgrade pip
```

> **Why `--system-site-packages`?** The NVIDIA-provided CUDA / TensorRT / numpy system packages already on the device remain visible inside the venv, so the GPU wheels installed in §3 can link against them. Without this flag you would need to re-install large NVIDIA system packages inside the venv.

---

## 3. Install Dependencies

### 3a. Everything that installs normally from PyPI

```bash
# Install the project requirements, temporarily excluding torch/onnxruntime
grep -vE '^(torch|onnxruntime)' backend/requirements.txt > /tmp/requirements-jetson.txt
pip install -r /tmp/requirements-jetson.txt
```

### 3b. L4T-compatible `torch` (NVIDIA Jetson wheel index)

PyPI's `torch` aarch64 wheel will **not** give you GPU support on Jetson. Install the NVIDIA-built wheel matching your JetPack:

```bash
# JetPack 6.x (L4T r36.x) example:
pip install torch==2.5.0a0 \
    -f https://developer.download.nvidia.com/compute/redist/jp/v61/torch/

# JetPack 5.x (L4T r35.x) example:
pip install torch==2.0.0+nv23.05 \
    -f https://developer.download.nvidia.com/compute/redist/jp/v51/torch/
```

Browse https://developer.download.nvidia.com/compute/redist/jp/ to find the exact wheel for your L4T version.

### 3c. `onnxruntime-gpu` from the Jetson wheels index

The plain `onnxruntime` wheel from PyPI is CPU-only and CUDA-incompatible on L4T. Use the GPU build:

```bash
pip install onnxruntime-gpu==1.19.0 \
    --extra-index-url https://aiinfra.pkgs.visualstudio.com/PublicPackages/_packaging/onnxruntime-cuda-12/pypi/simple/
```

(For JetPack 5 / CUDA 11, use the `onnxruntime-cuda-11` Azure DevOps index instead, or NVIDIA's shared wheel links from the [onnxruntime Jetson page](https://onnxruntime.ai/docs/execution-providers/CUDA-ExecutionProvider.html#_requirements).)

### 3d. Verify

```bash
python -c "import fastapi, uvicorn, pydantic, sqlalchemy, cryptography, PIL, numpy, onnx, onnxruntime; print('OK')"
python -c "import onnxruntime as ort; print(ort.get_available_providers())"
# Expect: ['CUDAExecutionProvider', 'CPUExecutionProvider'] on a correct GPU install
```

---

## 4. Launch TRUST-CV

### Option A — Project launcher

```bash
chmod +x run_trust_cv.sh   # first time only
./run_trust_cv.sh
```

The launcher verifies dependencies, creates the `data/` storage tree, runs smoke tests, and starts the server on port 8000. (The `.bat` launcher is Windows-only; `run_trust_cv.sh` is its Linux equivalent.)

### Option B — Manual launch (venv active, from `Block-Sentinal/`)

```bash
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
```

Then open (from any machine on the same network):

- **SOC Command Center UI:** `http://<jetson-ip>:8000`
- **OpenAPI docs:** `http://<jetson-ip>:8000/docs`

---

## 5. Verify the Deployment

```bash
cd backend
python tests/benchmark_latency.py --runs 100
```

The 42 ms p95 target is calibrated on x86_64; expect noticeably higher absolute numbers on Jetson (different CPU class, first-run ONNX session init). Watch the per-stage breakdown: fingerprinting and inference dominate, and both benefit from the GPU wheels in §3.

Also run the test suite:

```bash
cd ..
python -m pytest backend/tests/ -q
```

---

## 6. Platform-Specific Notes (Jetson)

- **L4T-compatible wheels are mandatory for GPU use.** PyPI `torch`/`onnxruntime` aarch64 wheels are built for generic ARM Linux and either lack CUDA or fail to load `libcudart` from L4T. Always use:
  - `torch` from NVIDIA's Jetson wheel index (`developer.download.nvidia.com/compute/redist/jp/...`)
  - `onnxruntime-gpu` from the Jetson wheels index (NVIDIA-shared wheel or the Azure DevOps `onnxruntime-cuda-12` / `-cuda-11` index)
- **Version coupling is strict.** The wheel series must match your JetPack/L4T and CUDA version (JetPack 6.x → CUDA 12 → `onnxruntime-cuda-12` index; JetPack 5.x → CUDA 11). Mismatches surface as `onnxruntime.capi` load errors at import time.
- **CPU fallback is acceptable.** TRUST-CV's own engines (hashing, Merkle, drift, fusion, graph) are pure NumPy — they run fine even if only CPU inference is available. The GPU wheels accelerate the ONNX inference stage of the assurance flow.
- **Don't use the generic ARM64 guide here** — see [`deployment/arm64/`](../arm64/README.md) only for non-Jetson aarch64 hosts.
- **Performance headroom:** on Orin-class modules, running the assurance flow on GPU-offloaded inference comfortably keeps the p95 latency target; on Nano-class modules use `--runs 100` and inspect p99, and consider pinning CPU governor to performance mode (`sudo jetson_clocks`).

---

## 7. Docker Deployment (Recommended)

The `Dockerfile` in this directory packages everything on the NVIDIA L4T ML base image — no manual wheel hunting on the device.

### Build on the Jetson (or any aarch64 host with NVIDIA Container Toolkit)

```bash
# From the repository root (MyModel-SIH-/)
docker build -t trust-cv:jetson \
    -f Block-Sentinal/deployment/nvidia_jetson/Dockerfile \
    Block-Sentinal/
```

The image is built `FROM nvcr.io/nvidia/l4t-ml:r36.4.0-py3` (JetPack 6.x series). For JetPack 5.x devices, change the base image tag to the matching `r35.x` L4T-ML image — the base tag **must** match your host's L4T version or CUDA will not initialize.

### Run with the NVIDIA runtime

```bash
docker run -d \
    --name trust-cv \
    --runtime nvidia \
    --network host \
    -v /home/<user>/trust-cv-data:/app/data \
    --restart unless-stopped \
    trust-cv:jetson
```

Key flags:

| Flag | Purpose |
| :--- | :--- |
| `--runtime nvidia` | Injects the host's CUDA driver libraries into the container (requires [NVIDIA Container Toolkit / nvidia-container-runtime](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) on the Jetson). Without it, onnxruntime-gpu falls back to CPU. |
| `--network host` | Exposes the server directly on the Jetson's port 8000 (no `-p` mapping needed). |
| `-v ...:/app/data` | Persists the air-gapped storage tree (manifests, ledger, inference DNA) outside the container. |

Equivalently with newer Docker (≥ 25) syntax: replace `--runtime nvidia` with `--gpus all`.

### Verify the container

```bash
# GPU provider visible inside the container?
docker exec trust-cv python3 -c \
    "import onnxruntime as ort; print(ort.get_available_providers())"

# Server healthy?
curl http://localhost:8000/api/v1/system/status
```

Then open `http://<jetson-ip>:8000` for the SOC Command Center.

### Prerequisite on the Jetson host

Docker must be able to use the NVIDIA runtime. If `docker run --runtime nvidia ...` fails with "unknown runtime", install the NVIDIA Container Toolkit and reconfigure Docker:

```bash
sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker
```
