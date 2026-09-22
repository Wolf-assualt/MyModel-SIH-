# TRUST-CV — NVIDIA Jetson (L4T / aarch64 + GPU)

FROM nvcr.io/nvidia/l4t-ml:r36.4.0-py3

LABEL org.opencontainers.image.title="TRUST-CV (SIH26228)" \
      org.opencontainers.image.description="Zero-Trust CV Integrity Assurance platform — Jetson L4T build" \
      org.opencontainers.image.source="https://github.com/example/trust-cv"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# --------------------------------------------------------------------------
# System deps: some L4T base images lack venv/pip tooling and OpenBLAS
# --------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-venv \
        python3-pip \
        libopenblas-dev \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------------------
# Copy requirements first for layer caching, then install.
#
# NOTE: torch / onnxruntime are intentionally NOT installed from PyPI here —
# PyPI's aarch64 wheels are not built against L4T's CUDA and will silently
# fall back to CPU or fail to load the GPU. The L4T PyTorch wheel is installed
# from NVIDIA's Jetson wheel index; onnxruntime is swapped for
# onnxruntime-gpu from the Jetson wheels index (see README).
#
# The filter drops torch/onnxruntime lines from requirements.txt at build
# time; if you add other GPU-sensitive packages, handle them the same way.
# --------------------------------------------------------------------------
COPY backend/requirements.txt /tmp/requirements.txt
RUN grep -vE '^(torch|onnxruntime)' /tmp/requirements.txt > /tmp/requirements-jetson.txt \
    && pip3 install --no-cache-dir -r /tmp/requirements-jetson.txt

# PyTorch for Jetson (JetPack 6.x / L4T r36.x). Version must match the L4T
# series; see https://developer.download.nvidia.com/compute/redist/jp/
RUN pip3 install --no-cache-dir torch==2.5.0a0 \
    -f https://developer.download.nvidia.com/compute/redist/jp/v61/torch/

# onnxruntime-gpu from the Jetson wheels index (L4T-compatible CUDA build).
# If this index URL 404s for your JetPack version, check NVIDIA's
# "onnxruntime for Jetson" wheel listing for the matching series.
RUN pip3 install --no-cache-dir onnxruntime-gpu==1.19.0 \
    -f https://nvidia.box.com/shared/static/49fzcqa1g2rresm9uk60ky6hv3rzuur5.whl \
    || pip3 install --no-cache-dir onnxruntime-gpu \
       --extra-index-url https://aiinfra.pkgs.visualstudio.com/PublicPackages/_packaging/onnxruntime-cuda-12/pypi/simple/

# --------------------------------------------------------------------------
# Copy the backend source
# --------------------------------------------------------------------------
COPY backend/ /app/backend/

# Air-gapped storage tree (mounted as a volume in production so data
# survives container restarts)
RUN mkdir -p /app/data/manifests /app/data/models /app/data/inference_dna \
             /app/data/fingerprints /app/data/drift /app/data/graph \
             /app/data/reports/assurance /app/data/quarantine/attacks
VOLUME ["/app/data"]

ENV PYTHONPATH=/app/backend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD python3 -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/system/status', timeout=4).status == 200 else 1)" \
    || exit 1

CMD ["python3", "-m", "uvicorn", "app.main:app", "--app-dir", "/app/backend", "--host", "0.0.0.0", "--port", "8000"]
