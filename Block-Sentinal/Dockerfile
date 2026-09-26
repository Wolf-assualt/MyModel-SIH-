# TRUST-CV (SIH26228) — Multi-Architecture Linux Production Build (x86_64 / arm64)
FROM python:3.12-slim

LABEL org.opencontainers.image.title="TRUST-CV Backend" \
      org.opencontainers.image.description="Zero-Trust Computer Vision Integrity & Assurance Platform" \
      org.opencontainers.image.version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/app/data \
    PYTHONPATH=/app/backend

WORKDIR /app

# Install native system dependencies:
# - build-essential for compiling C extensions
# - libgl1, libglib2.0-0 for OpenCV headless
# - libpango-1.0-0, libharfbuzz0b, libpangoft2-1.0-0 for WeasyPrint PDF reporting
# - curl for container health check
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        libgl1 \
        libglib2.0-0 \
        libpango-1.0-0 \
        libharfbuzz0b \
        libpangoft2-1.0-0 \
        libopenblas0 \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy backend source tree
COPY backend/ /app/backend/

# Create persistent storage directories for SQLite ledger, artifacts, and quarantine
RUN mkdir -p /app/data/manifests \
             /app/data/models \
             /app/data/inference_dna \
             /app/data/drift \
             /app/data/reports \
             /app/data/quarantine \
             /app/data/audit \
             /app/data/uploads

VOLUME ["/app/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/v1/system/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--app-dir", "/app/backend", "--host", "0.0.0.0", "--port", "8000"]
