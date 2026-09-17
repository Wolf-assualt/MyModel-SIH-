#!/usr/bin/env bash
set -e

# ==============================================================================
# TRUST-CV (SIH26228) - SYSTEM INITIALIZATION & OPERATIONS RUNNER
# Continuous Integrity, Cryptographic Lineage & Provenance Sentinel
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export PYTHONPATH="backend"

echo "==============================================================================="
echo "               TRUST-CV (SIH26228) - SYSTEM INITIALIZATION                     "
echo "       Continuous Integrity, Cryptographic Lineage & Provenance Sentinel       "
echo "==============================================================================="
echo ""

# 1. Verify Python Runtime
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo "[ERROR] Python runtime not found. Please install Python 3.10+."
    exit 1
fi

PY_CMD="python3"
if ! command -v python3 &>/dev/null; then
    PY_CMD="python"
fi

echo "[*] Python Runtime Detected: $($PY_CMD --version)"
echo ""

# 2. Create required directory tree
echo "[*] Checking required storage directories..."
mkdir -p data/manifests
mkdir -p data/models
mkdir -p data/inference_dna
mkdir -p data/fingerprints
mkdir -p data/drift
mkdir -p data/graph
mkdir -p data/reports/assurance
mkdir -p data/quarantine/attacks
echo "[OK] Storage tree verified."
echo ""

# 3. Check core dependencies
echo "[*] Checking package dependencies..."
if ! $PY_CMD -c "import fastapi, uvicorn, pydantic, sqlalchemy, cryptography, PIL, numpy" &>/dev/null; then
    echo "[!] Installing missing dependencies from requirements.txt..."
    pip install -r requirements.txt
fi
echo "[OK] All dependencies active."
echo ""

# 4. Quick Diagnostics
echo "[*] Executing core subsystem validation..."
if ! $PY_CMD -m pytest backend/tests/test_health.py backend/tests/test_crypto.py -q; then
    echo "[WARNING] Subsystem health check flagged potential issues. Check output above."
else
    echo "[OK] Trust foundation and cryptographic subroutines verified."
fi
echo ""

# 5. Launch FastAPI Server & Browser
echo "==============================================================================="
echo " Launching TRUST-CV Defense Dashboard:"
echo " API Documentation:  http://localhost:8000/docs"
echo " System Dashboard:   http://localhost:8000"
echo " System Status:      http://localhost:8000/api/v1/system/status"
echo "==============================================================================="
echo ""

# Attempt to open browser in background
(
    sleep 2
    if command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost:8000" &>/dev/null || true
    elif command -v open &>/dev/null; then
        open "http://localhost:8000" &>/dev/null || true
    fi
) &

exec $PY_CMD -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
