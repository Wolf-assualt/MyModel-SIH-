#!/usr/bin/env bash
# ==============================================================================
# TRUST-CV (SIH26228) - SYSTEM INITIALIZATION & OPERATIONS RUNNER
# Zero-Trust Computer Vision Integrity Assurance & Evidence Graph
# Linux / Zorin OS Native Launcher (Backend + Frontend)
# ==============================================================================

set -Eeuo pipefail

# ANSI Color Codes
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_GREEN="\033[1;32m"
CLR_BLUE="\033[1;34m"
CLR_CYAN="\033[1;36m"
CLR_YELLOW="\033[1;33m"
CLR_RED="\033[1;31m"
CLR_DIM="\033[2m"

# Resolve absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR"

# If invoked from Block-Sentinal subfolder, locate parent root
if [[ "$(basename "$ROOT")" == "Block-Sentinal" ]]; then
    ROOT="$(cd "$ROOT/.." && pwd)"
fi

BLOCK_DIR="$ROOT/Block-Sentinal"
BACKEND_DIR="$BLOCK_DIR/backend"
FRONTEND_DIR="$ROOT/frontend"
VENV_DIR="$ROOT/.venv"

# Ensure ~/.local/bin and antigravity IDE bin are in PATH
export PATH="$HOME/.local/bin:$HOME/.gemini/antigravity-ide/bin:$PATH"

# Mode parsing (default: dev)
MODE="${1:-dev}"
case "$MODE" in
    dev|demo|test|build) ;;
    *)
        echo -e "${CLR_YELLOW}[!] Unknown mode '$MODE'. Defaulting to 'dev'. Options: dev | demo | test | build${CLR_RESET}"
        MODE="dev"
        ;;
esac

echo -e "${CLR_CYAN}"
echo "================================================================================"
echo "   TRUST-CV  //  SIH26228 - Zero-Trust Computer Vision Integrity Assurance     "
echo "   Air-Gapped Cryptographic Lineage, Adversarial Defense & Evidence Graph       "
echo "   OS Platform: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s)"
echo "================================================================================"
echo -e "${CLR_RESET}"
echo -e " Target Mode: ${CLR_BOLD}${MODE}${CLR_RESET}"
echo ""

# ------------------------------------------------------------------------------
# 1. Python Runtime & Virtual Environment Setup
# ------------------------------------------------------------------------------
echo -e "${CLR_BOLD}[1/6] Checking Python runtime & virtual environment...${CLR_RESET}"

if ! command -v python3 &>/dev/null; then
    echo -e "${CLR_RED}[ERROR] Python 3 runtime not found. Please install Python 3.10+ (sudo apt install python3 python3-venv).${CLR_RESET}"
    exit 1
fi

PY_SYSTEM_VER="$(python3 --version)"
echo -e "      System Python: ${CLR_DIM}${PY_SYSTEM_VER}${CLR_RESET}"

# Create or reuse dedicated virtual environment to comply with PEP 668 (externally managed environment)
if [[ ! -d "$VENV_DIR" || ! -x "$VENV_DIR/bin/python" ]]; then
    echo -e "      ${CLR_YELLOW}[*] Initializing dedicated virtual environment at .venv...${CLR_RESET}"
    python3 -m venv "$VENV_DIR"
fi

PY_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"

echo -e "      Venv Python:   ${CLR_GREEN}$($PY_BIN --version)${CLR_RESET}"

# ------------------------------------------------------------------------------
# 2. Backend Dependency Verification
# ------------------------------------------------------------------------------
echo -e "${CLR_BOLD}[2/6] Verifying backend dependencies...${CLR_RESET}"

CORE_DEPS_CHECK="
import fastapi, uvicorn, pydantic, sqlalchemy, cryptography, PIL, numpy
"

if ! $PY_BIN -c "$CORE_DEPS_CHECK" &>/dev/null; then
    echo -e "      ${CLR_YELLOW}[*] Missing backend dependencies detected. Installing required stack...${CLR_RESET}"
    
    $PIP_BIN install --upgrade pip -q
    $PIP_BIN install \
        fastapi uvicorn pydantic pydantic-settings sqlalchemy cryptography \
        pillow numpy pytest python-multipart httpx scipy scikit-learn \
        networkx opencv-python-headless onnx onnxruntime
    
    # Install torch if missing
    if ! $PY_BIN -c "import torch" &>/dev/null; then
        echo -e "      ${CLR_YELLOW}[*] Installing CPU-optimized PyTorch...${CLR_RESET}"
        $PIP_BIN install torch --index-url https://download.pytorch.org/whl/cpu
    fi
    echo -e "      ${CLR_GREEN}[OK] Backend dependencies installed.${CLR_RESET}"
else
    echo -e "      ${CLR_GREEN}[OK] All core backend dependencies verified.${CLR_RESET}"
fi

# ------------------------------------------------------------------------------
# 3. Node.js & Frontend Environment Setup
# ------------------------------------------------------------------------------
echo -e "${CLR_BOLD}[3/6] Verifying Node.js & Frontend dependencies...${CLR_RESET}"

install_local_node() {
    echo -e "      ${CLR_YELLOW}[*] Downloading and installing standalone Node.js v22 LTS to ~/.local...${CLR_RESET}"
    local TMP_NODE="/tmp/node-install-$$"
    mkdir -p "$TMP_NODE"
    curl -fsSL https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz -o "$TMP_NODE/node.tar.xz"
    tar -xJf "$TMP_NODE/node.tar.xz" -C "$TMP_NODE"
    mkdir -p "$HOME/.local"
    cp -rf "$TMP_NODE"/node-v22.23.3-linux-x64/* "$HOME/.local/"
    rm -rf "$TMP_NODE"
    export PATH="$HOME/.local/bin:$PATH"
}

if ! command -v node &>/dev/null || ! command -v npm &>/dev/null; then
    install_local_node
fi

echo -e "      Node runtime:  ${CLR_GREEN}$(node --version)${CLR_RESET} (npm $(npm --version))"

# Verify frontend dependencies
if [[ ! -d "$FRONTEND_DIR/node_modules" || ! -f "$FRONTEND_DIR/node_modules/.bin/vite" ]]; then
    echo -e "      ${CLR_YELLOW}[*] Installing frontend npm packages...${CLR_RESET}"
    (
        cd "$FRONTEND_DIR"
        npm install
        # Ensure Linux native binding for Vite/Rolldown is present
        npm install --save-optional @rolldown/binding-linux-x64-gnu
    )
    echo -e "      ${CLR_GREEN}[OK] Frontend packages installed.${CLR_RESET}"
else
    # Check if rolldown linux binding is present
    if [[ ! -d "$FRONTEND_DIR/node_modules/@rolldown/binding-linux-x64-gnu" ]]; then
        (
            cd "$FRONTEND_DIR"
            npm install --save-optional @rolldown/binding-linux-x64-gnu
        )
    fi
    echo -e "      ${CLR_GREEN}[OK] Frontend modules verified.${CLR_RESET}"
fi

# ------------------------------------------------------------------------------
# 4. Storage Tree Verification
# ------------------------------------------------------------------------------
echo -e "${CLR_BOLD}[4/6] Verifying storage directory structure...${CLR_RESET}"

REQUIRED_DIRS=(
    "$BLOCK_DIR/data/manifests"
    "$BLOCK_DIR/data/models/manifests"
    "$BLOCK_DIR/data/models/baselines"
    "$BLOCK_DIR/data/models/uploads"
    "$BLOCK_DIR/data/inference_dna"
    "$BLOCK_DIR/data/fingerprints"
    "$BLOCK_DIR/data/drift/baselines"
    "$BLOCK_DIR/data/drift/reports"
    "$BLOCK_DIR/data/fusion/assessments"
    "$BLOCK_DIR/data/fusion/evidence"
    "$BLOCK_DIR/data/graph"
    "$BLOCK_DIR/data/ledger"
    "$BLOCK_DIR/data/reports/assurance"
    "$BLOCK_DIR/data/audit"
    "$BLOCK_DIR/data/uploads"
    "$BLOCK_DIR/data/quarantine/attacks"
    "$BLOCK_DIR/data/quarantine/models"
    "$BLOCK_DIR/data/redteam/sandbox"
    "$BLOCK_DIR/data/redteam/results"
    "$BLOCK_DIR/data/keys"
)

for dir_path in "${REQUIRED_DIRS[@]}"; do
    mkdir -p "$dir_path"
done

echo -e "      ${CLR_GREEN}[OK] Storage directories active.${CLR_RESET}"

# ------------------------------------------------------------------------------
# 5. Core Subsystem Smoke Test
# ------------------------------------------------------------------------------
echo -e "${CLR_BOLD}[5/6] Executing core subsystem validation...${CLR_RESET}"

(
    cd "$BLOCK_DIR"
    export PYTHONPATH="backend"
    $PY_BIN -m pytest backend/tests/test_config.py backend/tests/test_crypto.py backend/tests/test_health.py -q --tb=short
)

echo -e "      ${CLR_GREEN}[OK] Cryptographic & health foundations verified.${CLR_RESET}"

# ------------------------------------------------------------------------------
# Special Modes Handling: build & test
# ------------------------------------------------------------------------------
if [[ "$MODE" == "build" ]]; then
    echo -e "\n${CLR_CYAN}================================================================================${CLR_RESET}"
    echo -e " Building Production Frontend Bundle..."
    echo -e "${CLR_CYAN}================================================================================${CLR_RESET}"
    (
        cd "$FRONTEND_DIR"
        npm run build
    )
    mkdir -p "$BACKEND_DIR/app/static"
    mkdir -p "$BACKEND_DIR/app/templates"
    cp -rf "$FRONTEND_DIR/dist/"* "$BACKEND_DIR/app/static/"
    cp -f "$FRONTEND_DIR/dist/index.html" "$BACKEND_DIR/app/templates/index.html"
    echo -e "${CLR_GREEN}[SUCCESS] Production bundle built and synchronized to backend static/templates.${CLR_RESET}"
    exit 0
fi

if [[ "$MODE" == "test" ]]; then
    echo -e "\n${CLR_CYAN}================================================================================${CLR_RESET}"
    echo -e " Running Full Backend & Frontend Test Suites..."
    echo -e "${CLR_CYAN}================================================================================${CLR_RESET}"
    echo -e "\n[*] Running Backend Tests (pytest)..."
    (
        cd "$BLOCK_DIR"
        export PYTHONPATH="backend"
        $PY_BIN -m pytest backend/tests/ -q
    )
    echo -e "\n[*] Running Frontend Tests (vitest)..."
    (
        cd "$FRONTEND_DIR"
        npm run test
    )
    echo -e "\n${CLR_GREEN}[SUCCESS] All test suites completed successfully!${CLR_RESET}"
    exit 0
fi

# ------------------------------------------------------------------------------
# 6. Service Execution (dev or demo)
# ------------------------------------------------------------------------------
echo -e "${CLR_BOLD}[6/6] Launching TRUST-CV Defense Services (${MODE} mode)...${CLR_RESET}"

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    echo -e "${CLR_YELLOW}[*] Shutting down TRUST-CV services...${CLR_RESET}"
    if [[ -n "$FRONTEND_PID" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    echo -e "${CLR_GREEN}[OK] All services cleanly terminated.${CLR_RESET}"
    exit 0
}

trap cleanup INT TERM EXIT

# Check if port 8000 is currently in use
if nc -z 127.0.0.1 8000 2>/dev/null || (echo >/dev/tcp/127.0.0.1/8000) 2>/dev/null; then
    echo -e "${CLR_YELLOW}[!] Port 8000 is already in use. Reusing existing backend service.${CLR_RESET}"
else
    echo -e "      [*] Starting FastAPI Backend on port 8000..."
    (
        cd "$BLOCK_DIR"
        export PYTHONPATH="backend"
        exec "$PY_BIN" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
    ) &
    BACKEND_PID=$!
fi

# Wait for backend readiness
echo -n "      [*] Waiting for backend online..."
for i in {1..30}; do
    if curl -fs "http://127.0.0.1:8000/api/v1/system/health" &>/dev/null; then
        echo -e " ${CLR_GREEN}[ONLINE]${CLR_RESET}"
        break
    fi
    sleep 0.5
    echo -n "."
done

if [[ "$MODE" == "demo" ]]; then
    # In Demo Mode, backend serves the compiled frontend on port 8000
    if [[ ! -f "$FRONTEND_DIR/dist/index.html" ]]; then
        echo -e "      [*] Building frontend production bundle for demo mode..."
        (
            cd "$FRONTEND_DIR"
            npm run build
        )
        mkdir -p "$BACKEND_DIR/app/static" "$BACKEND_DIR/app/templates"
        cp -rf "$FRONTEND_DIR/dist/"* "$BACKEND_DIR/app/static/"
        cp -f "$FRONTEND_DIR/dist/index.html" "$BACKEND_DIR/app/templates/index.html"
    fi

    echo ""
    echo -e "${CLR_GREEN}================================================================================${CLR_RESET}"
    echo -e " ${CLR_BOLD}TRUST-CV SYSTEM ONLINE (DEMO MODE)${CLR_RESET}"
    echo -e "   Command Center UI  : ${CLR_CYAN}http://localhost:8000${CLR_RESET}"
    echo -e "   API Documentation  : ${CLR_CYAN}http://localhost:8000/docs${CLR_RESET}"
    echo -e "   System Health      : ${CLR_CYAN}http://localhost:8000/api/v1/system/health${CLR_RESET}"
    echo -e "${CLR_GREEN}================================================================================${CLR_RESET}"
    echo ""

    if command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost:8000" &>/dev/null || true
    fi

    wait "$BACKEND_PID"

else
    # In Dev Mode, start Vite Frontend on port 5173
    if nc -z 127.0.0.1 5173 2>/dev/null || (echo >/dev/tcp/127.0.0.1/5173) 2>/dev/null; then
        echo -e "${CLR_YELLOW}[!] Port 5173 is already in use. Reusing existing frontend service.${CLR_RESET}"
    else
        echo -e "      [*] Starting Vite Frontend server on port 5173..."
        (
            cd "$FRONTEND_DIR"
            exec npm run dev
        ) &
        FRONTEND_PID=$!
    fi

    echo -n "      [*] Waiting for frontend online..."
    for i in {1..30}; do
        if curl -fs "http://127.0.0.1:5173" &>/dev/null; then
            echo -e " ${CLR_GREEN}[ONLINE]${CLR_RESET}"
            break
        fi
        sleep 0.5
        echo -n "."
    done

    echo ""
    echo -e "${CLR_GREEN}================================================================================${CLR_RESET}"
    echo -e " ${CLR_BOLD}TRUST-CV FULL STACK DEFENSE SUITE ONLINE (DEV MODE)${CLR_RESET}"
    echo -e "   Frontend Web UI    : ${CLR_CYAN}http://localhost:5173${CLR_RESET}"
    echo -e "   Backend API Docs   : ${CLR_CYAN}http://localhost:8000/docs${CLR_RESET}"
    echo -e "   Built-in SOC UI    : ${CLR_CYAN}http://localhost:8000${CLR_RESET}"
    echo -e "   API Health Check   : ${CLR_CYAN}http://localhost:8000/api/v1/system/health${CLR_RESET}"
    echo -e "   System Status      : ${CLR_CYAN}http://localhost:8000/api/v1/system/status${CLR_RESET}"
    echo -e "${CLR_GREEN}================================================================================${CLR_RESET}"
    echo -e " ${CLR_DIM}Press [Ctrl+C] to gracefully stop both frontend and backend.${CLR_RESET}\n"

    # Open browser on Zorin OS / Linux desktop
    if command -v xdg-open &>/dev/null; then
        (sleep 1 && xdg-open "http://localhost:5173" &>/dev/null || true) &
    fi

    # Wait for either process
    if [[ -n "$FRONTEND_PID" && -n "$BACKEND_PID" ]]; then
        wait -n "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
    elif [[ -n "$BACKEND_PID" ]]; then
        wait "$BACKEND_PID" 2>/dev/null || true
    elif [[ -n "$FRONTEND_PID" ]]; then
        wait "$FRONTEND_PID" 2>/dev/null || true
    else
        while true; do sleep 1; done
    fi
fi
