#!/usr/bin/env bash
# ==============================================================================
# TRUST-CV (SIH26228) - SYSTEM INITIALIZATION & OPERATIONS RUNNER
# Forwarder to root launcher
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_LAUNCHER="$(cd "$SCRIPT_DIR/.." && pwd)/run_trust_cv.sh"

if [[ -f "$ROOT_LAUNCHER" ]]; then
    exec bash "$ROOT_LAUNCHER" "$@"
else
    echo "[ERROR] Root launcher not found at $ROOT_LAUNCHER"
    exit 1
fi
