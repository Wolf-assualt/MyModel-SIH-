# TRUST-CV Offline & Air-Gapped Deployment Guide

## Overview
TRUST-CV (SIH26228) is an offline-first, zero-trust computer vision assurance platform. It is engineered from the ground up for strict air-gapped defense networks where external network and internet connections are prohibited.

---

## Architectural Principles of Offline Assurance

1. **Zero External Runtime Dependencies:**
   - No Content Delivery Networks (CDNs) for JavaScript or CSS.
   - No external web fonts (e.g. Google Fonts / fonts.googleapis.com).
   - No remote analytics, telemetry, or metric beacons.
   - No cloud-based Key Management Systems (KMS) or cloud identity providers.

2. **Self-Contained Local Infrastructure:**
   - **Persistence:** Local SQLite database operating with Write-Ahead Logging (WAL) and foreign keys enabled.
   - **Cryptography:** Local Elliptic Curve Cryptography (ECDSA SECP256R1) signing keys with isolated filesystem storage (`data/keys/`).
   - **Frontend:** Pure Vanilla CSS design system and self-contained HTML5 Canvas 2D property graph renderer.

---

## Air-Gapped Installation & Setup Workflow

```text
┌─────────────────────────────────────────────────────────────┐
│              AIR-GAPPED DEPLOYMENT PIPELINE                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                1. Transfer Offline Bundle
                   (Wheel packages + Codebase)
                              │
                              ▼
                2. Install Local Environment
                   (pip install --no-index --find-links=wheels)
                              │
                              ▼
                3. Initialize Storage & Local Keys
                   (data/ directories + ECDSA SECP256R1)
                              │
                              ▼
                4. Initialize SQLite WAL Database
                              │
                              ▼
                5. Launch FastAPI SOC Server
                   (Uvicorn on 127.0.0.1:8000)
                              │
                              ▼
                6. Execute Readiness Verification Probe
                   (GET /api/v1/system/readiness)
```

---

## Step-by-Step Operator Instructions

### Step 1: Initialize Storage Directories
```bash
python -c "from app.core.config import settings; settings.ensure_directories()"
```

### Step 2: Initialize Cryptographic Subsystem
Generate or load the local defense signing key:
```bash
python -m app.cli crypto info
```

### Step 3: Launch Defense SOC Server
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

### Step 4: Verify Air-Gap & Readiness
Query the local readiness check:
```bash
curl http://127.0.0.1:8000/api/v1/system/readiness
```

---

## Verification & Validation

The air-gapped readiness test verifies:
- `assets_ok`: All static stylesheets, scripts, and HTML templates exist locally.
- `no_remote_urls`: No forbidden external domains (`googleapis.com`, `tailwindcss.com`, `unpkg.com`, `cloudflare.com`).
- `crypto_ok`: ECDSA SECP256R1 local key pair is active and signs canonically formatted manifests.
- `database_ok`: SQLite database responds in WAL mode.
