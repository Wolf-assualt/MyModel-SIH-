# TRUST-CV Defense SOC Production Runbook

## Scope & Target Audience
This runbook provides step-by-step procedures for Defense SOC operators, system administrators, and security auditors deploying, monitoring, and operating the TRUST-CV assurance platform.

---

## 1. System Startup Procedure

### Step 1: Pre-Flight Environment Check
Ensure local storage directories and Python virtual environment are ready:
```bash
python -c "from app.core.config import settings; print('Storage:', settings.ensure_directories())"
```

### Step 2: Initialize Defense Cryptographic Key
Verify the local ECDSA SECP256R1 signing identity:
```bash
python -m app.cli crypto info
```

### Step 3: Launch Local SOC Service
Launch the FastAPI application server:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Step 4: Verify Subsystem Readiness
Execute the health check probe:
```bash
curl -s http://127.0.0.1:8000/api/v1/system/readiness | jq .
```
Verify all subsystems (`database`, `cryptography`, `storage`, `graph_engine`, `dashboard_assets`) report status `HEALTHY`.

---

## 2. Daily Operational Workflows

### Workflow A: Ingest & Seal a Dataset Batch
```bash
python -m app.cli datasets ingest --name "recon_batch_01" --path "./data/samples/" --contributor "DIV_RECON_ALPHA"
```

### Workflow B: Register & Seal a Model Manifest
```bash
python -m app.cli models ingest --name "yolo_tactical" --version "1.0" --path "./data/models/yolo.pt"
```

### Workflow C: Execute Red-Team Defensive Validation
```bash
python -m app.cli redteam run --all
```

### Workflow D: Generate & Export Forensic Assurance Report
```bash
python -m app.cli reports generate --target "model_yolo_tactical" --type "MODEL"
python -m app.cli reports export --report-id "<REPORT_ID>" --format "HTML"
```

---

## 3. Incident Response & Quarantine Procedures

### Investigating a Quarantined Asset
1. Open the SOC Dashboard: `http://127.0.0.1:8000`
2. Navigate to **Quarantine Center** (`#view-quarantine`).
3. Click on the affected asset to view triggering findings and evidence IDs.
4. Navigate to **Blast Radius** (`#view-blast`) and calculate downstream affected models and inference records.

### Auditable Quarantine Release (Unquarantine)
1. Ensure a thorough forensic audit has been conducted.
2. In the Quarantine Center, click **Resolve / Release**.
3. Enter Operator ID (e.g. `LEAD-AUDITOR-07`) and detailed forensic justification notes.
4. Confirm resolution. The release event is cryptographically sealed and logged.

---

## 4. Graceful Shutdown & Maintenance

### Graceful Server Shutdown
Send `SIGINT` (Ctrl+C) to the running Uvicorn process. FastAPI lifespan will flush open log buffers and close database connections cleanly.

### Database Backup (Local Air-Gapped)
```bash
sqlite3 trust_cv.db ".backup 'trust_cv_backup_$(date +%Y%m%d_%H%M%S).db'"
```
