# TRUST-CV Frontend Assurance Flow

**Phase 8 — Frontend ↔ Backend Integration**

This document describes the real end-to-end workflow implemented between the
React frontend (`/frontend`) and the FastAPI backend (`/backend`).  It covers
the three-page user flow, the API contract, state lifecycle, authority
boundaries, error handling, offline operation, and known limitations.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Page 1 — Mission Ingestion](#2-page-1--mission-ingestion)
3. [Page 2 — Assurance Scan](#3-page-2--assurance-scan)
4. [Page 3 — Assurance Result](#4-page-3--assurance-result)
5. [API Flow](#5-api-flow)
6. [State Transitions](#6-state-transitions)
7. [Backend / Frontend Authority Boundary](#7-backend--frontend-authority-boundary)
8. [Unavailable and Error Handling](#8-unavailable-and-error-handling)
9. [Report Flow](#9-report-flow)
10. [Offline Operation](#10-offline-operation)
11. [Limitations](#11-limitations)

---

## 1. Architecture Overview

```
BROWSER (React)                          FastAPI (Python)
─────────────────────────────────────    ────────────────────────────────────
LaunchPage                               POST /api/v1/datasets/upload
  ArtifactUploader ────────── upload ──► ingests dataset, starts scan
                   ◄── ScanSession ─────  (returns scan_id immediately)

ScanPage                                 GET /api/v1/scan/{scan_id}
  pollScanProgress ─ poll every 1s ───► returns ScanSession (progress, stages)

ResultsPage                              GET /api/v1/graph/export
  VerdictCard, FindingsTable, etc.       GET /api/v1/ledger/verify
  ◄─── all data from ScanSession ──────  GET /api/v1/ledger/events/…
                                         POST /api/v1/ledger/decision
```

The frontend is a **display and analyst layer only**.  It renders results the
backend computes.  It never derives authoritative security verdicts locally.

---

## 2. Page 1 — Mission Ingestion

**Component tree:**
```
LaunchPage
  HeroSection            (static description)
  ArtifactUploader       (upload UI — dataset, model, inference, manifest)
  ValidationChecklist    (readiness gate + START SCAN button)
```

### Upload flow

1. User selects or drops a file on the **Computer Vision Dataset** card.
2. `ArtifactUploader` calls `updateArtifactWithFile('art-dataset', file)` in
   the investigation store.
3. The store POSTs the file to `POST /api/v1/datasets/upload` via
   `apiService.uploadAndScanDataset(file)`.
4. The backend:
   - Persists the file unchanged in an isolated upload directory.
   - Detects the format (COCO, YOLO, flat images, ZIP, BigEarthNet-S2).
   - Resolves the contributor identity.
   - Creates a `BatchManifest` with per-sample SHA-256 hashes and a Merkle root.
   - Creates a `ScanSession` and starts `_run_scan_pipeline` as a background
     task.
   - **Returns the `ScanSession` immediately** (status: `PENDING`).
5. The store stores `session.scan_id` and `session.batch_id` in state.
6. The artifact card updates to show real values: filename, file size, and the
   backend scan_id prefix.

### Readiness gate

`isReadyToScan` is `true` only when:
- The dataset artifact status is `'verified'` (backend accepted the upload), AND
- `currentScanId` is not null (a scan session ID was received from the backend).

The **MONITOR ASSURANCE PIPELINE** button is `disabled` until both conditions
are met.  Attempting to call `startScan()` without a scan_id sets
`backendError` and does not advance the page — it never fakes a scan.

### Non-dataset artifacts

Model (`.onnx`, `.pt`), inference (`.json`, `.csv`), and manifest (`.sig`,
`.json`) files are accepted locally in the artifact cards for user reference.
They are not currently uploaded separately — model assurance is triggered when
the backend manifest references a registered model ID.  If no model is
registered the backend reports `MODEL_INTEGRITY: UNAVAILABLE` which the
frontend displays faithfully.

---

## 3. Page 2 — Assurance Scan

**Component tree:**
```
ScanPage
  ScanHeader          (session ID, backend scan_id, elapsed time, controls)
  ScanProgress        (circular gauge — backend progress 0–100%)
  SystemHealth        (backend overview metrics)
  PipelineStages      (13 stage cards — status from backend stage_results)
  LiveMetrics         (counter cards — zeroed; populated from backend data)
  TerminalLog         (audit event stream — populated when backend sends logs)
  SignalMap           (latent feature scatter — populated from backend data)
```

### Polling mechanism

`startScan()` in the investigation store calls `pollScanProgress()` which sets
a `setInterval` at **1000 ms** that calls
`apiService.getScanSession(currentScanId)` on every tick.

On each response:

| Backend field | Frontend action |
|---|---|
| `session.progress` (0–1 float) | Multiplied by 100 → shown in circular gauge |
| `session.stage` (ScanStage enum) | Shown as current operation label |
| `session.stage_results[code]` | Mapped to the matching `PipelineStage` card |
| `session.status === 'COMPLETED'` | Calls `finalizeScan()` → transitions to ResultsPage |
| `session.status === 'FAILED'` | Calls `finalizeScan()` → shows FAILED state on result page |

### Stage code mapping

Each `PipelineStage` has a `code` that matches a key written into
`ScanSession.stage_results` by the backend pipeline.  The mapping is:

| # | Stage Code | Backend Phase |
|---|---|---|
| 1 | `DATA_INGESTION` | INGESTION/HASHING |
| 2 | `HASH_VERIFICATION` | HASHING |
| 3 | `DATASET_ANALYSIS` | DATA_INTEGRITY |
| 4 | `DUPLICATE_DETECTION` | DATA_INTEGRITY |
| 5 | `LABEL_INTEGRITY` | DATA_INTEGRITY |
| 6 | `OOD_DETECTION` | DATA_INTEGRITY (requires reference) |
| 7 | `MODEL_INTEGRITY` | MODEL_ASSURANCE |
| 8 | `BACKDOOR_ANALYSIS` | INFERENCE_ASSURANCE |
| 9 | `INFERENCE_VALIDATION` | INFERENCE_ASSURANCE |
| 10 | `DISTRIBUTION_SHIFT` | DISTRIBUTION_SHIFT (requires baseline) |
| 11 | `EVIDENCE_FUSION` | EVIDENCE_FUSION |
| 12 | `EVIDENCE_GRAPH` | EVIDENCE_FUSION |
| 13 | `FINAL_VERDICT` | REPORT |

Backend `ComponentStatus` → frontend `StageStatus` translation:

| Backend | Frontend |
|---|---|
| `PASSED` | `PASSED` |
| `FAILED` | `FAILED` |
| `UNAVAILABLE` | `UNAVAILABLE` |
| `RUNNING` | `RUNNING` (→ `PASSED` at completion) |
| Not present in stage_results | `UNAVAILABLE` (never auto-PASSED) |

### No fake progress

- No `setInterval` increments progress independently of the backend.
- No stage is ever marked `PASSED` unless the backend `ComponentState` for
  that key is `PASSED`.
- A stage that was never written into `stage_results` is shown as
  `UNAVAILABLE`, not `PASSED`.
- The circular gauge shows exactly `Math.round(session.progress * 100)`.

### Cleanup

The polling interval is cleared on:
- Scan `COMPLETED` or `FAILED` (inside `pollScanProgress`).
- Component unmount (`useEffect` cleanup in the store provider).

---

## 4. Page 3 — Assurance Result

**Component tree:**
```
ResultsPage
  BackendErrorBanner     (surfaces backendError from store)
  VerdictCard            (overall disposition from session.assessment.disposition)
  SummaryCards           (counts from liveMetrics — populated by backend)
  TrustScoreCard         (assuranceScore, dataRiskScore, modelRiskScore,
                          inferenceRiskScore — all from session.assessment)
  ImageAssessments       (session.assessment.imageResults)
  FindingsTable          (session.findings → mapped to Finding[])
  EvidenceGraph          (GET /api/v1/graph/export)
  LedgerAuditPanel       (GET /api/v1/ledger/verify)
  AnalystDecisionPanel   (POST /api/v1/ledger/decision)
  Recommendations        (session.assessment.fusionAssessment.recommended_actions)
  ExportActions          (JSON download of backend data)
  FindingDrawer          (detail panel for a selected finding)
```

### Assessment data contract

All result values come from `ScanSession.assessment` as returned by the
backend.  The frontend mapping is verbatim — no re-computation:

| Backend field | Frontend display |
|---|---|
| `assessment.assuranceScore` | Overall score (×100, rounded) |
| `assessment.disposition` | Verdict badge (`ACCEPTED`, `QUARANTINED`, etc.) |
| `assessment.dataRiskScore` | Data Integrity sub-score |
| `assessment.modelRiskScore` | Model Integrity sub-score (`-1` = UNAVAILABLE) |
| `assessment.inferenceRiskScore` | Inference Integrity sub-score (`-1` = UNAVAILABLE) |
| `assessment.totalSamples` | Sample count |
| `assessment.imageResults[]` | Per-image assessments |
| `assessment.fusionAssessment` | Fusion evidence (risk_level, coverage, etc.) |
| `session.findings[]` | Forensic findings table |

The `-1` sentinel from the backend is the explicit "module UNAVAILABLE" signal.
The frontend maps it to the string `UNAVAILABLE` in the UI — it is never
converted to a passing score.

### Evidence Graph

Populated by `GET /api/v1/graph/export` after the scan completes.  If the
backend has not built a graph the endpoint returns empty arrays.  The frontend
shows an empty graph with an UNAVAILABLE note — it does not synthesise nodes
or edges.

### Ledger Audit Panel

Shows only the result of `GET /api/v1/ledger/verify`.  The frontend performs
no hash-chain computation.  If the backend is unreachable the panel shows
`UNAVAILABLE`.

---

## 5. API Flow

```
POST /api/v1/datasets/upload
  → multipart/form-data: file=<binary>, dataset_name=<string>
  ← ResponseEnvelope<ScanSession>  { scan_id, batch_id, status: "PENDING", … }

GET /api/v1/scan/{scan_id}   (polled every 1s during scan)
  ← ResponseEnvelope<ScanSession>  {
       scan_id, batch_id, status, stage, progress,
       stage_results: { [code]: { status, explanation, error_code } },
       findings: [ { finding_id, check_type, severity, description, … } ],
       assessment: { assuranceScore, disposition, … },
       errors: [], warnings: []
     }

GET /api/v1/graph/export     (called once on scan completion)
  ← ResponseEnvelope<BackendGraphExport>  { nodes, edges, graph_digest }

GET /api/v1/ledger/verify    (called on scan completion, and on manual refresh)
  ← ResponseEnvelope<LedgerVerification>  { valid, events_checked, … }

GET /api/v1/ledger/events    (called to refresh analyst decisions)
  ← ResponseEnvelope<LedgerEventRecord[]>

POST /api/v1/ledger/decision (called when analyst submits a decision)
  ← ResponseEnvelope<LedgerEventRecord>

GET /api/v1/system/health    (polled every 15s for backend liveness)
  ← HTTP 200 OK

GET /api/v1/dashboard/overview
  ← ResponseEnvelope<SystemHealthOverview>
```

All responses follow the `ResponseEnvelope<T>` schema:
```json
{ "success": true, "data": <T>, "error": null, "timestamp": "…" }
```

---

## 6. State Transitions

```
IDLE (phase='launch')
  │
  ├─ user uploads dataset ──► backend returns scan_id
  │                             isReadyToScan = true
  │
  ├─ startScan() [no scan_id] ──► backendError set, stays in 'launch'
  │
  └─ startScan() [scan_id OK] ──► isScanning = true, phase = 'scan'
        │
        ├─ backend IN_PROGRESS ──► progress updates, stage cards update
        │
        ├─ backend COMPLETED ──► finalizeScan() → phase = 'results'
        │                         trustScore set from assessment
        │                         findings, imageResults populated
        │
        └─ backend FAILED ──► finalizeScan() → phase = 'results'
                               trustScore = null (UNAVAILABLE shown)
                               backendError set if present

phase = 'results'
  ├─ resetInvestigation() ──► back to 'launch', all state cleared
  └─ exportReport/exportEvidencePackage() ──► JSON download
```

### Persistence

The active scan session is held in React state.  A page refresh loses the
`currentScanId` and `scanSession`.  If the user refreshes mid-scan they will
need to re-upload.  The backend scan continues running and can be queried
directly at `GET /api/v1/scan/{scan_id}` if the ID is known.

A future enhancement could persist `currentScanId` to `sessionStorage` for
automatic recovery, but this is not implemented in Phase 8.

---

## 7. Backend / Frontend Authority Boundary

| Concern | Authority | Notes |
|---|---|---|
| SHA-256 hashing | **Backend** | Computed in `app/integrity/engine.py` |
| Merkle root | **Backend** | Computed in `app/datasets/engine.py` |
| Poisoning detection | **Backend** | `app/integrity/detectors/` |
| Duplicate detection | **Backend** | Cosine similarity + pHash |
| OOD detection | **Backend** | Requires reference baseline |
| Model assurance | **Backend** | `app/models_engine/registry.py` |
| Inference verification | **Backend** | `app/runtime/engine.py` |
| Distribution shift | **Backend** | `app/drift/engine.py` (requires baseline) |
| Evidence fusion | **Backend** | `app/fusion/engine.py` |
| Risk score | **Backend** | `fusionAssessment.risk_score` |
| Disposition verdict | **Backend** | `assessment.disposition` |
| Ledger hash-chain | **Backend** | `app/ledger/engine.py` |
| Evidence graph | **Backend** | `app/graph/engine.py` |
| Cryptographic signing | **Backend** | ECDSA SECP256R1 |
| Rendering results | Frontend | Display only |
| Filtering/sorting findings | Frontend | UI convenience |
| Analyst decision recording | Frontend triggers → **Backend persists** | |

The frontend **must not** calculate or infer:
- Risk scores
- Confidence values
- Security verdicts
- Poisoning status
- Model integrity
- Inference integrity
- Contributor risk
- Ledger validity

---

## 8. Unavailable and Error Handling

### When a backend module is unavailable

The backend writes `ComponentStatus.UNAVAILABLE` into `stage_results[code]`
with an `explanation` and `error_code`.

The frontend maps this to `StageStatus = 'UNAVAILABLE'` and displays the
explanation text.  Common cases:

| Scenario | Backend error_code | Frontend display |
|---|---|---|
| No reference dataset for OOD | `ERR_NO_REFERENCE` | `OOD DETECTION: UNAVAILABLE` |
| No model artifact provided | `ERR_MODULE_OFFLINE` | `MODEL INTEGRITY: UNAVAILABLE` |
| No drift baseline registered | `ERR_NO_BASELINE` | `DISTRIBUTION SHIFT: UNAVAILABLE` |
| Model binary not found | `ERR_MODULE_OFFLINE` | `BACKDOOR ANALYSIS: UNAVAILABLE` |
| Inference execution failed | `ERR_INFERENCE_FAILED` | `INFERENCE VALIDATION: FAILED` |

### When the backend is unreachable

- `isBackendAvailable()` returns `false` → `backendOnline = false`.
- `BackendErrorBanner` shows in the results page.
- Ledger panel shows `UNAVAILABLE`.
- Evidence graph shows empty.
- The upload button still works if the backend starts responding.

### Score sentinel values

- `modelRiskScore: -1` and `inferenceRiskScore: -1` are the backend's explicit
  "module UNAVAILABLE" signals.
- The frontend renders these as `UNAVAILABLE` in the TrustScoreCard.
- They are **never** converted to 0 or any passing percentage.

### Upload errors

If the backend rejects the upload (bad format, too many files, etc.) the
`updateArtifactWithFile` handler catches the error, sets `backendError`, and
marks the artifact as `'error'`.  `isReadyToScan` remains `false`.

---

## 9. Report Flow

Two export actions are available on the Results page:

### EXPORT REPORT (JSON)

Assembles a JSON document from the already-loaded `scanSession` data:

```json
{
  "report_id": "REP-<scan_id_prefix>",
  "generated_at": "<ISO timestamp>",
  "authority": "TRUST-CV backend assurance pipeline",
  "scan_id": "…",
  "batch_id": "…",
  "status": "COMPLETED",
  "stage_results": { … },
  "assessment": { … },
  "findings": [ … ],
  "evidence_graph_digest": "…",
  "ledger_verification": { … },
  "errors": [],
  "warnings": []
}
```

The ledger verification and graph digest are fetched fresh from the backend at
export time, not taken from stale in-memory state.

### EXPORT EVIDENCE (.SIG)

A broader package that includes:

- Full scan session data
- All findings
- Evidence graph nodes and edges
- Ledger verification result
- System overview
- Analyst decisions recorded in the backend ledger

Both exports are JSON files downloaded locally.  The backend report generation
endpoint (`POST /api/v1/reports/generate`) is available for sealed backend
reports if a fused assessment ID is available.

---

## 10. Offline Operation

The frontend is a static Vite/React build served by the FastAPI server via
`app/static/` and `app/templates/index.html`.  No external CDN or internet
connection is required.

In development, Vite proxies `/api` requests to `http://127.0.0.1:8000`
(configured in `vite.config.ts`).

In production (air-gapped deployment):
- Run `npm run build` to produce `dist/`.
- Copy `dist/` into `backend/app/static/` and `dist/index.html` into
  `backend/app/templates/`.
- Start the backend: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- Access at `http://<host>:8000/`

The backend health probe (`GET /api/v1/system/health`) is polled every 15s.
If it fails, `backendOnline` becomes `false` and the UI shows
`AIR-GAP ENCLAVE` status.  Analysis results that were already loaded remain
visible.

---

## 11. Limitations

The following are documented limitations as of Phase 8:

1. **No scan session recovery on page refresh.** The `currentScanId` is
   held in React state only.  A page refresh during a scan requires re-upload.
   The backend scan continues running and can be queried manually.

2. **No model/inference/manifest upload pipeline.** Non-dataset artifacts are
   accepted by the UI for display purposes.  Model assurance requires a model
   to be registered in the backend registry with a matching `model_id` in the
   dataset manifest metadata.

3. **OOD detection requires a reference baseline.** No baseline → stage shows
   `UNAVAILABLE`.  Baselines are registered via `POST /api/v1/drift/baseline`.

4. **Distribution shift requires a registered baseline.** Same requirement
   as OOD detection.

5. **LiveMetrics counters are zeroed during scan.** The backend does not
   stream incremental sample-level counters to the scan session; counters are
   populated from `session.assessment` only after the scan completes.

6. **TerminalLog and SignalMap are empty during Phase 8.** The backend does
   not yet push structured log events or latent-space embeddings to the scan
   session.  These components are ready to consume backend data once those
   endpoints are implemented.

7. **Single-session UI.** Only one scan session is tracked at a time.  Starting
   a new scan requires clicking "NEW INVESTIGATION" to clear state and re-upload.

8. **Report sealing via `/api/v1/reports/generate` requires a fused assessment
   ID** that is only available when the fusion engine runs successfully.  The
   local JSON download is always available regardless.

---

*Document verified against Phase 8 implementation — September 2026.*
*Backend tests: 525/525. Frontend tests: 10/10. Build: PASS.*
