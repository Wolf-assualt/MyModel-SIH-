# SIH26228 READINESS — TRUST-CV

**Problem Statement ID:** SIH26228
**System Name:** TRUST-CV — Zero-Trust Computer Vision Integrity Assurance &
Evidence Graph

---

## DEMO READINESS STATEMENT

The following pipeline is **ready for live demonstration** with real artifacts:

```
REAL FILE UPLOAD
  → INGESTION (manifest + Merkle root)
  → HASHING (per-sample SHA-256)
  → DATA ASSURANCE (duplicate, label, quality, trigger detectors)
  → MODEL ASSURANCE (binary hash + structural fingerprint + ECDSA identity)
  → INFERENCE ASSURANCE (ONNX runtime + DNA provenance + tamper detection)
  → DISTRIBUTION SHIFT (14-feature KS/PSI analysis vs reference baseline)
  → EVIDENCE FUSION (multi-source weighted risk + hard-veto rules)
  → EVIDENCE GRAPH (directed lineage from contributor to output)
  → TAMPER-EVIDENT LEDGER (hash-chain + restart recovery)
  → FINAL ASSESSMENT (three-tier disposition: ACCEPTED/UNDER_REVIEW/QUARANTINED)
  → REPORT (JSON export with all backend evidence)
```

This pipeline is verified by 573 passing backend tests and a live end-to-end
test that traces all 11 stages with real input.

---

## WHAT IS ACTUALLY DEMONSTRATED

### 1. Real Data Provenance

- Upload a real image dataset (ZIP, folder, COCO, YOLO, or individual images)
  through the browser UI.
- The backend computes SHA-256 per sample and a Merkle root for the entire
  batch. These are not calculated in the browser.
- Each sample gets a cryptographically sealed provenance record.

### 2. Real Data Assurance (Without Ground Truth Required)

The system can detect, without prior knowledge of what was injected:

| Condition | Detection Method | Confidence Basis |
|-----------|-----------------|-----------------|
| Exact duplicate samples | SHA-256 identity | 1.0 (deterministic) |
| Near-duplicate samples | 64-bit perceptual hash, Hamming ≤ threshold | `1 - hamming/64` |
| Label conflicts on similar images | dHash + label comparison | `1 - hamming/64` |
| Zero-variance / blackout frames | Pixel variance < 1.0 | 1.0 (deterministic) |
| Corrupt image files | PIL decode failure | 1.0 (deterministic) |
| Localized corner trigger patterns | Repeated patch SHA-256 across label group | `affected/group_size` |

The system does **not** claim these detections are exhaustive or evasion-proof.

### 3. Real Model Assurance

- Upload a model binary (ONNX, TorchScript, PyTorch weights) through the
  browser UI via `POST /api/v1/models/upload`.
- The backend computes SHA-256, inspects architecture, hashes per-layer
  weights, and signs the identity manifest with ECDSA SECP256R1.
- Any byte-level modification to the binary is detected by re-hashing at
  verification time.

### 4. Real Inference Provenance

- Execute inference via ONNX Runtime (CPU, local).
- Every inference is bound to its model hash, input hash, preprocessing hash,
  configuration hash, and output hash — a 5-pillar tuple sealed with ECDSA.
- Post-signing output tampering is detected by hash recomputation.
- Nonce replay attacks are detected by the persistent `seen_nonces` set.

### 5. Real Distribution Shift Detection

- Register an independent reference dataset as a signed baseline.
- Compare a candidate batch against the reference using KS distance, PSI,
  Wasserstein distance, and energy distance across 14 radiometric and
  geometric features.
- The system correctly distinguishes `CRITICAL_SHIFT` (UNDER_REVIEW) from
  operational environmental shift and from no-shift conditions.

### 6. Real Evidence Fusion

- All upstream evidence (data integrity findings, model identity, drift, inference DNA)
  is fused by a weighted multi-source engine.
- Six hard-veto rules trigger automatic QUARANTINED disposition.
- The drift isolation rule prevents drift alone from triggering false quarantine.
- The final `FusedAssessment` is ECDSA-signed.

### 7. Real Evidence Graph

- A directed property graph traces contributor → dataset → samples → model
  → inference → findings → assessment → quarantine.
- Every relationship is derived from real pipeline entity IDs.
- Blast radius calculation identifies all downstream assets affected by a
  compromised upstream entity.

### 8. Real Tamper-Evident Ledger

- Every pipeline event is recorded in a hash-chained SQLite ledger.
- Any modification to a committed event is detected by `verify_chain()`.
- Analyst decisions are additionally ECDSA-signed.
- The ledger persists across backend restarts.

### 9. Three-Tier Final Disposition

After Phase 10 fix:

| Risk Score | Fusion Disposition |
|---|---|
| < 0.30 | **ACCEPTED** — allow operational deployment |
| 0.30 – 0.70 | **UNDER_REVIEW** — flag for analyst review |
| ≥ 0.70 or hard-veto | **QUARANTINED** — block from pipeline |

`CRITICAL_SHIFT` alone → risk capped at 0.65 → `UNDER_REVIEW` (never
silently `ACCEPTED`).

### 10. Offline / Air-Gapped Operation

The core assurance pipeline has zero external network dependencies. All crypto
(ECDSA, SHA-256, Merkle), ML inference (ONNX Runtime), and storage (SQLite,
JSON files) are local.

---

## HOW TO RUN A LIVE DEMO

### Start the backend

```bash
cd Block-Sentinal/backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Start the frontend (development mode)

```bash
cd frontend
npm run dev
```

Access at `http://localhost:5173`

### Or serve via the backend (production mode)

```bash
cd frontend && npm run build
# Copy dist/ → Block-Sentinal/backend/app/static/
# Copy dist/index.html → Block-Sentinal/backend/app/templates/
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Access at `http://localhost:8000`

### Demo Scenario: Clean Dataset

1. Open the browser UI.
2. Upload any folder of images as a ZIP or drag individual files.
3. The backend creates a scan session and returns a `scan_id`.
4. Navigate to the Scan page — progress comes from real backend polling.
5. View the Results page — disposition, risk score, ledger verification, and
   evidence graph are all from the backend.
6. Export the JSON report.

### Demo Scenario: Tampered Model

1. Register a reference model via `POST /api/v1/models/register` (JSON path)
   or the browser model upload.
2. Flip bytes in the binary using any hex editor.
3. Register the tampered binary as a new candidate.
4. Call `POST /api/v1/models/{model_id}/verify` — `binary_match: false`,
   discrepancies list populated.

### Demo Scenario: Distribution Shift

```bash
# Register a baseline
curl -X POST http://localhost:8000/api/v1/drift/baseline \
  -H "Content-Type: application/json" \
  -d '{"baseline_id":"demo_ref","features":{"brightness":[50,55,48,52]}}'

# Upload a bright dataset → drift detected
```

---

## WHAT NOT TO CLAIM IN THE PRESENTATION

The following claims must **not** be made:

1. ❌ "TRUST-CV detects all attacks."
   The system covers approximately 64% of the mapped attack vector space.
   Gradient-based evasion, imperceptible adversarial perturbations, and
   semantic label errors on visually distinct images are not covered.

2. ❌ "The trigger detector confirms a backdoor."
   `TRIGGER_CANDIDATE` findings are heuristic corner-patch detections.
   They require human review. The system does not assert a confirmed backdoor.

3. ❌ "The ledger is immutable."
   The ledger detects tampering. System events (non-analyst) are not ECDSA-signed,
   so a compromised system could consistently rewrite all events without
   detection by the hash chain. Only analyst decisions are ECDSA-signed.

4. ❌ "OOD detection works without a reference dataset."
   The OOD detector returns UNAVAILABLE without a reference. Distribution
   shift analysis requires a separately registered baseline.

5. ❌ "The system provides 100% confidence scores."
   All confidence values have documented bases. Heuristic detectors produce
   `null` confidence. Trigger candidate confidence is a proportion, not a
   probability.

6. ❌ "The system prevents attacks."
   TRUST-CV is an assurance and detection platform. It detects and reports;
   it does not prevent an attacker from crafting evasion-resistant inputs.

7. ❌ "Black-box models are fully verified."
   Black-box models receive binary SHA-256 verification only. Architecture
   and behavioral analysis require white-box access.

---

## WHAT TO CLAIM

1. ✅ TRUST-CV provides **deterministic, cryptographically-grounded** integrity
   assurance for computer vision datasets, models, and inference records.

2. ✅ Every assurance verdict is derived from **real evidence** computed by
   the backend pipeline — the frontend renders results, never calculates them.

3. ✅ The system operates **fully offline / air-gapped** with no external
   dependencies.

4. ✅ A tamper-evident audit trail records every pipeline event in a
   **hash-chained ledger** with replay-protected analyst decisions.

5. ✅ **Multi-source evidence fusion** combines data integrity, model identity,
   behavioral fingerprint, inference DNA, and distribution shift evidence into
   a holistic risk score.

6. ✅ The **three-tier disposition** (ACCEPTED / UNDER_REVIEW / QUARANTINED)
   correctly reflects multi-source risk — `CRITICAL_SHIFT` alone produces
   `UNDER_REVIEW`, not a false ACCEPTED.

7. ✅ Coverage of approximately **64% of the mapped attack vector space** with
   documented gaps per `ATTACK_COVERAGE.md`.

---

## TEST EVIDENCE SUPPORTING READINESS

| Test Command | Result |
|---|---|
| `pytest backend/tests/ -q` | **573/573 PASS** |
| `npm test` (frontend) | **10/10 PASS** |
| `npm run build` (frontend) | **PASS** (363 KB bundle) |
| Phase 10 compliance tests | **10/10 PASS** |
| Phase 9 red-team scenarios | **38/38 PASS** |
| Live E2E pipeline (Phase 8) | **PASS** — real upload → scan → assessment |

---

*Document generated from Phase 10 audit — September 2026.*
