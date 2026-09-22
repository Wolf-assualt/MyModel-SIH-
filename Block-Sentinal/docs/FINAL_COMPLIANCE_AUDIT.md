# FINAL COMPLIANCE AUDIT — TRUST-CV Phase 10

**SIH26228 — Zero-Trust Computer Vision Integrity Assurance**
**Audit date: September 2026**

This document records the Phase 10 compliance audit of the full TRUST-CV
pipeline. Every claim is supported by test evidence cited at the end.

---

## Audit Scope

The following areas were audited in full:

- Upload → Ingestion → Hashing → Data Assurance → Model Assurance →
  Inference Assurance → Distribution Shift → Evidence Fusion →
  Evidence Graph → Tamper-Evident Ledger → Final Assessment → Report
- Simulation / fabrication search across the entire repository
- Critical CRITICAL_SHIFT + ACCEPTED disposition logic trace
- Model upload path (SIH readiness blocker)
- Inference provenance, tamper detection, replay protection
- Dataset assurance detectors and provenance
- Ledger persistence, restart recovery, tamper vectors
- Evidence fusion architecture: no silent fabrication
- Frontend: no fabricated security decisions, UNAVAILABLE display
- Offline / air-gapped requirement
- Report contents: backend-derived only

---

## PASS — Verified Requirements

### P-01: Data Integrity Pipeline

| Component | Status | Evidence |
|-----------|--------|---------|
| Dataset upload (multipart) | PASS | `POST /api/v1/datasets/upload` → `ScanSession` with `scan_id` |
| Per-sample SHA-256 hashing | PASS | `hash_file()` on every sample in manifest |
| Merkle root computation | PASS | `DatasetIngestionEngine.ingest()` → `BatchManifest.merkle_root` (64-char) |
| Exact duplicate detection | PASS | `DuplicateDetector` — SHA-256 group collision, `confidence=1.0` |
| Near-duplicate detection | PASS | `DuplicateDetector` — dHash Hamming ≤ threshold |
| Label conflict detection | PASS | `LabelInconsistencyDetector` — near-dup with differing labels |
| Quality anomaly detection | PASS | `QualityDetector` — zero-variance, corrupt file, extreme aspect ratio |
| Trigger candidate detection | PASS | `TriggerCandidateDetector` — repeated corner-patch signature |
| OOD (with reference) | PASS | `OODDetector` — Z-score vs reference stats |
| OOD (no reference) | UNAVAILABLE (by design) | Returns `[]` — never self-comparison |
| Contributor risk aggregation | PASS | `DataIntegrityEngine._aggregate_contributor_risk()` |
| Integrity report canonical digest | PASS | `report_digest = canonical_json_hash(report_data)` |

### P-02: Model Assurance Pipeline

| Component | Status | Evidence |
|-----------|--------|---------|
| Model upload (multipart) | PASS | `POST /api/v1/models/upload` — added Phase 10 |
| Model registration (JSON path) | PASS | `POST /api/v1/models/register` — existing |
| Binary SHA-256 hash | PASS | `hash_file()` on disk at registration time |
| Structural / architecture hash | PASS | `architecture_hash` = canonical JSON of `{layer_name, shape}` pairs |
| Per-layer weight hash | PASS | Per-tensor SHA-256 in `ModelRegistry.register_model()` |
| ECDSA identity signature | PASS | `KeyManager.sign_hash(identity_digest)` — SECP256R1 |
| Modified model detection | PASS | Re-hash on disk vs `artifact_hash`; `binary_match=False` on byte change |
| Black-box handling | PASS | `structural_identity = UNAVAILABLE`; limitations documented |
| Missing model | PASS | `FileNotFoundError` → 404; no fabricated verdict |

### P-03: Inference Assurance

| Component | Status | Evidence |
|-----------|--------|---------|
| ONNX Runtime execution | PASS | `ModelRuntimeEngine.execute_inference()` |
| Output SHA-256 | PASS | `hash_bytes(output_arr.tobytes())` |
| DNA record creation (5-pillar) | PASS | `InferenceDNAGenerator.create_dna_record()` |
| ECDSA DNA signature | PASS | `KeyManager.sign_hash(dna_hash)` — SECP256R1 |
| Post-signing tamper detection | PASS | `InferenceDNAVerifier.verify_record()` — hash recomputation |
| Nonce replay protection | PASS | `seen_nonces: Set[str]` — persistent across disk |
| Record ID replay protection | PASS | `seen_records: Set[str]` — persistent |
| Sequence rollback protection | PASS | Monotonic counter enforced |
| Chain continuity | PASS | `InferenceDNAVerifier.verify_chain()` |

### P-04: Distribution Shift

| Component | Status | Evidence |
|-----------|--------|---------|
| Baseline registration | PASS | `DistributionShiftEngine.register_baseline()` + ECDSA signature |
| Shift evaluation (14 features) | PASS | KS distance, PSI, Wasserstein, energy distance per feature |
| CRITICAL_SHIFT → UNDER_REVIEW | PASS | Drift isolation: caps `risk_score ≤ 0.65` alone |
| Self-comparison rejection | PASS | `baseline_id != target_batch_id` invariant → `ValueError` |
| Missing baseline → UNAVAILABLE | PASS | `FileNotFoundError` → UNAVAILABLE, never self-substitution |
| Baseline digest integrity | PASS | ECDSA-signed `baseline_digest` |

### P-05: Evidence Fusion

| Component | Status | Evidence |
|-----------|--------|---------|
| Multi-source evidence consumption | PASS | `EvidenceFusionEngine.fuse()` — real `evidence_items` from all upstream stages |
| Weighted risk scoring | PASS | `SOURCE_WEIGHTS` × `SEVERITY_MULTIPLIERS` |
| Drift isolation rule | PASS | Drift alone caps at 0.65; never auto-quarantine without corroboration |
| Hard-veto rules (6 rules) | PASS | Trigger → QUARANTINED/BLOCK regardless of risk_score |
| Three-tier disposition | PASS | QUARANTINED (≥0.70) / UNDER_REVIEW (0.30–0.70) / ACCEPTED (<0.30) |
| Fusion result reaches frontend | PASS | **Fixed Phase 10** — REPORT stage no longer overwrites |
| ECDSA-signed assessment digest | PASS | `canonical_json_hash(digest_payload)` + `sign_hash()` |
| Cross-subject injection prevention | PASS | `strict_subject_binding` mode available |

### P-06: Evidence Graph

| Component | Status | Evidence |
|-----------|--------|---------|
| Lineage construction | PASS | `EvidenceGraphEngine.build_lineage()` — 19 entity types |
| Real entity relationships | PASS | Nodes and edges from upstream pipeline IDs |
| Graph digest | PASS | `canonical_json_hash` of node+edge set |
| Blast radius calculation | PASS | `calculate_blast_radius()` — BFS downstream traversal |
| No fabricated graph relationships | PASS | `build_lineage()` only adds nodes for entities it receives as arguments |

### P-07: Tamper-Evident Audit Ledger

| Component | Status | Evidence |
|-----------|--------|---------|
| SQLite persistence | PASS | `LedgerEngine` with `get_ledger_db()` |
| Hash chain linkage | PASS | `previous_hash = prior_event.current_hash` |
| Field mutation detection | PASS | `verify_chain()` recomputes SHA-256 per event |
| Previous-hash break detection | PASS | Chain pointer validation |
| Sequence gap detection | PASS | Monotonic index check |
| ECDSA-signed analyst decisions | PASS | `record_analyst_decision(..., sign=True)` |
| Restart recovery | PASS | Ledger DB persisted to `DATA_DIR/ledger/ledger.db` |

### P-08: Final Assessment Correctness (Critical Fix)

**Pre-fix behaviour (DEFECT):** The `_run_scan_pipeline` REPORT stage
unconditionally overwrote `session.assessment` with a simplified dict built
only from `DataIntegrityEngine.overall_health_score`. This caused:

- `CRITICAL_SHIFT` + zero integrity findings → `disposition: ACCEPTED`
  (incorrect — fusion isolation rule requires `UNDER_REVIEW`)
- `UNDER_REVIEW` integrity recommendation collapsed to `QUARANTINED`
  via `else "QUARANTINED"` binary branch
- `fusionAssessment` nested dict never sent to frontend
- `modelRiskScore` always hardcoded `-1.0` even when model was present

**Post-fix behaviour (PASS):** The REPORT stage now:

1. Checks `session.assessment.get("fusionAssessment")`.
2. If fusion ran: enriches the existing fusion assessment with
   `imageResults`, `totalSamples`, `flaggedSamples`, `dataRiskScore`.
3. If fusion was unavailable: falls back to the three-tier integrity
   recommendation (`ACCEPTED` / `UNDER_REVIEW` / `QUARANTINED`) using
   `rec_value = report.recommendation.value`.

Policy verified: CRITICAL_SHIFT alone → `risk_score ≤ 0.65` →
`overall_status = UNDER_REVIEW`. Test: `test_critical_shift_alone_produces_under_review_not_accepted`.

### P-09: Frontend Security Boundary

| Requirement | Status | Evidence |
|-------------|--------|---------|
| No client-side security verdict calculation | PASS | `investigationStore.tsx` — all values from `session.assessment` verbatim |
| No fabricated progress | PASS | `pollScanProgress()` polls real `session.progress` from backend |
| No fabricated metrics | PASS | `liveMetrics` zeroed until backend provides data |
| No fabricated findings | PASS | `findings` populated from `session.findings[]` verbatim |
| UNAVAILABLE displayed correctly | PASS | `-1` sentinel → `"UNAVAILABLE"` in `TrustScoreCard` |
| UNDER_REVIEW displayed | PASS | `VerdictCard` and `TrustScoreCard` handle `UNDER_REVIEW`/`CAUTION` |
| Backend error surfaced | PASS | `BackendErrorBanner` displays `backendError` state |
| startScan guard | PASS | Refuses without `currentScanId`; sets `backendError` |

### P-10: Offline / Air-Gapped Operation

| Requirement | Status | Evidence |
|-------------|--------|---------|
| No external API calls in assurance core | PASS | `grep -r "import requests\|import httpx\|aiohttp"` → no matches in `app/` |
| All crypto uses local ECDSA | PASS | `cryptography` library, SECP256R1, local key pairs |
| All ML inference uses ONNX Runtime local | PASS | `onnxruntime`, CPU provider only |
| Vite dev server proxies to local backend | PASS | `vite.config.ts` proxy → `http://127.0.0.1:8000` |

### P-11: Report Contents

All exported reports (`exportReport()`, `exportEvidencePackage()`) assemble
data from:

- `scanSession.assessment` — backend assessment dict
- `scanSession.findings` — backend findings array
- `apiService.fetchGraphExport()` — backend graph digest
- `apiService.verifyLedger()` — backend ledger verification
- `apiService.fetchOverview()` — backend system overview

No report field is calculated or fabricated in the browser.

---

## PARTIAL — Implemented but Incomplete

### PA-01: OOD Detection

**Implemented:** Z-score comparison on brightness and entropy vs reference stats.

**Incomplete:** Only 2 features (brightness, entropy). The distribution shift
engine uses 14 features but the `OODDetector` is a separate lighter component.
Full feature-space per-sample OOD (using the 14-feature extractor) is not
implemented.

**Impact:** OOD detection on the per-sample level is less sensitive than the
batch-level distribution shift analysis.

### PA-02: Inference Assurance in Scan Pipeline

**Implemented:** Inference DNA creation and verification work fully when a
model binary is available and ONNX Runtime can process the sample.

**Incomplete:** The scan pipeline requires a `model_id` in the dataset manifest
metadata. When no model is provided at scan time, `BACKDOOR_ANALYSIS` and
`INFERENCE_VALIDATION` are marked `UNAVAILABLE`. There is no automatic model
selection.

### PA-03: Scan Session Recovery After Browser Refresh

**Implemented:** `currentScanId` is stored in React state during an active
session. The backend keeps the scan session in memory.

**Incomplete:** A browser refresh loses `currentScanId`. The scan continues
on the backend but the frontend cannot recover it without the ID. Persisting to
`sessionStorage` is not implemented.

### PA-04: LiveMetrics / TerminalLog Streaming

**Implemented:** Components render correctly with zeroed/empty initial state.
Full results appear after scan completion.

**Incomplete:** The backend does not stream incremental sample-level counters
or log events during scanning. LiveMetrics and TerminalLog are only populated
from the final assessment, not in real time.

### PA-05: Contributor Identity

**Implemented:** Contributor ID is extracted from the dataset manifest.
Contributor risk is aggregated from findings by contributor.

**Incomplete:** Contributor identity is a plain string — no cryptographic
contributor binding (e.g., signed manifests with key attestation). The system
reports `UNKNOWN` when the contributor field is empty or anonymous.

---

## UNAVAILABLE — Intentionally Absent Without Prerequisites

| Module | Condition | Behaviour |
|--------|-----------|-----------|
| OOD Detection | No reference stats provided | Returns `[]` — never self-comparison |
| Distribution Shift | No baseline registered | `FileNotFoundError` — UNAVAILABLE |
| Model Assurance | No model in scan batch manifest | `MODEL_INTEGRITY: UNAVAILABLE` |
| Inference Assurance | No model binary in registry | `BACKDOOR_ANALYSIS: UNAVAILABLE` |
| Behavioral Fingerprint | PyTorch model (no ONNX runtime) | Falls back to weight-sensitive synthetic forward; labelled PARTIAL |
| Black-box Structural Verification | `AccessMode.BLACK_BOX` | `structural_identity: UNAVAILABLE` — documented in finding |

These are correct and expected. None of these conditions produces a fabricated
PASS or ACCEPTED outcome.

---

## FAILED — Defects Found and Fixed

### F-01: REPORT Stage Overwrite (FIXED)

**File:** `backend/app/api/scan.py`, `_run_scan_pipeline`, REPORT stage

**Defect:** The REPORT stage unconditionally replaced `session.assessment` with
an integrity-only dict, discarding the Evidence Fusion result. This produced
`disposition: ACCEPTED` for datasets with `CRITICAL_SHIFT` but zero integrity
findings.

**Fix:** REPORT stage now checks for `fusionAssessment` key in existing
assessment and enriches it rather than replacing it. Fallback uses three-tier
`rec_value` from integrity engine.

**Regression test:** `test_critical_shift_alone_produces_under_review_not_accepted`

### F-02: UNDER_REVIEW Collapsed to QUARANTINED (FIXED)

**File:** `backend/app/api/scan.py`, exception fallback block

**Defect:** `"ACCEPTED" if report.recommendation == "ACCEPTED" else "QUARANTINED"`
— a binary branch with no `UNDER_REVIEW` arm.

**Fix:** Uses `rec_value = report.recommendation.value` directly.

**Regression test:** `test_under_review_is_not_collapsed_to_quarantined`

### F-03: No Model Multipart Upload Endpoint (FIXED)

**File:** `backend/app/api/models.py`

**Defect:** Only `POST /api/v1/models/register` existed, requiring a file path
already present on the backend. Frontend had no path to upload a model binary.

**Fix:** `POST /api/v1/models/upload` added — accepts multipart form with
`file`, `name`, `version`, `format`, `is_reference`. Frontend `investigationStore`
now calls `apiService.uploadModel()` for the model artifact slot.

**Regression test:** `test_model_upload_returns_manifest`,
`test_model_upload_json_path_still_works`

---

## SECURITY / ASSURANCE GAPS

These are documented limitations — they do not represent implementation
defects, but they bound the assurance claims that can be made.

| Gap | Category | Impact |
|-----|----------|--------|
| Clean-label poisoning (no visual artifact) | Data Integrity | Cannot detect pixel-level adversarial perturbations below detector thresholds |
| Non-corner / per-sample-variable triggers | Data Integrity | `TriggerCandidateDetector` covers 4 corners only |
| Semantic OOD (content shift without pixel statistics change) | Data Integrity | OOD uses brightness and entropy only |
| Black-box model structural / behavioral analysis | Model Assurance | Binary hash only; architecture cannot be verified |
| Full-chain ledger rewrite by compromised system | Ledger | Unsigned system events can be consistently rewritten; only analyst decisions are ECDSA-signed |
| Contributor identity binding | Provenance | No cryptographic attestation of contributor identity |
| Scan session recovery | Frontend | Browser refresh loses scan state |
| Incremental metrics during scan | Frontend | LiveMetrics/TerminalLog not streamed during scan |
| ~36% uncovered attack vectors | Overall | Phase 9 coverage analysis: 32/50 mapped attack vectors covered |

---

## REQUIREMENT → IMPLEMENTATION → EVIDENCE

| SIH Requirement | Implementation | Test Evidence |
|-----------------|---------------|---------------|
| Real dataset upload | `POST /api/v1/datasets/upload` multipart | Phase 8 live test + `test_datasets_phase3.py` |
| SHA-256 provenance | `hash_file()` + `BatchManifest.sha256_hash` per sample | `test_foundation_phase1.py` |
| Duplicate detection | `DuplicateDetector` SHA-256 + dHash | `test_phase9_redteam.py::TestScenario02` |
| Trigger candidate | `TriggerCandidateDetector` corner-patch | `test_phase9_redteam.py::TestScenario05` |
| Model assurance | `ModelRegistry` binary + structural + ECDSA | `test_phase9_redteam.py::TestScenario07` |
| Model upload (frontend) | `POST /api/v1/models/upload` + `apiService.uploadModel()` | `test_phase10_compliance.py::TestModelUploadEndpoint` |
| Inference DNA | `InferenceDNAGenerator` 5-pillar tuple + ECDSA | `test_phase9_redteam.py::TestScenario09` |
| Replay protection | `seen_nonces` / `seen_records` sets | `test_phase9_redteam.py::TestScenario10` |
| Distribution shift | `DistributionShiftEngine` 14-feature KS+PSI | `test_phase9_redteam.py::TestScenario06` |
| CRITICAL_SHIFT → UNDER_REVIEW | Fusion isolation rule + REPORT fix | `test_phase10_compliance.py::test_critical_shift_alone` |
| Evidence fusion | `EvidenceFusionEngine.fuse()` multi-source | `test_fusion.py` + `test_phase9_e2e.py` |
| Hard-veto → QUARANTINED | Hard-veto rules in `EvidenceFusionEngine` | `test_phase10_compliance.py::TestFusionHardVetoIntact` |
| Evidence graph | `EvidenceGraphEngine.build_lineage()` | `test_graph.py` + `test_phase9_e2e.py` |
| Ledger tamper detection | `LedgerEngine.verify_chain()` | `test_phase9_redteam.py::TestScenario11` |
| No fabricated verdicts | Audit search + frontend analysis | No matches in `grep` for fabrication patterns |
| Offline operation | No `requests`/`httpx` in app/ code | Network dependency search |
| E2E pipeline | 11-stage `TestE2EFullPipeline` | `test_phase9_e2e.py` |

---

## TEST EVIDENCE

```
Command: pytest backend/tests/ -q --tb=short
Result:  573 passed, 1 warning in 262.96s

Command: npm test (frontend)
Result:  Tests: 10 passed

Command: npm run build (frontend)
Result:  dist/assets/index-*.js 363 KB  ✓ built

Phase 10 new tests: 10/10 PASS
Phase 9 tests:      38/38 PASS
Prior test baseline: 563/563 PASS
```

---

## REMAINING BLOCKERS

**None** for SIH26228 demonstration readiness. The three defects found were
fixed and regression-tested during this audit.

Documented limitations exist (see KNOWN_LIMITATIONS.md) but they do not block
demonstration of the core TRUST-CV assurance pipeline.

---

*Audit completed: September 2026. All findings reflect the repository state
after Phase 10 fixes.*
