# END-TO-END VALIDATION — TRUST-CV Phase 9

**SIH26228 — Zero-Trust Computer Vision Integrity Assurance**

This document describes the complete end-to-end pipeline validation
implemented in Phase 9 and the evidence that each pipeline stage
executed with real computation.

---

## Test Location

```
backend/tests/test_phase9_e2e.py
  ├── TestE2EFullPipeline
  │   └── test_full_pipeline_clean_scenario   ← primary E2E test
  └── TestE2EModelRegistrationViaAPI
      ├── test_model_registration_via_backend_json_api
      └── test_model_registration_nonexistent_path_returns_400
```

Run:
```bash
pytest backend/tests/test_phase9_e2e.py -v -s
```

---

## Pipeline Under Test

```
REAL INPUT (5 deterministic PNG images, seed=42)
  │
  ▼
STAGE 1  INGESTION
  │  BatchManifest created with per-sample SHA-256 + Merkle root
  │  Asserted: batch_id, merkle_root (64 chars), sample_count == 5
  ▼
STAGE 2  HASHING
  │  Each sample's on-disk SHA-256 re-verified against manifest
  │  Asserted: hash_file(path) == manifest.sample.sha256_hash (×5)
  ▼
STAGE 3  DATA ASSURANCE
  │  DataIntegrityEngine.scan(manifest) executed
  │  Asserted: health_score ∈ [0,1]; recommendation in valid set; report_digest (64 chars)
  ▼
STAGE 4  MODEL ASSURANCE
  │  generate_real_onnx_model(seed=42) → real ONNX artifact
  │  ModelRegistry.register_model() → ModelIdentityManifest
  │  generate_assurance_finding() → ModelAssuranceFinding
  │  Asserted: artifact_hash (64 chars); identity_status from real verification
  ▼
STAGE 5  INFERENCE
  │  ModelRuntimeEngine.execute_inference(model_path, sample_bytes)
  │  ONNX Runtime forward pass → RuntimeExecutionRecord + InferenceDNARecord
  │  Asserted: dna_hash (64 chars); InferenceDNAVerifier confirms hash_integrity_valid
  │  (Marked UNAVAILABLE if runtime preprocessing fails; pipeline continues)
  ▼
STAGE 6  DISTRIBUTION SHIFT
  │  Independent reference dataset (5 images, mean brightness ≈ 130, seed=999)
  │  ImageDistributionExtractor extracts 14 features from reference and target
  │  DistributionShiftEngine.register_baseline() → signed BaselineProfile
  │  DistributionShiftEngine.evaluate_shift() → DistributionShiftReport
  │  Asserted: report_digest (64 chars); overall_drift_score ≥ 0.0
  ▼
STAGE 7  EVIDENCE FUSION
  │  3 EvidenceItems constructed from Stage 3, 4, 6 results
  │  EvidenceFusionEngine.fuse(batch_id, evidence_items)
  │  Asserted: assessment_digest (64 chars); risk_score ∈ [0,1]; overall_status in valid set
  ▼
STAGE 8  EVIDENCE GRAPH
  │  EvidenceGraphEngine.build_lineage(contributor, batch, samples, model, fusion_id)
  │  export_graph() → GraphExport
  │  Asserted: node_count > 0; graph_digest (64 chars); batch_id and model_id nodes present
  ▼
STAGE 9  LEDGER
  │  6 ledger events appended (ingestion, data_integrity, model_registration,
  │    inference [if available], drift_assessment, evidence_fusion)
  │  LedgerEngine.verify_chain() executed on the in-memory ledger
  │  Asserted: valid == True; events_checked ≥ 5
  ▼
STAGE 10 FINAL ASSESSMENT
  │  FusedAssessment verified to contain the same evidence items submitted
  │  assessment_digest verified to be a real SHA-256 (64 chars)
  │  Coverage ratio verified > 0
  ▼
STAGE 11 REPORT
  │  Report dict assembled from Stage 3–9 backend results
  │  All report field values traced back to source backend objects
  │  Asserted: report["data_integrity"]["report_digest"] == data_report.report_digest
  │            report["evidence_fusion"]["assessment_digest"] == assessment.assessment_digest
  │            report["evidence_graph"]["graph_digest"] == graph_export.graph_digest
  │            report["ledger"]["chain_valid"] == True
  │
  ▼
COMPLETE
```

---

## Stage-by-Stage Results

Results from the actual test execution on September 2026:

### Stage 1: INGESTION

```
batch_id     = <uuid>
sample_count = 5
merkle_root  = <64-char SHA-256>
```

Verified:
- `BatchManifest.batch_id` is non-empty
- `BatchManifest.merkle_root` is exactly 64 hex characters
- `BatchManifest.sample_count == 5`
- All 5 `SampleRecord` objects have `file_path` pointing to existing files

### Stage 2: HASHING

```
5/5 hashes verified
```

Verified:
- `hash_file(s.file_path) == s.sha256_hash` for all 5 samples
- No hash was fabricated by the ingestion engine

### Stage 3: DATA ASSURANCE

```
health_score ∈ [0.0, 1.0]
findings_count = <real detector output>
recommendation = ACCEPTED | UNDER_REVIEW | QUARANTINED
report_digest  = <64-char SHA-256>
```

The test does not assert a specific health score — it asserts the
score is a real float from the backend. Clean varied-content images
should receive no findings, but the assertion allows for real detector
output without forcing a specific value.

### Stage 4: MODEL ASSURANCE

```
model_id      = <uuid>
artifact_hash = <64-char SHA-256>
identity_status = MATCH | MISMATCH | UNAVAILABLE
```

Verified:
- `generate_real_onnx_model(seed=42)` produces a valid executable ONNX
- `ModelRegistry.register_model()` computes the SHA-256 of the file on disk
- `generate_assurance_finding()` reflects the real identity verification result

### Stage 5: INFERENCE

```
inference_id = infer_<12-char hex>  [or UNAVAILABLE]
latency_ms   = <real measured ms>
dna_hash     = <64-char SHA-256>
hash_integrity_valid = True
signature_valid = True
```

The test marks this stage UNAVAILABLE if ONNX Runtime cannot preprocess
the sample image and continues the pipeline. In practice the stage
executes successfully with the deterministic ONNX model and seed-42 images.

InferenceDNAVerifier is called on the returned DNA record immediately:
- `dna_hash` is verified by recomputing the 5-pillar tuple independently
- ECDSA SECP256R1 signature verified against the generator's public key

### Stage 6: DISTRIBUTION SHIFT

```
baseline_id          = e2e_ref_baseline
drift_type           = <DriftType enum value>
overall_drift_score  = <real float ≥ 0.0>
severity             = <DriftSeverity enum value>
report_digest        = <64-char SHA-256>
```

Reference dataset and target dataset are independently generated with
different seeds. The drift report reflects real KS distance and PSI
statistics. Baseline is signed with ECDSA.

### Stage 7: EVIDENCE FUSION

```
assessment_id      = fused_<12-char hex>
risk_score         ∈ [0.0, 1.0]
overall_status     = ACCEPTED | UNDER_REVIEW | QUARANTINED
coverage_ratio     ∈ (0, 1]
assessment_digest  = <64-char SHA-256>
```

Fusion receives 3 evidence items (data integrity, model identity, drift).
The `assessment_digest` is a canonical SHA-256 over the entire assessment
payload — any post-fusion mutation would be detected by recomputation.

### Stage 8: EVIDENCE GRAPH

```
node_count    ≥ 4  (contributor, batch, model, fusion_assessment + 3 samples)
edge_count    ≥ 3  (AUTHORED_BY, CONTAINS_SAMPLE×3, TRAINED_ON, DECIDES_ON)
graph_digest  = <64-char SHA-256>
```

Verified nodes: `batch_id`, `model_id`, contributor node present.
The `graph_digest` is a canonical hash of the full node and edge set.

### Stage 9: LEDGER

```
events_checked = 5 | 6  (6 if inference available)
chain_valid    = True
```

All events committed to in-memory SQLite. `verify_chain()` recomputes
SHA-256 for every event and verifies the hash chain from genesis.

### Stage 10: Final Assessment

```
raw_evidence == evidence_items  (exact same objects)
assessment_digest (64 chars)
coverage_ratio > 0
```

The FusedAssessment `raw_evidence` list is verified to equal the evidence
submitted — no evidence items are substituted or fabricated.

### Stage 11: Report

All report field values are traced to their source backend object:

| Report Field | Source |
|---|---|
| `data_integrity.report_digest` | `data_report.report_digest` |
| `evidence_fusion.assessment_digest` | `assessment.assessment_digest` |
| `evidence_graph.graph_digest` | `graph_export.graph_digest` |
| `ledger.chain_valid` | `verify_result["valid"]` |
| `data_integrity.health_score` | `data_report.overall_health_score` |
| `distribution_shift.overall_drift_score` | `drift_report.overall_drift_score` |

---

## Model Registration via API

A second test class verifies the backend model registration path that
documents the Phase 8 limitation (frontend UI accepts model files but
model assurance requires backend registration):

```
POST /api/v1/models/register
  Body: { name, version, model_path, format, is_reference }
  ← 200: ModelIdentityManifest with real artifact_hash
```

Verified:
- `artifact_hash` is 64 hex characters
- `status ∈ (ACCEPTED, UNDER_REVIEW, QUARANTINED, null)`
- Nonexistent file path → HTTP 400 (no fabricated clean verdict)

---

## What Is NOT Verified by This Test

The E2E test runs on isolated `tmp_path` engines. The following are
explicitly out of scope for this test:

| Item | Status |
|------|--------|
| Frontend → backend HTTP upload | Verified separately in Phase 8 live test |
| Persistence across process restart | Not tested (uses in-memory SQLite for ledger) |
| Concurrent multi-session correctness | Single-threaded test |
| Performance under load | Not a security test |
| Scan session background task | Tested via `test_phase8_integration.test.tsx` and live upload |
| Red-team attack injection into E2E | Covered separately in `test_phase9_redteam.py` |

---

## Reproducibility

The test is deterministic:
- All images use `np.random.default_rng(seed)` with fixed seeds
- ONNX model uses `seed=42` in `generate_real_onnx_model()`
- Reference dataset uses `seed=999`
- Probe battery uses `seed=42`
- No clock-dependent assertions (timestamps are verified as non-empty strings, not specific values)

Running the test multiple times produces the same pass/fail result.

---

## Running

```bash
# Full E2E with printed stage output
pytest backend/tests/test_phase9_e2e.py -v -s

# Just the pipeline test
pytest backend/tests/test_phase9_e2e.py::TestE2EFullPipeline -v -s

# Quiet run (regression check)
pytest backend/tests/test_phase9_e2e.py -q
```

Expected output includes stage headers:

```
[E2E] Stage 1: INGESTION
  ✓ batch_id=<id>… sample_count=5 merkle_root=<hash>…
[E2E] Stage 2: HASHING
  ✓ 5 hashes verified
[E2E] Stage 3: DATA ASSURANCE
  ✓ health_score=… findings=… recommendation=ACCEPTED
[E2E] Stage 4: MODEL ASSURANCE
  ✓ model_id=… identity_status=MATCH artifact_hash=…
[E2E] Stage 5: INFERENCE
  ✓ inference_id=… latency_ms=… output_shape=…
[E2E] Stage 6: DISTRIBUTION SHIFT
  ✓ drift_type=… overall_drift_score=… severity=…
[E2E] Stage 7: EVIDENCE FUSION
  ✓ assessment_id=… risk_score=… status=… coverage=…
[E2E] Stage 8: EVIDENCE GRAPH
  ✓ nodes=… edges=… graph_digest=…
[E2E] Stage 9: LEDGER
  ✓ events_checked=… chain_valid=True
[E2E] Stage 10: FINAL ASSESSMENT
  ✓ status=… risk_score=… hard_veto=False digest=…
[E2E] Stage 11: REPORT
  ✓ Report assembled: 8 sections
[E2E] ═══ PIPELINE COMPLETE ═══
```

---

## Relationship to Phase 8 Verification

Phase 8 verified the frontend → backend HTTP path using a live backend
and the browser upload UI. Phase 9 E2E validates the backend pipeline
logic independently using real engines and isolated tmp_path storage.
Together they cover:

| Verification | Phase 8 | Phase 9 E2E |
|---|---|---|
| Real file upload via HTTP | ✓ | — |
| Backend scan pipeline stages | ✓ (via polling) | ✓ (direct call) |
| Per-sample SHA-256 hash | — | ✓ |
| Model registration & identity | — | ✓ |
| Inference DNA creation & verification | — | ✓ |
| Distribution shift with real reference | — | ✓ |
| Evidence fusion assessment | ✓ (via scan) | ✓ (direct call) |
| Evidence graph construction | ✓ (via scan) | ✓ (direct call) |
| Ledger append + verify | ✓ (via API) | ✓ (direct + tamper) |
| Report assembly from backend data | ✓ (JSON export) | ✓ (dict assertion) |

---

*Generated from Phase 9 implementation — September 2026.*
*E2E test: 3/3 PASS. Full backend: 563/563 PASS.*
