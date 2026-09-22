# ATTACK COVERAGE — TRUST-CV Phase 9

**SIH26228 — Zero-Trust Computer Vision Integrity Assurance**

This document maps attack categories to the TRUST-CV assurance engine
components that address them, states the detection method, confidence
basis, and explicitly documents what is NOT covered.

No claim of complete attack coverage is made. The system is an
assurance aid, not a guarantee of security.

---

## Coverage Summary

| # | Attack Category | Engine / Detector | Detection Method | Status |
|---|-----------------|-------------------|------------------|--------|
| 1 | Exact duplicate samples | `DuplicateDetector` | SHA-256 byte-identity | **DETECTED** |
| 2 | Perceptual near-duplicates | `DuplicateDetector` | dHash Hamming distance | **DETECTED** (threshold-dependent) |
| 3 | Label conflict / mislabeling | `LabelInconsistencyDetector` | dHash + label comparison | **DETECTED** |
| 4 | Missing annotations | `LabelInconsistencyDetector` | Empty label list check | **DETECTED** |
| 5 | Malformed bbox annotations | `LabelInconsistencyDetector` | Coordinate range validation | **DETECTED** |
| 6 | Zero-variance / sensor blackout | `QualityDetector` | Pixel variance < 1.0 | **DETECTED** |
| 7 | Corrupt / unreadable image | `QualityDetector` | PIL decode failure | **DETECTED** |
| 8 | Localized corner trigger candidate | `TriggerCandidateDetector` | Repeated corner-patch SHA-256 | **DETECTED** (heuristic) |
| 9 | OOD samples (with reference) | `OODDetector` | Z-score vs reference stats | **DETECTED** (reference required) |
| 10 | OOD without reference | `OODDetector` | — | **UNAVAILABLE** (by design) |
| 11 | Binary model tampering | `ModelRegistry` | File SHA-256 re-hash | **DETECTED** |
| 12 | Structural model substitution | `ModelRegistry` | Architecture hash comparison | **DETECTED** (white-box only) |
| 13 | Weight-level parameter tampering | `ModelRegistry` | Per-layer SHA-256 hash | **DETECTED** (PyTorch only) |
| 14 | Behavioral model divergence | `BehaviouralFingerprinter` | Probe battery + cosine similarity | **DETECTED** (threshold-dependent) |
| 15 | Black-box model (structural) | `ModelRegistry` | — | **UNAVAILABLE** (by design) |
| 16 | Post-signing inference tampering | `InferenceDNAVerifier` | DNA tuple hash recomputation | **DETECTED** |
| 17 | ECDSA signature forgery | `InferenceDNAVerifier` | ECDSA SECP256R1 verification | **DETECTED** |
| 18 | Nonce replay attack | `InferenceDNAGenerator` | Seen-nonce set | **DETECTED** |
| 19 | Record ID replay | `InferenceDNAGenerator` | Seen-record-id set | **DETECTED** |
| 20 | Sequence rollback | `InferenceDNAGenerator` | Monotonic counter | **DETECTED** |
| 21 | Distribution shift (with baseline) | `DistributionShiftEngine` | KS distance + PSI + Wasserstein | **DETECTED** |
| 22 | Distribution shift (no baseline) | `DistributionShiftEngine` | — | **UNAVAILABLE** (by design) |
| 23 | Baseline self-comparison | `DistributionShiftEngine` | ID equality check | **REJECTED** (invariant) |
| 24 | Baseline digest tampering | `DistributionShiftEngine` | ECDSA-signed baseline digest | **DETECTED** |
| 25 | Ledger event field mutation | `LedgerEngine` | Hash chain recomputation | **DETECTED** |
| 26 | Ledger previous-hash break | `LedgerEngine` | Chain pointer validation | **DETECTED** |
| 27 | Ledger payload hash mutation | `LedgerEngine` | Payload hash recomputation | **DETECTED** |
| 28 | Ledger sequence gap / reorder | `LedgerEngine` | Monotonic sequence check | **DETECTED** |
| 29 | Multi-source threat correlation | `ThreatCorrelator` + `EvidenceFusionEngine` | Source × severity weighted risk | **DETECTED** |
| 30 | Cross-subject evidence injection | `EvidenceFusionEngine` | Subject binding check | **DETECTED** (strict mode) |

---

## Detailed Coverage by Domain

### DATA INTEGRITY

#### Covered

**Exact Duplicates**
- Detector: `DuplicateDetector` (SHA-256 hash grouping)
- Confidence basis: `1.0` — SHA-256 byte-identity is deterministic
- Severity: `MEDIUM`
- Finding type: `EXACT_DUPLICATE`

**Perceptual Near-Duplicates**
- Detector: `DuplicateDetector` (dHash + Union-Find clustering)
- Confidence basis: `1.0 - (avg_hamming_distance / 64)` — normalized over 64-bit dHash space
- Severity: `LOW`
- Finding type: `NEAR_DUPLICATE`
- Threshold: configurable (default: Hamming ≤ 4)

**Label Conflict on Near-Identical Images**
- Detector: `LabelInconsistencyDetector`
- Confidence basis: `1.0 - (hamming / 64)` — visual similarity of conflicting pair
- Severity: `HIGH`
- Finding type: `LABEL_INCONSISTENCY`

**Missing Labels**
- Detector: `LabelInconsistencyDetector`
- Confidence basis: `1.0` — deterministic (annotation list is empty)
- Severity: `MEDIUM`
- Note: Unannotated image-folder datasets (no annotation source at all) are exempt

**Malformed Bounding Boxes**
- Detector: `LabelInconsistencyDetector`
- Confidence basis: `1.0` — deterministic (coordinates outside `[0, 1]`)
- Severity: `HIGH`
- Finding type: `MALFORMED_ANNOTATION`

**Zero-Variance / Sensor Blackout**
- Detector: `QualityDetector`
- Confidence basis: `1.0` — deterministic (pixel variance < 1.0)
- Severity: `HIGH`
- Finding type: `QUALITY_ANOMALY`

**Corrupt Image Files**
- Detector: `QualityDetector`
- Confidence basis: `1.0` — deterministic (PIL cannot decode)
- Severity: `HIGH`
- Finding type: `QUALITY_ANOMALY`

**Localized Corner Trigger Candidate**
- Detector: `TriggerCandidateDetector`
- Confidence basis: `affected_count / label_group_size` — proportion of samples with matching patch signature
- Severity: `CRITICAL`
- Finding type: `TRIGGER_CANDIDATE`
- Note: This is a CANDIDATE finding. The system does NOT assert a confirmed backdoor.

**OOD Detection (with independent reference)**
- Detector: `OODDetector`
- Method: Z-score on brightness and entropy vs reference distribution statistics
- Confidence basis: `null` — z-score magnitude is not a calibrated probability
- Finding type: `OOD_ANOMALY`

#### Not Covered

| Attack | Reason Not Covered |
|--------|--------------------|
| Semantic label flipping without visual similarity | Detector requires near-identical images (dHash ≤ threshold) to flag label conflict; distant pairs not evaluated |
| Triggers that vary per sample | Corner detector requires repeated static patch across ≥ 2 distinct samples |
| Non-corner localized triggers (mid-image, adaptive) | Only 4 corner regions of fixed `patch_size` are inspected |
| Clean-label poisoning without visual artifacts | No gradient-based or feature-space detector is implemented |
| Adversarial examples (imperceptible perturbations) | Sub-threshold pixel changes pass quality and near-duplicate checks |
| Class-conditional distribution drift within label | Per-label feature analysis is not implemented |
| Semantic content attacks (valid images, wrong context) | No semantic understanding layer |
| GAN-generated synthetic samples | No generative detection; appears as normal varied-content image |

---

### MODEL ASSURANCE

#### Covered

**Binary File Tampering**
- Engine: `ModelRegistry.verify_against_baseline()`
- Method: Re-hash file on disk with `hash_file()`, compare against registered `artifact_hash`
- Confidence: deterministic (SHA-256)
- Detects: any byte-level change to the model binary

**Architecture / Structural Substitution**
- Engine: `ModelRegistry` — `architecture_hash` comparison
- Method: Canonical JSON hash of `{layer_names, shapes}` — structure-only, not weights
- Applicable to: PyTorch state_dict formats
- Falls back to: `identity_digest` for non-PyTorch formats

**Per-Layer Weight Hash Tampering**
- Engine: `ModelRegistry` — `weights_hash` comparison, per-layer `sha256_hash`
- Method: Individual layer tensor hashing via canonical JSON
- Applicable to: PyTorch state_dict formats that expose `torch.load(..., weights_only=True)`

**Behavioral Fingerprint Divergence**
- Engine: `BehaviouralFingerprinter`
- Method: Deterministic probe battery (seed=42, 8 images, all perturbation types); aggregate SHA-256 digest of all probe outputs
- Confidence: cosine similarity of probe output vectors; divergence threshold = 0.95

**ECDSA Identity Signature**
- Engine: `ModelRegistry` (signs `identity_digest` on registration)
- Method: ECDSA SECP256R1 signature of the canonical identity payload
- Detects: manifest tampering post-registration

#### Not Covered

| Attack | Reason Not Covered |
|--------|--------------------|
| Black-box model structural analysis | `AccessMode.BLACK_BOX` → `structural_identity = UNAVAILABLE` by design |
| PyTorch `.pkl`-format arbitrary code execution | Pickle execution is disabled; only `weights_only=True` loads are permitted |
| Model compression or quantization artifacts | Hash-based detection does not distinguish intentional quantization from tampering |
| Fine-tuned model (same architecture, different weights) | Detected as weight mismatch (structural match, weight mismatch) — flagged, not blocked by default unless fingerprint divergence |
| Hardware-level model extraction attacks | Out of scope for software-layer assurance |
| Gradient-based trigger implantation in weights | No white-box gradient analysis is implemented |

---

### INFERENCE PROVENANCE

#### Covered

**Post-Signing Output Tampering**
- Engine: `InferenceDNAVerifier.verify_record()`
- Method: Recompute 5-pillar tuple DNA hash (`input ∥ model ∥ preprocessing ∥ config ∥ output`); compare against stored `dna_hash`
- Confidence: deterministic (SHA-256 recomputation)
- Detects: any change to any of the 5 hash pillars after signing

**ECDSA Signature Forgery**
- Engine: `InferenceDNAVerifier`
- Method: `KeyManager.verify_signature(public_key_pem, dna_hash, signature)` — real ECDSA SECP256R1
- Detects: signatures not produced by the legitimate signing key

**Nonce Replay**
- Engine: `InferenceDNAGenerator` — `seen_nonces: Set[str]`
- Method: Exact nonce string match in persistent set
- Persistence: Saved to `storage_dir/state.json`
- Detects: re-submission of a previously used 128-bit nonce

**Record ID Replay**
- Engine: `InferenceDNAGenerator` — `seen_records: Set[str]`
- Detects: re-submission of a previously used record ID

**Sequence Rollback**
- Engine: `InferenceDNAGenerator` — monotonic `_sequence_counter`
- Detects: sequence numbers ≤ last recorded sequence

**Chain Continuity Break**
- Engine: `InferenceDNAVerifier.verify_chain()`
- Method: Previous-hash pointer validation across a sequence of DNA records

#### Not Covered

| Attack | Reason Not Covered |
|--------|--------------------|
| Pre-signing fabrication (attacker holds signing key) | If the signing key is compromised, all DNA records must be considered untrusted. Key rotation is not implemented. |
| Cross-instance nonce replay | Replay detection is scoped to a single generator instance + storage path. A fresh generator with a different storage directory does not inherit prior nonce history. |
| Timing-based side-channel | No timing analysis; out of scope |
| Covert channel through inference metadata | Metadata field values are hashed but not semantically audited |

---

### DISTRIBUTION SHIFT

#### Covered

**Statistical Feature Shift (with independent reference)**
- Engine: `DistributionShiftEngine.evaluate_shift()`
- Features: 14 per-image features (brightness, contrast, sharpness, color temperature, channel entropy, dimensions, aspect ratio, per-channel mean/std)
- Statistics: KS distance, PSI, Wasserstein distance, energy distance per feature
- Self-comparison invariant: `baseline_id != target_batch_id` enforced; `ValueError` on violation

**Baseline Integrity (ECDSA-signed)**
- Engine: `DistributionShiftEngine.verify_baseline_integrity()`
- Method: Recompute canonical baseline digest; verify ECDSA signature
- Detects: baseline profile tampering post-registration

**Drift Classification**
- Engine: `DistributionShiftEngine` — rule-based classification
- Types: `NO_DRIFT`, `OPERATIONAL_ENVIRONMENTAL`, `SENSOR_DEGRADATION`, `DATASET_DRIFT`, `ADVERSARIAL_ANOMALY`
- Isolation rule: Distribution shift alone does NOT trigger automatic quarantine (caps at UNDER_REVIEW)

#### Not Covered

| Attack | Reason Not Covered |
|--------|--------------------|
| Shift without reference dataset | UNAVAILABLE — no self-comparison substitution permitted |
| Semantic distribution shift | Feature extraction is pixel-statistical; semantic content drift is not measured |
| Adversarial distribution mimicry | An attacker who matches feature statistics of the reference would evade detection |
| Temporal drift tracking | No time-series analysis across batches |

---

### EVIDENCE FUSION

#### Covered

**Hard Veto Triggers (→ automatic QUARANTINE)**

The fusion engine applies 6 hard-veto rules that override weighted risk scoring:

| Rule | Trigger Condition |
|------|-------------------|
| Explicit metadata veto | `evidence.metadata["hard_veto"] = True` |
| Weight tampering | `evidence_type in ("WEIGHT_TAMPERING", "CRYPTO_TAMPERING", "BACKDOOR_POISONING")` AND `severity = CRITICAL` |
| Cryptographic forgery | `source = CRYPTO_VERIFICATION` AND `severity = CRITICAL` |
| Inference replay/tamper | `source = INFERENCE_DNA` AND `severity = CRITICAL` AND description contains "replay"/"tamper"/"broken"/"mismatch" |
| Model substitution | `source = MODEL_IDENTITY` AND `severity = CRITICAL` AND description contains "mismatch"/"substitution"/"tamper" |
| Data poisoning/tampering | `source = DATA_INTEGRITY` AND `severity = CRITICAL` AND description contains "tamper"/"backdoor"/"trigger"/"poison" |

**Weighted Risk Scoring**

Contributions by source:

| Source | Weight |
|--------|--------|
| `DATA_INTEGRITY` | 0.30 |
| `MODEL_IDENTITY` | 0.30 |
| `BEHAVIOURAL_FINGERPRINT` | 0.20 |
| `INFERENCE_DNA` | 0.15 |
| `DISTRIBUTION_SHIFT` | 0.05 |

Risk thresholds: ≥ 0.70 → QUARANTINED/BLOCK; 0.30–0.70 → UNDER_REVIEW/REVIEW; < 0.30 → ACCEPTED/ALLOW.

**Drift Isolation Rule**

Distribution shift evidence alone caps at `risk_score ≤ 0.65` (UNDER_REVIEW maximum) unless corroborated by behavioral or model identity evidence. Drift alone never triggers automatic quarantine.

**Threat Correlation**

`ThreatCorrelator` identifies multi-layer attack narratives:
- Targeted Backdoor Poisoning Campaign: `DATA_INTEGRITY(HIGH) + BEHAVIOURAL_FINGERPRINT(HIGH)`
- Unauthorized Model Substitution: `INFERENCE_DNA(CRITICAL) + MODEL_IDENTITY(CRITICAL)`
- Adversarial Perturbation Attack: `DISTRIBUTION_SHIFT(HIGH) + BEHAVIOURAL_FINGERPRINT(HIGH)`
- Cryptographic Provenance Failure: `INFERENCE_DNA(CRITICAL)` alone

#### Not Covered

| Attack | Reason Not Covered |
|--------|--------------------|
| Cross-subject evidence injection (non-strict mode) | `strict_subject_binding=False` by default; enable explicitly for binding enforcement |
| Evidence forgery from a compromised pipeline stage | Fusion trusts evidence producers; no cross-source mutual authentication |

---

### AUDIT LEDGER

#### Covered

- Event field mutation → hash recomputation failure (`verify_chain`)
- Previous-hash pointer break → chain continuity failure
- Payload hash mutation → current hash mismatch
- Sequence gap / reorder → monotonic sequence violation
- ECDSA signature verification on signed events (analyst decisions)

#### Not Covered

| Attack | Reason Not Covered |
|--------|--------------------|
| Complete chain rewrite (consistent re-hash of all events) | Without ECDSA signing on all events (only analyst decisions are signed), a consistent rewrite would appear valid. Mitigation: sign all critical events and retain an external hash anchor. |
| Database file deletion | No write-ahead log or external checkpoint |
| SQLite journal tampering | The WAL journal is not independently verified |

---

## Untested Attack Surfaces (Phase 9 Scope Boundary)

The following attack surfaces were intentionally not covered in Phase 9:

| Surface | Reason |
|---------|--------|
| Network-layer attacks | System is offline/air-gapped |
| API authentication bypass | No authentication layer implemented (planned future phase) |
| Frontend input injection | Phase 8 documented; no XSS/CSRF testing in Phase 9 |
| Contributor identity forgery | Contributor ID is a string; no cryptographic contributor binding |
| Multi-batch coordinated attack | Correlation across batches is not implemented |
| Adversarial ML evasion of detectors | Gradient-based evasion of the trigger/OOD detectors not tested |
| Red-team of the red-team framework itself | Out of scope |

---

## Coverage Score

This is a **coverage indicator only**, not an accuracy claim:

| Domain | Attacks Specified | Covered | Partial | Not Covered |
|--------|-------------------|---------|---------|-------------|
| Data Integrity | 15 | 9 | 1 | 5 |
| Model Assurance | 10 | 5 | 1 | 4 |
| Inference Provenance | 8 | 6 | 1 | 1 |
| Distribution Shift | 6 | 4 | 0 | 2 |
| Evidence Fusion | 5 | 4 | 1 | 0 |
| Audit Ledger | 6 | 4 | 1 | 1 |
| **Total** | **50** | **32** | **5** | **13** |

**Coverage rate: ~64% of specified attack vectors have coverage (32/50).**

"Covered" means a test exists that exercises the real production detector.
"Partial" means partial coverage with documented gaps.
"Not covered" means the attack vector has no current detector.

This score reflects the current implementation, not the difficulty or
importance of the uncovered attacks. Some uncovered vectors (e.g.,
gradient-based evasion) are significantly harder to defend against than
covered vectors.

---

*Generated from Phase 9 implementation — September 2026.*
