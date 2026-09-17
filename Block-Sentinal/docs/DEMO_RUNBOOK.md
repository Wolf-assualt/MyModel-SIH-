# TRUST-CV Live Demonstration Runbook

## 1. Quick-Start Preflight Check

Ensure your Python environment has local dependencies installed. No internet connection is required.

```bash
# 1. Initialize local SQLite database and cryptographic keys
python -m app.cli init-db

# 2. Run cryptographic self-test
python -m app.cli crypto-test

# 3. Start local backend and Web SOC Dashboard
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open Web SOC Command Center in your browser: `http://127.0.0.1:8000/`

---

## 2. Live Demo Script 1: Full End-to-End Assurance Lifecycle (3 Minutes)

Execute the complete end-to-end assurance pipeline from dataset ingestion to sealed report:

```bash
python scripts/demo_full_pipeline.py
```

### What Judges Observe:
1. **BigEarthNet-S2 Read-Only Inspection:** 3 compound Sentinel-2 patches discovered and validated across 12 GeoTIFF bands without disk mutations.
2. **Merkle Tree & ECDSA Signature:** Patch digests assembled into a binary Merkle tree with signed root digest.
3. **Model Weight Hashing:** Layer-by-layer state-dict hash and architecture graph hash.
4. **Behavioral Fingerprinting:** 7 physical transformations (noise, blur, contrast, rotation, occlusion).
5. **Sequential Inference DNA:** Inference record chaining with cryptographic nonce uniqueness and previous-hash binding.
6. **Distribution Drift:** Physical EO spectral indices (NDVI, visible brightness) evaluated against reference baseline.
7. **Evidence Fusion:** Multi-domain evidence combined into a unified disposition.
8. **Lineage Provenance Graph:** Upstream root cause and downstream dependencies linked.
9. **Sealed Forensic Report:** RFC 8785 canonical digest generated, signed, and cryptographically verified.

---

## 3. Live Demo Script 2: Defensive Tamper & Hard-Veto Quarantine (3 Minutes)

Demonstrate zero-trust detection when an adversary modifies a single byte in a satellite band:

```bash
python scripts/demo_tamper_scenario.py
```

### Demonstration Steps & Talking Points:
1. **Baseline Ingestion:** Ingests Sentinel-2 patch batch `Target_EO_Recon_Dataset`. Initial verification returns `PASS`.
2. **Adversarial Injection:** Injects `0xDEADBEEF` into Band 4 (`B04.tif` - Red channel).
3. **Immediate Tamper Detection:** Re-verification fails; Merkle root diverges, and `S2A_Patch_Alpha` is isolated.
4. **Hard-Veto Enforcement:** Gatekeeper triggers immediate **Hard Veto** (`BLOCK` & `QUARANTINED`), overriding all benign indicators.
5. **Blast-Radius Calculation:** Identifies all downstream training runs, models, and inferences as *"Potentially Affected / Requires Review"*.
6. **Sealed Forensic Incident Report:** Issues an auditable forensic report.
7. **Report Tamper Rejection:** When the report verdict is deliberately modified from `QUARANTINED` to `ACCEPTED`, signature verification instantly flags `REJECTED / TAMPERED`.

---

## 4. Live Demo Script 3: Benign Distribution Shift vs Integrity Violation (2 Minutes)

Demonstrate why TRUST-CV does not trigger false alarms on natural seasonal changes:

```bash
python scripts/demo_drift_scenario.py
```

### Demonstration Steps & Talking Points:
1. **Golden Baseline:** Establishes summer satellite profile (high NDVI, high solar elevation).
2. **Natural Seasonal Shift:** Ingests autumn satellite stream (moderate foliage loss, lower sun angle).
3. **Quantitative Metrics:** Calculates KS distance, PSI, Wasserstein-1 distance, and Energy distance.
4. **Calibrated Action:** Gatekeeper issues disposition `ALLOW_WITH_MONITORING / REVIEW` instead of automatic `QUARANTINE`.
5. **Key Principle:** *"Drift requires contextual operational review; cryptographic tampering demands immediate quarantine."*

---

## 5. Web SOC Dashboard Live Navigation Sequence (2 Minutes)

Open `http://127.0.0.1:8000/` and guide the judges through the 13 command views:

1. **Dashboard Overview:** System health, active dispositions, and activity timeline.
2. **Health Status:** Multi-subsystem readiness (DB, Crypto, Storage, Graph, Static Assets).
3. **Datasets View:** Inspect ingested BigEarthNet-S2 batches, Merkle roots, and band counts.
4. **Models View:** Inspect 4-dimensional model identities and layer-level weight digests.
5. **Inferences View:** Review the immutable Inference DNA sequential hash chain and nonces.
6. **Drift View:** Inspect statistical metric cards (KS, PSI, Wasserstein-1, Energy Distance).
7. **Evidence & Fusion Views:** Review cross-domain evidence items and Hard-Veto triggers.
8. **Quarantine View:** Inspect quarantined assets and auditable release justification workflows.
9. **Provenance Graph & Blast Radius:** Interactive SVG topology visualization showing upstream root cause and downstream affected consumers.
10. **Forensic Reports View:** Inspect, verify, and export cryptographically sealed forensic assurance certificates.
