# TRUST-CV (SIH26228)
### Zero-Trust Computer Vision Integrity Assurance, Cryptographic Lineage & Evidence Graph Platform
**Ministry of Defence (MoD) — Smart India Hackathon (SIH 2024 / SIH26228)**

---

## Executive Summary

**TRUST-CV** is an air-gapped, zero-trust cryptographic assurance platform purpose-engineered for mission-critical military and Earth Observation (EO) computer vision (CV) pipelines. In contested defense environments, CV models (YOLO, ResNet, Vision Transformers) are vulnerable to supply-chain attacks, including:
- **Data Poisoning & Clean-Label Backdoors:** Adversaries inject imperceptible physical patches into training datasets.
- **Model Weight Tampering & Substitution:** Unauthorized alterations to neural network weights or malicious architecture swaps.
- **Inference Spoofing & Replay Attacks:** Adversaries replay stale target detection outputs or forge inference results to mislead command systems.
- **Adversarial Distribution Shift & Sensor Degradation:** Environmental anomalies, sensor blinding, or out-of-distribution inputs.

TRUST-CV establishes an end-to-end chain of cryptographic custody across the entire AI/ML lifecycle—from raw Sentinel-2 / BigEarthNet-S2 multi-spectral dataset ingestion to runtime battlefield inference delivery—guaranteeing tamper evidence, contributor non-repudiation, automated quarantine, and continuous forensic auditability without reliance on external cloud services.

---

## Complete 16-Phase Roadmap & Capability Matrix

| Phase | Subsystem | Defense Mission & Core Capabilities | Engine / Modules | Status |
| :---: | :--- | :--- | :--- | :---: |
| **01** | **Foundation & Relational DB** | SQLite WAL mode, schema validation, foreign key enforcement, and air-gapped configuration. | `app.core`, `app.db`, `app.schemas` | **100% Verified ✅** |
| **02** | **Cryptographic Trust Foundation** | Deterministic canonical JSON (RFC 8785), SHA-256 Merkle trees, ECDSA SECP256R1 signatures, sequential hash chains. | `app.crypto.canonical`, `signer`, `merkle`, `chain` | **100% Verified ✅** |
| **03** | **Dataset Ingestion Pipeline** | Multi-format dataset parsing (Directory, YOLO TXT, COCO JSON), sample digest hashing, Merkle manifest sealing. | `app.datasets.parsers`, `app.datasets.engine` | **100% Verified ✅** |
| **04** | **Training Data Integrity Engine** | DCT perceptual hashing, exact/near-duplicate detection, label inconsistency auditing, and physical trigger detection. | `app.integrity.hasher`, `detectors`, `engine` | **100% Verified ✅** |
| **05** | **Model Ingestion & Identity** | Layer-wise weight tensor hashing, architecture structure normalization, and cryptographically signed identity manifests. | `app.models_engine.identity`, `engine` | **100% Verified ✅** |
| **06** | **Behavioural Fingerprinting** | Deterministic synthetic probe battery, spatial/noise transformations, IoU / L1 divergence comparison, substitution detection. | `app.fingerprint.battery`, `comparator`, `engine` | **100% Verified ✅** |
| **07** | **Inference DNA & Provenance** | 8-tuple provenance record $\langle \text{Input}, \text{Model}, \text{Output}, \text{Nonce}, \text{SeqID}, \dots \rangle$, ECDSA signature, anti-replay hash chain. | `app.inference.engine`, `schemas.inference` | **100% Verified ✅** |
| **08** | **Distribution-Shift Engine** | Pure statistical distance (Wasserstein-1, KS, PSI, Energy distance), operational drift classification without false-alarm quarantine. | `app.drift.statistical`, `features`, `engine` | **100% Verified ✅** |
| **09** | **Evidence Fusion Engine** | Multi-source evidence aggregation, Hard-Veto cryptographic override, cross-layer correlation rules, and automatic quarantine. | `app.fusion.aggregator`, `correlator`, `engine` | **100% Verified ✅** |
| **10** | **Contributor Risk & Lineage Graph** | In-engine directed property graph, upstream lineage traversal, downstream blast-radius impact analysis, contributor risk scoring. | `app.graph.engine`, `contributor`, `schemas.graph` | **100% Verified ✅** |
| **11** | **Red-Team Adversarial Lab** | Controlled defensive validation: label flipping, backdoor injection, weight tampering, inference replay, and coverage scorecards. | `app.redteam.attacks`, `runner`, `api.redteam` | **100% Verified ✅** |
| **12** | **Cryptographic Forensic Reports** | Sealed assurance manifests (RFC 8785 canonical digest + ECDSA SECP256R1), multi-format export (JSON, Markdown, HTML, Executive Brief). | `app.reports.engine`, `formatter`, `schemas.report` | **100% Verified ✅** |
| **13** | **SOC Command Center Dashboard** | 13 operational views, Obsidian Dark HUD, interactive SVG graph traversal, live telemetry, and 100% offline static assets. | `app.static/`, `app.templates/`, `main.py` | **100% Verified ✅** |
| **14** | **Performance & Air-Gap Hardening** | Performance profiling, streaming Merkle scaling up to 5,000 samples, SQLite WAL concurrent reads, multi-subsystem readiness probe. | `app.core.hardening`, `docs/PERFORMANCE.md` | **100% Verified ✅** |
| **15** | **BigEarthNet-S2 / EO Integration** | Sentinel-2 12-band multi-spectral adapter, read-only inspection, NDVI/NDWI spectral feature extraction, and EO drift analysis. | `app.datasets.bigearthnet`, `docs/BIGEARTHNET_S2.md` | **100% Verified ✅** |
| **16** | **Final System Delivery & Demo** | Clean startup packaging, end-to-end demo scripts, tamper & hard-veto demo, claims audit, and complete regression suite (373+ tests). | `scripts/`, `docs/DEMO_RUNBOOK.md` | **100% Verified ✅** |

---

## Quick Start (Air-Gapped & Offline)

### 1. Preflight Initialization
```bash
# Initialize local SQLite database and cryptographic keys
python -m app.cli init-db

# Run cryptographic self-test
python -m app.cli crypto-test
```

### 2. Start Backend & SOC Command Center
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open Command Center: **`http://127.0.0.1:8000/`**

### 3. Run Live Demonstrations
```bash
# 1. Complete End-to-End Operational Lifecycle Demo
python scripts/demo_full_pipeline.py

# 2. Defensive Tamper & Hard-Veto Quarantine Demo
python scripts/demo_tamper_scenario.py

# 3. Benign Distribution Shift vs Integrity Failure Demo
python scripts/demo_drift_scenario.py
```

---

## Documentation Index

Detailed engineering and operational manuals are available in [`docs/`](docs/):
* **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Complete system architecture, dataflows, and assurance layers.
* **[docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md)** — Step-by-step 5-10 minute live judge demonstration sequence and script guide.
* **[docs/SIH_PRESENTATION_GUIDE.md](docs/SIH_PRESENTATION_GUIDE.md)** — Slide-by-slide structure, talking points, and judge Q&A defense.
* **[docs/SECURITY_CLAIMS.md](docs/SECURITY_CLAIMS.md)** — Formal audit of cryptographic facts vs heuristic observations, and calibrated terminology.
* **[docs/BIGEARTHNET_S2.md](docs/BIGEARTHNET_S2.md)** — Sentinel-2 12-band multi-spectral dataset layout, operator import protocol, and spectral feature extraction.
* **[docs/OFFLINE_DEPLOYMENT.md](docs/OFFLINE_DEPLOYMENT.md)** — Air-gap deployment verification and network isolation guidelines.
* **[docs/PERFORMANCE.md](docs/PERFORMANCE.md)** — Subsystem latency benchmarks, throughput metrics, and scaling limits.
* **[docs/SECURITY_HARDENING.md](docs/SECURITY_HARDENING.md)** — Defensive threat model, Hard-Veto mechanics, and path safety.
* **[docs/PRODUCTION_RUNBOOK.md](docs/PRODUCTION_RUNBOOK.md)** — Operator daily workflows, quarantine release protocol, and crash recovery.

---

## Test Execution

Run the complete regression suite across all 16 phases:
```bash
pytest -v backend/tests/
```
**Current Baseline: 373+ Tests Passing (100%), 0 Failures, 0 Regressions.**
