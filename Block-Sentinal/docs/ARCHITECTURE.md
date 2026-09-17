# TRUST-CV Architecture Specification

## 1. System Overview

**TRUST-CV** is an air-gapped, zero-trust cryptographic and behavioral assurance platform designed for computer vision pipelines in defense, intelligence, and mission-critical Earth Observation (EO) operations.

```text
                               ┌─────────────────────────────┐
                               │   MULTI-SPECTRAL EO DATA    │
                               │   Sentinel-2 / BigEarthNet  │
                               └──────────────┬──────────────┘
                                              ↓
                                     READ-ONLY INSPECTION
                                              ↓
                               ┌─────────────────────────────┐
                               │   CRYPTOGRAPHIC IDENTITY    │
                               │   SHA-256 / Merkle / ECDSA  │
                               └──────────────┬──────────────┘
                                              ↓
                        ┌─────────────────────┴─────────────────────┐
                        ↓                                           ↓
             DATA INTEGRITY ASSURANCE                    MODEL IDENTITY & WEIGHTS
             - Exact & Near Duplicates                   - Binary SHA-256
             - Perceptual dHash                          - Layer-by-Layer State Dict
             - Backdoor Corner Triggers                  - Structural Architecture Hash
                        │                                           │
                        └─────────────────────┬─────────────────────┘
                                              ↓
                                 BEHAVIORAL FINGERPRINTING
                                 - 7 Physical Transformations
                                 - Non-Destructive Invariance
                                              ↓
                                  RUNTIME INFERENCE DNA
                                  - Nonce Uniqueness & Anti-Replay
                                  - Sequential SHA-256 Hash Chain
                                              ↓
                                 DISTRIBUTION DRIFT ENGINE
                                 - 2-Sample Kolmogorov-Smirnov
                                 - Population Stability Index (PSI)
                                 - Wasserstein-1 Distance
                                 - Statistical Energy Distance
                                              ↓
                                  MULTI-DOMAIN EVIDENCE FUSION
                                  - Hard-Veto Cryptographic Override
                                  - Corroboration Matrix
                                              ↓
                              ┌───────────────┴───────────────┐
                              ↓                               ↓
                        ALLOW / REVIEW                    QUARANTINE
                              │                               │
                              └───────────────┬───────────────┘
                                              ↓
                                  PROVENANCE PROPERTY GRAPH
                                  - Upstream Lineage Tracing
                                  - Downstream Blast-Radius Analysis
                                              ↓
                                  FORENSIC ASSURANCE REPORT
                                  - RFC 8785 Canonical JSON
                                  - ECDSA SECP256R1 Digital Seal
                                              ↓
                                    WEB SOC DASHBOARD
                                    - 13 Operational Command Views
                                    - 100% Offline Static Delivery
```

---

## 2. Assurance Layers

### 2.1 Dataset Identity & Integrity (Phases 3, 4, 15)
* **Multi-Spectral Compound Ingestion:** Dedicated `BigEarthNetS2Adapter` processes 12 Sentinel-2 bands (10m, 20m, 60m) and CORINE land-cover metadata.
* **Merkle Inclusion Trees:** Leaves are formed by canonical sample digests; the root hash is signed via ECDSA SECP256R1.
* **Integrity Scanners:** Automated duplicate detection, perceptual difference hashing (dHash), and trigger backdoor detection.

### 2.2 Model Identity & Behavioral Fingerprinting (Phases 5, 6)
* **Four-Dimensional Model Identity:** (1) File SHA-256, (2) Layer-by-layer weight tensor state dict hash, (3) Model architecture graph hash, (4) ECDSA digital signature.
* **Behavioral Probes:** Evaluates candidate models against 7 deterministic physical perturbations (Identity, Gaussian Noise, Blur, Brightness, Contrast, Rotation, Occlusion) to detect stealth weight trojans and behavioral deviations.

### 2.3 Runtime Inference DNA & Anti-Replay (Phase 7)
* **Sequential Hash Chain:** Every inference produces an authenticated record:
  $$\langle \text{Input SHA-256}, \text{Model ID}, \text{Model Digest}, \text{Output Digest}, \text{Nonce}, \text{Sequence ID}, \text{Timestamp}, \text{Previous Hash} \rangle$$
* **Replay Protection:** Prevents duplicate nonce injection, sequence manipulation, or history rewriting.

### 2.4 Earth Observation Distribution Drift (Phases 8, 15)
* **Spectral Feature Extraction:** Computes NDVI, NDWI, visible brightness, and SWIR absorption.
* **Statistical Metrics:** Simultaneously evaluates KS distance, PSI, Wasserstein-1 distance, and Energy distance.
* **Calibrated Boundary:** Differentiates natural seasonal/environmental shifts from adversarial data corruption.

### 2.5 Multi-Domain Evidence Fusion & Hard Veto (Phase 9)
* **Precedence Rules:** Any cryptographic failure (e.g. weight tampering, signature mismatch, broken hash chain) triggers an immediate **Hard Veto**, resulting in disposition `BLOCK` and `QUARANTINED`, regardless of high benign scores in other domains.
* **Explainable Risk Scoring:** Aggregates multi-source evidence without opaque black-box scoring.

### 2.6 Lineage Provenance Property Graph & Blast Radius (Phase 10)
* **Bi-Directional Traversal:** Traces upstream root-cause lineage (Contributor -> Dataset -> Training Run -> Model) and downstream blast radius (Model -> Inferences -> Outputs).
* **Impact Framing:** Downstream affected dependencies are categorized as *"Potentially Affected / Requires Review"*.

### 2.7 Sealed Forensic Assurance Reports (Phase 12)
* **Cryptographic Tamper-Proofing:** Full evidence reports are canonicalized via RFC 8785, hashed with SHA-256, and signed with ECDSA SECP256R1.
* **Multi-Format Offline Export:** Markdown, Executive Summary, Standalone HTML, and JSON Manifest.

### 2.8 Web SOC Dashboard (Phase 13)
* **Thin Visualization Layer:** 13 operational views consuming REST API endpoints without duplicate assurance logic.
* **Air-Gap Strictness:** 100% local assets served from `/static/` (zero CDNs, zero Google Fonts, zero external analytics).
