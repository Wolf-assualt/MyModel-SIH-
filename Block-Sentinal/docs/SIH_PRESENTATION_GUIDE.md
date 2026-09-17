# TRUST-CV: SIH Presentation & Defense Guide

## 1. Problem Statement & Operational Challenge

### The Vulnerability of Computer Vision in Mission-Critical Systems
In defense, remote sensing, reconnaissance, and border surveillance operations, computer vision models are deployed to make high-stakes automated decisions (target classification, infrastructure monitoring, change detection).

However, modern computer vision supply chains face acute vulnerabilities:
1. **Data Poisoning & Subtle Tampering:** Single-byte or imperceptible pixel modifications in training imagery can induce targeted misclassifications or create backdoor triggers.
2. **Model Substitution & Supply Chain Trojans:** Binary model files can be swapped, or a few weights manipulated without altering top-level file names or superficial parameters.
3. **Black-Box Inference Vulnerability:** Once deployed, standard inference servers do not prove *which* model version produced a classification, nor do they protect against replayed inferences or historical falsification.
4. **Natural Drift vs Adversarial Attacks:** Natural seasonal, illumination, and weather shifts in satellite data are often conflated with adversarial attacks, leading to false-alarm shutdowns.
5. **Air-Gap Constraint:** Defense installations operate in disconnected, air-gapped enclaves with **zero cloud connectivity, zero remote CDNs, and zero third-party telemetry**.

---

## 2. The TRUST-CV Solution

**TRUST-CV** solves this challenge through a **Zero-Trust Computer Vision Integrity Assurance Architecture**:
* **Cryptographic Foundation:** Binds dataset samples into Merkle inclusion trees and models into layer-by-layer weight state-dict digests sealed with ECDSA SECP256R1 digital signatures.
* **Multi-Spectral Earth Observation Adapter:** Understands 12-band Sentinel-2 / BigEarthNet-S2 compound patches in read-only mode.
* **Sequential Inference DNA:** Chains every inference prediction to its input SHA-256, model identity, nonce, and preceding inference hash in an immutable sequential chain.
* **Quantitative Distribution Drift Engine:** Employs 4 statistical distance metrics (Kolmogorov-Smirnov, Population Stability Index, Wasserstein-1, Energy Distance) to measure spectral drift without triggering false alarms.
* **Multi-Domain Evidence Fusion & Hard Veto:** Unifies evidence across data, models, behavior, inference, and drift. Any cryptographic compromise triggers an unbypassable **Hard Veto** that forces immediate quarantine.
* **Traceable Lineage & Blast Radius:** Graphs upstream contributor origins and downstream affected models/inferences.
* **Sealed Forensic Reports:** Exports RFC 8785 canonical JSON forensic assurance certificates sealed with ECDSA signatures.

---

## 3. Recommended 10-Minute Slide & Demo Presentation Structure

| Slide / Segment | Duration | Key Talking Points | Visual / Demo Action |
| :--- | :--- | :--- | :--- |
| **1. The Problem** | 1.0 min | Why mission-critical CV pipelines cannot be trusted blindly; supply chain attacks, weight tampering, lack of audit trails. | High-stakes satellite reconnaissance example. |
| **2. Zero-Trust Architecture** | 1.5 min | Full chain: Dataset -> Model -> Behavior -> Inference DNA -> Drift -> Fusion -> Provenance -> Sealed Report. | System architecture diagram. |
| **3. Live Command Center** | 1.0 min | Web SOC Dashboard operating 100% offline with zero external network dependencies. | Show Dashboard, Health, and Datasets views. |
| **4. Live Tamper Demo** | 2.5 min | Ingest Sentinel-2 patch, verify baseline, inject 1-byte tamper into Band 4 GeoTIFF, watch Merkle root fail, Hard Veto trigger, and asset quarantine. | Execute `scripts/demo_tamper_scenario.py` or trigger via UI. |
| **5. Lineage & Blast Radius** | 1.0 min | Trace root cause to contributor and calculate downstream affected models and inference records. | Show interactive Provenance Graph and Blast Radius view. |
| **6. Benign Drift vs Attack** | 1.0 min | Explain how seasonal satellite shifts result in REVIEW rather than false-alarm quarantine. | Execute `scripts/demo_drift_scenario.py`. |
| **7. Sealed Forensic Reports** | 1.0 min | Show RFC 8785 canonical JSON sealing, verify signature, tamper with verdict, show instant signature rejection. | Show Forensic Report export & verification. |
| **8. Conclusion & Q&A** | 1.0 min | Air-gapped readiness, calibrated boundaries, real-world applicability. | Open floor for judge questions. |

---

## 4. Anticipated Judge Questions & Defensible Answers

### Q1: "How is TRUST-CV different from standard model monitoring or MLOps tools (e.g. Evidently, MLflow)?"
> **Answer:** Standard MLOps tools monitor high-level statistical metrics in connected cloud environments. TRUST-CV is a **zero-trust cryptographic security platform** built for disconnected, air-gapped defense enclaves. It creates mathematically verifiable digital signatures over individual weight tensors, Merkle inclusion trees over dataset samples, and immutable hash chains over runtime inferences, backed by a hard-veto gatekeeper that blocks unverified assets.

### Q2: "Why do you hash model weights layer-by-layer instead of just hashing the entire `.pt` or `.onnx` file?"
> **Answer:** Whole-file hashing is brittle and easily bypassed or obscured by metadata variations. By canonicalizing and hashing each weight tensor in the model state dict separately, TRUST-CV can:
> 1. Detect if even a single weight parameter is modified.
> 2. Identify the exact layer where tampering occurred.
> 3. Verify architecture graph structure independently of weight values.

### Q3: "Does your system claim to detect 100% of all possible AI attacks?"
> **Answer:** No. We maintain strict, calibrated claim boundaries. TRUST-CV detects **100% of evaluated controlled scenarios** within its assurance model. Statistical drift indicators identify distributional divergence without making absolute claims of adversarial intent. Cryptographic signing guarantees that evidence and reports cannot be modified post-hoc without detection.

### Q4: "How does the platform operate in a real air-gapped defense environment?"
> **Answer:** TRUST-CV is designed and validated for fully offline operation. It has **zero external CDN calls, zero Google Fonts, zero remote JavaScript, zero cloud KMS dependencies, and zero telemetry beacons**. All database storage uses local SQLite with Write-Ahead Logging, and cryptographic keypairs are generated and managed locally using NIST P-256 (SECP256R1) curves.
