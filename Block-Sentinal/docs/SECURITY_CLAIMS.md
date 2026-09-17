# TRUST-CV: Formal Security Claims & Calibrated Boundaries

## 1. Principle of Honest Assurance

TRUST-CV distinguishes between **mathematically proven cryptographic facts** and **observable empirical/heuristic findings**. Exaggerated or uncalibrated claims (e.g., "100% unhackable", "proves malicious intent") undermine technical credibility and are strictly forbidden.

---

## 2. Cryptographic vs Heuristic Assurance Taxonomy

| Dimension | What TRUST-CV Proves Mathematically | What TRUST-CV Observes Empirically / Heuristically | What TRUST-CV Does NOT Claim |
| :--- | :--- | :--- | :--- |
| **Dataset Ingestion** | Exact bit-level reproducibility of all files via SHA-256 and Merkle inclusion proofs signed by ECDSA SECP256R1. | Duplicate sample pairs, perceptual near-duplicates via dHash, and corner backdoor trigger anomalies. | Does not prove that a non-duplicated sample contains correct ground-truth annotations in the physical world. |
| **Model Identity** | Exact bit-level match of individual layer weight tensors, structural architecture graph hashes, and digital signature authenticity. | Behavioral deviations across 7 deterministic perturbation batteries. | Does not claim universal detection of all possible zero-day backdoor architectures. |
| **Inference DNA** | Nonce freshness, sequential order monotonicity, previous-hash linkage, and authenticity of input/output digest pairs. | Anomaly indicators and execution timestamp correlations. | Does not claim to judge whether a classification model's prediction was physically correct in the real world. |
| **Distribution Drift** | Deterministic mathematical distance values across 4 metrics (KS, PSI, Wasserstein-1, Energy Distance). | Spectral indices (NDVI, NDWI, brightness) and distributional shift severity tiers. | Does **NOT** claim that distribution shift proves an adversarial attack or data poisoning. |
| **Evidence Fusion** | Strict execution of Hard-Veto rules (cryptographic failure $\to$ immediate quarantine). | Weighted risk scoring across multi-source evidence items. | Does not claim that a low risk score is an absolute guarantee against unknown threats. |
| **Provenance Graph** | Direct graph traversability of recorded parent-child relationships in the local database. | Blast-radius enumeration of downstream consumers labeled *"Potentially Affected / Requires Review"*. | Does **NOT** claim that all downstream assets are permanently compromised or corrupted. |
| **Forensic Reports** | Post-hoc tamper detection via RFC 8785 canonical JSON hashing and ECDSA SECP256R1 digital sealing. | Formatted narrative summary of findings and evidence items. | Does not claim that signing a report proves heuristic conclusions are universal ground truths. |
| **Air-Gap Readiness** | Zero declared remote CDNs, fonts, telemetry, external KMS, or network dependencies at application runtime. | Fully local execution on isolated workstations. | Does not claim the underlying host operating system is physically incapable of networking. |

---

## 3. Standardized Terminology Replacement Guide

| Prohibited / Uncalibrated Phrase | Approved Calibrated Phrase | Rationale |
| :--- | :--- | :--- |
| *"100% attack detection"* | *"100% of evaluated controlled scenarios detected"* | Accurately reflects empirical test suite coverage without claiming omniscience. |
| *"Proves malicious intent / insider threat"* | *"Provides evidence consistent with elevated risk"* | Software measures artifact anomalies, not human intent. |
| *"Drift proves the dataset is poisoned"* | *"Distribution shift requiring contextual operational review"* | Natural seasonal/illumination variance also causes measurable drift. |
| *"Downstream models are completely destroyed"* | *"Potentially affected / requires review"* | Accurately reflects blast-radius dependency scope. |
| *"Cryptographically proves the model is safe"* | *"Cryptographically proves the model matches approved golden reference weights"* | Signatures prove authenticity and integrity, not algorithmic safety. |
