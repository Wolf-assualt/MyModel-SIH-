# TRUST-CV Security & Hardening Architecture

## Overview
TRUST-CV implements a defense-in-depth zero-trust security architecture designed to operate securely even in adversarial environments. This document specifies the defensive controls, threat models, and hardening measures embedded in the platform.

---

## 1. Threat Matrix & Defensive Controls

| Threat Category | Attack Vector | TRUST-CV Defensive Control |
|---|---|---|
| **Data Supply Chain** | Poisoned images / Backdoors | Corner trigger detection, Near-duplicate pHash, Label inconsistency checking, Merkle inclusion root sealing. |
| **Model Tampering** | Bit-flip weight attacks, Layer swaps | Layer-by-layer parameter SHA-256 hashing, Architecture structure hashing, ECDSA signature verification. |
| **Execution Bypass** | Pickling exploits / Malicious code | Safe deserialization (`weights_only=True`), PyTorch TorchScript/ONNX inspection, forbidden opcode rejection. |
| **Runtime Manipulation** | Inference record spoofing / Replays | Nonce validation, sequence ID validation, previous-hash linkage, ECDSA signed DNA receipts. |
| **Distribution Shift** | Adversarial perturbation vs Domain shift | Kolmogorov-Smirnov, Population Stability Index, Wasserstein-1, and Energy Distance analysis. |
| **Evidence Tampering** | Altering findings or verdicts | RFC 8785 canonical JSON serialization, SHA-256 digest sealing, ECDSA signature verification. |
| **Operational UI** | Cross-Site Scripting (XSS) / Injection | Strict character entity escaping (`escapeHtml`), parameter sanitization, local asset delivery. |
| **Filesystem Access** | Path traversal (`../`) | Strict path resolution with `Path.resolve()` boundary checking against allowed data directories. |

---

## 2. Hard-Veto Override Guarantee

The Evidence Fusion Engine enforces a non-negotiable **Hard Veto Policy**:
* If any cryptographic verification fails (e.g. invalid ECDSA signature, broken dataset Merkle tree, altered model layer hash, broken inference hash chain), the asset is **immediately quarantined with verdict `BLOCK`**.
* Cryptographic failures cannot be averaged out or diluted by high statistical confidence or benign findings elsewhere in the pipeline.

---

## 3. Auditable Quarantine Protocol

* When an asset is placed in quarantine, its containment status is cryptographically logged and attached to the provenance graph.
* **No Silent Unquarantine:** Releasing an asset requires an explicit, authenticated operator action with recorded operator badge ID, forensic rationale, and timestamp.

---

## 4. Calibrated Security Terminology

To maintain scientific integrity and prevent false operational assumptions:
* Cryptographic sealing proves **unaltered state since signing**, not absolute correctness of heuristic conclusions.
* Provenance graphs illustrate **historical structural dependencies**, not guaranteed compromise.
* Contributor risk profiles represent **empirical historical defect rates**, not accusations of malicious intent.
