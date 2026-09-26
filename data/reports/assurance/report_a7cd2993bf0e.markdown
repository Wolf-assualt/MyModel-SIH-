# [RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT]
**SIH26228 — Ministry of Defence (MoD)**  
*Zero-Trust Computer Vision Integrity Assurance & Evidence Graph*

---

## Report Metadata
- **Report ID**: `report_a7cd2993bf0e`
- **Target Asset ID**: `yolov8_tactical_v1` (`MODEL`)
- **Assessment Reference**: `fused_test_12345`
- **Generated At**: `2026-09-21T02:09:36.799744+00:00`

---

### OPERATIONAL VERDICT: QUARANTINED

## Threat & Integrity Metrics Matrix
| Metric | Score | Operational Significance |
| :--- | :--- | :--- |
| **Composite Risk Score** | `0.8850` | 0.0 = Verified Secure; 1.0 = Severely Compromised |
| **Assurance Confidence** | `0.5400` | Statistical confidence derived from verified evidence breadth |
| **Layer Coverage Ratio** | `60.0%` | Percentage of foundational assurance layers inspected |

## Verified Findings Breakdown
| Severity Tier | Incident Count | Actionable Response |
| :--- | :--- | :--- |
| **CRITICAL** | **1** | Immediate Pipeline Halt & Quarantine Mandated |
| **HIGH** | **1** | Secondary Verification & Policy Review Required |
| **MEDIUM** | **1** | Operational Monitoring & Discrepancy Logging |
| **LOW** | **0** | Informational Baseline Recording |

## Correlated Threat Narratives
- Correlated Targeted Backdoor Poisoning Campaign detected: Training data contains synthetic triggers.

## Audit Limitations & Operational Disclaimers
- Uninspected assurance layers: [MODEL_IDENTITY, INFERENCE_DNA]. Risk scores represent partial assurance.
- Integrity and drift metrics are bounded by operational camera sensor dynamics and calibration.
- Zero-trust provenance assurance assumes asymmetric root signing key confidentiality.

---

## Cryptographic Provenance Seal
- **Canonical Report Digest (SHA-256)**: `b8eda7ee937615bb2b6f15f803bf28480c9be9c4fde18701254ca3b29bf778b5`
- **Ed25519 Digital Signature**: `30440220517ebac9048d4cee1a0aadf32e00607b3e490b202cb39f2bd3e3ba0160479d97022014587c76285ad60496df8990f6de6a6c8b0895328f696eccd066a3ee9b3a7ddd`
- **Signing Authority Public Key (SubjectPublicKeyInfo)**:
```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5iNW826nZ4SUnoUkEkg9vMGS32cg
IlujWHy+ey0wAvAY7VJmwc4OXGv9dF7niCrctJvvAiEj1g0doO1qDNmPrg==
-----END PUBLIC KEY-----
```

---
*RESTRICTED DOCUMENT // NOT TO BE DISCLOSED OUTSIDE DEFENSE ASSURANCE CHANNELS*