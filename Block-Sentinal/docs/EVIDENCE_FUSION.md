# Multi-Source Evidence Fusion & Authoritative Threat Assessment

## 1. Architectural Philosophy

The Evidence Fusion subsystem in TRUST-CV acts as the single authoritative decision gatekeeper across the entire computer vision lifecycle.

### Core Architectural Invariants:
1. **Single Source of Truth**: All risk verdicts (`ACCEPTED`, `UNDER_REVIEW`, `QUARANTINED`), risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and gatekeeper actions (`ALLOW`, `REVIEW`, `BLOCK`) are computed **exclusively** on the backend. The frontend is strictly a visualization layer and must never implement competing, synthetic, or ad-hoc risk formulas.
2. **Mandatory Evidence Grounding**: Every input piece of verification evidence must contain an authenticated, non-empty `evidence_id` and a canonical SHA-256 digest (`evidence_digest`). Floating, ungrounded, or simulated findings are rejected at the input boundary.
3. **Hard-Veto Precedence**: Certain critical security failures (such as cryptographic forgery, inference sequence breaks, or model substitution) immediately trigger an authoritative hard veto (`QUARANTINED` / `BLOCK`), completely overriding low-risk signals from other layers.
4. **Drift Isolation Rule**: Statistical distribution shift alone never triggers an automatic hard veto or immediate quarantine. Operational shifts remain in `UNDER_REVIEW` / `REVIEW` pending human or multi-sensor corroboration.

---

## 2. Multi-Domain Evidence Inputs

The engine ingests structured `EvidenceItem` records spanning 5 key architectural domains:

```
+-------------------------------------------------------------------------+
|                    Authoritative Evidence Fusion Engine                 |
+-------------------------------------------------------------------------+
       ^                  ^                 ^               ^          ^
       |                  |                 |               |          |
 [DATASET LAYER]    [MODEL LAYER]    [INFERENCE DNA]    [DRIFT]  [CONTRIBUTOR]
 - Duplicates       - Identity Hash  - Nonce Sequence   - KS/PSI - Historical Trust
 - Backdoors        - Fingerprints   - Hash Continuity  - W1/EMD - Batch Volume
 - Format validity  - Quantization   - ECDSA Signature  - Energy - Penalty Record
```

---

## 3. Decision Logic & Hard Veto Rules

### 3.1 Hard Veto Conditions
A single occurrence of any of the following mandatory conditions forces:
- `hard_veto_triggered = True`
- `overall_status = AssetStatus.QUARANTINED`
- `risk_level = AssuranceRiskLevel.CRITICAL`
- `action = AssuranceAction.BLOCK`
- Immediate generation of an active `QuarantineRecord`.

| Rule ID | Domain | Trigger Criterion | Rationale |
| :--- | :--- | :--- | :--- |
| **HV-01** | Cryptographic Verification | Invalid, mismatched, or forged ECDSA signature on any sealed artifact. | System integrity failure; prevents unauthorized tampering or forgery. |
| **HV-02** | Inference Provenance | Duplicate nonce reuse (replay attack) or broken hash chain between inference receipts. | Telemetry spoofing defense; ensures in-flight decisions correspond to actual model runs. |
| **HV-03** | Model Identity | Active model weights SHA-256 mismatch against registered golden baseline manifest. | Model substitution defense; prevents unauthorized trojan weight replacement. |

### 3.2 Cross-Domain Threat Correlation Rules

When multiple weak or medium findings co-occur across different domains, the `ThreatCorrelator` synthesizes higher-order threat narratives:

1. **Targeted Backdoor Poisoning Campaign**:
   - Condition: Synthetic backdoor trigger artifacts in training data (`DATA_INTEGRITY`) co-occurring with model behavioral probe divergence (`BEHAVIOURAL_FINGERPRINT`).
   - Outcome: Elevated risk score $\ge 0.85$, quarantine recommendation.
2. **Unauthorized Model Substitution & Telemetry Tampering**:
   - Condition: Inference receipt DNA failure (`INFERENCE_DNA`) co-occurring with model identity hash mismatch (`MODEL_IDENTITY`).
   - Outcome: Hard veto, immediate asset quarantine.
3. **Coordinated Evasion / Adversarial Perturbation Attack**:
   - Condition: Severe input distribution shift (`DISTRIBUTION_SHIFT`) co-occurring with behavioral output divergence (`BEHAVIOURAL_FINGERPRINT`).
   - Outcome: Elevated risk score $\ge 0.75$, investigative quarantine.
4. **Input Distribution Anomalies Accompany Model Discrepancies**:
   - Condition: Distribution drift co-occurring with model weight integrity discrepancies.
   - Outcome: Cross-layer warning for misaligned model checkpoints.
5. **Benign Operational Environmental Drift**:
   - Condition: Optical/illumination drift without model tampering, backdoor patterns, or broken telemetry.
   - Outcome: Status remains `UNDER_REVIEW`, gatekeeper action `REVIEW`.

---

## 4. Central Risk Assessment Record

Every evaluation produces a cryptographically sealed `FusedAssessment` containing:

- **`overall_status`**: Final authoritative asset status (`ACCEPTED`, `UNDER_REVIEW`, `QUARANTINED`).
- **`risk_level`**: Authoritative risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **`action`**: Authoritative gatekeeper enforcement action (`ALLOW`, `REVIEW`, `BLOCK`).
- **`risk_score`**: Normalized composite risk value $[0.0000, 1.0000]$.
- **`confidence`**: Statistical confidence metric derived from audit coverage ratio and evidence sample volume.
- **`coverage`**: Detailed audit of verified vs. missing evidence sources.
- **`findings`**: Corroborated cross-layer threat narratives.
- **`contributors`**: Real, verified contributor identities (unverified contributors remain `UNKNOWN`).
- **`recommended_actions`**: Operational SOP guidance for SOC operators and ML engineers.
- **`limitations`**: Explicit accounting of coverage gaps, unchecked components, and air-gapped operating bounds.
- **`decisive_evidence`**: Explicit list of `evidence_id` identifiers that drove the verdict.
- **`hard_veto_triggered` & `veto_reasons`**: Complete forensic audit trail of hard-veto activations.
- **`assessment_digest`**: Canonical JSON SHA-256 hash sealing all fields.
- **`signature`**: Real ECDSA SECP256R1 digital signature.

---

## 5. Automatic and Manual Quarantine Lifecycle

```
[ Compromised Entity / Hard Veto ]
               |
               v
     ( Automatic Quarantine )
               |
               v
   [ Active Quarantine Record ] <------- ( Manual Quarantine via API / CLI )
               |
               v
       [ Forensic Review ]
               |
               v
     ( Resolve Quarantine )
   - Human Analyst Identity
   - Forensic Resolution Notes
   - Timestamped Audit Ledger
```

All quarantine events are written to the persistent ledger (`data/fusion/quarantine/`) and exposed via REST endpoints (`/api/v1/fusion/quarantine`) and CLI subcommands (`quarantine`, `list-quarantine`).
