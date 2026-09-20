# Model Assurance & Backdoor Coverage

## 1. Supported Local Assurance Methods

TRUST-CV implements defensible, deterministic, gradient-free behavioural analysis for model assurance:

| Assurance Method | Target Threat / Vulnerability | Evaluation Mechanism | Supported Access Modes | Output Finding / Metric |
|---|---|---|---|---|
| **Cryptographic Rehash** | Artifact tampering, offline bit flips, unauthorized weight replacement | Direct SHA-256 calculation of current artifact bytes on disk | `WHITE_BOX`, `PARTIAL`, `BLACK_BOX` | `binary_identity`: `MATCH` \| `MISMATCH` |
| **Structural Layout Verification** | Graph alterations, extra Trojan bypass layers, pruned weights | Graph canonical AST hash, parameter counts, tensor dimension matching | `WHITE_BOX` | `structural_identity`: `MATCH` \| `MISMATCH` \| `UNAVAILABLE` |
| **Deterministic Probe Battery** | Covert behavioural divergence, weight perturbation, transfer attacks | Fixed deterministic synthetic RGB probes across 5 perturbation regimes | `WHITE_BOX`, `BLACK_BOX` | `behavioural_identity`: `MATCH` \| `MISMATCH` \| `UNAVAILABLE` |
| **ProbeRecord Tracing** | Traceability and auditability of individual inference steps | Records per-probe `input_hash`, `output_hash`, `canonical_output`, `model_hash` | `WHITE_BOX`, `BLACK_BOX` | `probe_records` inside `ModelFingerprint` |
| **Localized Patch Sensitivity** | Fixed-pattern trigger backdoors (e.g. corner checkerboards, BadNets) | Compares prediction flip rates between localized trigger patch and equal-energy noise control | `WHITE_BOX`, `BLACK_BOX` | `trigger_status`: `CLEAN` \| `SUSPICIOUS_TRIGGER_SENSITIVITY` |
| **Prediction Collapse Check** | Trojan targeted misclassification to single target label | Evaluates whether triggered probes disproportionately collapse into a dominant class (>75%) | `WHITE_BOX`, `BLACK_BOX` | `dominant_target_ratio`, `sensitivity_difference` |
| **Perturbation Stability Analysis** | Adversarial brittleness, excessive output variance under noise | Measures activation shift across Gaussian blur, noise, contrast, and rotation | `WHITE_BOX`, `BLACK_BOX` | `mean_confidence`, `top_class_id`, `mean_squared_error` |

---

## 2. Trigger Sensitivity Evaluation Details

### 2.1 Methodology
The `TriggerDetector` in [`backend/app/models_engine/trigger_detector.py`](file:///c:/Users/sce24/Desktop/sih-project/Block-Sentinal/backend/app/models_engine/trigger_detector.py) performs a controlled comparison:
1. **Clean Probes ($X$)**: Deterministic probes generated with a fixed seed. Evaluates model baseline predictions $P(X)$.
2. **Triggered Probes ($X_{\text{trig}}$)**: Injects a 4x4 high-contrast checkerboard pattern in the bottom-right corner. Evaluates $P(X_{\text{trig}})$.
3. **Noise Control Probes ($X_{\text{noise}}$)**: Injects equal-energy Gaussian noise in the exact same spatial bounding box. Evaluates $P(X_{\text{noise}})$.
4. **Metrics**:
   - $\text{FlipRate}_{\text{trig}} = \frac{1}{N} \sum_{i=1}^N \mathbb{I}(\text{argmax}(P(X_{\text{trig}}^{(i)})) \neq \text{argmax}(P(X^{(i)})))$
   - $\text{FlipRate}_{\text{noise}} = \frac{1}{N} \sum_{i=1}^N \mathbb{I}(\text{argmax}(P(X_{\text{noise}}^{(i)})) \neq \text{argmax}(P(X^{(i)})))$
   - $\Delta_{\text{sensitivity}} = \text{FlipRate}_{\text{trig}} - \text{FlipRate}_{\text{noise}}$
   - $\text{DominantRatio} = \max_c \frac{\text{Count}(\text{trig\_class} == c)}{N}$
5. **Verdict Rule**:
   - If $\Delta_{\text{sensitivity}} \ge 0.50$ AND $\text{DominantRatio} \ge 0.75$ AND $\text{Flips} \ge 3$: flagged as `SUSPICIOUS_TRIGGER_SENSITIVITY`.
   - Otherwise: `CLEAN`.

### 2.2 Justified Confidence
- Confidence is calculated based on sample battery size:
  $$\text{Confidence} = \min\left(1.0, \max\left(0.5, 1.0 - \frac{1}{N}\right)\right)$$
- When suspicious sensitivity is flagged, confidence is tied directly to the observed $\text{DominantRatio}$.

---

## 3. Explicit Gaps & Unsupported Methods

To maintain operational integrity without claiming untested capabilities, the following methods are explicitly documented as **unsupported** in TRUST-CV Phase 4:

| Method | Reason for Non-Inclusion / Gap | Status |
|---|---|---|
| **Gradient-Based Trigger Inversion (Neural Cleanse)** | Requires full backpropagation across arbitrary computational graphs with optimization loops. Non-differentiable or black-box graphs cannot execute this offline. | ❌ UNSUPPORTED |
| **Universal Adversarial Perturbation (UAP) Search** | Requires extensive full training dataset and GPU gradient loops. Unviable in lightweight air-gapped CPU runtime. | ❌ UNSUPPORTED |
| **Input-Dependent / Dynamic Backdoors (WaNet, Blended)** | Triggers conditioned on feature distribution or low-amplitude whole-image watermarks cannot be reliably discovered without gradient inversion or clean validation datasets. | ❌ UNSUPPORTED |
| **Certified Robustness Verification (Interval Bound Propagation, α-β-CROWN)** | Requires exact piecewise-linear formal solvers (SMT/MILP) with high computational overhead. | ❌ UNSUPPORTED |
| **Arbitrary Pickled PyTorch Execution** | Disallowed by security invariant: prevents remote code execution vulnerabilities in model ingestion pipeline. | ❌ STRICTLY FORBIDDEN |
