# Distribution Shift & Drift Assurance Specification

## 1. Overview & Architectural Principle

The Distribution Shift subsystem in TRUST-CV provides statistical and forensic verification of computer vision data streams against cryptographically registered reference baselines.

Distribution shift is not inherently malicious. Natural operating environments undergo diurnal cycles, cloud cover variations, seasonal shifts, sensor wear, and camera vibration. Therefore, TRUST-CV enforces a strict **Drift Isolation Principle**:
> **Invariant**: Statistical distribution shift alone never triggers hard vetoes or automatic quarantine. Drift findings are classified according to physical and statistical root causes and passed into the Authoritative Evidence Fusion pipeline for cross-layer correlation.

---

## 2. Reference Baseline Contract

A drift assessment mathematically requires an authentic reference baseline. TRUST-CV supports three reference baseline formats:
1. **Reference Dataset (`REFERENCE_DATASET`)**: A sealed, verified historical corpus of imagery representing acceptable operational conditions. Features are extracted locally and deterministically.
2. **Reference Feature Profile (`FEATURE_PROFILE`)**: Pre-extracted, cryptographically signed statistical moment summaries (mean, standard deviation, min, max, quantiles).
3. **Reference Canonical Manifest (`CANONICAL_MANIFEST`)**: A signed manifest binding asset relative paths, sizes, and file SHA-256 hashes.

### Mandatory Baseline Invariants
- **Missing Baseline Rule**: If no valid registered baseline profile is supplied or found on disk, drift analysis cannot execute. The pipeline records `status = UNAVAILABLE` with code `ERR_BASELINE_UNAVAILABLE`. Under no circumstances does the system default to `PASS`, `CLEAN`, or substitute synthetic reference data.
- **Anti-Self-Comparison Invariant**: A candidate batch must **never** be copied or used as its own reference baseline (`baseline_id == target_batch_id` is strictly rejected with `ValueError`).
- **Cryptographic Grounding**: Every baseline profile is sealed with a canonical SHA-256 digest (`baseline_digest`) and signed using ECDSA SECP256R1. Before comparison, the candidate evaluation checks baseline cryptographic integrity.

---

## 3. Deterministic Local Feature Extraction

Feature extraction is executed completely offline without reliance on external cloud APIs or closed web services. The extractor computes:

| Feature | Extraction Algorithm | Defense / Domain Relevance |
| :--- | :--- | :--- |
| **Brightness** | Standard Rec. 601 grayscale luma: $Y = 0.2989 R + 0.5870 G + 0.1140 B$ | Detects daylight transitions, dusk/night operations, and optical overexposure. |
| **Contrast** | Root Mean Square (RMS) standard deviation of pixel intensities | Detects fog, haze, smoke, lens condensation, or glare. |
| **Sharpness** | Variance of discrete 2D Laplacian operator: $\sigma^2(\nabla^2 I)$ | Detects lens defocusing, sensor occlusion, motion blur, and dirty optics. |
| **Channel Entropy** | Shannon entropy: $H = -\sum p_i \log_2 p_i$ across normalized 256-bin histogram | Detects sensor noise collapse, adversarial perturbation, and uniform noise injection. |
| **Dimensions** | Pixel width, height, and aspect ratio ($W/H$) | Detects format alterations, unauthorized cropping, or resolution downgrading. |
| **Colour Statistics** | Per-channel RGB means ($\mu_R, \mu_G, \mu_B$) and standard deviations ($\sigma_R, \sigma_G, \sigma_B$) | Detects optical sensor drift, thermal calibration shift, and color grading alterations. |
| **Colour Temperature** | Ratio of red to blue spectral energy: $\mu_R / (\mu_B + \epsilon)$ | Detects dawn/dusk lighting changes vs. artificial indoor illumination. |

*Embeddings Policy*: High-dimensional neural embeddings are extracted only when an authenticated local model checkpoint is available on disk; no synthetic or randomized embeddings are ever produced.

---

## 4. Distribution Comparison Metrics

For each extracted feature vector between baseline distribution $U$ and target distribution $V$, TRUST-CV computes four non-parametric statistical metrics:

### 4.1 Two-Sample Kolmogorov-Smirnov (KS) Statistic
Measures the supremum distance between empirical cumulative distribution functions (ECDFs):
$$D_{KS} = \sup_{x} |F_U(x) - F_V(x)|$$
Together with the asymptotic two-sided Kolmogorov-Smirnov $p$-value:
$$p = 2 \sum_{j=1}^{\infty} (-1)^{j-1} e^{-2 j^2 \lambda^2}, \quad \lambda = D_{KS} \sqrt{\frac{n_1 n_2}{n_1 + n_2}}$$

### 4.2 Population Stability Index (PSI)
Quantifies divergence across 10 equal-frequency baseline quantiles with smoothing epsilon $\epsilon = 10^{-4}$:
$$\text{PSI} = \sum_{k=1}^{K} (p_k - q_k) \ln\left(\frac{p_k}{q_k}\right)$$
- $\text{PSI} < 0.10$: Stable distribution (no significant shift).
- $0.10 \le \text{PSI} < 0.25$: Moderate shift; warranting telemetry monitoring.
- $\text{PSI} \ge 0.25$: Significant population shift; flagged for review.

### 4.3 1D Wasserstein Distance (Earth Mover's Distance)
Evaluates the minimal transport work required to transform distribution $U$ into $V$:
$$W_1(U, V) = \int_0^1 |F_U^{-1}(t) - F_V^{-1}(t)| \, dt$$
Implemented deterministically using 100 uniformly spaced quantiles.

### 4.4 Energy Distance
Statistical distance between cumulative distributions with exact metric properties:
$$\mathcal{E}^2(U, V) = 2 \mathbb{E}|U - V| - \mathbb{E}|U - U'| - \mathbb{E}|V - V'|$$

---

## 5. Operational vs. Suspicious Shift Taxonomy

TRUST-CV distinguishes benign operational environmental changes from hostile anomalies using multi-feature pattern rules:

```
                          [ Extracted Feature Distributions ]
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
 [Sharpness Alone]             [Brightness / Color Temp]           [Channel Entropy / Extreme]
        |                                 |                                 |
  SENSOR_SHIFT                   ILLUMINATION_SHIFT                  SUSPICIOUS_SHIFT
(Optical Defocus / Dirt)       (Dusk / Dawn / Weather)             (Adversarial Distortion)
  [UNDER_REVIEW]                 [UNDER_REVIEW]                     [UNDER_REVIEW -> Fusion]
```

- `ENVIRONMENTAL_SHIFT`: Coordinated changes across brightness, contrast, and color temperature without entropy loss or model divergence.
- `DATASET_DRIFT`: Broader population shifts across multiple non-adversarial feature dimensions.
- `SENSOR_SHIFT` (Sensor Degradation): Sharpness collapse indicating lens smudging, vibration, or optical defocus.
- `ILLUMINATION_SHIFT`: Radiometric luminance variations reflecting diurnal sunlight changes.
- `SUSPICIOUS_SHIFT` (Adversarial Anomaly): Sudden channel entropy collapse, extreme clipping, or high multi-feature divergence.
- `UNKNOWN`: Insufficient statistical samples ($N < 5$) or conflicting metric vectors.

---

## 6. Integration with Evidence Fusion

Every drift analysis yields a sealed `DistributionShiftReport` with a canonical SHA-256 digest. Findings from this report generate structured `EvidenceItem` records referencing the specific `report_id` and feature evidence IDs. These items flow into the **Authoritative Evidence Fusion Engine** for gatekeeper verdicts.
