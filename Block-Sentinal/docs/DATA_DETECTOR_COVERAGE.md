# Data Detector Coverage

## Implemented Detectors

### 1. Duplicate Detector (`DUPLICATE_DETECTOR` v2.0.0)

**What it detects**:
- **Exact duplicates**: Byte-identical files via SHA-256 hash comparison
- **Near-duplicate clusters**: Perceptually similar images via dHash with union-find clustering

**Method**: SHA-256 for exact; 64-bit difference hash (dHash) with Hamming distance for perceptual similarity.

**Confidence**:
- Exact: `1.0` (deterministic)
- Near-dup: `1.0 - (avg_hamming / 64)` (normalized over dHash bit space)

**Known limitations**:
- Near-duplicate threshold is configurable but defaults to Hamming distance ≤ 4
- dHash is rotation-variant; rotated copies may not be detected
- Clustering uses union-find; transitive connections merge clusters

---

### 2. Label Inconsistency Detector (`LABEL_INCONSISTENCY_DETECTOR` v2.0.0)

**What it detects**:
- **Label conflicts**: Near-identical images with different label annotations
- **Missing labels**: Images with empty annotation lists
- **Malformed annotations**: YOLO bbox coordinates outside [0,1] range

**Method**: dHash comparison for visual similarity; deterministic checks for missing/malformed.

**Confidence**:
- Label conflict: `1.0 - (hamming / 64)`
- Missing label: `1.0` (deterministic)
- Malformed annotation: `1.0` (deterministic)

**Known limitations**:
- Label conflict detection relies on perceptual hash similarity threshold
- Does not detect semantic label errors (e.g. "automobile" vs "car")
- Malformed annotation check currently covers YOLO normalized bbox format only

---

### 3. Quality Detector (`QUALITY_DETECTOR` v2.0.0)

**What it detects**:
- **Zero-variance images**: Solid-color or sensor blackout (pixel variance < 1.0)
- **Corrupt files**: Images that PIL cannot decode
- **Extreme aspect ratios**: Width/height ratio > 20 or < 0.05

**Method**: Pixel-level statistical analysis (grayscale variance, aspect ratio computation).

**Confidence**:
- Zero variance: `1.0` (deterministic)
- Corrupt file: `1.0` (deterministic)
- Aspect ratio: `null` (heuristic threshold, no statistical basis for exact boundary)

**Known limitations**:
- Does not detect subtle quality issues (slight blur, noise, compression artifacts)
- Aspect ratio thresholds are heuristic

---

### 4. OOD Detector (`OOD_DETECTOR` v1.0.0)

**What it detects**:
- Out-of-distribution samples based on feature statistics (brightness, entropy) compared against an independently provided reference dataset

**Method**: Z-score comparison of candidate features against reference distribution.

**Confidence**: `null` (z-score magnitude is not a calibrated probability)

**Current status**: **UNAVAILABLE** — requires an independently sourced reference dataset. The system never fabricates a baseline from the candidate data being evaluated.

**Known limitations**:
- Feature-based OOD uses brightness and entropy only
- Does not capture semantic or structural distribution shift
- Requires reference_stats to be pre-computed and independently provided

---

### 5. Trigger Candidate Detector (`TRIGGER_CANDIDATE_DETECTOR` v2.0.0)

**What it detects**:
- **Repeated patch patterns**: Static localized patches in corner regions that appear across multiple samples sharing the same target label
- **Isolated high-contrast patches**: Single-sample high-variance corner regions with mixed dark/light content

**Method**: Corner region extraction, SHA-256 patch signature comparison across label groups.

**Confidence**:
- Repeated: `affected_count / group_size` (proportion of samples with matching signature)
- Isolated: `null` (heuristic thresholds, no ground truth)

**Known limitations**:
- Only inspects 4 corner regions of fixed 4×4 patch size
- Cannot detect non-localized, semantic, or per-sample-variable triggers
- Cannot detect triggers outside corner regions
- A positive finding is a **CANDIDATE** requiring human review, not a confirmed backdoor

## Coverage Gaps

| Capability | Status | Reason |
|---|---|---|
| Reference-based OOD | UNAVAILABLE | Requires independently sourced reference dataset |
| Semantic label validation | Not implemented | Would require domain-specific ontology |
| Non-corner trigger detection | Not implemented | Would require full-image analysis |
| Model integrity | Phase 4 | Not in Phase 3 scope |
| Inference assurance | Phase 4 | Not in Phase 3 scope |
| Distribution shift | UNAVAILABLE | No reference provided |
