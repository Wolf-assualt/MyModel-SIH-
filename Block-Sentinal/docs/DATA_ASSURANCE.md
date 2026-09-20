# Data Assurance Architecture

## Pipeline Flow

```
UPLOAD → PRESERVE ORIGINAL → HASH → PARSE → ANALYSE → REPORT → OPTIONAL QUARANTINE
```

Original files are **NEVER** modified, resized, deduplicated, overwritten, or deleted during analysis.

## `dataset_sha256` Definition

A content-addressable dataset identity computed as follows:

1. For every original file in the dataset, collect a tuple of:
   - `relative_path` — deterministic POSIX-style path relative to the dataset root
   - `file_size` — size in bytes
   - `sha256` — SHA-256 hex digest of file content

2. Sort entries by `relative_path` (lexicographic).

3. Serialize to canonical JSON:
   ```json
   {"files":[{"relative_path":"a.png","file_size":1234,"sha256":"abc..."},{"relative_path":"b.png","file_size":5678,"sha256":"def..."}]}
   ```

4. SHA-256 hash the canonical serialized string.

**Properties**:
- Same files → same hash, regardless of directory location or ingestion order
- Adding, removing, or modifying any file changes the hash
- Does not depend on filesystem metadata (timestamps, permissions)

## Severity Rules

Severity indicates **potential impact**, NOT probability or certainty.

| Severity | Rule |
|---|---|
| `CRITICAL` | Confirmed evidence of data manipulation that could compromise model training (e.g. trigger pattern across multiple samples sharing a target label). |
| `HIGH` | Strong evidence of data quality failure that could affect model integrity (e.g. zero-variance image, label conflict on near-identical images, corrupt file). |
| `MEDIUM` | Moderate evidence requiring human review (e.g. exact duplicate group, extreme aspect ratio anomaly). |
| `LOW` | Informational finding (e.g. near-duplicate cluster, minor quality anomaly). |

A finding may have HIGH severity with LOW confidence. For example, a trigger candidate in a corner region has CRITICAL severity (potential backdoor) but null confidence (heuristic detection, no ground truth).

## Confidence Basis

Every finding confidence value has a documented calculation or is explicitly `null`.

| Detector | Confidence | Basis |
|---|---|---|
| Exact duplicate | `1.0` | SHA-256 byte-identity is deterministic |
| Near-duplicate | `1.0 - (hamming / 64)` | Normalized Hamming distance over 64-bit dHash space |
| Label conflict | `1.0 - (hamming / 64)` | Visual similarity of the conflicting pair |
| Missing label | `1.0` | Deterministic: annotation list is empty |
| Malformed annotation | `1.0` | Deterministic: bbox coordinates outside [0,1] |
| Quality: zero variance | `1.0` | Deterministic pixel analysis: variance < 1.0 |
| Quality: aspect ratio | `null` | Heuristic threshold (>20 or <0.05); no statistical basis |
| Quality: corrupt file | `1.0` | Deterministic: PIL cannot decode |
| Trigger: repeated patch | `affected / group_size` | Proportion of samples with matching patch signature |
| Trigger: isolated | `null` | Heuristic thresholds; no ground truth |
| OOD (no reference) | N/A | UNAVAILABLE — no findings produced |

## Finding Provenance

Every finding includes:

```python
detector_id: str           # e.g. "DUPLICATE_DETECTOR"
detector_version: str      # e.g. "2.0.0"
detector_parameters: dict  # e.g. {"duplicate_threshold": 4}
created_at: datetime       # UTC timestamp
```

## Evidence Preservation

- Original files are never modified during analysis
- The `_remove_exact_duplicate_images()` function was **removed** in Phase 3
- Quarantine copies files to isolation storage; originals remain at their original path
- Every quarantine event records: original hash, original path, contributor ID, finding IDs, scan ID, timestamp

## Contributor Resolution

Priority chain:
1. Explicit manifest metadata (`manifest.json` / `meta.json` with `contributor` field)
2. Dataset metadata (COCO `info.contributor`)
3. Archive/folder structure (single top-level directory name)
4. `UNKNOWN`

Never invents a contributor. If resolution fails: `contributor_id = "UNKNOWN"`.

## Contributor Risk Aggregation

Only produced when `contributor_id != "UNKNOWN"`:
- `sample_count`, `finding_count`, `finding_types`
- `severity_distribution`: counts per severity level
- `risk_indicators`: machine-readable flags (e.g. `CRITICAL_FINDINGS_PRESENT`)

## No Fabricated Evidence Rule

If a detector cannot execute reliably, the system reports `UNAVAILABLE` or `FAILED`. It does not substitute PASS, CLEAN, zero findings, fabricated confidence, fabricated reference data, or fabricated contributor identity.
