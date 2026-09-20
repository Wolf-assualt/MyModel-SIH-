# Dataset Format Support

## Supported Formats

| Format | Detection Rule | Annotation Source | Status |
|---|---|---|---|
| **IMAGE_FOLDER** | Subdirectories with image files, or flat image directory | Class inferred from parent directory name | ✅ Verified |
| **COCO** | `.json` file containing `images`, `annotations`, `categories` keys | COCO annotation JSON | ✅ Verified |
| **YOLO** | `images/` + `labels/` directories, or `.txt` files alongside images | YOLO `.txt` annotation files | ✅ Verified |
| BIGEARTHNET_S2 | GeoTIFF band files with Sentinel-2 band naming | Band label from filename | Existing (not Phase 3 scope) |

## Auto-Detection

Format is detected from actual directory structure and content — not user-specified:

1. **COCO check**: Scan for `.json` files. If any contains `images`, `annotations`, and `categories` top-level keys → **COCO**
2. **YOLO check**: If `images/` and `labels/` directories both exist → **YOLO**. Also detected if ≥50% of image files have companion `.txt` annotation files.
3. **Fallback**: Any directory with image files → **IMAGE_FOLDER**

## Per-Format Output

Every ingested dataset produces:

| Field | Source |
|---|---|
| `format` | Auto-detected |
| `sample_count` | Count of parsed records |
| `annotation_count` | Sum of labels across all records |
| `invalid_annotations` | Reported via `MALFORMED_ANNOTATION` findings |
| `missing_images` | COCO images referenced in JSON but not found on disk are skipped |
| `duplicate_count` | Reported via `EXACT_DUPLICATE` findings |
| `contributor_id` | Resolved via priority chain |
| `contributor_source` | How contributor was resolved |
| `dataset_sha256` | Deterministic content-addressable hash |
| `merkle_root` | Merkle tree root of sample leaf hashes |
| `batch_id` | UUID for this ingestion batch |

## Supported Image Extensions

`.jpg`, `.jpeg`, `.png`, `.bmp`, `.webp`, `.tif`, `.tiff`
