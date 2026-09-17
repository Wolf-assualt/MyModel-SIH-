# BigEarthNet-S2 Multi-Spectral Dataset Integration & Operator Guide

## 1. Overview

**BigEarthNet-S2** is a large-scale multi-spectral satellite imagery benchmark dataset derived from the European Space Agency's (ESA) **Sentinel-2** Earth Observation (EO) satellite constellation. 

In operational defence, intelligence, and remote sensing environments, multi-spectral satellite imagery provides multi-band spectral measurements (visible, red-edge, near-infrared, and shortwave-infrared) critical for land use, infrastructure reconnaissance, environmental monitoring, and change detection.

TRUST-CV incorporates a dedicated, read-only **BigEarthNet-S2 Adapter & Parser** designed to ingest, hash, cryptographically seal, and analyze Sentinel-2 patch archives within a fully offline / air-gapped infrastructure.

---

## 2. Dataset Architecture & Expected Layout

Authentic BigEarthNet-S2 archives consist of compound image patch folders. Each patch covers a 1.2 km × 1.2 km ground area across 12 spectral bands plus one multi-label metadata file.

### 2.1 File & Directory Structure

```text
bigearthnet_dataset_root/
├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45/
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B01.tif (60m)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B02.tif (10m - Blue)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B03.tif (10m - Green)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B04.tif (10m - Red)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B05.tif (20m - Red Edge 1)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B06.tif (20m - Red Edge 2)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B07.tif (20m - Red Edge 3)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B08.tif (10m - NIR)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B8A.tif (20m - Narrow NIR)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B09.tif (60m - Water Vapour)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B11.tif (20m - SWIR 1)
│   ├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_B12.tif (20m - SWIR 2)
│   └── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_45_labels_metadata.json
├── S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU_14_46/
│   └── ...
```

### 2.2 Sentinel-2 Spectral Band Specifications

| Band Code | Wavelength (nm) | Spatial Resolution | Spectrum Domain | Primary Remote Sensing Utility |
| :--- | :--- | :--- | :--- | :--- |
| **B01** | 443 nm | 60 m | Coastal Aerosol | Atmospheric correction, coastal bathymetry |
| **B02** | 490 nm | 10 m | Blue | True-color imaging, soil vs vegetation |
| **B03** | 560 nm | 10 m | Green | True-color imaging, peak vegetation reflectance |
| **B04** | 665 nm | 10 m | Red | True-color imaging, chlorophyll absorption |
| **B05** | 705 nm | 20 m | Red Edge 1 | Vegetation status and stress classification |
| **B06** | 740 nm | 20 m | Red Edge 2 | Chlorophyll content and leaf structure |
| **B07** | 783 nm | 20 m | Red Edge 3 | Biomass estimations |
| **B08** | 842 nm | 10 m | Wide NIR | High-resolution vegetation, NDVI calculation |
| **B8A** | 865 nm | 20 m | Narrow NIR | Water vapor reference, atmospheric correction |
| **B09** | 945 nm | 60 m | Water Vapour | Atmospheric water vapor absorption |
| **B11** | 1610 nm | 20 m | SWIR 1 | Soil moisture, cloud vs snow discrimination |
| **B12** | 2190 nm | 20 m | SWIR 2 | Mineral mapping, moisture stress detection |

### 2.3 Multi-Label Metadata Schema (`*_labels_metadata.json`)

```json
{
  "labels": [
    "Coniferous forest",
    "Broad-leaved forest",
    "Natural grassland and sparsely vegetated areas"
  ],
  "tile_source": "S2A_MSIL2A_20170717T113321_N0205_R080_T30UVU",
  "acquisition_time": "2017-07-17 11:33:21",
  "coordinates": {
    "ulx": 484800.0,
    "uly": 5462280.0,
    "lrx": 486000.0,
    "lry": 5461080.0
  },
  "projection": "EPSG:32630"
}
```

---

## 3. Dataset Acquisition & Offline Air-Gap Import Workflow

TRUST-CV strictly adheres to an air-gapped deployment architecture. The application **never** attempts network connections to download datasets automatically.

```text
┌──────────────────────────────────────────────┐
│  ONLINE STAGING WORKSTATION (OPTIONAL)       │
│  1. Download authentic BigEarthNet-S2 subset │
│  2. Verify source SHA-256 archive checksum   │
└──────────────────────┬───────────────────────┘
                       │
                       ▼ Secure Optical Media / Signed USB
┌──────────────────────────────────────────────┐
│  AIR-GAPPED TRUST-CV SYSTEM                  │
│  3. Mount dataset on local filesystem        │
│  4. Execute Read-Only Inspection             │
│  5. Ingest & Seal Batch Manifest (Merkle)    │
│  6. Execute Data Integrity & Drift Assurance │
└──────────────────────────────────────────────┘
```

### 3.1 Storage Requirements

* **Full Dataset (590,326 patches):** ~50–60 GB compressed / ~120 GB uncompressed.
* **Representative Operational Subset (50–500 patches):** ~15–150 MB.
* **Minimal Validation Patch Set (5–20 patches):** ~1.5–6.0 MB.

> **Operational Note:** Ingesting a representative subset of 50 to 500 authentic patches provides full cryptographic verification, spectral feature distribution analysis, and model inference assurance without requiring the entire 50 GB archive.

---

## 4. Operational Procedures

### 4.1 Step 1: Read-Only Structural Inspection

Before ingesting or modifying any records, perform a read-only structural audit.

**Via CLI:**
```bash
python -m app.cli inspect-bigearthnet --path /path/to/BigEarthNet-v1.0
```

**Output Example:**
```text
============================================================
BIGEARTHNET-S2 DATASET INSPECTION REPORT
============================================================
  Source Directory:    /data/datasets/BigEarthNet-v1.0
  Total Patches:       25
  Complete Patches:    25
  Incomplete Patches:  0
  Corrupt Patches:     0
  Total Volume:        8.45 MB
  Bands Present:       B01, B02, B03, B04, B05, B06, B07, B08, B8A, B09, B11, B12
  Temporal Range:      2017-06-13 10:10:20 to 2017-08-22 11:45:00
  Label Classes Count: 7
  Anomalies Detected:  0
============================================================
```

**Via REST API:**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/datasets/bigearthnet/inspect \
     -H "Content-Type: application/json" \
     -d '{"dataset_name": "EO_Inspect", "format": "BIGEARTHNET_S2", "contributor_id": "operator", "source_path": "/data/datasets/BigEarthNet-v1.0"}'
```

---

### 4.2 Step 2: Ingest & Cryptographically Seal the Batch

Ingest the dataset into the TRUST-CV assurance engine:

```bash
python -m app.cli ingest-dataset \
    --name "BigEarthNet-S2-Sentinel" \
    --path "/data/datasets/BigEarthNet-v1.0" \
    --format "BIGEARTHNET_S2" \
    --contributor "eo_ground_station_01"
```

The ingestion engine:
1. Canonicalizes each multi-spectral patch by hashing each of the 12 band files in fixed canonical order.
2. Canonicalizes metadata JSON into a deterministic SHA-256 digest.
3. Computes the compound patch SHA-256: `SHA256(canonical_json({"bands": {...}, "metadata_digest": "..."}))`.
4. Assembles all patch digests into a deterministic binary **Merkle Inclusion Tree**.
5. Digitally signs the root digest using ECDSA SECP256R1 and issues the `BatchManifest`.

---

### 4.3 Step 3: Training Data Integrity Audit

Scan the ingested batch for missing spectral bands, corrupt GeoTIFFs, duplicated patches, and label discrepancies:

```bash
python -m app.cli audit-integrity --batch-id "<BATCH_ID>"
```

---

### 4.4 Step 4: Earth Observation Spectral Drift Analysis

TRUST-CV extracts scientific spectral indices across Sentinel-2 bands:
* **NDVI (Normalized Difference Vegetation Index):** $(B08 - B04) / (B08 + B04)$
* **NDWI (Normalized Difference Water Index):** $(B03 - B08) / (B03 + B08)$
* **Visible Channel Brightness:** $(B02 + B03 + B04) / 3.0$
* **SWIR Moisture Absorption:** Band 11 / Band 12 reflectance

To evaluate operational drift (e.g. seasonal daylight or atmospheric shift vs sensor degradation):

```bash
# 1. Establish baseline from reference EO batch
python -m app.cli create-drift-baseline --name "Summer_Sentinel_Baseline" --source-dir "/data/eo_summer"

# 2. Analyze candidate evaluation batch against baseline
python -m app.cli analyze-drift --baseline-id "<BASELINE_ID>" --eval-dir "/data/eo_autumn"
```

---

## 5. Calibrated Operational Boundaries

* **Drift ≠ Attack:** Spectral distribution drift indicates seasonal, weather, or sensor calibration changes. It does *not* automatically prove malicious data poisoning.
* **Missing Bands ≠ Insider Malice:** Incomplete patch archives indicate collection dropouts, transmission errors, or format anomalies requiring review.
* **Compound Identity Integrity:** The compound patch SHA-256 guarantees exact byte reproducibility across all 12 bands and metadata.
