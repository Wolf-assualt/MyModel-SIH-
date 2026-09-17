# TRUST-CV: Complete End-to-End System & User Guide

> **System Designation:** TRUST-CV (SIH26228)  
> **Platform Name:** Zero-Trust Computer Vision Integrity Assurance & Forensic Platform  
> **Target Environment:** Air-gapped defense computer vision pipelines, tactical operations centers (SOC), and security audit teams.

---

## 1. What This System Does (In Simple Terms)

### The Real-World Problem
Modern military defense systems rely heavily on Computer Vision (AI cameras, drone feeds, satellite imagery, target detection models like YOLO or ResNet). However, AI can be hacked in subtle, dangerous ways:
1. **Data Poisoning / Backdoors:** An adversary subtly edits training images (e.g., adding an invisible watermark or tiny pixel patch). The AI learns that whenever that patch appears, it should classify a hostile vehicle as a friendly civilian car.
2. **Model Weight Tampering:** A malicious actor swaps or modifies a few weights inside the neural network checkpoint file so the AI fails at critical moments.
3. **Inference Spoofing & Replay:** An adversary replays old sensor footage or fakes the AI's detection telemetry (e.g., repeating "airspace clear" when an intrusion is happening).
4. **Sensor Noise / Drift:** Heavy rain, night-vision degradation, or camera blinding causes the AI to make unpredictable decisions.

### What TRUST-CV Does
**TRUST-CV acts like an automated forensic investigator and cryptographic gatekeeper for AI.** 

Before an AI model or its predictions are allowed into mission-critical systems, TRUST-CV verifies:
- **Did anyone touch the data?** (Cryptographic hashes & Merkle trees)
- **Are there hidden trigger patches or poisoned images?** (Perceptual DCT hashing & anomaly probes)
- **Were the model weights tampered with?** (Tensor-level hash verification & synthetic behavioral testing)
- **Are the prediction outputs fresh, authentic, and signed?** (Inference DNA with sequence nonces)
- **Is the whole system safe?** (Bayesian Evidence Fusion Engine combining all checks into a single verdict: `ACCEPTED` or `QUARANTINED`).

---

## 2. System Architecture: How Everything Fits Together

The project has two distinct components working together over local HTTP APIs:

```
┌─────────────────────────────────────────────────────────────┐
│                   BROWSER / FRONTEND (React)                │
│  Port: 5173 (http://localhost:5173)                         │
│                                                             │
│  [Launch / Upload]  -->  [11-Stage Scan]  -->  [Results HUD]│
│         │                       │                     │     │
│  • Local SHA-256 Hashing • Live Progress      • Trust Score │
│  • File Type Inspection  • Pipeline Logs      • Verdict Card│
│  • Artifact Slot State   • Metrics Counter    • Graph View  │
└──────────────────────────────┬──────────────────────────────┘
                               │  REST API Calls (/api/v1/...)
                               ▼  (Proxied by Vite to port 8000)
┌─────────────────────────────────────────────────────────────┐
│                   BACKEND ENGINE (FastAPI)                  │
│  Port: 8000 (http://localhost:8000)                         │
│                                                             │
│  • SQLite Ledger (WAL Mode) & Merkle Tree Verification      │
│  • Dataset Integrity Engine (DCT Perceptual Hasher)         │
│  • Model Weight Hash & Behavioral Synthetic Probes          │
│  • Inference DNA Provenance Engine (ECDSA Signatures)       │
│  • Evidence Fusion Engine (Multi-Source Bayesian Scorer)    │
│  • Directed Evidence Property Graph Engine                  │
└─────────────────────────────────────────────────────────────┘
```

- **100% Air-Gapped:** Zero external cloud dependencies. All hashing, model checks, and graph rendering run strictly on the local machine.
- **Continuous Merkle Ledger:** Every file or event is cryptographically sealed into an append-only hash chain ($H_i = \text{SHA256}(i \parallel \text{timestamp} \parallel \text{digest} \parallel H_{i-1})$).

---

## 3. The 3 Phases of the Frontend & What Each Screen Does

The interface is structured into three consecutive operational phases:

```
[ Phase 01: LAUNCH ]  ────▶  [ Phase 02: SCAN ]  ────▶  [ Phase 03: RESULTS ]
 Upload & Validation         11-Stage Engine Run          Verdict & Forensic Graph
```

---

### Phase 01 — LAUNCH: Artifact Ingestion & Pre-Scan Setup

This is the intake screen where you tell the system what you want to audit.

#### The 4 Artifact Slots:
In high-security environments, you do not just scan an image alone; an AI pipeline has four pillars:
1. **Computer Vision Dataset (Data Frame / Training Batch):**
   - *What it is:* The raw image(s) or video frame(s) to inspect.
   - *Accepted formats:* `.jpg`, `.jpeg`, `.png`, `.webp`, or a `.zip` archive.
   - *What the frontend does:* Immediately computes the exact `SHA-256` hash in your browser via the Web Crypto API.
2. **Target Neural Network Model (The Model Weights):**
   - *What it is:* The AI weights checkpoint file.
   - *Accepted formats:* `.onnx`, `.pt`, `.pth`, `.bin`.
   - *What the frontend does:* Validates weight format and tracks layer integrity.
3. **Inference Output Batch (The Predictions):**
   - *What it is:* The detection results outputted by the model (bounding boxes, class labels, confidence).
   - *Accepted formats:* `.json`, `.jsonl`, `.csv`.
   - *What the frontend does:* Checks timestamp validity and record counts.
4. **Cryptographic Manifest / Sig (The Security Seal):**
   - *What it is:* A digital signature or digest manifest signed by the operator.
   - *Accepted formats:* `.sig`, `.json`, `.pem`, `.sha256`.
   - *What the frontend does:* Asserts that the manifest matches the files.

#### Key Actions on the Launch Page:
- **Drop / Upload Your Own File:** Drag any file onto an artifact slot. The slot will turn green (`VERIFIED`) and show the actual file name, file size, and calculated SHA-256 hash.
- **Click Any Slot:** Clicking a slot lets you manually verify or select a file.
- **Load Defense Benchmark Scenario (One-Click Preset):** In the top banner or helper section, click the benchmark loader to instantly populate the slots with a pre-configured defense surveillance scenario containing known poisoned samples for demonstration.
- **Initialize Integrity Scan Button:** Becomes active once required artifacts are satisfied. Clicking this button moves the application to Phase 02.

---

### Phase 02 — SCAN: The 11-Stage Forensic Pipeline

When you start the scan, the system runs 11 sequential forensic tests. You will see a real-time terminal log, progress bar, and metrics counters.

#### The 11 Stages Explained in Plain English:
| Stage # | Stage Name | What It Actually Tests |
| :---: | :--- | :--- |
| **01** | **Ingestion & Manifest Sealing** | Verifies file sizes, canonical JSON encoding, and calculates initial Merkle roots. |
| **02** | **SHA-256 Merkle Verification** | Confirms that every sample matches its declared cryptographic hash with zero byte tampering. |
| **03** | **Perceptual Hash Matrix (pHash)** | Uses Discrete Cosine Transform (DCT) to detect unauthorized image duplicates or subtle crops. |
| **04** | **Clean-Label Backdoor Probe** | Scans image pixels for invisible high-frequency trigger patterns or checkerboard watermarks. |
| **05** | **Out-Of-Distribution (OOD) Sensor Check** | Calculates statistical distance (Wasserstein & KS tests) to flag sensor blinding, blur, or severe distribution shift. |
| **06** | **Model Architecture & Layer Hash** | Hashes individual neural network layers (`conv2d`, attention blocks) to spot altered layers. |
| **07** | **Synthetic Behavioral Battery** | Sends standard synthetic probe images through the model to verify output consistency against baseline expectations. |
| **08** | **Inference DNA & Nonce Verification** | Checks that inference records have strictly increasing timestamps and unique cryptographic nonces (blocks replay attacks). |
| **09** | **Statistical Drift Classification** | Classifies environmental drift (e.g., fog, low-light, IR sensor thermal noise). |
| **10** | **Bayesian Evidence Fusion** | Aggregates all anomalies from stages 1–9 using Bayesian probability to compute an overall risk score. |
| **11** | **Assurance Report & Lineage Seal** | Generates an immutable, cryptographically signed audit report and updates the hash chain. |

#### Live Controls During Scan:
- **Speed Multiplier (`1x`, `2x`, `5x`):** Accelerates or slows the audit playback.
- **Pause / Resume:** Temporarily freezes scanning to inspect the terminal logs.
- **Skip to End:** Instantly jumps to the completed state and redirects to Results.

---

### Phase 03 — RESULTS: The Forensic Intelligence HUD

Once the scan is complete, you are brought to the comprehensive results screen.

#### What You See on the Results Dashboard:
1. **The Verdict Card:**
   - `ACCEPTED (CLEAN)`: All 11 stages passed with zero critical anomalies. The asset is safe for deployment.
   - `QUARANTINED (HIGH RISK)`: Critical backdoors, weight mismatches, or replay attacks were detected. The asset is blocked from deployment.
2. **The Trust Score Gauge:**
   - A score from **0% to 100%**:
     - **90% – 100%:** High trust (Green) — Verified Clean.
     - **70% – 89%:** Moderate trust (Yellow) — Minor warnings (e.g., low-light sensor drift).
     - **< 70%:** Unacceptable risk (Red) — Critical violation / Quarantined.
3. **Findings Table with Filters:**
   - Filter by Severity: `ALL`, `CRITICAL`, `WARNING`, `INFO`.
   - Filter by Category: `Data Integrity`, `Model Identity`, `Inference DNA`, `Drift`.
   - Search Bar: Search findings by name (e.g., `"conv2d"` or `"trigger"`).
   - Detail Drawer: Click any row to view exact technical telemetry, affected layer names, and cryptographic evidence.
4. **Interactive Evidence Lineage Graph:**
   - Renders a node-and-edge graph showing how the contributor, dataset, model, and inferences connect.
   - Nodes turn red if quarantined, yellow if under review, and cyan/green if clean.
   - Click any node to see its properties and upstream/downstream blast radius.
5. **Remediation & Action Plan:**
   - Concrete instructions on how to fix flagged issues (e.g., "Retrain model without batch #4", "Regenerate ECDSA manifest signature").
6. **Export Buttons:**
   - **Export Assurance Report (JSON):** Downloads the full machine-readable cryptographic report.
   - **Export Evidence Package:** Downloads the full package including node digests and raw findings.

---

## 4. Step-by-Step Walkthrough: How to Use the System End-to-End

### Scenario A: Auditing Your Own Single Image (Live Clean Scan)

Follow these steps to test a clean image:

1. **Open the App:** Navigate to `http://localhost:5173` in your browser.
2. **Observe the Initial State:**
   - You are on the `01 LAUNCH` page.
   - The artifact slots are clean and ready.
   - Notice the status pill at the top: `LIVE BACKEND API CONNECTED`.
3. **Upload Your Image:**
   - Locate the **Computer Vision Dataset** slot (first box).
   - Drag and drop your image (e.g., `my_surveillance_feed.png` or any `.jpg` file) directly into the box.
   - Notice that the slot updates instantly:
     - Shows your exact file name (e.g., `my_surveillance_feed.png`).
     - Shows the exact file size (e.g., `245.1 KB`).
     - Displays the real computed `SHA-256` hash (e.g., `d4f7a1...8c9e`).
     - Badge changes to `READY`.
4. **Verify Supporting Artifacts:**
   - Click on the remaining slots (Model, Inference, Manifest) to simulate/verify their presence or upload your own `.onnx` / `.json` files.
5. **Start the Scan:**
   - Click the green **INITIALIZE INTEGRITY SCAN** button.
   - The screen smoothly transitions to `02 SCAN`.
6. **Watch the Scan Progress:**
   - Watch the live terminal logs stream across your screen.
   - The progress bar counts from `0%` to `100%`.
   - Notice that all stages turn to green `PASSED`.
7. **Inspect the Results:**
   - The page automatically transitions to `03 RESULTS`.
   - **Verdict:** Displays `ACCEPTED` (Green badge).
   - **Trust Score:** Displays `98.4%` (High Trust).
   - **Findings Table:** Displays the clean audit banner: `Zero Forensic Vulnerabilities Detected`.
   - **Lineage Graph:** Shows your image connected to the clean model and inference chain.
8. **Export Evidence:**
   - Click **Export Report** in the top right corner to download the cryptographically sealed JSON report.

---

### Scenario B: Auditing a Tainted Defense Batch (Adversarial Detection & Quarantine)

Follow these steps to see how the system detects and quarantines a sophisticated attack:

1. **Navigate to Launch:** Click on `01 LAUNCH` in the top navigation bar.
2. **Load Benchmark Scenario:**
   - Click the **Load Preset Scenario** / **Evaluation Benchmark** button.
   - The slots immediately populate with:
     - Dataset: `defense_surveillance_corpus.zip` (52,000 frames)
     - Model: `yolov8x_tactical_v4.onnx`
     - Inference: `telemetry_sector7_batch.json`
     - Manifest: `mod_defense_seal.sig`
3. **Start the Scan:**
   - Click **INITIALIZE INTEGRITY SCAN**.
4. **Observe the Findings During Scan:**
   - The scanner detects issues at:
     - Stage 04 (Clean-Label Backdoor Probe): `WARNING` (18 suspicious trigger patterns).
     - Stage 06 (Model Layer Hash): `FAILED` (Layer `conv2d_19` hash mismatch).
     - Stage 08 (Inference DNA): `FAILED` (7 inference records with replay/nonce inversion).
5. **Review the Quarantine Verdict in Results:**
   - **Verdict:** `QUARANTINED` (Red badge).
   - **Trust Score:** Drops to `34.2%` (Critical Risk).
   - **Findings Table:** Populated with detailed findings:
     - `CRITICAL`: Model layer `conv2d_19` weight tensor altered.
     - `CRITICAL`: 18 clean-label backdoor trigger patterns confirmed.
     - `HIGH`: 7 inference records demonstrate adversarial confidence inversion.
6. **Interact with the Findings:**
   - Click on any finding row to expand technical details and remediation steps.
   - Switch category filters (`Data Integrity`, `Model Identity`) to isolate specific problems.
7. **Inspect the Lineage Graph:**
   - Scroll down to the Evidence Graph.
   - Click on the node labeled `conv2d_19` (highlighted in red) to trace upstream contributor identity and downstream blast radius.

---

## 5. Concrete Example Data & Schemas

### Example 1: What a Clean Verification Output Looks Like (JSON)

When an image passes all checks, the backend generates an assurance manifest structured like this:

```json
{
  "report_id": "REP-2026-9812A",
  "generated_at": "2026-09-11T02:15:00Z",
  "target_asset": {
    "asset_id": "sample_feed_01.jpg",
    "asset_type": "DATASET_FRAME",
    "sha256": "e82109fda1c54b03948192837401928471928374918237491827394817182734",
    "size_bytes": 1258291
  },
  "overall_verdict": "ACCEPTED",
  "trust_score": 98.4,
  "risk_score": 0.016,
  "coverage": {
    "stages_executed": 11,
    "stages_passed": 11,
    "stages_failed": 0
  },
  "findings": [],
  "cryptographic_seal": {
    "algorithm": "ECDSA_SECP256R1",
    "signer_id": "DEFENSE_SOC_NODE_01",
    "merkle_root": "7f8b91a2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
    "chain_block_index": 482
  }
}
```

---

### Example 2: What a Quarantined Attack Output Looks Like (JSON)

When an adversary tampers with model weights or data, the fusion engine flags it:

```json
{
  "report_id": "REP-2026-4402Q",
  "generated_at": "2026-09-11T02:15:00Z",
  "target_asset": {
    "asset_id": "yolov8x_tactical_v4.onnx",
    "asset_type": "MODEL_CHECKPOINT",
    "sha256": "a3b948192837401928471928374918237491827394817182734e82109fda1c54"
  },
  "overall_verdict": "QUARANTINED",
  "trust_score": 34.2,
  "risk_score": 0.895,
  "findings": [
    {
      "finding_id": "FND-001",
      "stage": "MODEL_IDENTITY",
      "severity": "CRITICAL",
      "layer": "model.22.cv3.2.conv",
      "description": "Layer parameter tensor hash diverges from signed gold-standard manifest.",
      "remediation": "Immediately isolate model binary. Check commit signature on model repository."
    },
    {
      "finding_id": "FND-002",
      "stage": "DATA_INTEGRITY",
      "severity": "CRITICAL",
      "samples_affected": 18,
      "description": "High-frequency DCT trigger patch detected (Clean-label poisoning attempt).",
      "remediation": "Quarantine contributor ID 'CONTRIB-EXT-88' and purge training batch #14."
    }
  ],
  "quarantine_action": {
    "status": "ENFORCED",
    "isolation_timestamp": "2026-09-11T02:15:01Z",
    "deployment_gate": "BLOCKED"
  }
}
```

---

## 6. How to Start and Verify the System Locally

If you need to restart the application or run it on a new development machine:

### 1. Start the Backend Server (FastAPI)
Open a terminal in the project root:
```powershell
# Navigate to the backend directory
cd c:\Users\sce24\Desktop\sih-project\Block-Sentinal

# Run Uvicorn on port 8000
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend Health Check:** Visit `http://localhost:8000/api/v1/system/health`
- **Interactive API Documentation:** Visit `http://localhost:8000/docs`

### 2. Start the Frontend Application (Vite + React)
Open a second terminal:
```powershell
# Navigate to the frontend directory
cd c:\Users\sce24\Desktop\sih-project\frontend

# Start Vite dev server on port 5173
npm run dev
```
- **Web App Dashboard:** Visit `http://localhost:5173` in any browser.

### 3. Run the Automated Test Suite (Backend)
To verify that all 15 cryptographic and detection engines are operating correctly:
```powershell
cd c:\Users\sce24\Desktop\sih-project\Block-Sentinal
python -m pytest -v
```
*(All 98 tests should return `PASSED` with a 100% pass rate).*

---

## 7. Glossary of Key Terms

| Term | Simple Definition |
| :--- | :--- |
| **Zero-Trust** | A security model where nothing is trusted by default. Every image, model, and prediction must prove its authenticity cryptographically before use. |
| **Air-Gapped** | Completely isolated from the public internet. No data ever leaves the local machine or classified defense network. |
| **SHA-256 Hash** | A unique mathematical fingerprint generated from a file's bytes. If even a single pixel in an image changes, the hash changes completely. |
| **Merkle Tree** | A tree of cryptographic hashes used to verify millions of dataset images quickly without reading all files one by one. |
| **Clean-Label Backdoor** | A sneaky attack where training images look completely normal to human eyes, but contain mathematical patterns that trick the AI. |
| **Inference DNA** | A signed 5-tuple record $\langle \text{Input}, \text{Model}, \text{Output}, \text{Nonce}, \text{Timestamp} \rangle$ that proves an AI decision was made by a legitimate model at a specific moment in time. |
| **Evidence Fusion Engine** | The system's central decision maker. It combines clues from all 11 stages to give a single mathematically grounded risk score. |
| **Quarantine** | An automated containment action that blocks a suspicious model or dataset from being deployed to battlefield operations. |

---

*Document version: 2.4 (Defense SOC Assurance Edition)*  
*Maintained for: Smart India Hackathon (SIH26228) / Ministry of Defence*
