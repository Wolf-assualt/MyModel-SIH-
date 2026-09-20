# TRUST-CV Real Backend Pipeline

This document describes the authoritative backend-driven scan pipeline implemented in Phase 2.

## Overview

The TRUST-CV backend now manages the complete state of any forensic scan via the `ScanSession` model. The frontend no longer generates mock scenarios, deterministic test hashes, or fake backdoor triggers.

### Flow
1. **Upload & Ingest**: The user uploads a dataset or model to `/api/v1/datasets/upload`. The backend ingests the artifacts, creates a `ScanSession`, stores it in-memory, spawns a background task for `_run_scan_pipeline`, and immediately returns the `scan_id`.
2. **Polling**: The frontend `ScanPage` polls `/api/v1/scan/{scan_id}` every second.
3. **Stage Execution**: The background pipeline runs through predefined stages:
   - `INGESTION`
   - `HASHING`
   - `DATA_INTEGRITY` (Calls actual `default_integrity_engine.scan`)
   - `MODEL_ASSURANCE` (Currently `UNAVAILABLE`)
   - `INFERENCE_ASSURANCE` (Currently `UNAVAILABLE`)
   - `DISTRIBUTION_SHIFT` (Currently `UNAVAILABLE`)
   - `EVIDENCE_FUSION` (Currently `UNAVAILABLE`)
   - `AUDIT`
   - `REPORT`
4. **Completion**: Once finished, the session status updates to `COMPLETED`. The frontend retrieves the `findings` and `assessment` from the `ScanSession` directly and navigates to the Results page.

## Future Phases
Future phases will replace the `UNAVAILABLE` module statuses with real ML and cryptography models, integrating PyTorch models and actual dataset processing instead of just returning warnings.
