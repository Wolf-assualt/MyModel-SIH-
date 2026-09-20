# TRUST-CV CURRENT WORKFLOW

The actual workflow currently implemented in the repository:

1. **UPLOAD**: MIXED 
   - Frontend UI supports file selection and upload API requests.
   - However, the backend parsers (while partially implemented) are not fully integrated or tested. The frontend falls back to generating fake files via `generateSampleDatasetFiles()`.

2. **INGESTION**: MIXED
   - `app/datasets/parsers.py` implements REAL parsing for YOLO, COCO, and Directory formats.
   - The test suite for ingestion fails due to missing factories.

3. **SCAN**: FRONTEND ONLY / MIXED
   - `trustPreviewService.ts` runs Web Canvas-based scans (Laplacian variance, dHash) directly in the browser instead of the backend.
   - Backend `app/integrity/detectors.py` exists but is largely disconnected from the main frontend workflow.

4. **ANALYSIS**: SIMULATED
   - Uses hardcoded mock scenarios (`mockGraph.ts`, `mockScenario.ts`) to simulate threat analysis, evidence fusion, and risk aggregation.
   - Inference API returns hardcoded bounding boxes.

5. **RESULT**: SIMULATED
   - Final decisions, scores, and verdicts are generated via mock logic or synthetic fallback endpoints.

6. **REPORT**: SIMULATED
   - Reports (like Assurance Reports) are either mocked in the frontend or rely on missing backend implementations (fusion, drift calculation).
