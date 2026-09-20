# TRUST-CV SIMULATION AUDIT

A significant amount of functionality is simulated, mocked, or hardcoded.

## 1. Frontend "Preview" Simulation

**Status as of Phase 2**: The frontend simulation has been COMPLETELY REMOVED. `trustPreviewService.ts` has been deleted, and `investigationStore.tsx` has been refactored to rely exclusively on backend API polling via the `ScanSession` endpoint. The information below serves as a historical record of Phase 1.

**File**: `frontend/src/services/trustPreviewService.ts`:
  - `generateSampleDatasetFiles()`: Generates fake "Clean Sentinel" and "BadNets Trigger" images using HTML5 canvas.
  - `generateSampleModelFile()`: Creates a dummy 4KB byte array to fake an ONNX model.
  - `generateSampleInputImage()`: Creates a synthetic surveillance feed image.
  - Parses risk and contributor based on file names (e.g., `alice__patch01.png` -> `alice`).
- `frontend/src/data/mockGraph.ts` and `mockScenario.ts`: Hardcoded JSON data to represent evidence graphs and security scenarios.
- `frontend/src/services/api.ts`: Many backend API calls have catch blocks that fallback to returning dummy data with a console warning `using air-gapped cache`.

## Backend Simulation
- `app/api/inference.py`:
  - The inference engine is completely simulated. The predictions array is hardcoded:
    ```python
    predictions = [
        BoundingBox(label="military_vehicle", confidence=0.94, box=[120.0, 140.0, 320.0, 420.0]),
        BoundingBox(label="personnel", confidence=0.88, box=[50.0, 75.0, 110.0, 200.0]),
    ]
    ```
  - Input hashes are generated deterministically if raw bytes are omitted.
- Missing files: Many tests imply the existence of complex logic (`BaselineProfile`, `DatasetParserFactory`) that has not actually been written. These act as "vaporware" tests that fail on import.
