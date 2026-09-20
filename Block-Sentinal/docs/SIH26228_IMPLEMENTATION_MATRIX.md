# SIH26228 IMPLEMENTATION MATRIX

## A. Training-data integrity
- trigger injection: PARTIAL (`frontend/src/services/trustPreviewService.ts` and `app/integrity/detectors.py`)
- label flipping: PARTIAL (`app/integrity/detectors.py` LabelInconsistencyDetector)
- systematic mislabelling: UNKNOWN
- near-duplicate flooding: REAL (`app/integrity/detectors.py` and `trustPreviewService.ts`)
- OOD insertion: REAL (`app/integrity/detectors.py` QualityAndOODDetector)
- contributor/source risk aggregation: SIMULATED (`trustPreviewService.ts` string splitting)

## B. Model integrity
- model identity: PARTIAL (Backend structure exists but incomplete)
- cryptographic fingerprint: SIMULATED
- structural checks: SIMULATED (ONNX/PyTorch inspectors missing in backend)
- behavioural fingerprinting: SIMULATED
- trigger/backdoor analysis: SIMULATED
- reference comparison: SIMULATED
- white-box handling: SIMULATED
- black-box fallback: UNKNOWN

## C. Inference provenance
- input identity: REAL (`app/api/inference.py` hash_bytes)
- model identity: SIMULATED
- preprocessing configuration: SIMULATED
- inference configuration: SIMULATED
- output identity: REAL (`app/api/inference.py` canonical_json_hash)
- sequence/nonce/timestamp: REAL (`trustPreviewService.ts` hash chain)
- replay detection: SIMULATED
- output tampering detection: SIMULATED
- cryptographic binding: REAL

## D. Distribution shift
- reference baseline: SIMULATED/MISSING (`app/schemas/drift.py` missing BaselineProfile)
- operational distribution: MISSING
- feature extraction: MISSING
- drift measurement: MISSING
- operational/environmental shift: MISSING
- suspicious shift: MISSING

## E. Evidence and governance
- evidence records: SIMULATED (`mockGraph.ts`, `mockScenario.ts`)
- severity: SIMULATED
- confidence: SIMULATED
- contributor risk: SIMULATED
- accept/review/quarantine: SIMULATED
- analyst decisions: MISSING
- evidence graph: SIMULATED
- assurance report: SIMULATED
- coverage/limitations: SIMULATED

## F. Tamper-evident audit
- hashing: REAL
- signatures: SIMULATED
- Merkle structures: MISSING
- hash chain: REAL (`trustPreviewService.ts` ledger)
- persistent audit history: SIMULATED (in-memory)
- chain verification: REAL (`trustPreviewService.ts` verifyLedgerChain)

## G. Required formats
- COCO: REAL (`app/datasets/parsers.py`)
- YOLO: REAL (`app/datasets/parsers.py`)
- image folders: REAL (`app/datasets/parsers.py`)
- ONNX: MISSING
- PyTorch: MISSING
- TorchScript: MISSING

## H. Operational constraints
- offline: REAL (Frontend logic runs locally)
- air-gapped: REAL (API service falls back to local)
- model-agnostic: SIMULATED (Hardcoded model generation)
- no mandatory cloud dependency: REAL
- no mandatory external API: REAL
