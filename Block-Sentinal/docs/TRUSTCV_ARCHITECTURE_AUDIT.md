# TRUST-CV ARCHITECTURE AUDIT

## General Overview
The TRUST-CV repository contains a split architecture between a React+Vite frontend and a FastAPI backend. However, significant portions of the core integrity and security features are either entirely simulated in the frontend, missing from the backend, or implemented as isolated mock tests.

## Backend Architecture
- **Language/Framework**: Python 3.13, FastAPI.
- **Structure**: Extensive directory structure (`app/api`, `app/datasets`, `app/integrity`, etc.) giving the illusion of a fully featured backend.
- **Reality**: Several modules define schemas and basic routes, but core engines are missing implementation. E.g. models inspectors (`PyTorchInspector`, `ONNXInspector`) do not exist.
- **Tests**: The test suite covers "Phases 1-16", but tests from phase 3 onwards break due to missing imports (`DatasetParserFactory`, `BaselineProfile`, `compute_psi`, etc.).

## Frontend Architecture
- **Language/Framework**: TypeScript, React, Vite.
- **Services**: The `api.ts` handles communication but falls back to `trustPreviewService.ts` for "air-gapped" demoing. 
- **Security Logic**: Significant cryptographic and security logic (e.g. `computeSha256`, `computeLaplacianVariance`, `detectBackdoorTrigger`) is duplicated or implemented solely in the browser. 
- **State**: The application state relies heavily on mock data (`mockGraph.ts`, `mockScenario.ts`).

## Duplicated Security Logic
- **Frontend vs Backend Detection**: Both `app/integrity/detectors.py` and `trustPreviewService.ts` attempt to implement duplicates and backdoor trigger detection. 
- **Hash Chains**: The frontend implements a local `verifyLedgerChain` and block creation which acts as a simulated immutable ledger. The backend has a similar inference DNA concept (`app/api/inference.py`).
- **Recommendation**: Backend must become the authoritative source of all cryptographic operations, security decisions, and state management. Frontend should be strictly a presentation layer.
