/**
 * TRUST-CV — Presentation-only initial state.
 *
 * NOTE (Phase 8, backend-authoritative refactor):
 * All previously exported *simulated security data* (fake trust scores, fake
 * findings with fabricated SHA-256 proofs, fake terminal logs asserting
 * "VERDICT: ACCEPTED", and the fabricated evidence graph in mockGraph.ts) has
 * been REMOVED. Authoritative results now come exclusively from the FastAPI
 * backend via src/services/api.ts. This module retains only harmless
 * presentation constants: empty artifact slots, stage definitions, and zeroed
 * metric counters.
 *
 * Stage codes (PipelineStage.code) MUST match the keys used in the backend
 * ScanSession.stage_results dict so the polling mapper in investigationStore
 * can resolve them without guesswork. Backend source of truth:
 *   app/api/scan.py  — _run_scan_pipeline assigns stage_results[<code>]
 */
import type {
  ArtifactItem,
  PipelineStage,
  LiveMetrics,
} from '../types/investigation';

/**
 * Production Initial State: Artifact slots initialize clean, awaiting input.
 */
export const INITIAL_ARTIFACTS: ArtifactItem[] = [
  {
    id: 'art-dataset',
    type: 'dataset',
    title: 'Computer Vision Dataset',
    filename: '',
    size: '0 B',
    hash: '',
    status: 'empty',
    progress: 0,
    metadata: {
      samplesCount: 0,
      format: 'Supports single images (.jpg, .png) or archives (.zip, .tar)',
    },
  },
  {
    id: 'art-model',
    type: 'model',
    title: 'Target Neural Network Model',
    filename: '',
    size: '0 B',
    hash: '',
    status: 'empty',
    progress: 0,
    metadata: {
      layersCount: 0,
      format: 'ONNX Runtime / PyTorch (.onnx, .pt)',
    },
  },
  {
    id: 'art-inference',
    type: 'inference',
    title: 'Inference Output Batch',
    filename: '',
    size: '0 B',
    hash: '',
    status: 'empty',
    progress: 0,
    metadata: {
      recordsCount: 0,
      format: 'JSON / CSV Predictions & Telemetry',
    },
  },
  {
    id: 'art-manifest',
    type: 'manifest',
    title: 'Cryptographic Manifest / Sig',
    filename: '',
    size: '0 B',
    hash: '',
    status: 'empty',
    progress: 0,
    metadata: {
      signature: 'SHA-256 / Ed25519 Hardware Digest',
      format: 'Defense Signed Manifest (.sig, .json)',
    },
  },
];

/**
 * Pipeline stage definitions whose `code` values correspond 1-to-1 with the
 * keys written into ScanSession.stage_results by the backend scan pipeline
 * (app/api/scan.py → _run_scan_pipeline).
 *
 * Two sets of codes exist in the backend:
 *   a. ScanStage enum values — used for session.stage (the current active phase)
 *   b. stage_results keys   — per-component outcomes written during each phase
 *
 * These stages map the stage_results keys so the UI can reflect the exact
 * per-component status the backend reports. The ordering follows the pipeline
 * execution sequence.
 */
export const PIPELINE_STAGES: PipelineStage[] = [
  {
    id: 1,
    code: 'DATA_INGESTION',
    title: '01 Data Ingestion',
    status: 'WAITING',
    progress: 0,
    summary: 'Dataset upload accepted; manifest and Merkle root verified',
  },
  {
    id: 2,
    code: 'HASH_VERIFICATION',
    title: '02 Hash Verification',
    status: 'WAITING',
    progress: 0,
    summary: 'SHA-256 per-sample cryptographic integrity check',
  },
  {
    id: 3,
    code: 'DATASET_ANALYSIS',
    title: '03 Dataset Analysis',
    status: 'WAITING',
    progress: 0,
    summary: 'Visual feature extraction and structural inspection',
  },
  {
    id: 4,
    code: 'DUPLICATE_DETECTION',
    title: '04 Duplicate Detection',
    status: 'WAITING',
    progress: 0,
    summary: 'Exact and near-duplicate sample identification',
  },
  {
    id: 5,
    code: 'LABEL_INTEGRITY',
    title: '05 Label Integrity',
    status: 'WAITING',
    progress: 0,
    summary: 'Label consistency and anomaly detection',
  },
  {
    id: 6,
    code: 'OOD_DETECTION',
    title: '06 OOD Detection',
    status: 'WAITING',
    progress: 0,
    summary: 'Out-of-distribution sample isolation (requires reference)',
  },
  {
    id: 7,
    code: 'MODEL_INTEGRITY',
    title: '07 Model Integrity',
    status: 'WAITING',
    progress: 0,
    summary: 'Weight tensor hashing and golden baseline comparison',
  },
  {
    id: 8,
    code: 'BACKDOOR_ANALYSIS',
    title: '08 Backdoor Analysis',
    status: 'WAITING',
    progress: 0,
    summary: 'Runtime inference and backdoor trigger pattern audit',
  },
  {
    id: 9,
    code: 'INFERENCE_VALIDATION',
    title: '09 Inference Validation',
    status: 'WAITING',
    progress: 0,
    summary: 'Inference chain provenance and replay verification',
  },
  {
    id: 10,
    code: 'DISTRIBUTION_SHIFT',
    title: '10 Distribution Shift',
    status: 'WAITING',
    progress: 0,
    summary: 'Statistical drift vs reference baseline (requires baseline)',
  },
  {
    id: 11,
    code: 'EVIDENCE_FUSION',
    title: '11 Evidence Fusion',
    status: 'WAITING',
    progress: 0,
    summary: 'Multi-source evidence correlation and risk scoring',
  },
  {
    id: 12,
    code: 'EVIDENCE_GRAPH',
    title: '12 Evidence Graph',
    status: 'WAITING',
    progress: 0,
    summary: 'Directed lineage graph construction',
  },
  {
    id: 13,
    code: 'FINAL_VERDICT',
    title: '13 Final Verdict',
    status: 'WAITING',
    progress: 0,
    summary: 'Consolidated zero-trust disposition and sealed report',
  },
];

export const INITIAL_METRICS: LiveMetrics = {
  samplesAnalyzed: 0,
  totalSamples: 0,
  modelLayersInspected: 0,
  totalLayers: 24,
  hashesVerified: 0,
  duplicatesFound: 0,
  poisonedSamples: 0,
  oodCandidates: 0,
  modelAnomalies: 0,
  inferenceAnomalies: 0,
};
