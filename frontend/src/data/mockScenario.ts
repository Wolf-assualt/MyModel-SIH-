/**
 * TRUST-CV â€” Presentation-only initial state.
 *
 * NOTE (Phase 8, backend-authoritative refactor):
 * All previously exported *simulated security data* (fake trust scores, fake
 * findings with fabricated SHA-256 proofs, fake terminal logs asserting
 * "VERDICT: ACCEPTED", and the fabricated evidence graph in mockGraph.ts) has
 * been REMOVED. Authoritative results now come exclusively from the FastAPI
 * backend via src/services/api.ts. This module retains only harmless
 * presentation constants: empty artifact slots, stage labels, and zeroed
 * metric counters.
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
 * Pre-Configured Defense Benchmark Evaluation Suite (Loaded on Demand)
 */
export const PIPELINE_STAGES: PipelineStage[] = [
  { id: 1, code: 'DATA_INGESTION', title: '01 Data Ingestion', status: 'WAITING', progress: 0, summary: 'Mounting air-gapped forensic storage sandbox' },
  { id: 2, code: 'HASH_VERIFICATION', title: '02 Hash Verification', status: 'WAITING', progress: 0, summary: 'Hardware accelerated SHA-256 integrity hashing' },
  { id: 3, code: 'DATASET_ANALYSIS', title: '03 Dataset Analysis', status: 'WAITING', progress: 0, summary: 'Extracting 512-dim visual latent embeddings' },
  { id: 4, code: 'DUPLICATE_DETECTION', title: '04 Duplicate Detection', status: 'WAITING', progress: 0, summary: 'Cosine similarity & pHash perceptual indexing' },
  { id: 5, code: 'POISONING_ANALYSIS', title: '05 Poisoning Analysis', status: 'WAITING', progress: 0, summary: 'Spectral signature & clean-label perturbation audit' },
  { id: 6, code: 'OOD_DETECTION', title: '06 OOD Detection', status: 'WAITING', progress: 0, summary: 'Mahalanobis distance & manifold outlier isolation' },
  { id: 7, code: 'MODEL_INTEGRITY', title: '07 Model Integrity', status: 'WAITING', progress: 0, summary: 'Weight tensor hashing & golden baseline verification' },
  { id: 8, code: 'BACKDOOR_ANALYSIS', title: '08 Backdoor Analysis', status: 'WAITING', progress: 0, summary: 'Neural Cleanse reverse trigger pattern extraction' },
  { id: 9, code: 'INFERENCE_VALIDATION', title: '09 Inference Validation', status: 'WAITING', progress: 0, summary: 'Adversarial robustness & prediction drift audit' },
  { id: 10, code: 'EVIDENCE_GRAPH', title: '10 Evidence Graph', status: 'WAITING', progress: 0, summary: 'Synthesizing directed cryptographic lineage graph' },
  { id: 11, code: 'FINAL_VERDICT', title: '11 Final Verdict', status: 'WAITING', progress: 0, summary: 'Consolidating zero-trust risk score & sealing report' },
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


