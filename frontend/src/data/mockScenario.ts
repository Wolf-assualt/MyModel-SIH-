import type {
  ArtifactItem,
  PipelineStage,
  TerminalLog,
  LiveMetrics,
  SignalPoint,
  Finding,
  TrustScore,
  Recommendation,
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

/**
 * Dynamically generate pipeline terminal logs matching the actual file under analysis.
 */
export function generatePipelineLogs(
  filename: string,
  sampleCount: number,
  hash: string,
  isClean: boolean = true
): TerminalLog[] {
  const shortHash = hash ? hash.slice(0, 16) + '...' + hash.slice(-8) : 'e821...9b04';
  const label = sampleCount === 1 ? `1 image frame (${filename || 'Single Frame'})` : `${sampleCount.toLocaleString()} visual samples`;

  if (isClean) {
    return [
      { id: 'log-1', timestamp: '00:00.6', level: 'INFO', message: 'TRUST-CV Zero-Trust Kernel v2.4 initialized in AIR-GAPPED DEFENSE mode.', stageCode: 'DATA_INGESTION' },
      { id: 'log-2', timestamp: '00:01.2', level: 'INFO', message: 'Mounted read-only sandbox environment /dev/nvme0n1p3.', stageCode: 'DATA_INGESTION' },
      { id: 'log-3', timestamp: '00:01.8', level: 'PASS', message: `Artifact ingested: ${label} indexed successfully.`, stageCode: 'DATA_INGESTION' },
      { id: 'log-4', timestamp: '00:02.5', level: 'INFO', message: 'Executing hardware SHA-256 cryptographic verification...', stageCode: 'HASH_VERIFICATION' },
      { id: 'log-5', timestamp: '00:03.4', level: 'PASS', message: `Hardware SHA-256 validated: [${shortHash}]. Merkle leaf verified.`, stageCode: 'HASH_VERIFICATION' },
      { id: 'log-6', timestamp: '00:04.2', level: 'INFO', message: 'Extracting 512-dim visual embeddings via ResNet50-Forensic extractor...', stageCode: 'DATASET_ANALYSIS' },
      { id: 'log-7', timestamp: '00:05.1', level: 'PASS', message: 'Embeddings normalized across perceptual manifolds with nominal variance.', stageCode: 'DATASET_ANALYSIS' },
      { id: 'log-8', timestamp: '00:06.0', level: 'INFO', message: 'Perceptual hashing (pHash) and cosine similarity indexing complete.', stageCode: 'DUPLICATE_DETECTION' },
      { id: 'log-9', timestamp: '00:06.8', level: 'PASS', message: '0 duplicate collisions or Sybil flooding patterns detected.', stageCode: 'DUPLICATE_DETECTION' },
      { id: 'log-10', timestamp: '00:07.7', level: 'INFO', message: 'Executing spectral signature and clean-label poisoning audit...', stageCode: 'POISONING_ANALYSIS' },
      { id: 'log-11', timestamp: '00:08.5', level: 'PASS', message: 'Spectral saliency eigenvalues nominal. No backdoor trigger patterns identified.', stageCode: 'POISONING_ANALYSIS' },
      { id: 'log-12', timestamp: '00:09.3', level: 'PASS', message: 'Mahalanobis latent distance z < 1.20 sigma. All samples within nominal training manifold.', stageCode: 'OOD_DETECTION' },
      { id: 'log-13', timestamp: '00:10.1', level: 'INFO', message: 'Inspecting target neural network parameter weights (24 layers)...', stageCode: 'MODEL_INTEGRITY' },
      { id: 'log-14', timestamp: '00:11.0', level: 'PASS', message: 'Layer weight tensors match golden baseline signature manifest (100.0% parity).', stageCode: 'MODEL_INTEGRITY' },
      { id: 'log-15', timestamp: '00:11.8', level: 'PASS', message: 'Neural Cleanse reverse trigger optimization converged: L1 trigger norm > 0.450 (Nominal).', stageCode: 'BACKDOOR_ANALYSIS' },
      { id: 'log-16', timestamp: '00:12.6', level: 'PASS', message: 'Adversarial perturbation battery passed: Cross-entropy residuals within certified bounds.', stageCode: 'INFERENCE_VALIDATION' },
      { id: 'log-17', timestamp: '00:13.4', level: 'INFO', message: 'Synthesizing Directed Evidence Property Graph and lineage relationships...', stageCode: 'EVIDENCE_GRAPH' },
      { id: 'log-18', timestamp: '00:14.2', level: 'PASS', message: 'Evidence Graph sealed with canonical SHA-256 digest.', stageCode: 'EVIDENCE_GRAPH' },
      { id: 'log-19', timestamp: '00:15.0', level: 'PASS', message: 'Consolidated Trust Score: 100/100. VERDICT: ACCEPTED. Cryptographic report sealed.', stageCode: 'FINAL_VERDICT' },
    ];
  }

  // Tainted Benchmark logs
  return [
    { id: 'log-1', timestamp: '00:00.8', level: 'INFO', message: 'TRUST-CV Zero-Trust Kernel v2.4 initialized in AIR-GAPPED DEFENSE mode.', stageCode: 'DATA_INGESTION' },
    { id: 'log-2', timestamp: '00:01.4', level: 'INFO', message: 'Mounted encrypted block device /dev/nvme0n1p3 (Read-Only Forensic Sandbox).', stageCode: 'DATA_INGESTION' },
    { id: 'log-3', timestamp: '00:02.1', level: 'PASS', message: 'Dataset archive unpacked: 52,000 visual frames indexed in memory.', stageCode: 'DATA_INGESTION' },
    { id: 'log-4', timestamp: '00:03.0', level: 'INFO', message: 'Executing hardware SHA-256 verification against baseline signature manifest...', stageCode: 'HASH_VERIFICATION' },
    { id: 'log-5', timestamp: '00:04.2', level: 'PASS', message: '51,999 sample digests matched signed root Merkle tree hash.', stageCode: 'HASH_VERIFICATION' },
    { id: 'log-6', timestamp: '00:04.9', level: 'CRIT', message: 'HASH MISMATCH on block manifest #18472: SHA-256 differs from expected digest!', stageCode: 'HASH_VERIFICATION' },
    { id: 'log-7', timestamp: '00:06.1', level: 'INFO', message: 'Extracting latent embeddings via ResNet50-Forensic feature extractor...', stageCode: 'DATASET_ANALYSIS' },
    { id: 'log-8', timestamp: '00:08.5', level: 'INFO', message: 'Generating locality-sensitive hashing (LSH) index across 52,000 representations...', stageCode: 'DUPLICATE_DETECTION' },
    { id: 'log-9', timestamp: '00:10.2', level: 'WARN', message: 'Identified 127 exact/near-duplicate sample pairs exceeding 0.992 cosine threshold.', stageCode: 'DUPLICATE_DETECTION' },
    { id: 'log-10', timestamp: '00:12.7', level: 'CRIT', message: 'Spectral signature audit detected anomalous cluster in contributor batch EXT-DEV-09.', stageCode: 'POISONING_ANALYSIS' },
    { id: 'log-11', timestamp: '00:14.3', level: 'CRIT', message: '18 samples confirmed with trigger-like spatial pattern (Backdoor Alpha-9 signature).', stageCode: 'POISONING_ANALYSIS' },
    { id: 'log-12', timestamp: '00:16.8', level: 'WARN', message: 'Mahalanobis distance threshold exceeded on 42 samples (OOD distribution drift).', stageCode: 'OOD_DETECTION' },
    { id: 'log-13', timestamp: '00:19.4', level: 'INFO', message: 'Inspecting ONNX model graph structure (24 layers, 148 MB parameters)...', stageCode: 'MODEL_INTEGRITY' },
    { id: 'log-14', timestamp: '00:21.0', level: 'CRIT', message: 'Layer conv2d_19 weight tensor SHA-256 mismatch against golden baseline!', stageCode: 'MODEL_INTEGRITY' },
    { id: 'log-15', timestamp: '00:23.5', level: 'CRIT', message: 'Neural Cleanse optimization converged on L1 trigger norm 0.014 in output class #3.', stageCode: 'BACKDOOR_ANALYSIS' },
    { id: 'log-16', timestamp: '00:26.1', level: 'WARN', message: '7 inference records demonstrate output confidence inversion under adversarial test.', stageCode: 'INFERENCE_VALIDATION' },
    { id: 'log-17', timestamp: '00:28.4', level: 'INFO', message: 'Synthesizing Directed Evidence Property Graph (48 nodes, 62 relations)...', stageCode: 'EVIDENCE_GRAPH' },
    { id: 'log-18', timestamp: '00:30.0', level: 'PASS', message: 'Evidence Graph sealed with canonical SHA-256 digest.', stageCode: 'EVIDENCE_GRAPH' },
    { id: 'log-19', timestamp: '00:31.2', level: 'WARN', message: 'Consolidated Trust Score: 72/100. VERDICT: COMPROMISED. Generating report...', stageCode: 'FINAL_VERDICT' },
  ];
}

/**
 * Backward compatibility constant
 */
export const MOCK_TERMINAL_LOGS: TerminalLog[] = generatePipelineLogs('uploaded-dataset', 1, '', true);

/**
 * Generate deterministic points for the Integrity Signal Map based on actual sample count.
 */
export function generateSignalPoints(
  sampleCount: number = 1,
  poisonedCount: number = 0,
  oodCount: number = 0,
  sampleLabel: string = 'sample'
): SignalPoint[] {
  const points: SignalPoint[] = [];

  // Case 1: Single sample (e.g. single image upload)
  if (sampleCount <= 1) {
    points.push({
      id: 'pt-single-0',
      sampleId: sampleLabel.includes('.') ? sampleLabel : `${sampleLabel}_frame.jpg`,
      x: 250,
      y: 120,
      status: poisonedCount > 0 ? 'poisoned' : oodCount > 0 ? 'ood' : 'normal',
      score: poisonedCount > 0 ? 0.98 : 0.02,
      cluster: poisonedCount > 0 ? 'Anomalous Trigger Space' : 'Nominal Feature Space',
    });
    return points;
  }

  // Case 2: Multi-sample dataset
  const normalCount = Math.max(1, Math.min(160, sampleCount - poisonedCount - oodCount));
  for (let i = 0; i < normalCount; i++) {
    const angle = (i / normalCount) * Math.PI * 2 + (i % 5) * 0.2;
    const r = 25 + (i % 23) * 3.2;
    const cx = 250;
    const cy = 120;
    points.push({
      id: `pt-norm-${i}`,
      sampleId: `sample_${String(1000 + i * 14).padStart(5, '0')}.jpg`,
      x: cx + Math.cos(angle) * r,
      y: cy + Math.sin(angle) * r * 0.75,
      status: 'normal',
      score: 0.02 + ((i % 17) / 100),
      cluster: 'Normal Feature Cluster',
    });
  }

  // OOD Samples
  const renderOod = Math.min(42, oodCount);
  for (let i = 0; i < renderOod; i++) {
    const angle = (i / Math.max(1, renderOod)) * Math.PI * 2;
    const r = 110 + (i % 11) * 5;
    const cx = 250;
    const cy = 120;
    points.push({
      id: `pt-ood-${i}`,
      sampleId: `sample_${String(28000 + i * 35).padStart(5, '0')}.jpg`,
      x: cx + Math.cos(angle) * r,
      y: cy + Math.sin(angle) * r * 0.8,
      status: 'ood',
      score: 0.72 + ((i % 19) / 100),
      cluster: 'OOD Outlier Periphery',
    });
  }

  // Poisoned Samples
  const renderPois = Math.min(18, poisonedCount);
  for (let i = 0; i < renderPois; i++) {
    const angle = (i / Math.max(1, renderPois)) * Math.PI * 2;
    const r = 16 + (i % 5) * 3;
    const cx = 410;
    const cy = 70;
    points.push({
      id: `pt-pois-${i}`,
      sampleId: `sample_${18470 + i}.jpg`,
      x: cx + Math.cos(angle) * r,
      y: cy + Math.sin(angle) * r,
      status: 'poisoned',
      score: 0.96 + ((i % 5) / 100),
      cluster: 'Anomalous Poisoning Subspace',
    });
  }

  return points;
}

export const CLEAN_TRUST_SCORE: TrustScore = {
  overall: 100,
  dataIntegrity: 100,
  modelIntegrity: 100,
  inferenceIntegrity: 100,
  pipelineIntegrity: 100,
  verdict: 'ACCEPTED',
  headline: 'Zero-Trust Integrity Verified: PASS',
  summary: 'All cryptographic checksums, spectral trigger audits, and neural parameter integrity assertions passed with zero vulnerabilities detected. Full mission deployment authorized.',
};

export const BENCHMARK_TRUST_SCORE: TrustScore = {
  overall: 72,
  dataIntegrity: 82,
  modelIntegrity: 94,
  inferenceIntegrity: 71,
  pipelineIntegrity: 88,
  verdict: 'COMPROMISED',
  headline: 'Integrity violations detected in dataset and model pipeline.',
  summary: '18 confirmed clean-label poisoned samples with backdoor triggers, 1 model layer weight tampering anomaly, and 7 inference output deviations. Defense deployment NOT RECOMMENDED until remediation steps are completed.',
};

export const MOCK_TRUST_SCORE = BENCHMARK_TRUST_SCORE;

export const BENCHMARK_FINDINGS: Finding[] = [
  {
    id: 'FND-00182',
    title: 'Potential Clean-Label Data Poisoning',
    category: 'DATA POISONING',
    severity: 'CRITICAL',
    affectedArtifact: 'sample_18472.jpg (Batch BATCH-2026-ALPHA)',
    evidenceSummary: 'Visual embedding deviates significantly from ground-truth class centroid (Spectral Saliency p < 0.0001). Trigger-like pixel watermark isolated in bottom-right corner.',
    confidence: 98.2,
    status: 'Confirmed',
    detectionMethod: 'Spectral Signature + Latent Representation Clustering',
    expectedValue: 'Class Centroid Dist < 0.150 | SHA-256: 91a7...3f12',
    observedValue: 'Class Centroid Dist = 0.892 | SHA-256: e821...9b04',
    sha256Proof: 'e82109fda1c54b03948192837401928471928374918237491827394817182734',
    recommendedAction: 'Quarantine sample immediately. Revoke ingestion batch BATCH-2026-ALPHA and audit contributor EXT-DEV-09.',
    relatedNodeId: 'node-sample-18472',
  },
  {
    id: 'FND-00183',
    title: 'Backdoor Trigger Watermark Injected',
    category: 'BACKDOOR',
    severity: 'CRITICAL',
    affectedArtifact: 'sample_18489.jpg (Dataset)',
    evidenceSummary: 'Checkerboard high-frequency spatial perturbation pattern discovered matching known defense adversary trigger signature Alpha-9.',
    confidence: 97.4,
    status: 'Confirmed',
    detectionMethod: 'Neural Cleanse Reverse Trigger Optimization',
    expectedValue: 'Trigger L1 Norm > 0.350',
    observedValue: 'Trigger L1 Norm = 0.014 (High Backdoor Vulnerability)',
    sha256Proof: '74bba87326c14d24b3f10ab7458f9601a9182938471928471928374918237491',
    recommendedAction: 'Isolate affected training partition. Re-train target classifier after removing contaminated samples.',
    relatedNodeId: 'node-finding-backdoor',
  },
  {
    id: 'FND-00204',
    title: 'Model Weight Tensor Tampering / Hash Mismatch',
    category: 'MODEL INTEGRITY',
    severity: 'CRITICAL',
    affectedArtifact: 'recon_yolo_v8n.onnx (Layer: conv2d_19)',
    evidenceSummary: 'Cryptographic digest of conv2d_19 parameter tensors differs from signed golden baseline manifest. Potential weight backdoor insertion.',
    confidence: 100.0,
    status: 'Confirmed',
    detectionMethod: 'Hardware Accelerated Per-Layer Weight Hashing',
    expectedValue: 'SHA-256: a0c04734095c4beb826aee02cb6bf50c82910293847192837491827394817283',
    observedValue: 'SHA-256: f56aafa12cc7491caef9b4ba5681d2da91029384719283749182739481728394',
    sha256Proof: 'f56aafa12cc7491caef9b4ba5681d2da91029384719283749182739481728394',
    recommendedAction: 'Reject current model checkpoint. Revert to signed baseline v1.2 and trigger air-gapped cryptographic re-validation.',
    relatedNodeId: 'node-model-yolo',
  },
  {
    id: 'FND-00215',
    title: 'Inference Output Confidence Inversion Anomaly',
    category: 'INFERENCE',
    severity: 'HIGH',
    affectedArtifact: 'batch_recon_eval.json (Record #4012)',
    evidenceSummary: 'High-confidence target misclassification (99.1% false class) triggered only when input contains subtle background watermark.',
    confidence: 94.1,
    status: 'Review',
    detectionMethod: 'Cross-Entropy Residual & Adversarial Robustness Probe',
    expectedValue: 'Prediction: MILITARY_TRUCK (0.91)',
    observedValue: 'Prediction: CIVILIAN_SEDAN (0.991) [Adversarial Flipping]',
    sha256Proof: 'c4979f6593ff45289cada52a471288e9a9182938471928471928374918237491',
    recommendedAction: 'Inspect upstream inference log lineage and verify camera feed sensor authenticity.',
    relatedNodeId: 'node-inference-batch',
  },
  {
    id: 'FND-00142',
    title: 'Extreme Out-of-Distribution (OOD) Samples',
    category: 'OOD',
    severity: 'WARNING',
    affectedArtifact: 'sample_29381.jpg to sample_29422.jpg (42 samples)',
    evidenceSummary: 'Embedding representation deviates by > 4.2 standard deviations from training manifold. Extreme weather / lens flare simulation artifact.',
    confidence: 91.4,
    status: 'Review',
    detectionMethod: 'Mahalanobis Latent Space Distance Metric',
    expectedValue: 'Mahalanobis Distance < 2.50 sigma',
    observedValue: 'Mahalanobis Distance = 4.38 sigma',
    sha256Proof: '85db8adc6fd74bc59d4339e02afd245591029384719283749182739481728394',
    recommendedAction: 'Flag for human forensic analyst review before incorporating into fine-tuning corpus.',
    relatedNodeId: 'node-dataset-batch',
  },
  {
    id: 'FND-00098',
    title: 'Near-Duplicate Flooding / Sybil Pattern',
    category: 'DUPLICATES',
    severity: 'WARNING',
    affectedArtifact: 'sample_04912.jpg to sample_05038.jpg (127 pairs)',
    evidenceSummary: '127 identical image frames with subtle 1% noise addition uploaded across different timestamps to artificially skew classification prior.',
    confidence: 99.8,
    status: 'Confirmed',
    detectionMethod: 'Perceptual Hashing (pHash) & Normalized Cross-Correlation',
    expectedValue: 'pHash Hamming Distance > 12',
    observedValue: 'pHash Hamming Distance <= 1 (Near Clone)',
    sha256Proof: 'd3cf1241d4f24733a6bba0bfb9034af791029384719283749182739481728394',
    recommendedAction: 'Deduplicate dataset archive and rebalance class weightings.',
  },
];

export const MOCK_FINDINGS = BENCHMARK_FINDINGS;

export const BENCHMARK_RECOMMENDATIONS: Recommendation[] = [
  {
    id: 'rec-1',
    priority: 'IMMEDIATE',
    title: 'Quarantine 18 Clean-Label Poisoned Samples',
    description: 'Samples in batch BATCH-2026-ALPHA exhibit confirmed clean-label backdoor triggers. Immediately isolate sample_18470.jpg through sample_18489.jpg to prevent poisoning propagation.',
    actionLabel: 'Execute Quarantine',
    actionType: 'quarantine',
  },
  {
    id: 'rec-2',
    priority: 'IMMEDIATE',
    title: 'Revert ONNX Model Layer conv2d_19 Weights',
    description: 'Hardware hash mismatch detected in conv2d_19 tensor parameters. Revert model checkpoint to certified golden baseline v1.2 and invalidate current weights.',
    actionLabel: 'Rollback Layer Weights',
    actionType: 'rollback',
  },
  {
    id: 'rec-3',
    priority: 'HIGH',
    title: 'Revoke Ingestion Token for Contributor EXT-DEV-09',
    description: 'All 18 poisoned samples and duplicate clusters originated from external contributor identity EXT-DEV-09. Revoke cryptographic submission keys and conduct lineage audit.',
    actionLabel: 'Revoke & Audit Lineage',
    actionType: 'revalidate',
  },
  {
    id: 'rec-4',
    priority: 'HIGH',
    title: 'Re-execute Cross-Validation on Clean Partition',
    description: 'Filter the 127 duplicate frames and 42 OOD outliers. Run the inference validation stage again to ensure target precision returns above the 95% zero-trust threshold.',
    actionLabel: 'Re-run Validation',
    actionType: 'revalidate',
  },
  {
    id: 'rec-5',
    priority: 'MEDIUM',
    title: 'Export Digitally Signed Forensic Audit Package',
    description: 'Package all SHA-256 proofs, evidence graph lineage, and telemetry logs into an immutable defense audit zip archive for compliance review.',
    actionLabel: 'Export Signed Package',
    actionType: 'export',
  },
];

export const MOCK_RECOMMENDATIONS = BENCHMARK_RECOMMENDATIONS;
