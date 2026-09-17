import type { GraphNode, GraphEdge } from '../types/graph';

export const MOCK_GRAPH_NODES: GraphNode[] = [
  // 1. Contributor (Top Left)
  {
    id: 'node-contrib-09',
    nodeType: 'CONTRIBUTOR',
    label: 'Contributor EXT-DEV-09',
    subLabel: 'External Defense Vendor',
    status: 'critical',
    properties: {
      contributorId: 'EXT-DEV-09',
      riskScore: 0.88,
      status: 'QUARANTINE_RECOMMENDED',
      totalBatches: 6,
      flaggedCount: 18,
      details: 'Author of batch BATCH-2026-ALPHA containing 18 poisoned visual samples.',
    },
    x: 80,
    y: 120,
  },

  // 2. Dataset Batch
  {
    id: 'node-dataset-batch',
    nodeType: 'DATASET_BATCH',
    label: 'Batch 2026-ALPHA',
    subLabel: 'Surveillance Dataset v4',
    status: 'critical',
    properties: {
      batchId: 'BATCH-2026-ALPHA',
      sampleCount: 0,
      sha256: '91a74e5c829e1f...8f21',
      format: 'COCO / ImageFolder',
      details: 'Ingested on 2026-09-02 from air-gapped staging server.',
    },
    x: 260,
    y: 120,
  },

  // 3. Clean Sample Baseline (Top branch)
  {
    id: 'node-sample-clean',
    nodeType: 'SAMPLE',
    label: 'Sample #04910',
    subLabel: 'Clean Baseline (Truck)',
    status: 'normal',
    properties: {
      sampleId: 'sample_04910.jpg',
      confidence: 0.994,
      spectralAnomaly: 0.02,
      sha256: '3a41b89...112e',
      details: 'Normal cluster member matching baseline distribution.',
    },
    x: 440,
    y: 50,
  },

  // 4. Poisoned Sample (Middle branch)
  {
    id: 'node-sample-18472',
    nodeType: 'SAMPLE',
    label: 'Sample #18472',
    subLabel: 'Poisoned Watermark',
    status: 'critical',
    properties: {
      sampleId: 'sample_18472.jpg',
      confidence: 0.982,
      spectralAnomaly: 0.892,
      sha256: 'e82109f...2734',
      details: 'Clean-label attack with subtle checkerboard watermark in lower quadrant.',
    },
    x: 440,
    y: 180,
  },

  // 5. Target Model
  {
    id: 'node-model-yolo',
    nodeType: 'MODEL',
    label: 'recon_yolo_v8n.onnx',
    subLabel: 'ONNX 24-Layer Network',
    status: 'critical',
    properties: {
      modelName: 'recon_yolo_v8n.onnx',
      framework: 'ONNX Runtime v1.18',
      paramCount: '3.2M parameters',
      sha256: '7f2c81a...4d90',
      details: 'Trained on surveillance corpus. Layer conv2d_19 parameter tensor mismatch.',
    },
    x: 640,
    y: 120,
  },

  // 6. Model Layer
  {
    id: 'node-layer-19',
    nodeType: 'MODEL',
    label: 'Layer conv2d_19',
    subLabel: 'Tampered Weights',
    status: 'critical',
    properties: {
      layerName: 'conv2d_19',
      weightsHash: 'f56aafa...8394',
      expectedHash: 'a0c0473...7283',
      deviation: 'Weight divergence detected',
      details: 'Weights deviate by 3.4% from certified golden checkpoint.',
    },
    x: 640,
    y: 260,
  },

  // 7. Inference Output Record
  {
    id: 'node-inference-batch',
    nodeType: 'INFERENCE_RECORD',
    label: 'Inference Log #4012',
    subLabel: 'Adversarial Misclassification',
    status: 'warning',
    properties: {
      inferenceId: 'inf_record_4012',
      predictedClass: 'CIVILIAN_SEDAN (99.1%)',
      groundTruth: 'MILITARY_TRUCK',
      residualScore: 0.941,
      details: 'Adversarial target evasion triggered by Alpha-9 backdoor activation.',
    },
    x: 840,
    y: 120,
  },

  // 8. Finding 182: Poisoning
  {
    id: 'node-fnd-182',
    nodeType: 'FINDING',
    label: 'Finding FND-00182',
    subLabel: 'CRITICAL Data Poisoning',
    status: 'critical',
    properties: {
      findingId: 'FND-00182',
      severity: 'CRITICAL',
      confidence: 0.982,
      method: 'Spectral Signature',
      details: '18 samples confirmed with trigger-like spatial pattern.',
    },
    x: 440,
    y: 310,
  },

  // 9. Finding 204: Model Tampering
  {
    id: 'node-fnd-204',
    nodeType: 'FINDING',
    label: 'Finding FND-00204',
    subLabel: 'CRITICAL Weight Tampering',
    status: 'critical',
    properties: {
      findingId: 'FND-00204',
      severity: 'CRITICAL',
      confidence: 1.0,
      method: 'Hardware Hash Verification',
      details: 'Layer conv2d_19 hash fails baseline check.',
    },
    x: 840,
    y: 260,
  },

  // 10. Finding 215: Inference Deviation
  {
    id: 'node-fnd-215',
    nodeType: 'FINDING',
    label: 'Finding FND-00215',
    subLabel: 'HIGH Inference Deviation',
    status: 'warning',
    properties: {
      findingId: 'FND-00215',
      severity: 'HIGH',
      confidence: 0.941,
      method: 'Cross-Entropy Residuals',
      details: 'Adversarial evasion triggered in test batch.',
    },
    x: 1020,
    y: 120,
  },
];

export const MOCK_GRAPH_EDGES: GraphEdge[] = [
  // Contributor authored Dataset Batch
  { id: 'edge-1', sourceId: 'node-contrib-09', targetId: 'node-dataset-batch', edgeType: 'AUTHORED_BY', label: 'Authored' },
  // Batch contains clean sample
  { id: 'edge-2', sourceId: 'node-dataset-batch', targetId: 'node-sample-clean', edgeType: 'CONTAINS_SAMPLE', label: 'Contains' },
  // Batch contains poisoned sample
  { id: 'edge-3', sourceId: 'node-dataset-batch', targetId: 'node-sample-18472', edgeType: 'CONTAINS_SAMPLE', label: 'Contains' },
  // Model trained on Dataset Batch
  { id: 'edge-4', sourceId: 'node-dataset-batch', targetId: 'node-model-yolo', edgeType: 'TRAINED_ON', label: 'Trained On' },
  // Model has layer 19
  { id: 'edge-5', sourceId: 'node-model-yolo', targetId: 'node-layer-19', edgeType: 'CONTAINS_SAMPLE', label: 'Layer' },
  // Model generated Inference record
  { id: 'edge-6', sourceId: 'node-model-yolo', targetId: 'node-inference-batch', edgeType: 'GENERATED_BY', label: 'Inferred' },
  // Poisoned sample flagged with Finding 182
  { id: 'edge-7', sourceId: 'node-sample-18472', targetId: 'node-fnd-182', edgeType: 'FLAGGED_WITH', label: 'Triggers' },
  // Layer 19 flagged with Finding 204
  { id: 'edge-8', sourceId: 'node-layer-19', targetId: 'node-fnd-204', edgeType: 'FLAGGED_WITH', label: 'Violates' },
  // Inference record flagged with Finding 215
  { id: 'edge-9', sourceId: 'node-inference-batch', targetId: 'node-fnd-215', edgeType: 'FLAGGED_WITH', label: 'Flagged With' },
  // Poisoning causes Inference anomaly
  { id: 'edge-10', sourceId: 'node-sample-18472', targetId: 'node-inference-batch', edgeType: 'FLAGGED_WITH', label: 'Evaded In' },
];

export const GRAPH_CANONICAL_DIGEST = '84a9e2182049bf9283749102837491028374910293847192837491823749f721';

/**
 * Dynamically generate real lineage graph nodes and edges for the investigated artifact.
 */
export function generateLineageGraph(
  fileName: string = 'sample_frame.jpg',
  hash: string = '',
  isClean: boolean = true
): { nodes: GraphNode[]; edges: GraphEdge[]; digest: string } {
  const shortHash = hash ? hash.substring(0, 12) + '...' + hash.substring(hash.length - 6) : 'e821...9b04';

  if (isClean) {
    const nodes: GraphNode[] = [
      {
        id: 'node-operator',
        nodeType: 'CONTRIBUTOR',
        label: 'Defense Air-Gap Console',
        subLabel: 'Forensic Workstation (Verified Operator)',
        status: 'normal',
        properties: {
          operatorId: 'DEF-SEC-OPS-01',
          clearance: 'TOP-SECRET-FORENSIC',
          status: 'VERIFIED',
          ingestionMode: 'AIR_GAPPED_SANDBOX',
        },
        x: 120,
        y: 180,
      },
      {
        id: 'node-asset',
        nodeType: 'SAMPLE',
        label: fileName || 'Target Frame',
        subLabel: `SHA-256: ${shortHash}`,
        status: 'normal',
        properties: {
          filename: fileName || 'Target Frame',
          sha256: hash || 'Verified Cryptographic Hash',
          status: 'VERIFIED_CLEAN',
          verification: 'Hardware Digest Matches Leaf Hash',
        },
        x: 420,
        y: 180,
      },
      {
        id: 'node-baseline-model',
        nodeType: 'MODEL',
        label: 'YOLOv8-Tactical FP16',
        subLabel: 'Defense Golden Baseline v1.2',
        status: 'normal',
        properties: {
          modelId: 'recon_yolov8n_baseline',
          layers: 24,
          parameterHash: 'a0c04734095c4beb826aee02cb6bf50c82910293847192837491827394817283',
          status: 'BASELINE_VERIFIED',
        },
        x: 720,
        y: 120,
      },
      {
        id: 'node-assurance-engine',
        nodeType: 'INFERENCE_RECORD',
        label: 'Zero-Trust Kernel Seal',
        subLabel: 'Assurance Verdict: ACCEPTED',
        status: 'normal',
        properties: {
          trustScore: '100/100',
          verdict: 'ACCEPTED',
          integrityAssertions: '11/11 PASSED',
          tamperCheck: '0 Anomalies Detected',
        },
        x: 980,
        y: 180,
      },
    ];

    const edges: GraphEdge[] = [
      {
        id: 'edge-ingest',
        sourceId: 'node-operator',
        targetId: 'node-asset',
        edgeType: 'AUTHORED_BY',
        label: 'Ingested By',
      },
      {
        id: 'edge-model-eval',
        sourceId: 'node-asset',
        targetId: 'node-baseline-model',
        edgeType: 'TRAINED_ON',
        label: 'Evaluated On',
      },
      {
        id: 'edge-verified-seal',
        sourceId: 'node-baseline-model',
        targetId: 'node-assurance-engine',
        edgeType: 'GENERATED_BY',
        label: 'Audited By',
      },
      {
        id: 'edge-direct-seal',
        sourceId: 'node-asset',
        targetId: 'node-assurance-engine',
        edgeType: 'FLAGGED_WITH',
        label: 'Certified Clean',
      },
    ];

    return {
      nodes,
      edges,
      digest: hash || '57501e5c6808b3e14852a4ea21dc7873abf9409032a06f9b740c973e83f62cf7',
    };
  }

  return {
    nodes: MOCK_GRAPH_NODES,
    edges: MOCK_GRAPH_EDGES,
    digest: GRAPH_CANONICAL_DIGEST,
  };
}
