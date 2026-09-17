export type NodeType =
  | 'CONTRIBUTOR'
  | 'DATASET_BATCH'
  | 'SAMPLE'
  | 'MODEL'
  | 'INFERENCE_RECORD'
  | 'FINDING';

export type EdgeType =
  | 'AUTHORED_BY'
  | 'CONTAINS_SAMPLE'
  | 'TRAINED_ON'
  | 'GENERATED_BY'
  | 'FLAGGED_WITH';

export interface GraphNode {
  id: string;
  nodeType: NodeType;
  label: string;
  subLabel?: string;
  status: 'normal' | 'warning' | 'critical';
  properties: {
    hash?: string;
    contributorId?: string;
    confidence?: number;
    severity?: string;
    details?: string;
    [key: string]: any;
  };
  x: number;
  y: number;
}

export interface GraphEdge {
  id: string;
  sourceId: string;
  targetId: string;
  edgeType: EdgeType;
  label?: string;
}

export interface LineageTrace {
  targetId: string;
  upstreamIds: string[];
  downstreamIds: string[];
  findingIds: string[];
  blastRadiusCount: number;
}
