import React, { useMemo, useState } from 'react';
import {
  Network,
  Users,
  Database,
  FileImage,
  Cpu,
  Activity,
  ShieldAlert,
} from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { GraphNode, NodeType } from '../../types/graph';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

const GRAPH_W = 1140;
const GRAPH_H = 400;

function edgeWeight(edgeType: string): number {
  const t = String(edgeType || '').toUpperCase();
  if (t.includes('TRAINED') || t.includes('GENERATED') || t.includes('SIGNED') || t.includes('SEAL')) return 1.45;
  if (t.includes('CONTAIN') || t.includes('AUTHORED') || t.includes('PROVIDED')) return 1.15;
  if (t.includes('FLAG') || t.includes('QUARANTINE') || t.includes('VETO')) return 0.55;
  return 0.9;
}

function typeColumn(nodeType: string): number {
  const t = String(nodeType || '').toUpperCase();
  if (t.includes('CONTRIBUTOR')) return GRAPH_W * 0.08;
  if (t.includes('DATASET') || t.includes('SAMPLE') || t.includes('BATCH')) return GRAPH_W * 0.26;
  if (t.includes('MODEL') || t.includes('WEIGHT')) return GRAPH_W * 0.46;
  if (t.includes('INFER')) return GRAPH_W * 0.66;
  if (t.includes('FINDING') || t.includes('EVIDENCE') || t.includes('FUSION')) return GRAPH_W * 0.86;
  return GRAPH_W * 0.5;
}

/** Force-directed layout so nodes never share a single origin or type slot. */
function layoutGraph(rawNodes: GraphNode[], edges: { sourceId: string; targetId: string; edgeType?: string }[]): GraphNode[] {
  const seen = new Set<string>();
  const nodes = rawNodes.filter(n => {
    if (!n?.id || seen.has(n.id)) return false;
    seen.add(n.id);
    return true;
  }).map((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, rawNodes.length);
    const r = 120;
    return {
      ...n,
      x: n.x && n.y ? n.x : GRAPH_W / 2 + r * Math.cos(angle),
      y: n.x && n.y ? n.y : GRAPH_H / 2 + r * Math.sin(angle),
      vx: 0,
      vy: 0,
    };
  });

  const byCol: Record<number, typeof nodes> = {};
  nodes.forEach(n => {
    const col = Math.round(typeColumn(n.nodeType));
    (byCol[col] || (byCol[col] = [])).push(n);
  });
  Object.entries(byCol).forEach(([col, list]) => {
    const spacing = Math.min(80, (GRAPH_H - 80) / Math.max(1, list.length));
    const startY = (GRAPH_H - (list.length - 1) * spacing) / 2;
    list.forEach((n, i) => {
      n.x = Number(col);
      n.y = startY + i * spacing;
    });
  });

  const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
  const links = edges
    .map(e => ({ source: byId[e.sourceId], target: byId[e.targetId], weight: edgeWeight(e.edgeType || '') }))
    .filter(l => l.source && l.target && l.source !== l.target);

  let alpha = 1;
  for (let tick = 0; tick < 300; tick++) {
    alpha *= 0.98;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        let dx = nodes[i].x - nodes[j].x;
        let dy = nodes[i].y - nodes[j].y;
        let dist2 = dx * dx + dy * dy;
        if (dist2 < 1) { dist2 = 1; dx = 0.5; dy = 0.5; }
        const dist = Math.sqrt(dist2);
        const force = (-180 * alpha) / dist2;
        nodes[i].vx += (dx / dist) * force;
        nodes[i].vy += (dy / dist) * force;
        nodes[j].vx -= (dx / dist) * force;
        nodes[j].vy -= (dy / dist) * force;
        if (dist < 48) {
          const push = (48 - dist) * 0.08 * alpha;
          nodes[i].vx += (dx / dist) * push;
          nodes[i].vy += (dy / dist) * push;
          nodes[j].vx -= (dx / dist) * push;
          nodes[j].vy -= (dy / dist) * push;
        }
      }
    }
    links.forEach(l => {
      const dx = l.target.x - l.source.x;
      const dy = l.target.y - l.source.y;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const desired = 110 / l.weight;
      const k = ((dist - desired) / dist) * 0.06 * alpha * l.weight;
      l.source.vx += dx * k;
      l.source.vy += dy * k;
      l.target.vx -= dx * k;
      l.target.vy -= dy * k;
    });
    nodes.forEach(n => {
      n.vx += (GRAPH_W / 2 - n.x) * 0.004 * alpha;
      n.vy += (GRAPH_H / 2 - n.y) * 0.008 * alpha;
      n.vx *= 0.85;
      n.vy *= 0.85;
      n.x = Math.max(40, Math.min(GRAPH_W - 40, n.x + n.vx));
      n.y = Math.max(40, Math.min(GRAPH_H - 40, n.y + n.vy));
    });
  }

  if (typeof console !== 'undefined' && console.debug) {
    console.debug('[TRUST-CV graph]', {
      nodes: nodes.length,
      edges: edges.length,
      positions: nodes.map(n => ({ id: n.id, x: Math.round(n.x), y: Math.round(n.y) })),
    });
  }

  return nodes.map(({ vx: _vx, vy: _vy, ...n }) => n as GraphNode);
}

export const EvidenceGraph: React.FC = () => {
  const {
    graphNodes,
    graphEdges,
    graphDigest,
    selectedGraphNode,
    setSelectedGraphNode,
  } = useInvestigation();

  const [activeFilter, setActiveFilter] = useState<'ALL' | 'ASSETS' | 'FINDINGS'>('ALL');

  const laidOutNodes = useMemo(
    () => layoutGraph(graphNodes as GraphNode[], graphEdges),
    [graphNodes, graphEdges],
  );

  // Filter nodes
  const filteredNodes = laidOutNodes.filter(node => {
    if (activeFilter === 'ALL') return true;
    if (activeFilter === 'FINDINGS') return node.nodeType === 'FINDING';
    if (activeFilter === 'ASSETS') return node.nodeType !== 'FINDING';
    return true;
  });

  // Calculate connected node IDs if a node is selected (Blast radius)
  const connectedNodeIds = new Set<string>();
  if (selectedGraphNode) {
    connectedNodeIds.add(selectedGraphNode.id);
    graphEdges.forEach(edge => {
      if (edge.sourceId === selectedGraphNode.id) connectedNodeIds.add(edge.targetId);
      if (edge.targetId === selectedGraphNode.id) connectedNodeIds.add(edge.sourceId);
    });
  }

  const getNodeIcon = (nodeType: NodeType) => {
    switch (nodeType) {
      case 'CONTRIBUTOR':
        return <Users size={14} strokeWidth={1.5} />;
      case 'DATASET_BATCH':
        return <Database size={14} strokeWidth={1.5} />;
      case 'SAMPLE':
        return <FileImage size={14} strokeWidth={1.5} />;
      case 'MODEL':
        return <Cpu size={14} strokeWidth={1.5} />;
      case 'INFERENCE_RECORD':
        return <Activity size={14} strokeWidth={1.5} />;
      case 'FINDING':
        return <ShieldAlert size={14} strokeWidth={1.5} />;
    }
  };

  const getNodeColor = (node: GraphNode) => {
    if (node.status === 'critical') return 'var(--critical)';
    if (node.status === 'warning') return 'var(--warning)';
    return 'var(--accent)';
  };

  const getNodeBg = (node: GraphNode) => {
    if (node.status === 'critical') return 'var(--critical-surface)';
    if (node.status === 'warning') return 'var(--warning-surface)';
    return 'var(--accent-surface)';
  };

  return (
    <div
      id="evidence-graph-section"
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
      }}
    >
      {/* Title & Graph Metadata */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Network size={16} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />
            <h3
              style={{
                fontSize: '16px',
                fontWeight: 600,
                color: 'var(--text-primary)',
                letterSpacing: '-0.01em',
                margin: 0,
              }}
            >
              Directed Evidence & Lineage Property Graph
            </h3>
            <Badge
              variant={graphDigest ? 'success' : 'warning'}
              size="sm"
            >
              {graphDigest ? 'Graph sealed' : 'Graph unavailable'}
            </Badge>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
            Trace causal connections from external contributors and dataset batches to compromised neural weights and adversarial misclassifications.
          </p>
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {(['ALL', 'ASSETS', 'FINDINGS'] as const).map(f => (
            <button
              key={f}
              onClick={() => setActiveFilter(f)}
              style={{
                padding: '0.25rem 0.625rem',
                fontSize: '11px',
                fontWeight: activeFilter === f ? 500 : 400,
                border: '1px solid',
                borderColor: activeFilter === f ? 'var(--accent-border)' : 'var(--border)',
                backgroundColor: activeFilter === f ? 'var(--accent-surface)' : 'transparent',
                color: activeFilter === f ? 'var(--accent-text)' : 'var(--text-secondary)',
                borderRadius: '0.25rem',
                cursor: 'pointer',
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Main Interactive Graph Area */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: selectedGraphNode ? '1fr 300px' : '1fr',
          gap: '16px',
          minHeight: '440px',
        }}
      >
        {/* SVG Canvas */}
        <div
          style={{
            backgroundColor: 'var(--terminal-bg)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          <svg
            viewBox="0 0 1140 400"
            style={{
              width: '100%',
              height: '100%',
              minHeight: '420px',
            }}
          >
            <defs>
              {/* Arrow markers */}
              <marker id="arrow-normal" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--border-strong)" />
              </marker>
              <marker id="arrow-active" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent)" />
              </marker>
              <marker id="arrow-critical" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--critical)" />
              </marker>
            </defs>

            {/* Render Edges */}
            {graphEdges.length === 0 && (
              <text
                x="570"
                y="200"
                textAnchor="middle"
                style={{ fill: 'var(--text-muted)', fontSize: '13px' }}
              >
                No backend evidence graph data — relationships are not reconstructed client-side.
              </text>
            )}

            {graphEdges.map(edge => {
              const source = laidOutNodes.find(n => n.id === edge.sourceId);
              const target = laidOutNodes.find(n => n.id === edge.targetId);
              if (!source || !target) return null;

              const isConnected =
                connectedNodeIds.has(edge.sourceId) && connectedNodeIds.has(edge.targetId);
              const isCriticalEdge = source.status === 'critical' && target.status === 'critical';

              const strokeColor = isConnected
                ? isCriticalEdge
                  ? 'var(--critical)'
                  : 'var(--accent)'
                : 'var(--border-strong)';
              const strokeWidth = isConnected ? 2 : 1.2;
              const markerId = isConnected
                ? isCriticalEdge
                  ? 'url(#arrow-critical)'
                  : 'url(#arrow-active)'
                : 'url(#arrow-normal)';

              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;

              return (
                <g key={edge.id}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    markerEnd={markerId}
                    strokeDasharray={isConnected ? 'none' : '3 3'}
                    opacity={selectedGraphNode ? (isConnected ? 1 : 0.25) : 0.75}
                    style={{ transition: 'opacity 0.2s ease' }}
                  />
                  {edge.label && (
                    <text
                      x={midX}
                      y={midY - 5}
                      fill="var(--text-muted)"
                      fontSize="9"
                      fontFamily="Inter, sans-serif"
                      textAnchor="middle"
                      opacity={selectedGraphNode ? (isConnected ? 1 : 0.2) : 0.6}
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Render Nodes */}
            {filteredNodes.map(node => {
              const isSelected = selectedGraphNode?.id === node.id;
              const isConnected = connectedNodeIds.has(node.id);
              const color = getNodeColor(node);
              const bg = getNodeBg(node);
              const opacity = selectedGraphNode ? (isConnected ? 1 : 0.3) : 1;

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setSelectedGraphNode(node)}
                  style={{ cursor: 'pointer', opacity, transition: 'opacity 0.2s ease' }}
                >
                  {/* Outer selection ring */}
                  {isSelected && (
                    <circle
                      r="28"
                      fill="none"
                      stroke={color}
                      strokeWidth="1.5"
                      strokeDasharray="4 4"
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    r="20"
                    fill={bg}
                    stroke={color}
                    strokeWidth={isSelected ? 2 : 1.5}
                  />

                  {/* Center Node Icon Dot */}
                  <circle r="5" fill={color} opacity="0.85" />

                  {/* Node Label Text */}
                  <text
                    y="34"
                    fill="var(--text-primary)"
                    fontSize="11"
                    fontFamily="Inter, sans-serif"
                    fontWeight="500"
                    textAnchor="middle"
                  >
                    {node.label}
                  </text>
                  {node.subLabel && (
                    <text
                      y="46"
                      fill="var(--text-muted)"
                      fontSize="9"
                      fontFamily="Inter, sans-serif"
                      textAnchor="middle"
                    >
                      {node.subLabel}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>

          {/* Quick instructions in canvas */}
          <div
            style={{
              position: 'absolute',
              bottom: '10px',
              left: '12px',
              fontSize: '11px',
              color: 'var(--text-muted)',
              pointerEvents: 'none',
            }}
          >
            Click any node to trace blast radius and inspect provenance metadata.
          </div>
        </div>

        {/* Selected Node Details Drawer */}
        {selectedGraphNode && (
          <div
            style={{
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                <Badge
                  variant={
                    selectedGraphNode.status === 'critical'
                      ? 'critical'
                      : selectedGraphNode.status === 'warning'
                      ? 'warning'
                      : 'accent'
                  }
                  size="sm"
                  icon={getNodeIcon(selectedGraphNode.nodeType)}
                >
                  {selectedGraphNode.nodeType}
                </Badge>
                <button
                  onClick={() => setSelectedGraphNode(null)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    fontSize: '12px',
                  }}
                >
                  Clear
                </button>
              </div>

              <h4
                style={{
                  fontSize: '0.9375rem',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  margin: '0 0 4px 0',
                }}
              >
                {selectedGraphNode.label}
              </h4>

              <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '0 0 16px 0' }}>
                {selectedGraphNode.subLabel}
              </p>

              {/* Properties list */}
              <div
                style={{
                  backgroundColor: 'var(--surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '0.375rem',
                  padding: '12px',
                  fontSize: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                {Object.entries(selectedGraphNode.properties).map(([k, v]) => (
                  <div key={k}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                      {k}:
                    </span>
                    <div className="font-mono" style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {String(v)}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ marginTop: '16px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                Blast radius traversal: {connectedNodeIds.size - 1} linked entities
              </div>
              <Button
                variant="outline"
                size="sm"
                style={{ width: '100%' }}
                onClick={() => setSelectedGraphNode(null)}
              >
                Reset Graph Focus
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Merkle Root Banner */}
      <div
        style={{
          padding: '12px 16px',
          backgroundColor: 'var(--surface-elevated)',
          border: '1px solid var(--border)',
          borderRadius: '0.375rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          fontSize: '12px',
        }}
      >
        <span style={{ color: 'var(--text-muted)' }}>
          Canonical evidence graph digest (SHA-256):
        </span>
        <span className="font-mono" style={{ color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{graphDigest}</span>
      </div>
    </div>
  );
};
