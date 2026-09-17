import React, { useState } from 'react';
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

export const EvidenceGraph: React.FC = () => {
  const {
    graphNodes,
    graphEdges,
    graphDigest,
    selectedGraphNode,
    setSelectedGraphNode,
  } = useInvestigation();

  const [activeFilter, setActiveFilter] = useState<'ALL' | 'ASSETS' | 'FINDINGS'>('ALL');

  // Filter nodes
  const filteredNodes = graphNodes.filter(node => {
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
        return <Users size={14} />;
      case 'DATASET_BATCH':
        return <Database size={14} />;
      case 'SAMPLE':
        return <FileImage size={14} />;
      case 'MODEL':
        return <Cpu size={14} />;
      case 'INFERENCE_RECORD':
        return <Activity size={14} />;
      case 'FINDING':
        return <ShieldAlert size={14} />;
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
        borderRadius: '0.625rem',
        padding: '1.5rem',
        boxShadow: 'var(--card-shadow)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      {/* Title & Graph Metadata */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '0.875rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Network size={18} style={{ color: 'var(--accent-text)' }} />
            <h3
              style={{
                fontSize: '1.125rem',
                fontWeight: 700,
                color: 'var(--text-primary)',
                letterSpacing: '0.04em',
                textTransform: 'uppercase',
                margin: 0,
              }}
              className="font-display"
            >
              Directed Evidence & Lineage Property Graph
            </h3>
            <Badge variant="accent" size="sm">
              CRYPTOGRAPHICALLY SEALED
            </Badge>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0.25rem 0 0 0' }}>
            Trace causal connections from external contributors and dataset batches to compromised neural weights and adversarial misclassifications.
          </p>
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {(['ALL', 'ASSETS', 'FINDINGS'] as const).map(f => (
            <button
              key={f}
              onClick={() => setActiveFilter(f)}
              style={{
                padding: '0.25rem 0.625rem',
                fontSize: '0.6875rem',
                fontWeight: activeFilter === f ? 600 : 500,
                border: '1px solid',
                borderColor: activeFilter === f ? 'var(--accent)' : 'var(--border)',
                backgroundColor: activeFilter === f ? 'var(--accent-surface)' : 'var(--surface-elevated)',
                color: activeFilter === f ? 'var(--accent-text)' : 'var(--text-secondary)',
                borderRadius: '0.25rem',
                cursor: 'pointer',
              }}
              className="font-mono"
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
          gap: '1rem',
          minHeight: '440px',
        }}
      >
        {/* SVG Canvas */}
        <div
          style={{
            backgroundColor: 'var(--terminal-bg)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '0.5rem',
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
            {graphEdges.map(edge => {
              const source = graphNodes.find(n => n.id === edge.sourceId);
              const target = graphNodes.find(n => n.id === edge.targetId);
              if (!source || !target) return null;

              const isConnected =
                connectedNodeIds.has(edge.sourceId) && connectedNodeIds.has(edge.targetId);
              const isCriticalEdge = source.status === 'critical' && target.status === 'critical';

              const strokeColor = isConnected
                ? isCriticalEdge
                  ? 'var(--critical)'
                  : 'var(--accent)'
                : 'var(--border-strong)';
              const strokeWidth = isConnected ? 2.5 : 1.2;
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
                    style={{ transition: 'all 0.2s ease' }}
                  />
                  {edge.label && (
                    <text
                      x={midX}
                      y={midY - 5}
                      fill="var(--text-muted)"
                      fontSize="9"
                      fontFamily="'JetBrains Mono', monospace"
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
                  style={{ cursor: 'pointer', opacity, transition: 'all 0.2s ease' }}
                >
                  {/* Outer selection ring */}
                  {isSelected && (
                    <circle
                      r="28"
                      fill="none"
                      stroke={color}
                      strokeWidth="2"
                      strokeDasharray="4 4"
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    r="20"
                    fill={bg}
                    stroke={color}
                    strokeWidth={isSelected ? 3 : 2}
                  />

                  {/* Center Node Icon Dot */}
                  <circle r="5" fill={color} />

                  {/* Node Label Text */}
                  <text
                    y="34"
                    fill="var(--text-primary)"
                    fontSize="11"
                    fontFamily="'JetBrains Mono', monospace"
                    fontWeight="600"
                    textAnchor="middle"
                  >
                    {node.label}
                  </text>
                  {node.subLabel && (
                    <text
                      y="46"
                      fill="var(--text-muted)"
                      fontSize="9"
                      fontFamily="'Inter', sans-serif"
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
              fontSize: '0.6875rem',
              color: 'var(--text-muted)',
              pointerEvents: 'none',
            }}
            className="font-mono"
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
              borderRadius: '0.5rem',
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              animation: 'modal-appear 0.2s ease',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
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
                    fontSize: '0.75rem',
                  }}
                  className="font-mono"
                >
                  CLEAR
                </button>
              </div>

              <h4
                style={{
                  fontSize: '1rem',
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  margin: '0 0 0.25rem 0',
                }}
                className="font-mono"
              >
                {selectedGraphNode.label}
              </h4>

              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0 0 1rem 0' }}>
                {selectedGraphNode.subLabel}
              </p>

              {/* Properties list */}
              <div
                style={{
                  backgroundColor: 'var(--surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '0.375rem',
                  padding: '0.75rem',
                  fontSize: '0.75rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem',
                }}
                className="font-mono"
              >
                {Object.entries(selectedGraphNode.properties).map(([k, v]) => (
                  <div key={k}>
                    <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.625rem' }}>
                      {k}:
                    </span>
                    <div style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {String(v)}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ marginTop: '1rem' }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }} className="font-mono">
                BLAST RADIUS TRAVERSAL: {connectedNodeIds.size - 1} LINKED ENTITIES
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
          padding: '0.625rem 1rem',
          backgroundColor: 'var(--surface-elevated)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '0.375rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
          fontSize: '0.6875rem',
        }}
        className="font-mono"
      >
        <span style={{ color: 'var(--text-muted)' }}>
          CANONICAL EVIDENCE GRAPH DIGEST (SHA-256):
        </span>
        <span style={{ color: 'var(--accent-text)', fontWeight: 600 }}>{graphDigest}</span>
      </div>
    </div>
  );
};
