import React from 'react';
import { Network, Copy } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Modal } from '../ui/Modal';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

export const FindingDrawer: React.FC = () => {
  const { selectedFinding, setSelectedFinding, focusNodeInGraph } = useInvestigation();

  if (!selectedFinding) return null;

  const handleCopyHash = () => {
    navigator.clipboard.writeText(selectedFinding.sha256Proof);
  };

  const handleFocusGraph = () => {
    if (selectedFinding.relatedNodeId) {
      focusNodeInGraph(selectedFinding.relatedNodeId);
    }
    // Close modal to see graph
    setSelectedFinding(null);
    const graphSection = document.getElementById('evidence-graph-section');
    if (graphSection) {
      graphSection.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <Modal
      isOpen={Boolean(selectedFinding)}
      onClose={() => setSelectedFinding(null)}
      title={`Forensic Inspection: ${selectedFinding.id}`}
      subtitle={selectedFinding.title}
      maxWidth="780px"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Top Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', flexWrap: 'wrap' }}>
          <Badge
            variant={
              selectedFinding.severity === 'CRITICAL'
                ? 'critical'
                : selectedFinding.severity === 'HIGH'
                ? 'danger'
                : 'warning'
            }
            size="md"
          >
            {selectedFinding.severity}
          </Badge>
          <Badge variant="accent" size="md">
            {selectedFinding.category}
          </Badge>
          <Badge variant="default" size="md">
            Confidence: {selectedFinding.confidence}%
          </Badge>
          <Badge variant="default" size="md">
            Status: {selectedFinding.status}
          </Badge>
        </div>

        {/* Evidence Summary Box */}
        <div
          style={{
            backgroundColor: 'var(--surface-elevated)',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
            padding: '1rem 1.25rem',
          }}
        >
          <h4
            style={{
              fontSize: '0.8125rem',
              fontWeight: 700,
              color: 'var(--text-muted)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              margin: '0 0 0.5rem 0',
            }}
            className="font-mono"
          >
            Forensic Evidence Summary
          </h4>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-primary)', margin: 0, lineHeight: 1.5 }}>
            {selectedFinding.evidenceSummary}
          </p>
        </div>

        {/* Details Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '1rem',
          }}
        >
          <div
            style={{
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '0.375rem',
              padding: '0.875rem 1rem',
            }}
          >
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }} className="font-mono">
              AFFECTED ARTIFACT
            </span>
            <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.25rem' }} className="font-mono">
              {selectedFinding.affectedArtifact}
            </div>
          </div>

          <div
            style={{
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '0.375rem',
              padding: '0.875rem 1rem',
            }}
          >
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }} className="font-mono">
              DETECTION METHOD
            </span>
            <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.25rem' }} className="font-mono">
              {selectedFinding.detectionMethod}
            </div>
          </div>
        </div>

        {/* Value Comparison: Expected vs Observed */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '1rem',
          }}
        >
          <div
            style={{
              backgroundColor: 'var(--success-surface)',
              border: '1px solid var(--success-border)',
              borderRadius: '0.375rem',
              padding: '0.875rem 1rem',
            }}
          >
            <span style={{ fontSize: '0.6875rem', color: 'var(--success-text)', fontWeight: 600 }} className="font-mono">
              EXPECTED BASELINE VALUE
            </span>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', marginTop: '0.25rem' }} className="font-mono">
              {selectedFinding.expectedValue}
            </div>
          </div>

          <div
            style={{
              backgroundColor: 'var(--critical-surface)',
              border: '1px solid var(--critical-border)',
              borderRadius: '0.375rem',
              padding: '0.875rem 1rem',
            }}
          >
            <span style={{ fontSize: '0.6875rem', color: 'var(--critical-text)', fontWeight: 600 }} className="font-mono">
              OBSERVED ANOMALY VALUE
            </span>
            <div style={{ fontSize: '0.8125rem', color: 'var(--critical-text)', fontWeight: 600, marginTop: '0.25rem' }} className="font-mono">
              {selectedFinding.observedValue}
            </div>
          </div>
        </div>

        {/* Cryptographic SHA-256 Proof */}
        <div
          style={{
            backgroundColor: 'var(--surface-elevated)',
            border: '1px solid var(--border)',
            borderRadius: '0.375rem',
            padding: '0.875rem 1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }} className="font-mono">
              CRYPTOGRAPHIC EVIDENCE SHA-256 DIGEST
            </span>
            <button
              onClick={handleCopyHash}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--accent-text)',
                cursor: 'pointer',
                fontSize: '0.6875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
              }}
              className="font-mono"
            >
              <Copy size={11} /> COPY
            </button>
          </div>
          <div
            style={{
              fontSize: '0.75rem',
              color: 'var(--accent-text)',
              wordBreak: 'break-all',
              backgroundColor: 'var(--terminal-bg)',
              padding: '0.5rem 0.75rem',
              borderRadius: '0.25rem',
              border: '1px solid var(--border-subtle)',
            }}
            className="font-mono"
          >
            {selectedFinding.sha256Proof}
          </div>
        </div>

        {/* Actionable Recommendation */}
        <div
          style={{
            backgroundColor: 'var(--warning-surface)',
            border: '1px solid var(--warning-border)',
            borderRadius: '0.5rem',
            padding: '1rem 1.25rem',
          }}
        >
          <span style={{ fontSize: '0.6875rem', color: 'var(--warning-text)', fontWeight: 700 }} className="font-mono">
            RECOMMENDED FORENSIC MITIGATION
          </span>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-primary)', margin: '0.375rem 0 0 0', lineHeight: 1.5 }}>
            {selectedFinding.recommendedAction}
          </p>
        </div>

        {/* Actions Footer */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderTop: '1px solid var(--border)',
            paddingTop: '1rem',
            marginTop: '0.5rem',
          }}
        >
          <Button
            variant="outline"
            size="md"
            icon={<Network size={16} />}
            onClick={handleFocusGraph}
          >
            Focus in Evidence Graph
          </Button>

          <Button variant="secondary" size="md" onClick={() => setSelectedFinding(null)}>
            Close Inspection
          </Button>
        </div>
      </div>
    </Modal>
  );
};
