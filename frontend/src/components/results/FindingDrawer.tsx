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
              fontSize: '12px',
              fontWeight: 500,
              color: 'var(--text-muted)',
              letterSpacing: '0.02em',
              margin: '0 0 8px 0',
            }}
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
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
              Affected artifact
            </span>
            <div style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)', marginTop: '4px' }} className="font-mono">
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
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
              Detection method
            </span>
            <div style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)', marginTop: '4px' }} className="font-mono">
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
            <span style={{ fontSize: '11px', color: 'var(--success-text)', fontWeight: 500 }}>
              Expected baseline value
            </span>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', marginTop: '4px' }} className="font-mono">
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
            <span style={{ fontSize: '11px', color: 'var(--critical-text)', fontWeight: 500 }}>
              Observed anomaly value
            </span>
            <div style={{ fontSize: '0.8125rem', color: 'var(--critical-text)', fontWeight: 500, marginTop: '4px' }} className="font-mono">
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
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
              Cryptographic evidence SHA-256 digest
            </span>
            <button
              onClick={handleCopyHash}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--accent-text)',
                cursor: 'pointer',
                fontSize: '11px',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <Copy size={11} strokeWidth={1.5} /> Copy
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
          <span style={{ fontSize: '11px', color: 'var(--warning-text)', fontWeight: 500 }}>
            Recommended forensic mitigation
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
