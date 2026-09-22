import React from 'react';
import { FileInput, Cpu, MonitorUp, KeyRound, Hash } from 'lucide-react';

const NODES: Array<{ label: string; icon: React.ReactNode }> = [
  { label: 'Input', icon: <FileInput size={11} strokeWidth={1.5} /> },
  { label: 'Model', icon: <Cpu size={11} strokeWidth={1.5} /> },
  { label: 'Output', icon: <MonitorUp size={11} strokeWidth={1.5} /> },
  { label: 'Nonce', icon: <KeyRound size={11} strokeWidth={1.5} /> },
  { label: 'SeqID', icon: <Hash size={11} strokeWidth={1.5} /> },
];

/**
 * Compact provenance-chain visual for the Cryptographic Manifest card.
 * Renders the signed artifact's lineage as connected nodes:
 * Input → Model → Output → Nonce → SeqID.
 */
export const ProvenanceChain: React.FC = () => {
  return (
    <div
      style={{
        marginTop: '12px',
        padding: '12px',
        backgroundColor: 'var(--surface-elevated)',
        border: '1px solid var(--border)',
        borderRadius: '0.375rem',
      }}
    >
      <div
        style={{
          fontSize: '11px',
          fontWeight: 500,
          color: 'var(--text-muted)',
          letterSpacing: '0.02em',
          marginBottom: '8px',
        }}
      >
        Provenance chain — signed lineage
      </div>
      <div className="provenance-chain">
        {NODES.map((node, i) => (
          <React.Fragment key={node.label}>
            {i > 0 && <span className="provenance-link" aria-hidden="true" />}
            <span className="provenance-node" title={`Provenance stage: ${node.label}`}>
              {node.icon}
              {node.label}
            </span>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
