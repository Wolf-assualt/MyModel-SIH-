import React from 'react';
import { FileInput, Cpu, MonitorUp, KeyRound, Hash } from 'lucide-react';

const NODES: Array<{ label: string; icon: React.ReactNode }> = [
  { label: 'Input', icon: <FileInput size={11} /> },
  { label: 'Model', icon: <Cpu size={11} /> },
  { label: 'Output', icon: <MonitorUp size={11} /> },
  { label: 'Nonce', icon: <KeyRound size={11} /> },
  { label: 'SeqID', icon: <Hash size={11} /> },
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
        marginTop: '0.625rem',
        padding: '0.625rem 0.75rem',
        backgroundColor: 'var(--surface-elevated)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '0.375rem',
      }}
    >
      <div
        className="font-mono"
        style={{
          fontSize: '0.5625rem',
          color: 'var(--text-muted)',
          letterSpacing: '0.1em',
          marginBottom: '0.5rem',
        }}
      >
        PROVENANCE CHAIN — SIGNED LINEAGE
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
