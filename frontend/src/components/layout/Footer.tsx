import React from 'react';
import { Lock, Cpu, Check } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer
      style={{
        backgroundColor: 'var(--surface-elevated)',
        borderTop: '1px solid var(--border)',
        padding: '0.75rem 2rem',
        marginTop: 'auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Lock size={13} style={{ color: 'var(--success-text)' }} />
          <span
            style={{
              fontSize: '0.6875rem',
              fontWeight: 700,
              color: 'var(--text-secondary)',
              letterSpacing: '0.04em',
            }}
            className="font-mono"
          >
            UNCLASSIFIED // DEFENSE ASSURANCE USE ONLY
          </span>
        </div>
        <span style={{ color: 'var(--border-strong)', fontSize: '0.75rem' }}>|</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
          <Check size={13} style={{ color: 'var(--success-text)' }} />
          <span
            style={{
              fontSize: '0.6875rem',
              color: 'var(--text-tertiary)',
            }}
            className="font-mono"
          >
            HASH CONTINUITY: CONTINUOUS MERKLE SEAL
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
          <Cpu size={13} style={{ color: 'var(--accent-text)' }} />
          <span
            style={{
              fontSize: '0.6875rem',
              color: 'var(--text-muted)',
            }}
            className="font-mono"
          >
            HARDWARE SHA-256 ACCELERATION ACTIVE
          </span>
        </div>
        <span style={{ color: 'var(--border-strong)', fontSize: '0.75rem' }}>|</span>
        <span
          style={{
            fontSize: '0.6875rem',
            color: 'var(--text-muted)',
          }}
          className="font-mono"
        >
          TRUST-CV v2.4 (OFFLINE SOC DEFENSE)
        </span>
      </div>
    </footer>
  );
};
