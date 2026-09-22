import React from 'react';
import { AlertOctagon } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';

/**
 * Surfaces backend/API failures to the operator.
 * Backend problems must never be hidden behind success UI.
 */
export const BackendErrorBanner: React.FC = () => {
  const { backendError } = useInvestigation();
  if (!backendError) return null;

  return (
    <div
      role="alert"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.75rem',
        backgroundColor: 'var(--critical-surface)',
        border: '1px solid var(--critical-border)',
        borderRadius: '0.625rem',
        padding: '1rem 1.25rem',
      }}
    >
      <AlertOctagon size={18} strokeWidth={1.5} style={{ color: 'var(--critical-text)', flexShrink: 0, marginTop: '2px' }} />
      <div>
        <div
          style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--critical-text)' }}
        >
          Backend reported an error
        </div>
        <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.25rem', lineHeight: 1.5 }}>
          {backendError}
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
          Results shown above reflect only what the backend actually returned. Unavailable stages remain
          marked UNAVAILABLE and are not treated as passed.
        </div>
      </div>
    </div>
  );
};
