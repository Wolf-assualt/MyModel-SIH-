import React from 'react';
import { Wifi, WifiOff } from 'lucide-react';

interface BackendStatusProps {
  online: boolean;
  compact?: boolean;
}

/**
 * BackendStatus chip — shows whether the FastAPI backend is reachable.
 * Displays a pulsing green dot (LIVE BACKEND) or a static orange dot (AIR-GAPPED MODE).
 */
export const BackendStatus: React.FC<BackendStatusProps> = ({ online, compact = false }) => {
  return (
    <div
      role="status"
      aria-label={online ? 'Backend server connected' : 'Air-gapped offline mode'}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        padding: compact ? '0.25rem 0.5rem' : '0.375rem 0.75rem',
        backgroundColor: 'var(--surface-elevated)',
        border: `1px solid ${online ? 'var(--success-border)' : 'var(--border)'}`,
        borderRadius: '0.375rem',
        transition: 'border-color 0.3s ease',
      }}
    >
      {/* Pulsing status dot */}
      <span
        style={{
          position: 'relative',
          display: 'inline-flex',
          width: '8px',
          height: '8px',
          flexShrink: 0,
        }}
      >
        {online && (
          <span
            className="pulse-dot--success pulse-dot"
            style={{
              position: 'absolute',
              inset: 0,
              borderRadius: '50%',
              backgroundColor: 'var(--success)',
              opacity: 0.6,
            }}
          />
        )}
        <span
          className={online ? 'pulse-dot--success pulse-dot' : 'pulse-dot--warning pulse-dot'}
          style={{
            position: 'relative',
            display: 'inline-flex',
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: online ? 'var(--success)' : 'var(--warning)',
          }}
        />
      </span>

      {/* Icon + text */}
      {online ? (
        <Wifi size={compact ? 12 : 13} style={{ color: 'var(--success-text)', flexShrink: 0 }} />
      ) : (
        <WifiOff size={compact ? 12 : 13} style={{ color: 'var(--warning-text)', flexShrink: 0 }} />
      )}

      {!compact && (
        <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1 }}>
          <span
            className="font-mono"
            style={{
              fontSize: '0.6875rem',
              fontWeight: 700,
              color: online ? 'var(--success-text)' : 'var(--warning-text)',
              letterSpacing: '0.04em',
            }}
          >
            {online ? 'LIVE BACKEND' : 'AIR-GAPPED'}
          </span>
          <span
            className="font-mono"
            style={{
              fontSize: '0.625rem',
              color: 'var(--text-muted)',
              letterSpacing: '0.02em',
            }}
          >
            {online ? 'API CONNECTED' : 'OFFLINE MODE'}
          </span>
        </div>
      )}
    </div>
  );
};
