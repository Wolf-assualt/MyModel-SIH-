import React from 'react';
import { useInvestigation } from '../../state/investigationStore';

export const ScanProgress: React.FC = () => {
  const { scanProgress, currentOperation, isScanCompleted } = useInvestigation();

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (scanProgress / 100) * circumference;

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        padding: '1.5rem',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        boxShadow: 'var(--card-shadow)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background radial glow */}
      <div
        style={{
          position: 'absolute',
          width: '180px',
          height: '180px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, var(--accent-surface) 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />

      {/* SVG Circular Progress Gauge */}
      <div style={{ position: 'relative', width: '130px', height: '130px', marginBottom: '0.75rem' }}>
        <svg width="130" height="130" viewBox="0 0 130 130">
          {/* Background circle track */}
          <circle
            cx="65"
            cy="65"
            r={radius}
            fill="none"
            stroke="var(--surface-active)"
            strokeWidth="8"
          />
          {/* Active progress stroke */}
          <circle
            cx="65"
            cy="65"
            r={radius}
            fill="none"
            stroke="var(--accent)"
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            transform="rotate(-90 65 65)"
            style={{
              transition: 'stroke-dashoffset 0.3s ease, stroke 0.3s ease',
            }}
          />
        </svg>

        {/* Center Percentage Display */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span
            style={{
              fontSize: '1.75rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              lineHeight: 1,
            }}
            className="font-mono"
          >
            {scanProgress}%
          </span>
          <span
            style={{
              fontSize: '0.625rem',
              fontWeight: 600,
              color: 'var(--accent-text)',
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              marginTop: '0.25rem',
            }}
            className="font-mono"
          >
            {isScanCompleted ? 'SEALED' : 'ANALYZING'}
          </span>
        </div>
      </div>

      <div style={{ maxWidth: '320px' }}>
        <h3
          style={{
            fontSize: '0.875rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            margin: 0,
          }}
          className="font-display"
        >
          {isScanCompleted ? 'INTEGRITY ANALYSIS COMPLETE' : 'ZERO-TRUST KERNEL EXECUTION'}
        </h3>
        <p
          style={{
            fontSize: '0.8125rem',
            color: 'var(--accent-text)',
            marginTop: '0.25rem',
            margin: 0,
            minHeight: '1.25rem',
          }}
          className="font-mono"
        >
          {currentOperation}
        </p>
      </div>
    </div>
  );
};
