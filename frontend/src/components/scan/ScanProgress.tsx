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
        borderRadius: '12px',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        position: 'relative',
      }}
    >
      {/* SVG Circular Progress Gauge */}
      <div style={{ position: 'relative', width: '130px', height: '130px', marginBottom: '12px' }}>
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
              transition: 'stroke-dashoffset 0.3s ease',
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
            className="font-mono"
            style={{
              fontSize: '1.75rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              lineHeight: 1,
            }}
          >
            {scanProgress}%
          </span>
          <span
            style={{
              fontSize: '11px',
              fontWeight: 500,
              color: 'var(--text-muted)',
              letterSpacing: '0.02em',
              marginTop: '4px',
            }}
          >
            {isScanCompleted ? 'Sealed' : 'Analyzing'}
          </span>
        </div>
      </div>

      <div style={{ maxWidth: '320px' }}>
        <h3
          style={{
            fontSize: '0.875rem',
            fontWeight: 600,
            color: 'var(--text-primary)',
            margin: 0,
          }}
        >
          {isScanCompleted ? 'Integrity analysis complete' : 'Zero-Trust kernel execution'}
        </h3>
        <p
          style={{
            fontSize: '0.8125rem',
            color: 'var(--text-secondary)',
            marginTop: '4px',
            margin: '4px 0 0 0',
            minHeight: '1.25rem',
          }}
        >
          {currentOperation}
        </p>
      </div>
    </div>
  );
};
