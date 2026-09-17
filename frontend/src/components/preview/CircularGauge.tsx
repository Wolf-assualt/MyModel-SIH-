import React from 'react';

interface CircularGaugeProps {
  score: number | null; // 0 - 100 or null if awaiting
  size?: number;
  strokeWidth?: number;
  isScanning?: boolean;
}

export const CircularGauge: React.FC<CircularGaugeProps> = ({
  score,
  size = 110,
  strokeWidth = 7,
  isScanning = false,
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  // Determine fill percentage
  const displayScore = score !== null ? Math.max(0, Math.min(100, score)) : 0;
  const strokeDashoffset = score !== null ? circumference - (displayScore / 100) * circumference : circumference;

  // Color according to score or state
  let strokeColor = 'var(--text-muted)';
  let glowColor = 'transparent';

  if (score !== null) {
    if (score >= 80) {
      strokeColor = '#10b981'; // Green
      glowColor = 'rgba(16, 185, 129, 0.4)';
    } else if (score >= 50) {
      strokeColor = '#f59e0b'; // Amber
      glowColor = 'rgba(245, 158, 11, 0.4)';
    } else {
      strokeColor = '#ef4444'; // Red (Hard Veto)
      glowColor = 'rgba(239, 68, 68, 0.4)';
    }
  } else if (isScanning) {
    strokeColor = '#00f2ff';
    glowColor = 'rgba(0, 242, 255, 0.5)';
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        width: size,
        height: size,
        minWidth: size,
      }}
    >
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', overflow: 'visible' }}>
        {/* Background track circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(255, 255, 255, 0.08)"
          strokeWidth={strokeWidth}
          fill="transparent"
        />

        {/* Dynamic active score arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          style={{
            transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.4s ease',
            filter: score !== null ? `drop-shadow(0 0 6px ${glowColor})` : 'none',
          }}
        />
      </svg>

      {/* Center content */}
      <div
        style={{
          position: 'absolute',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          lineHeight: 1,
        }}
      >
        <span
          style={{
            fontSize: score !== null ? '1.85rem' : '2.2rem',
            fontWeight: 800,
            fontFamily: 'var(--font-mono)',
            color: score !== null ? (score >= 80 ? '#10b981' : score >= 50 ? '#f59e0b' : '#ef4444') : 'var(--text-muted)',
            letterSpacing: '-0.02em',
          }}
        >
          {isScanning ? '...' : score !== null ? score : '—'}
        </span>
        <span
          style={{
            fontSize: '0.625rem',
            fontWeight: 700,
            letterSpacing: '0.08em',
            color: 'var(--text-muted)',
            marginTop: '3px',
            fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase',
          }}
        >
          ASSURANCE / 100
        </span>
      </div>
    </div>
  );
};
