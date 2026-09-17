import React, { useState } from 'react';
import { useInvestigation } from '../../state/investigationStore';
import type { SignalPoint } from '../../types/investigation';
import { Badge } from '../ui/Badge';

export const SignalMap: React.FC = () => {
  const { signalPoints, liveMetrics, isScanning } = useInvestigation();
  const [hoveredPoint, setHoveredPoint] = useState<SignalPoint | null>(null);

  const poisonedCount = liveMetrics.poisonedSamples;
  const oodCount = liveMetrics.oodCandidates;
  const normalCount = Math.max(0, (liveMetrics.totalSamples || signalPoints.length) - poisonedCount - oodCount);

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        padding: '1.25rem 1.5rem',
        boxShadow: 'var(--card-shadow)',
        display: 'flex',
        flexDirection: 'column',
        height: '380px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Title & Legend Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '0.75rem',
          zIndex: 2,
        }}
      >
        <div>
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
            Integrity Signal Map (Latent Feature Space)
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>
            Visual embedding cluster deviation separating nominal data from backdoor triggers
          </p>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--accent)' }} />
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }} className="font-mono">
              Normal ({normalCount.toLocaleString()})
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--warning)' }} />
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }} className="font-mono">
              OOD ({oodCount.toLocaleString()})
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--critical)' }} />
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }} className="font-mono">
              Poisoned ({poisonedCount.toLocaleString()})
            </span>
          </div>
        </div>
      </div>

      {/* SVG Canvas Scatter Visualizer */}
      <div style={{ flex: 1, position: 'relative', width: '100%', height: '100%' }}>
        <svg
          viewBox="0 0 500 240"
          style={{
            width: '100%',
            height: '100%',
            backgroundColor: 'var(--terminal-bg)',
            borderRadius: '0.375rem',
            border: '1px solid var(--border-subtle)',
          }}
        >
          {/* Coordinate Grid Crosshairs */}
          <line x1="250" y1="10" x2="250" y2="230" stroke="var(--border-subtle)" strokeDasharray="3 3" />
          <line x1="10" y1="120" x2="490" y2="120" stroke="var(--border-subtle)" strokeDasharray="3 3" />

          {/* Normal Boundary Ring */}
          <circle cx="250" cy="120" r="85" fill="none" stroke="var(--accent-border)" strokeDasharray="4 4" opacity="0.4" />
          {/* Outlier Threshold Ring */}
          <circle cx="250" cy="120" r="140" fill="none" stroke="var(--warning-border)" strokeDasharray="4 4" opacity="0.3" />

          {/* Poisoning Subspace Region Indicator - conditionally rendered */}
          {poisonedCount > 0 && (
            <>
              <circle cx="410" cy="70" r="34" fill="var(--critical-surface)" stroke="var(--critical-border)" strokeDasharray="3 3" />
              <text x="410" y="30" fill="var(--critical-text)" fontSize="9" textAnchor="middle" fontFamily="'JetBrains Mono', monospace" fontWeight="600">
                POISONED TRIGGER CLUSTER
              </text>
            </>
          )}

          {/* Points rendering */}
          {signalPoints.map(pt => {
            const isPoisoned = pt.status === 'poisoned';
            const isOod = pt.status === 'ood';
            const color = isPoisoned ? 'var(--critical)' : isOod ? 'var(--warning)' : 'var(--accent)';
            const r = isPoisoned ? 4.5 : isOod ? 3.5 : 2.5;

            return (
              <circle
                key={pt.id}
                cx={pt.x}
                cy={pt.y}
                r={r}
                fill={color}
                opacity={isPoisoned ? 0.95 : isOod ? 0.85 : 0.65}
                style={{
                  cursor: 'pointer',
                  transition: 'r 0.15s ease, opacity 0.15s ease',
                }}
                onMouseEnter={() => setHoveredPoint(pt)}
                onMouseLeave={() => setHoveredPoint(null)}
              />
            );
          })}

          {/* Scanning Sweep beam if scanning */}
          {isScanning && (
            <line
              x1="0"
              y1="0"
              x2="500"
              y2="0"
              stroke="var(--accent)"
              strokeWidth="1.5"
              opacity="0.75"
              style={{
                animation: 'radar-sweep-vertical 3s linear infinite',
              }}
            />
          )}
        </svg>

        {/* Hover Tooltip Card */}
        {hoveredPoint && (
          <div
            style={{
              position: 'absolute',
              bottom: '12px',
              left: '12px',
              backgroundColor: 'var(--surface)',
              border: `1px solid ${
                hoveredPoint.status === 'poisoned'
                  ? 'var(--critical-border)'
                  : hoveredPoint.status === 'ood'
                  ? 'var(--warning-border)'
                  : 'var(--accent-border)'
              }`,
              borderRadius: '0.375rem',
              padding: '0.625rem 0.875rem',
              boxShadow: 'var(--card-shadow)',
              pointerEvents: 'none',
              zIndex: 10,
              fontSize: '0.75rem',
            }}
            className="font-mono"
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>{hoveredPoint.sampleId}</strong>
              <Badge
                variant={
                  hoveredPoint.status === 'poisoned'
                    ? 'critical'
                    : hoveredPoint.status === 'ood'
                    ? 'warning'
                    : 'accent'
                }
                size="sm"
              >
                {hoveredPoint.status.toUpperCase()}
              </Badge>
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>
              Anomaly Score: <strong style={{ color: 'var(--text-primary)' }}>{hoveredPoint.score.toFixed(3)}</strong>
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.6875rem' }}>
              Subspace: {hoveredPoint.cluster}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
