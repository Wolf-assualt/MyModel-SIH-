import React from 'react';
import { AlertOctagon, Skull, Activity, AlertTriangle, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';

export const VerdictCard: React.FC = () => {
  const { trustScore, liveMetrics } = useInvestigation();

  const isAccepted = trustScore.verdict === 'ACCEPTED' || trustScore.overall >= 95;
  const isUnderReview = trustScore.verdict === 'UNDER_REVIEW' || (trustScore.overall >= 70 && trustScore.overall < 95);

  const borderColor = isAccepted
    ? 'var(--success-border)'
    : isUnderReview
    ? 'var(--warning-border)'
    : 'var(--critical-border)';

  const glowStyle = isAccepted
    ? 'var(--success-glow)'
    : isUnderReview
    ? 'var(--warning-glow)'
    : 'var(--critical-glow)';

  const iconSurface = isAccepted
    ? 'var(--success-surface)'
    : isUnderReview
    ? 'var(--warning-surface)'
    : 'var(--critical-surface)';

  const iconColor = isAccepted
    ? 'var(--success-text)'
    : isUnderReview
    ? 'var(--warning-text)'
    : 'var(--critical-text)';

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: `1px solid ${borderColor}`,
        borderRadius: '0.75rem',
        padding: '1.5rem 2rem',
        boxShadow: glowStyle,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1.5rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div
          style={{
            width: '54px',
            height: '54px',
            borderRadius: '0.5rem',
            backgroundColor: iconSurface,
            border: `1px solid ${borderColor}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: iconColor,
            flexShrink: 0,
          }}
        >
          {isAccepted ? (
            <ShieldCheck size={32} />
          ) : isUnderReview ? (
            <AlertTriangle size={32} />
          ) : (
            <AlertOctagon size={32} />
          )}
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                color: 'var(--text-muted)',
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
              }}
              className="font-mono"
            >
              INTEGRITY VERDICT
            </span>
            <Badge
              variant={isAccepted ? 'success' : isUnderReview ? 'warning' : 'critical'}
              size="md"
              pulse={!isAccepted}
            >
              {isAccepted ? '✓' : '⚠'} {trustScore.verdict}
            </Badge>
          </div>

          <h2
            style={{
              fontSize: '1.5rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '0.02em',
              margin: '0.25rem 0',
            }}
            className="font-display"
          >
            {trustScore.headline}
          </h2>

          <p
            style={{
              fontSize: '0.875rem',
              color: 'var(--text-secondary)',
              margin: 0,
              maxWidth: '850px',
              lineHeight: 1.5,
            }}
          >
            {trustScore.summary}
          </p>
        </div>
      </div>

      {/* Dynamic Summary Chips */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
        {isAccepted ? (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 0.875rem',
                backgroundColor: 'var(--success-surface)',
                border: '1px solid var(--success-border)',
                borderRadius: '0.375rem',
              }}
            >
              <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--success-text)' }} className="font-mono">
                0 ANOMALIES DETECTED
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 0.875rem',
                backgroundColor: 'var(--success-surface)',
                border: '1px solid var(--success-border)',
                borderRadius: '0.375rem',
              }}
            >
              <ShieldCheck size={15} style={{ color: 'var(--success-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--success-text)' }} className="font-mono">
                100% ZERO-TRUST INTEGRITY
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 0.875rem',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
              }}
            >
              <Activity size={15} style={{ color: 'var(--accent-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--accent-text)' }} className="font-mono">
                CRYPTOGRAPHICALLY SEALED
              </span>
            </div>
          </>
        ) : (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 0.875rem',
                backgroundColor: 'var(--critical-surface)',
                border: '1px solid var(--critical-border)',
                borderRadius: '0.375rem',
              }}
            >
              <Skull size={15} style={{ color: 'var(--critical-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--critical-text)' }} className="font-mono">
                {liveMetrics.poisonedSamples} POISONED SAMPLES
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 0.875rem',
                backgroundColor: 'var(--critical-surface)',
                border: '1px solid var(--critical-border)',
                borderRadius: '0.375rem',
              }}
            >
              <AlertTriangle size={15} style={{ color: 'var(--critical-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--critical-text)' }} className="font-mono">
                {liveMetrics.modelAnomalies} MODEL ANOMALIES
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 0.875rem',
                backgroundColor: 'var(--warning-surface)',
                border: '1px solid var(--warning-border)',
                borderRadius: '0.375rem',
              }}
            >
              <Activity size={15} style={{ color: 'var(--warning-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--warning-text)' }} className="font-mono">
                {liveMetrics.inferenceAnomalies} INFERENCE DEVIATIONS
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
