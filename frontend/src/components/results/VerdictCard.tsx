import React from 'react';
import { motion } from 'framer-motion';
import { AlertOctagon, Skull, Activity, AlertTriangle, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';

export const VerdictCard: React.FC = () => {
  const { trustScore, liveMetrics, ledgerVerification } = useInvestigation();

  if (!trustScore) {
    return (
      <div
        style={{
          backgroundColor: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: '12px',
          padding: '24px 32px',
          display: 'flex',
          alignItems: 'center',
          gap: '20px',
        }}
      >
        <div
          style={{
            width: '48px',
            height: '48px',
            borderRadius: '0.5rem',
            backgroundColor: 'var(--surface-elevated)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--text-muted)',
            flexShrink: 0,
          }}
        >
          <AlertTriangle size={24} strokeWidth={1.5} />
        </div>
        <div>
          <span
            style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-muted)', letterSpacing: '0.02em' }}
          >
            Integrity verdict
          </span>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-secondary)', margin: '4px 0' }}>
            Unavailable — no backend assessment
          </h2>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: 0 }}>
            No authoritative assessment has been received from the backend assurance pipeline.
            This client does not generate a verdict on its own.
          </p>
        </div>
      </div>
    );
  }

  const isAccepted = trustScore.verdict === 'ACCEPTED' || trustScore.verdict === 'TRUSTED';
  const isUnderReview = trustScore.verdict === 'UNDER_REVIEW' || trustScore.verdict === 'CAUTION';

  const edgeColor = isAccepted
    ? 'var(--success)'
    : isUnderReview
    ? 'var(--warning)'
    : 'var(--critical)';

  const iconColor = isAccepted
    ? 'var(--success-text)'
    : isUnderReview
    ? 'var(--warning-text)'
    : 'var(--critical-text)';

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: 'easeOut' }}
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderLeft: `2px solid ${edgeColor}`,
        borderRadius: '12px',
        padding: '24px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '24px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <div
          style={{
            width: '48px',
            height: '48px',
            borderRadius: '0.5rem',
            backgroundColor: 'var(--surface-elevated)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: iconColor,
            flexShrink: 0,
          }}
        >
          {isAccepted ? (
            <ShieldCheck size={24} strokeWidth={1.5} />
          ) : isUnderReview ? (
            <AlertTriangle size={24} strokeWidth={1.5} />
          ) : (
            <AlertOctagon size={24} strokeWidth={1.5} />
          )}
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span
              style={{
                fontSize: '12px',
                fontWeight: 500,
                color: 'var(--text-muted)',
                letterSpacing: '0.02em',
              }}
            >
              Integrity verdict
            </span>
            <Badge
              variant={isAccepted ? 'success' : isUnderReview ? 'warning' : 'critical'}
              size="md"
            >
              {trustScore.verdict}
            </Badge>
          </div>

          <h2
            style={{
              fontSize: '1.25rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              letterSpacing: '-0.01em',
              margin: '4px 0',
            }}
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

      {/* Summary chips — quiet labels, color only where meaningful */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
        {isAccepted ? (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
              }}
            >
              <CheckCircle2 size={15} strokeWidth={1.5} style={{ color: 'var(--success-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                0 anomalies detected
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
              }}
            >
              <ShieldCheck size={15} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {trustScore.overall}% assurance score
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
              }}
            >
              <Activity size={15} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {ledgerVerification?.valid === true
                  ? `Ledger valid (${ledgerVerification.events_checked} events)`
                  : ledgerVerification?.valid === false
                  ? 'Ledger verification failed'
                  : 'Ledger verification unavailable'}
              </span>
            </div>
          </>
        ) : (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
              }}
            >
              <Skull size={15} strokeWidth={1.5} style={{ color: 'var(--critical-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {liveMetrics.poisonedSamples} poisoned samples
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
              }}
            >
              <AlertTriangle size={15} strokeWidth={1.5} style={{ color: 'var(--critical-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {liveMetrics.modelAnomalies} model anomalies
              </span>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
              }}
            >
              <Activity size={15} strokeWidth={1.5} style={{ color: 'var(--warning-text)' }} />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {liveMetrics.inferenceAnomalies} inference deviations
              </span>
            </div>
          </>
        )}
      </div>
    </motion.div>
  );
};
