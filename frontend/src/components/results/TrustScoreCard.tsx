import React from 'react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';

export const TrustScoreCard: React.FC = () => {
  const { trustScore } = useInvestigation();

  if (!trustScore) {
    return (
      <div
        style={{
          backgroundColor: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: '12px',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}
      >
        <h3
          style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}
        >
          Zero-Trust Assurance Score
        </h3>
        <div
          style={{
            padding: '16px',
            backgroundColor: 'var(--surface-elevated)',
            border: '1px dashed var(--border)',
            borderRadius: '0.375rem',
            fontSize: '0.8125rem',
            color: 'var(--text-muted)',
          }}
        >
          Unavailable — the backend assurance pipeline has not returned a score for this asset.
        </div>
      </div>
    );
  }

  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (trustScore.overall / 100) * circumference;

  const isPassing = trustScore.verdict === 'ACCEPTED' || trustScore.verdict === 'TRUSTED';
  const isReview = trustScore.verdict === 'UNDER_REVIEW' || trustScore.verdict === 'CAUTION';

  const gaugeColor = isPassing ? 'var(--success)' : isReview ? 'var(--warning)' : 'var(--critical)';

  // -1 is the backend sentinel for "module UNAVAILABLE" (never assessed).
  const getSubscoreColor = (val: number) => {
    if (val < 0) return 'var(--border-strong)';
    if (val >= 95) return 'var(--success)';
    if (val >= 75) return 'var(--warning)';
    return 'var(--critical)';
  };

  const formatSubscore = (val: number) => (val < 0 ? 'Unavailable' : `${val}%`);

  const subscores = [
    { label: 'Data Integrity', value: trustScore.dataIntegrity, color: getSubscoreColor(trustScore.dataIntegrity) },
    { label: 'Model Integrity', value: trustScore.modelIntegrity, color: getSubscoreColor(trustScore.modelIntegrity) },
    { label: 'Inference Integrity', value: trustScore.inferenceIntegrity, color: getSubscoreColor(trustScore.inferenceIntegrity) },
    { label: 'Pipeline Integrity', value: trustScore.pipelineIntegrity, color: getSubscoreColor(trustScore.pipelineIntegrity) },
  ];

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        gap: '20px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h3
            style={{
              fontSize: '0.9375rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              margin: 0,
            }}
          >
            Zero-Trust Assurance Score
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
            Composite integrity rating across dataset, neural architecture, and inferences
          </p>
        </div>

        {isPassing ? (
          <Badge variant="success" size="sm">
            Backend disposition: {trustScore.verdict}
          </Badge>
        ) : isReview ? (
          <Badge variant="warning" size="sm">
            Backend disposition: {trustScore.verdict}
          </Badge>
        ) : (
          <Badge variant="critical" size="sm">
            Backend disposition: {trustScore.verdict}
          </Badge>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '24px', flexWrap: 'wrap' }}>
        {/* Radial gauge */}
        <div style={{ position: 'relative', width: '120px', height: '120px', flexShrink: 0 }}>
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="none"
              stroke="var(--surface-active)"
              strokeWidth="8"
            />
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="none"
              stroke={gaugeColor}
              strokeWidth="8"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              transform="rotate(-90 60 60)"
              style={{ transition: 'stroke-dashoffset 0.8s ease' }}
            />
          </svg>

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
              {trustScore.overall}
            </span>
            <span
              style={{
                fontSize: '11px',
                color: 'var(--text-muted)',
                fontWeight: 500,
              }}
            >
              / 100
            </span>
          </div>
        </div>

        {/* Breakdown bars */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '12px', minWidth: '200px' }}>
          {subscores.map((s, idx) => (
            <div key={idx}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: '12px',
                  marginBottom: '4px',
                }}
              >
                <span style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
                <span className="font-mono" style={{ fontWeight: 500, color: s.value < 0 ? 'var(--text-muted)' : 'var(--text-primary)' }}>{formatSubscore(s.value)}</span>
              </div>
              <div
                style={{
                  height: '4px',
                  backgroundColor: 'var(--surface-active)',
                  borderRadius: '2px',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${s.value < 0 ? 0 : s.value}%`,
                    height: '100%',
                    backgroundColor: s.color,
                    borderRadius: '2px',
                    transition: 'width 0.6s ease',
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div
        style={{
          padding: '12px 16px',
          backgroundColor: 'var(--surface-elevated)',
          border: '1px solid var(--border)',
          borderRadius: '0.375rem',
          fontSize: '12px',
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
        }}
      >
        <strong style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Threshold requirement:</strong> Zero-Trust defense standard mandates ≥ 95% overall score for autonomous operational deployment. Lower scores require forensic analyst review before authorization.
      </div>
    </div>
  );
};
