import React from 'react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';

export const TrustScoreCard: React.FC = () => {
  const { trustScore } = useInvestigation();

  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (trustScore.overall / 100) * circumference;

  const isPassing = trustScore.overall >= 95;
  const isReview = trustScore.overall >= 70 && trustScore.overall < 95;

  const gaugeColor = isPassing ? 'var(--success)' : isReview ? 'var(--warning)' : 'var(--critical)';

  const getSubscoreColor = (val: number) => {
    if (val >= 95) return 'var(--success)';
    if (val >= 75) return 'var(--warning)';
    return 'var(--critical)';
  };

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
        borderRadius: '0.625rem',
        padding: '1.5rem',
        boxShadow: 'var(--card-shadow)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        gap: '1.25rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h3
            style={{
              fontSize: '0.9375rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              margin: 0,
            }}
            className="font-display"
          >
            Zero-Trust Assurance Score
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>
            Composite integrity rating across dataset, neural architecture, and inferences
          </p>
        </div>

        {isPassing ? (
          <Badge variant="success" size="sm">
            ✓ DEPLOYMENT APPROVED
          </Badge>
        ) : isReview ? (
          <Badge variant="warning" size="sm">
            ⚠ REVIEW RECOMMENDED
          </Badge>
        ) : (
          <Badge variant="critical" size="sm">
            ✕ QUARANTINE REQUIRED
          </Badge>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
        {/* Radial gauge */}
        <div style={{ position: 'relative', width: '120px', height: '120px', flexShrink: 0 }}>
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="none"
              stroke="var(--surface-active)"
              strokeWidth="10"
            />
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="none"
              stroke={gaugeColor}
              strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              transform="rotate(-90 60 60)"
              style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.3s ease' }}
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
              style={{
                fontSize: '1.75rem',
                fontWeight: 700,
                color: 'var(--text-primary)',
                lineHeight: 1,
              }}
              className="font-mono"
            >
              {trustScore.overall}
            </span>
            <span
              style={{
                fontSize: '0.6875rem',
                color: 'var(--text-muted)',
                fontWeight: 600,
              }}
              className="font-mono"
            >
              / 100
            </span>
          </div>
        </div>

        {/* Breakdown bars */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.625rem', minWidth: '200px' }}>
          {subscores.map((s, idx) => (
            <div key={idx}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: '0.75rem',
                  marginBottom: '0.25rem',
                }}
                className="font-mono"
              >
                <span style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{s.value}%</span>
              </div>
              <div
                style={{
                  height: '6px',
                  backgroundColor: 'var(--surface-active)',
                  borderRadius: '3px',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${s.value}%`,
                    height: '100%',
                    backgroundColor: s.color,
                    borderRadius: '3px',
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
          padding: '0.75rem 1rem',
          backgroundColor: 'var(--surface-elevated)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '0.375rem',
          fontSize: '0.75rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
        }}
      >
        <strong style={{ color: 'var(--text-primary)' }}>Threshold Requirement:</strong> Zero-Trust defense standard mandates ≥ 95% overall score for autonomous operational deployment. Lower scores require forensic analyst review before authorization.
      </div>
    </div>
  );
};
