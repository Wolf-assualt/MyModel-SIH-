import React from 'react';
import { CheckCircle2 } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { Phase } from '../../types/investigation';

export const PhaseStepper: React.FC = () => {
  const { phase, setPhase, isScanning } = useInvestigation();

  const steps: { id: Phase; stepNum: string; label: string; desc: string }[] = [
    {
      id: 'launch',
      stepNum: '01',
      label: 'PHASE 01 — LAUNCH / UPLOAD',
      desc: 'Dataset & Model Ingestion',
    },
    {
      id: 'scan',
      stepNum: '02',
      label: 'PHASE 02 — SCAN / ANALYZE',
      desc: '11-Stage Forensic Pipeline',
    },
    {
      id: 'results',
      stepNum: '03',
      label: 'PHASE 03 — RESULTS / EVIDENCE',
      desc: 'Zero-Trust Verdict & Lineage',
    },
  ];

  const getStepStatus = (stepId: Phase) => {
    if (stepId === phase) return 'active';
    if (stepId === 'launch' && (phase === 'scan' || phase === 'results')) return 'completed';
    if (stepId === 'scan' && phase === 'results') return 'completed';
    return 'upcoming';
  };

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: '1rem',
        marginBottom: '1.5rem',
      }}
    >
      {steps.map(step => {
        const status = getStepStatus(step.id);
        const isActive = status === 'active';
        const isCompleted = status === 'completed';

        return (
          <div
            key={step.id}
            onClick={() => setPhase(step.id)}
            role="button"
            tabIndex={0}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') setPhase(step.id);
            }}
            style={{
              padding: '0.875rem 1.25rem',
              backgroundColor: isActive ? 'var(--surface)' : 'var(--surface-elevated)',
              borderWidth: '1px',
              borderStyle: 'solid',
              borderColor: isActive
                ? 'var(--accent)'
                : isCompleted
                ? 'var(--success-border)'
                : 'var(--border)',
              borderRadius: '0.5rem',
              boxShadow: isActive ? 'var(--accent-glow)' : 'none',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
            onMouseEnter={e => {
              if (!isActive) e.currentTarget.style.borderColor = 'var(--border-strong)';
            }}
            onMouseLeave={e => {
              if (!isActive) e.currentTarget.style.borderColor = isCompleted ? 'var(--success-border)' : 'var(--border)';
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    color: isActive
                      ? 'var(--accent-text)'
                      : isCompleted
                      ? 'var(--success-text)'
                      : 'var(--text-muted)',
                  }}
                  className="font-mono"
                >
                  {step.label}
                </span>
              </div>
              <p
                style={{
                  fontSize: '0.8125rem',
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  fontWeight: isActive ? 600 : 500,
                  marginTop: '0.125rem',
                  margin: 0,
                }}
              >
                {step.desc}
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center' }}>
              {isCompleted ? (
                <CheckCircle2 size={18} style={{ color: 'var(--success-text)' }} />
              ) : isActive ? (
                <div
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: 'var(--accent-surface)',
                    border: '1px solid var(--accent)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent-text)',
                  }}
                >
                  <span
                    style={{
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      backgroundColor: 'var(--accent)',
                      display: 'inline-block',
                      animation: isScanning ? 'ping-subtle 1.2s infinite ease-in-out' : 'none',
                    }}
                  />
                </div>
              ) : (
                <div
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: 'var(--surface-active)',
                    border: '1px solid var(--border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--text-muted)',
                    fontSize: '0.6875rem',
                  }}
                  className="font-mono"
                >
                  {step.stepNum}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};
