import React from 'react';
import { Database, CheckCircle2, AlertTriangle, ShieldAlert } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';

export const SummaryCards: React.FC = () => {
  const { liveMetrics } = useInvestigation();

  const totalArtifacts = liveMetrics.totalSamples;
  const criticalCount = liveMetrics.poisonedSamples;
  const warningCount = liveMetrics.oodCandidates;
  const verifiedCount = Math.max(0, totalArtifacts - criticalCount - warningCount);

  const cards = [
    {
      label: 'TOTAL ARTIFACTS',
      value: totalArtifacts.toLocaleString(),
      sublabel: totalArtifacts === 1 ? 'Single surveillance frame (Direct Ingestion)' : 'Surveillance frames, neural weights & telemetry',
      icon: <Database size={20} style={{ color: 'var(--accent-text)' }} />,
      borderColor: 'var(--border)',
      glow: 'none',
      textColor: 'var(--text-primary)',
    },
    {
      label: 'VERIFIED ASSETS',
      value: verifiedCount.toLocaleString(),
      sublabel: 'Cryptographically passed zero-trust assertions',
      icon: <CheckCircle2 size={20} style={{ color: 'var(--success-text)' }} />,
      borderColor: 'var(--success-border)',
      glow: 'var(--success-glow)',
      textColor: 'var(--success-text)',
    },
    {
      label: 'INTEGRITY WARNINGS',
      value: warningCount.toString(),
      sublabel: 'Out-of-distribution & near-duplicate frames',
      icon: <AlertTriangle size={20} style={{ color: 'var(--warning-text)' }} />,
      borderColor: 'var(--warning-border)',
      glow: 'var(--warning-glow)',
      textColor: 'var(--warning-text)',
    },
    {
      label: 'CRITICAL FINDINGS',
      value: criticalCount.toString(),
      sublabel: 'Clean-label poisoning & weight backdoor matches',
      icon: <ShieldAlert size={20} style={{ color: 'var(--critical-text)' }} />,
      borderColor: 'var(--critical-border)',
      glow: 'var(--critical-glow)',
      textColor: 'var(--critical-text)',
    },
  ];

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '1.25rem',
      }}
    >
      {cards.map((c, idx) => (
        <div
          key={idx}
          style={{
            backgroundColor: 'var(--surface)',
            border: `1px solid ${c.borderColor}`,
            borderRadius: '0.625rem',
            padding: '1.25rem 1.5rem',
            boxShadow: c.glow !== 'none' ? c.glow : 'var(--card-shadow)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            transition: 'all 0.2s ease',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: '0.5rem',
            }}
          >
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                color: 'var(--text-muted)',
                letterSpacing: '0.04em',
              }}
              className="font-mono"
            >
              {c.label}
            </span>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '0.375rem',
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {c.icon}
            </div>
          </div>

          <div
            style={{
              fontSize: '2rem',
              fontWeight: 700,
              color: c.textColor,
              lineHeight: 1.1,
              marginBottom: '0.375rem',
            }}
            className="font-mono"
          >
            {c.value}
          </div>

          <p
            style={{
              fontSize: '0.75rem',
              color: 'var(--text-secondary)',
              margin: 0,
            }}
          >
            {c.sublabel}
          </p>
        </div>
      ))}
    </div>
  );
};
