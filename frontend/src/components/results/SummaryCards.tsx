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
      label: 'Total artifacts',
      value: totalArtifacts.toLocaleString(),
      sublabel: totalArtifacts === 1 ? 'Single surveillance frame (Direct Ingestion)' : 'Surveillance frames, neural weights & telemetry',
      icon: <Database size={16} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />,
      valueColor: 'var(--text-primary)',
    },
    {
      label: 'Verified assets',
      value: verifiedCount.toLocaleString(),
      sublabel: 'Cryptographically passed zero-trust assertions',
      icon: <CheckCircle2 size={16} strokeWidth={1.5} style={{ color: 'var(--success-text)' }} />,
      valueColor: 'var(--text-primary)',
    },
    {
      label: 'Integrity warnings',
      value: warningCount.toString(),
      sublabel: 'Out-of-distribution & near-duplicate frames',
      icon: <AlertTriangle size={16} strokeWidth={1.5} style={{ color: warningCount > 0 ? 'var(--warning-text)' : 'var(--text-muted)' }} />,
      valueColor: warningCount > 0 ? 'var(--warning-text)' : 'var(--text-primary)',
    },
    {
      label: 'Critical findings',
      value: criticalCount.toString(),
      sublabel: 'Clean-label poisoning & weight backdoor matches',
      icon: <ShieldAlert size={16} strokeWidth={1.5} style={{ color: criticalCount > 0 ? 'var(--critical-text)' : 'var(--text-muted)' }} />,
      valueColor: criticalCount > 0 ? 'var(--critical-text)' : 'var(--text-primary)',
    },
  ];

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '24px',
      }}
    >
      {cards.map((c, idx) => (
        <div
          key={idx}
          style={{
            backgroundColor: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: '12px',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: '8px',
            }}
          >
            <span
              style={{
                fontSize: '12px',
                fontWeight: 500,
                color: 'var(--text-muted)',
                letterSpacing: '0.02em',
              }}
            >
              {c.label}
            </span>
            {c.icon}
          </div>

          <div
            className="font-mono"
            style={{
              fontSize: '24px',
              fontWeight: 600,
              color: c.valueColor,
              lineHeight: 1.2,
              marginBottom: '4px',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {c.value}
          </div>

          <p
            style={{
              fontSize: '12px',
              color: 'var(--text-muted)',
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
