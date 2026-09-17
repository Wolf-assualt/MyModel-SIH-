import React from 'react';
import { Database, Cpu, CheckCircle2, Copy, Skull, Compass, AlertOctagon, Activity } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';

export const LiveMetrics: React.FC = () => {
  const { liveMetrics } = useInvestigation();

  const metrics = [
    {
      label: 'Samples Analyzed',
      value: `${liveMetrics.samplesAnalyzed.toLocaleString()} / ${liveMetrics.totalSamples.toLocaleString()}`,
      icon: <Database size={16} style={{ color: 'var(--accent-text)' }} />,
      color: 'var(--accent-text)',
    },
    {
      label: 'Hashes Verified',
      value: liveMetrics.hashesVerified.toLocaleString(),
      icon: <CheckCircle2 size={16} style={{ color: 'var(--success-text)' }} />,
      color: 'var(--success-text)',
    },
    {
      label: 'Model Layers Inspected',
      value: `${liveMetrics.modelLayersInspected} / ${liveMetrics.totalLayers}`,
      icon: <Cpu size={16} style={{ color: 'var(--info-text)' }} />,
      color: 'var(--info-text)',
    },
    {
      label: 'Duplicates Found',
      value: liveMetrics.duplicatesFound.toString(),
      icon: <Copy size={16} style={{ color: 'var(--warning-text)' }} />,
      color: 'var(--warning-text)',
      isWarning: liveMetrics.duplicatesFound > 0,
    },
    {
      label: 'Poisoned Samples',
      value: liveMetrics.poisonedSamples.toString(),
      icon: <Skull size={16} style={{ color: 'var(--critical-text)' }} />,
      color: 'var(--critical-text)',
      isCritical: liveMetrics.poisonedSamples > 0,
    },
    {
      label: 'OOD Candidates',
      value: liveMetrics.oodCandidates.toString(),
      icon: <Compass size={16} style={{ color: 'var(--warning-text)' }} />,
      color: 'var(--warning-text)',
      isWarning: liveMetrics.oodCandidates > 0,
    },
    {
      label: 'Model Anomalies',
      value: liveMetrics.modelAnomalies.toString(),
      icon: <AlertOctagon size={16} style={{ color: 'var(--critical-text)' }} />,
      color: 'var(--critical-text)',
      isCritical: liveMetrics.modelAnomalies > 0,
    },
    {
      label: 'Inference Anomalies',
      value: liveMetrics.inferenceAnomalies.toString(),
      icon: <Activity size={16} style={{ color: 'var(--danger-text)' }} />,
      color: 'var(--danger-text)',
      isWarning: liveMetrics.inferenceAnomalies > 0,
    },
  ];

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))',
        gap: '0.75rem',
      }}
    >
      {metrics.map((m, i) => {
        return (
          <div
            key={i}
            style={{
              backgroundColor: 'var(--surface)',
              border: `1px solid ${
                m.isCritical
                  ? 'var(--critical-border)'
                  : m.isWarning
                  ? 'var(--warning-border)'
                  : 'var(--border)'
              }`,
              borderRadius: '0.5rem',
              padding: '0.875rem 1rem',
              boxShadow: m.isCritical ? 'var(--critical-glow)' : 'var(--card-shadow)',
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
                marginBottom: '0.375rem',
              }}
            >
              <span
                style={{
                  fontSize: '0.6875rem',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}
                className="font-mono"
              >
                {m.label}
              </span>
              {m.icon}
            </div>

            <div
              style={{
                fontSize: '1.25rem',
                fontWeight: 700,
                color: m.isCritical ? 'var(--critical-text)' : 'var(--text-primary)',
              }}
              className="font-mono"
            >
              {m.value}
            </div>
          </div>
        );
      })}
    </div>
  );
};
