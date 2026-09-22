import React from 'react';
import { Database, Cpu, CheckCircle2, Copy, Skull, Compass, AlertOctagon, Activity } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';

export const LiveMetrics: React.FC = () => {
  const { liveMetrics } = useInvestigation();

  const metrics = [
    {
      label: 'Samples Analyzed',
      value: `${liveMetrics.samplesAnalyzed.toLocaleString()} / ${liveMetrics.totalSamples.toLocaleString()}`,
      icon: <Database size={16} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />,
    },
    {
      label: 'Hashes Verified',
      value: liveMetrics.hashesVerified.toLocaleString(),
      icon: <CheckCircle2 size={16} strokeWidth={1.5} style={{ color: 'var(--success-text)' }} />,
      isAlert: liveMetrics.hashesVerified === 0,
      alertColor: 'var(--warning-text)',
    },
    {
      label: 'Model Layers Inspected',
      value: `${liveMetrics.modelLayersInspected} / ${liveMetrics.totalLayers}`,
      icon: <Cpu size={16} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />,
    },
    {
      label: 'Duplicates Found',
      value: liveMetrics.duplicatesFound.toString(),
      icon: <Copy size={16} strokeWidth={1.5} style={{ color: liveMetrics.duplicatesFound > 0 ? 'var(--warning-text)' : 'var(--text-muted)' }} />,
      isAlert: liveMetrics.duplicatesFound > 0,
      alertColor: 'var(--warning-text)',
    },
    {
      label: 'Poisoned Samples',
      value: liveMetrics.poisonedSamples.toString(),
      icon: <Skull size={16} strokeWidth={1.5} style={{ color: liveMetrics.poisonedSamples > 0 ? 'var(--critical-text)' : 'var(--text-muted)' }} />,
      isAlert: liveMetrics.poisonedSamples > 0,
      alertColor: 'var(--critical-text)',
    },
    {
      label: 'OOD Candidates',
      value: liveMetrics.oodCandidates.toString(),
      icon: <Compass size={16} strokeWidth={1.5} style={{ color: liveMetrics.oodCandidates > 0 ? 'var(--warning-text)' : 'var(--text-muted)' }} />,
      isAlert: liveMetrics.oodCandidates > 0,
      alertColor: 'var(--warning-text)',
    },
    {
      label: 'Model Anomalies',
      value: liveMetrics.modelAnomalies.toString(),
      icon: <AlertOctagon size={16} strokeWidth={1.5} style={{ color: liveMetrics.modelAnomalies > 0 ? 'var(--critical-text)' : 'var(--text-muted)' }} />,
      isAlert: liveMetrics.modelAnomalies > 0,
      alertColor: 'var(--critical-text)',
    },
    {
      label: 'Inference Anomalies',
      value: liveMetrics.inferenceAnomalies.toString(),
      icon: <Activity size={16} strokeWidth={1.5} style={{ color: liveMetrics.inferenceAnomalies > 0 ? 'var(--warning-text)' : 'var(--text-muted)' }} />,
      isAlert: liveMetrics.inferenceAnomalies > 0,
      alertColor: 'var(--warning-text)',
    },
  ];

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))',
        gap: '12px',
      }}
    >
      {metrics.map((m, i) => {
        return (
          <div
            key={i}
            style={{
              backgroundColor: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '16px',
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
                {m.label}
              </span>
              {m.icon}
            </div>

            <div
              className="font-mono"
              style={{
                fontSize: '20px',
                fontWeight: 600,
                color: m.isAlert ? m.alertColor : 'var(--text-primary)',
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {m.value}
            </div>
          </div>
        );
      })}
    </div>
  );
};
