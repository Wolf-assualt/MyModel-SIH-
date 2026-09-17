import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Clock, Loader2 } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { StageStatus } from '../../types/investigation';
import { Badge } from '../ui/Badge';

export const PipelineStages: React.FC = () => {
  const { stages } = useInvestigation();

  const getStatusIcon = (status: StageStatus) => {
    switch (status) {
      case 'PASSED':
        return <CheckCircle2 size={15} style={{ color: 'var(--success-text)' }} />;
      case 'WARNING':
        return <AlertTriangle size={15} style={{ color: 'var(--warning-text)' }} />;
      case 'FAILED':
        return <XCircle size={15} style={{ color: 'var(--critical-text)' }} />;
      case 'RUNNING':
        return <Loader2 size={15} style={{ color: 'var(--accent-text)', animation: 'radar-sweep 1s linear infinite' }} />;
      case 'WAITING':
      default:
        return <Clock size={15} style={{ color: 'var(--text-muted)' }} />;
    }
  };

  const getStatusBadge = (status: StageStatus) => {
    switch (status) {
      case 'PASSED':
        return <Badge variant="success" size="sm">PASSED</Badge>;
      case 'WARNING':
        return <Badge variant="warning" size="sm">WARNING</Badge>;
      case 'FAILED':
        return <Badge variant="critical" size="sm">FAILED</Badge>;
      case 'RUNNING':
        return <Badge variant="accent" size="sm" pulse>RUNNING</Badge>;
      case 'WAITING':
      default:
        return <Badge variant="default" size="sm">WAITING</Badge>;
    }
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        padding: '1.25rem 1.5rem',
        boxShadow: 'var(--card-shadow)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '1rem',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '0.75rem',
        }}
      >
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
            Forensic Analysis Pipeline
          </h3>
          <p
            style={{
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              margin: 0,
            }}
          >
            11 zero-trust verification phases executed in isolated cryptographic order
          </p>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '0.625rem',
        }}
      >
        {stages.map(stage => {
          const isRunning = stage.status === 'RUNNING';
          const isFailed = stage.status === 'FAILED';
          const isWarning = stage.status === 'WARNING';
          const isPassed = stage.status === 'PASSED';

          return (
            <div
              key={stage.id}
              style={{
                backgroundColor: isRunning
                  ? 'var(--surface-elevated)'
                  : isFailed
                  ? 'var(--critical-surface)'
                  : isWarning
                  ? 'var(--warning-surface)'
                  : isPassed
                  ? 'var(--surface-elevated)'
                  : 'var(--surface)',
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: isRunning
                  ? 'var(--accent)'
                  : isFailed
                  ? 'var(--critical-border)'
                  : isWarning
                  ? 'var(--warning-border)'
                  : isPassed
                  ? 'var(--success-border)'
                  : 'var(--border)',
                borderRadius: '0.375rem',
                padding: '0.625rem 0.875rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '0.5rem',
                boxShadow: isRunning ? 'var(--accent-glow)' : 'none',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', minWidth: 0 }}>
                {getStatusIcon(stage.status)}
                <div style={{ overflow: 'hidden' }}>
                  <div
                    style={{
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      color: 'var(--text-primary)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                    className="font-mono"
                  >
                    {stage.title}
                  </div>
                  <div
                    style={{
                      fontSize: '0.625rem',
                      color: 'var(--text-muted)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {stage.summary}
                  </div>
                </div>
              </div>

              {getStatusBadge(stage.status)}
            </div>
          );
        })}
      </div>
    </div>
  );
};
