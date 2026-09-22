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
        return <CheckCircle2 size={15} strokeWidth={1.5} style={{ color: 'var(--success-text)' }} />;
      case 'WARNING':
        return <AlertTriangle size={15} strokeWidth={1.5} style={{ color: 'var(--warning-text)' }} />;
      case 'FAILED':
        return <XCircle size={15} strokeWidth={1.5} style={{ color: 'var(--critical-text)' }} />;
      case 'UNAVAILABLE':
        return <XCircle size={15} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />;
      case 'RUNNING':
        return <Loader2 size={15} strokeWidth={1.5} style={{ color: 'var(--accent-text)', animation: 'radar-sweep 1s linear infinite' }} />;
      case 'WAITING':
      default:
        return <Clock size={15} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />;
    }
  };

  const getStatusBadge = (status: StageStatus) => {
    switch (status) {
      case 'PASSED':
        return <Badge variant="success" size="sm">Passed</Badge>;
      case 'WARNING':
        return <Badge variant="warning" size="sm">Warning</Badge>;
      case 'FAILED':
        return <Badge variant="critical" size="sm">Failed</Badge>;
      case 'UNAVAILABLE':
        return <Badge variant="default" size="sm">Unavail</Badge>;
      case 'RUNNING':
        return <Badge variant="accent" size="sm">Running</Badge>;
      case 'WAITING':
      default:
        return <Badge variant="default" size="sm">Waiting</Badge>;
    }
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        padding: '20px 24px',
      }}
    >
      <div
        style={{
          marginBottom: '16px',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '12px',
        }}
      >
        <h3
          style={{
            fontSize: '0.9375rem',
            fontWeight: 600,
            color: 'var(--text-primary)',
            margin: 0,
          }}
        >
          Forensic Analysis Pipeline
        </h3>
        <p
          style={{
            fontSize: '12px',
            color: 'var(--text-muted)',
            margin: '4px 0 0 0',
          }}
        >
          13 zero-trust verification phases executed in isolated cryptographic order
        </p>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '12px',
        }}
      >
        {stages.map(stage => {
          const isRunning = stage.status === 'RUNNING';
          const isFailed = stage.status === 'FAILED';
          const isWarning = stage.status === 'WARNING';
          const isPassed = stage.status === 'PASSED';
          const isUnavailable = stage.status === 'UNAVAILABLE';

          return (
            <div
              key={stage.id}
              style={{
                backgroundColor: 'var(--surface-elevated)',
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: isRunning
                  ? 'var(--accent-border)'
                  : isFailed
                  ? 'var(--critical-border)'
                  : isWarning
                  ? 'var(--warning-border)'
                  : isPassed
                  ? 'var(--border)'
                  : isUnavailable
                  ? 'var(--border-subtle)'
                  : 'var(--border)',
                borderLeftWidth: '2px',
                borderLeftColor: isRunning
                  ? 'var(--accent)'
                  : isFailed
                  ? 'var(--critical)'
                  : isWarning
                  ? 'var(--warning)'
                  : isPassed
                  ? 'var(--success)'
                  : 'var(--border-strong)',
                borderRadius: '0.375rem',
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '8px',
                opacity: isUnavailable ? 0.6 : 1,
                transition: 'border-color 0.15s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                {getStatusIcon(stage.status)}
                <div style={{ overflow: 'hidden' }}>
                  <div
                    style={{
                      fontSize: '12px',
                      fontWeight: 500,
                      color: 'var(--text-primary)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {stage.title}
                  </div>
                  <div
                    style={{
                      fontSize: '11px',
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
