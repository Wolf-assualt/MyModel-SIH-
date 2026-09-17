import React from 'react';
import { Terminal, Clock, Play, Pause, FastForward } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { BackendStatus } from '../ui/BackendStatus';

export const ScanHeader: React.FC = () => {
  const {
    sessionId,
    elapsedSeconds,
    isScanning,
    isScanCompleted,
    scanProgress,
    startScan,
    pauseScan,
    resumeScan,
    skipScanToEnd,
    speedMultiplier,
    setSpeedMultiplier,
    backendOnline,
    setPhase,
  } = useInvestigation();

  const formatElapsed = (totalSec: number) => {
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        padding: '1rem 1.5rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
      }}
    >
      {/* Title & Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div
          style={{
            width: '36px',
            height: '36px',
            borderRadius: '0.375rem',
            backgroundColor: 'var(--accent-surface)',
            border: '1px solid var(--accent)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-text)',
          }}
        >
          <Terminal size={20} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <h2
              style={{
                fontSize: '1.125rem',
                fontWeight: 700,
                color: 'var(--text-primary)',
                letterSpacing: '0.04em',
                margin: 0,
              }}
              className="font-display"
            >
              INTEGRITY ANALYSIS TERMINAL
            </h2>
            {isScanCompleted ? (
              <Badge variant="success" size="sm">
                ANALYSIS COMPLETE
              </Badge>
            ) : isScanning ? (
              <Badge variant="accent" size="sm" pulse>
                SCAN IN PROGRESS
              </Badge>
            ) : scanProgress > 0 ? (
              <Badge variant="warning" size="sm">
                PAUSED ({scanProgress}%)
              </Badge>
            ) : (
              <Badge variant="default" size="sm">
                READY TO INITIALIZE
              </Badge>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.25rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }} className="font-mono">
              SESSION: <strong style={{ color: 'var(--accent-text)' }}>{sessionId}</strong>
            </span>
            <span style={{ color: 'var(--border-strong)', fontSize: '0.75rem' }}>•</span>
            <span
              style={{
                fontSize: '0.75rem',
                color: 'var(--text-secondary)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.375rem',
              }}
              className="font-mono"
            >
              <Clock size={13} style={{ color: 'var(--text-muted)' }} />
              ELAPSED: <strong style={{ color: 'var(--text-primary)' }}>{formatElapsed(elapsedSeconds)}</strong>
            </span>
            <BackendStatus online={backendOnline} compact />
          </div>
        </div>
      </div>

      {/* Interactive Controls: Speed + Skip + Pause */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
        {/* Speed Multiplier */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            backgroundColor: 'var(--surface-elevated)',
            border: '1px solid var(--border)',
            borderRadius: '0.375rem',
            padding: '0.125rem',
          }}
        >
          {[1, 2, 5].map(multiplier => (
            <button
              key={multiplier}
              onClick={() => setSpeedMultiplier(multiplier)}
              style={{
                padding: '0.25rem 0.5rem',
                fontSize: '0.6875rem',
                fontWeight: 600,
                border: 'none',
                borderRadius: '0.25rem',
                cursor: 'pointer',
                backgroundColor: speedMultiplier === multiplier ? 'var(--accent)' : 'transparent',
                color: speedMultiplier === multiplier ? 'var(--text-inverse)' : 'var(--text-secondary)',
                transition: 'all 0.15s ease',
              }}
              className="font-mono"
            >
              {multiplier}X
            </button>
          ))}
        </div>

        {/* Context-aware scan controls */}
        {!isScanCompleted && scanProgress === 0 && !isScanning && (
          <Button
            variant="primary"
            size="sm"
            onClick={startScan}
            icon={<Play size={14} />}
          >
            START FORENSIC SCAN
          </Button>
        )}

        {!isScanCompleted && (isScanning || scanProgress > 0) && (
          <Button
            variant={isScanning ? 'outline' : 'primary'}
            size="sm"
            onClick={isScanning ? pauseScan : resumeScan}
            icon={isScanning ? <Pause size={14} /> : <Play size={14} />}
          >
            {isScanning ? 'Pause' : 'Resume Scan'}
          </Button>
        )}

        {!isScanCompleted && (isScanning || scanProgress > 0) && (
          <Button
            variant="outline"
            size="sm"
            onClick={skipScanToEnd}
            icon={<FastForward size={14} />}
          >
            Skip to End
          </Button>
        )}

        {isScanCompleted && (
          <>
            <Button
              variant="primary"
              size="sm"
              onClick={() => setPhase('results')}
            >
              VIEW VERDICT & EVIDENCE →
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={startScan}
              icon={<Play size={14} />}
            >
              Re-Run Scan
            </Button>
          </>
        )}
      </div>
    </div>
  );
};
