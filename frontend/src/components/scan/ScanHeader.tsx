import React from 'react';
import { Terminal, Clock, Play } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { BackendStatus } from '../ui/BackendStatus';

/**
 * ScanHeader — displays real backend scan progress controls.
 *
 * Phase 8 changes:
 * - Removed "Speed Multiplier" (1X/2X/5X) — meaningless when progress comes
 *   from the backend; incrementing the interval would not accelerate analysis.
 * - Removed "Skip to End" — would have moved to the results page before the
 *   backend completed, showing UNAVAILABLE for all results.
 * - "Re-Run Scan" re-uses the existing scan_id from the current upload session
 *   rather than starting a new one; the upload must be repeated for a new scan.
 */
export const ScanHeader: React.FC = () => {
  const {
    sessionId,
    currentScanId,
    elapsedSeconds,
    isScanning,
    isScanCompleted,
    scanProgress,
    startScan,
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
              <Badge variant="success" size="sm">ANALYSIS COMPLETE</Badge>
            ) : isScanning ? (
              <Badge variant="accent" size="sm" pulse>SCAN IN PROGRESS</Badge>
            ) : scanProgress > 0 ? (
              <Badge variant="warning" size="sm">PAUSED ({scanProgress}%)</Badge>
            ) : (
              <Badge variant="default" size="sm">READY TO INITIALIZE</Badge>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.25rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }} className="font-mono">
              SESSION: <strong style={{ color: 'var(--accent-text)' }}>{sessionId}</strong>
            </span>
            {currentScanId && (
              <>
                <span style={{ color: 'var(--border-strong)', fontSize: '0.75rem' }}>•</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }} className="font-mono">
                  SCAN: <strong style={{ color: 'var(--accent-text)' }}>{currentScanId.substring(0, 8)}…</strong>
                </span>
              </>
            )}
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

      {/* Scan Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
        {!isScanCompleted && !isScanning && (
          <Button
            variant="primary"
            size="sm"
            onClick={startScan}
            icon={<Play size={14} />}
          >
            START FORENSIC SCAN
          </Button>
        )}

        {isScanCompleted && (
          <Button
            variant="primary"
            size="sm"
            onClick={() => setPhase('results')}
          >
            VIEW VERDICT & EVIDENCE →
          </Button>
        )}
      </div>
    </div>
  );
};
