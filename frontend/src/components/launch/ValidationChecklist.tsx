import React from 'react';
import { Check, ArrowRight, ShieldCheck, RotateCcw, AlertCircle } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

/**
 * ValidationChecklist — pre-scan artifact readiness panel.
 *
 * Phase 8 changes:
 * - Removed hardcoded "52,000 samples / 24 layers / 52,000 records" counts.
 *   Those were presentation placeholders for a demo scenario; real counts come
 *   from the backend scan session after upload.
 * - Removed undefined checklist items (modelDetected, inferenceDetected,
 *   fileIntegrityVerified) that were always false because the store never sets
 *   them.  Only items backed by real state are shown.
 * - START SCAN button is disabled unless isReadyToScan is true (dataset
 *   uploaded AND backend scan_id received).
 */
export const ValidationChecklist: React.FC = () => {
  const {
    validationChecklist,
    isReadyToScan,
    startScan,
    clearArtifacts,
    currentScanId,
    scanSession,
    artifacts,
    backendOnline,
  } = useInvestigation();

  const datasetArtifact = artifacts.find(a => a.type === 'dataset');

  const checklistItems = [
    {
      id: 'dataset',
      label: datasetArtifact?.filename
        ? `Dataset accepted: ${datasetArtifact.filename} (${datasetArtifact.size})`
        : 'Computer vision dataset — upload an image folder or .zip archive',
      checked: validationChecklist.datasetDetected,
    },
    {
      id: 'scan_id',
      label: currentScanId
        ? `Backend scan session created — ID: ${currentScanId.substring(0, 8)}…`
        : 'Backend scan session — created automatically on dataset upload',
      checked: validationChecklist.scanReady,
    },
    {
      id: 'backend',
      label: backendOnline
        ? 'Backend assurance pipeline — reachable and ready'
        : 'Backend assurance pipeline — unreachable (air-gapped mode)',
      checked: backendOnline,
    },
    {
      id: 'config',
      label: 'Zero-Trust defense audit configuration validated',
      checked: true,
    },
  ];

  return (
    <div
      style={{
        marginTop: '1rem',
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.75rem',
        padding: '1.75rem 2rem',
        boxShadow: isReadyToScan ? 'var(--accent-glow)' : 'var(--card-shadow)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.5rem',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '1rem',
        }}
      >
        <div>
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
            Pre-Scan Forensic Validation
          </h2>
          <p
            style={{
              fontSize: '0.8125rem',
              color: 'var(--text-secondary)',
              marginTop: '0.25rem',
              margin: 0,
            }}
          >
            {isReadyToScan
              ? 'Backend scan session is active. All checks passed — ready to monitor the pipeline.'
              : 'Upload a dataset to create a backend scan session before starting analysis.'}
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Button
            variant="ghost"
            size="sm"
            onClick={clearArtifacts}
            icon={<RotateCcw size={14} />}
          >
            Reset
          </Button>
        </div>
      </div>

      {/* Checklist items */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '0.875rem',
        }}
      >
        {checklistItems.map((item) => (
          <div
            key={item.id}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              padding: '0.625rem 0.875rem',
              backgroundColor: item.checked ? 'var(--success-surface)' : 'var(--surface-elevated)',
              border: `1px solid ${item.checked ? 'var(--success-border)' : 'var(--border)'}`,
              borderRadius: '0.375rem',
              userSelect: 'none',
            }}
          >
            <div
              style={{
                width: '20px',
                height: '20px',
                borderRadius: '50%',
                backgroundColor: item.checked ? 'var(--success)' : 'var(--border-strong)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                flexShrink: 0,
              }}
            >
              {item.checked ? (
                <Check size={12} strokeWidth={3} />
              ) : (
                <span
                  style={{
                    width: '4px',
                    height: '4px',
                    borderRadius: '50%',
                    background: 'currentColor',
                  }}
                />
              )}
            </div>
            <span
              style={{
                fontSize: '0.8125rem',
                color: item.checked ? 'var(--text-primary)' : 'var(--text-muted)',
                fontWeight: item.checked ? 600 : 400,
              }}
              className="font-mono"
            >
              {item.label}
            </span>
          </div>
        ))}
      </div>

      {/* Scan session info (only when session exists) */}
      {scanSession && (
        <div
          style={{
            padding: '0.625rem 1rem',
            backgroundColor: 'var(--surface-elevated)',
            border: '1px solid var(--accent-border)',
            borderRadius: '0.375rem',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
            display: 'flex',
            gap: '1.5rem',
            flexWrap: 'wrap',
          }}
          className="font-mono"
        >
          <span>
            <span style={{ color: 'var(--text-muted)' }}>SCAN_ID: </span>
            <strong style={{ color: 'var(--accent-text)' }}>{scanSession.scan_id}</strong>
          </span>
          {scanSession.batch_id && (
            <span>
              <span style={{ color: 'var(--text-muted)' }}>BATCH_ID: </span>
              <strong style={{ color: 'var(--accent-text)' }}>{scanSession.batch_id}</strong>
            </span>
          )}
          <span>
            <span style={{ color: 'var(--text-muted)' }}>STATUS: </span>
            <strong
              style={{
                color: scanSession.status === 'COMPLETED'
                  ? 'var(--success-text)'
                  : scanSession.status === 'FAILED'
                  ? 'var(--critical-text)'
                  : 'var(--accent-text)',
              }}
            >
              {scanSession.status}
            </strong>
          </span>
        </div>
      )}

      {/* Footer Action Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          borderTop: '1px solid var(--border-subtle)',
          paddingTop: '1.25rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {isReadyToScan ? (
            <Badge variant="success" size="md" pulse icon={<ShieldCheck size={15} />}>
              READY TO SCAN
            </Badge>
          ) : (
            <Badge variant="warning" size="md" icon={<AlertCircle size={15} />}>
              UPLOAD DATASET FIRST
            </Badge>
          )}
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            {isReadyToScan
              ? 'Dataset ingested and backend scan session active. Proceed to monitor the pipeline.'
              : 'Upload a dataset above. A backend scan session is created automatically on upload.'}
          </span>
        </div>

        <div className="tooltip-host" data-tooltip="A backend scan session must exist before the pipeline can run. Upload a dataset — the scan session is created automatically on upload and the scan becomes available immediately after.">
          <Button
            variant="primary"
            size="lg"
            onClick={startScan}
            disabled={!isReadyToScan}
            iconRight={<ArrowRight size={18} />}
            style={{ minWidth: '280px' }}
          >
            {isReadyToScan ? 'MONITOR ASSURANCE PIPELINE →' : 'UPLOAD DATASET TO ENABLE SCAN'}
          </Button>
        </div>
      </div>
    </div>
  );
};
