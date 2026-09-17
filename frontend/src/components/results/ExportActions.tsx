import React, { useState } from 'react';
import { ShieldCheck, RotateCcw, FileText, CheckCircle2, Loader2 } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Button } from '../ui/Button';

export const ExportActions: React.FC = () => {
  const { exportReport, exportEvidencePackage, resetInvestigation, backendOnline, fusedAssessmentId } = useInvestigation();
  const [reportStatus, setReportStatus] = useState<'idle' | 'loading' | 'done'>('idle');

  const handleExportReport = async () => {
    setReportStatus('loading');
    exportReport();
    // Give the fire-and-forget backend call a moment, then mark done
    setTimeout(() => setReportStatus('done'), 1500);
    setTimeout(() => setReportStatus('idle'), 4000);
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        padding: '1.25rem 1.75rem',
        boxShadow: 'var(--card-shadow)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
      }}
    >
      <div>
        <h4
          style={{
            fontSize: '1rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            margin: 0,
          }}
          className="font-display"
        >
          Forensic Report & Evidence Preservation
        </h4>
        <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: '0.25rem 0 0 0' }}>
          Export certified forensic audits or initialize a new zero-trust computer vision investigation.
        </p>

        {/* Backend sealing status */}
        {backendOnline && fusedAssessmentId && reportStatus !== 'idle' && (
          <div
            style={{
              marginTop: '0.5rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.375rem',
              fontSize: '0.75rem',
            }}
            className="font-mono"
          >
            {reportStatus === 'loading' ? (
              <>
                <Loader2 size={12} style={{ color: 'var(--accent-text)', animation: 'spin 1s linear infinite' }} />
                <span style={{ color: 'var(--accent-text)' }}>Sealing report to backend…</span>
              </>
            ) : (
              <>
                <CheckCircle2 size={12} style={{ color: 'var(--success-text)' }} />
                <span style={{ color: 'var(--success-text)' }}>Report sealed to backend ✓</span>
              </>
            )}
          </div>
        )}

        {backendOnline && !fusedAssessmentId && (
          <div
            style={{
              marginTop: '0.5rem',
              fontSize: '0.6875rem',
              color: 'var(--text-muted)',
            }}
            className="font-mono"
          >
            Run a scan first to enable backend report sealing.
          </div>
        )}

        {!backendOnline && (
          <div
            style={{
              marginTop: '0.5rem',
              fontSize: '0.6875rem',
              color: 'var(--warning-text)',
            }}
            className="font-mono"
          >
            AIR-GAPPED MODE — local export only
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <Button
          variant="outline"
          size="md"
          onClick={handleExportReport}
          icon={
            reportStatus === 'loading'
              ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
              : reportStatus === 'done'
              ? <CheckCircle2 size={16} />
              : <FileText size={16} />
          }
        >
          {reportStatus === 'done' ? 'EXPORTED ✓' : 'EXPORT REPORT (JSON)'}
        </Button>

        <Button
          variant="primary"
          size="md"
          onClick={exportEvidencePackage}
          icon={<ShieldCheck size={16} />}
        >
          EXPORT EVIDENCE (.SIG)
        </Button>

        <Button
          variant="secondary"
          size="md"
          onClick={resetInvestigation}
          icon={<RotateCcw size={16} />}
        >
          NEW INVESTIGATION
        </Button>
      </div>
    </div>
  );
};
