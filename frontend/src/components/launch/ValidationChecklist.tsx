import React from 'react';
import { Check, ArrowRight, ShieldCheck, RotateCcw, AlertCircle } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

export const ValidationChecklist: React.FC = () => {
  const {
    validationChecklist,
    isReadyToScan,
    startScan,
    clearArtifacts,
    verifyArtifact,
    artifacts,
  } = useInvestigation();

  const checklistItems = [
    {
      id: 'dataset',
      label: 'Computer vision dataset detected (52,000 samples)',
      checked: validationChecklist.datasetDetected,
      artifactId: artifacts.find(a => a.type === 'dataset')?.id || 'art-dataset',
    },
    {
      id: 'model',
      label: 'Target ONNX model detected (24 neural layers)',
      checked: validationChecklist.modelDetected,
      artifactId: artifacts.find(a => a.type === 'model')?.id || 'art-model',
    },
    {
      id: 'inference',
      label: 'Inference telemetry outputs detected (52,000 records)',
      checked: validationChecklist.inferenceDetected,
      artifactId: artifacts.find(a => a.type === 'inference')?.id || 'art-inference',
    },
    {
      id: 'integrity',
      label: 'Air-gapped file SHA-256 integrity verified',
      checked: validationChecklist.fileIntegrityVerified,
      artifactId: artifacts.find(a => a.type === 'manifest')?.id || 'art-manifest',
    },
    {
      id: 'config',
      label: 'Zero-Trust defense audit configuration validated',
      checked: validationChecklist.configValidated,
      artifactId: null,
    },
  ];

  const handleItemClick = (item: typeof checklistItems[0]) => {
    if (item.artifactId) {
      verifyArtifact(item.artifactId);
    } else {
      verifyArtifact('art-dataset');
    }
  };

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
            All artifacts satisfy zero-trust checksum assertions. Click any item to verify individually.
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

      {/* Checklist grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '0.875rem',
        }}
      >
        {checklistItems.map((item, index) => (
          <div
            key={index}
            onClick={() => handleItemClick(item)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              padding: '0.625rem 0.875rem',
              backgroundColor: item.checked ? 'var(--success-surface)' : 'var(--surface-elevated)',
              border: `1px solid ${item.checked ? 'var(--success-border)' : 'var(--border)'}`,
              borderRadius: '0.375rem',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              userSelect: 'none',
            }}
            title={item.checked ? 'Verified ✓ (Click to re-validate)' : 'Click to quickly verify'}
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
                <span style={{ width: '4px', height: '4px', borderRadius: '50%', background: 'currentColor' }} />
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
              READY FOR INGESTION
            </Badge>
          )}
          <span
            style={{
              fontSize: '0.8125rem',
              color: 'var(--text-secondary)',
            }}
          >
            {isReadyToScan
              ? 'All mission artifacts verified. Ready to launch 11-stage forensic kernel.'
              : 'Click "Initialize Scan" to auto-verify and run, or upload files above.'}
          </span>
        </div>

        <Button
          variant="primary"
          size="lg"
          onClick={startScan}
          iconRight={<ArrowRight size={18} />}
          style={{
            minWidth: '280px',
          }}
        >
          {isReadyToScan ? 'INITIALIZE INTEGRITY SCAN →' : '⚡ INITIALIZE SCAN (AUTO-VERIFY) →'}
        </Button>
      </div>
    </div>
  );
};
