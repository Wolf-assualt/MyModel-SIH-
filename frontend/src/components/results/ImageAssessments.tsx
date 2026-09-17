import React from 'react';
import { CheckCircle2, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { ImageAssessment } from '../../services/api';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

const resultColor = (result: ImageAssessment['result']) => {
  if (result === 'POISONED / ALTERED') return 'var(--critical-text)';
  if (result === 'SUSPICIOUS') return 'var(--warning-text)';
  return 'var(--success-text)';
};

export const ImageAssessments: React.FC = () => {
  const { imageResults, quarantineImage } = useInvestigation();
  const [busy, setBusy] = React.useState<string | null>(null);
  if (!imageResults.length) return null;

  const handleQuarantine = async (image: ImageAssessment) => {
    setBusy(image.sample_id);
    try {
      await quarantineImage(image.sample_id);
    } finally {
      setBusy(null);
    }
  };

  return (
    <section style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div>
        <h3 style={{ margin: 0, color: 'var(--text-primary)' }} className="font-display">Per-Image Trust Assessments</h3>
        <p style={{ margin: '0.25rem 0 0', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
          Individual integrity results from the backend evidence pipeline.
        </p>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
        {imageResults.map(image => (
          <article key={image.sample_id} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '0.5rem', overflow: 'hidden' }}>
            {image.preview_data_url ? (
              <img src={image.preview_data_url} alt={image.file_name} style={{ width: '100%', height: 180, objectFit: 'contain', background: 'var(--surface-elevated)' }} />
            ) : (
              <div style={{ height: 180, display: 'grid', placeItems: 'center', color: 'var(--text-muted)', background: 'var(--surface-elevated)' }}>Preview unavailable</div>
            )}
            <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
              <strong style={{ color: 'var(--text-primary)', overflowWrap: 'anywhere' }}>{image.file_name}</strong>
              <div style={{ color: resultColor(image.result), fontWeight: 800 }}>{image.result}</div>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                <Badge variant={image.integrity_status === 'PASS' ? 'success' : 'critical'} size="sm" icon={image.integrity_status === 'PASS' ? <CheckCircle2 size={12} /> : <ShieldAlert size={12} />}>
                  Integrity: {image.integrity_status}
                </Badge>
                <Badge variant={image.trust_status === 'VERIFIED' ? 'success' : 'warning'} size="sm" icon={<ShieldCheck size={12} />}>
                  Trust: {image.trust_status}
                </Badge>
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', overflowWrap: 'anywhere' }} className="font-mono">Trust Fingerprint<br />SHA256: {image.sha256_hash}</div>
              {image.anomaly_score !== null && <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Measured anomaly score: {image.anomaly_score.toFixed(3)}</div>}
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}><strong>Evidence:</strong> {image.evidence.length ? image.evidence.join(' ') : 'No integrity anomaly detected.'}</div>
              {image.quarantined ? (
                <div style={{ color: 'var(--critical-text)', fontWeight: 800 }}><LockKeyhole size={15} style={{ verticalAlign: 'middle' }} /> QUARANTINED<br /><span style={{ fontWeight: 400 }}>Status: BLOCKED | Trust: REVOKED | Action: Excluded from inference</span></div>
              ) : image.action === 'QUARANTINE' ? (
                <Button variant="danger" size="sm" onClick={() => handleQuarantine(image)} disabled={busy === image.sample_id} icon={<LockKeyhole size={14} />}>{busy === image.sample_id ? 'QUARANTINING...' : 'QUARANTINE'}</Button>
              ) : <div style={{ color: 'var(--success-text)', fontSize: '0.8rem' }}>Action: Allowed after verification</div>}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
};
