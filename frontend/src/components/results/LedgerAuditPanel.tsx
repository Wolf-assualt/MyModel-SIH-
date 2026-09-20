import React from 'react';
import { ShieldCheck, ShieldX, Loader2, RefreshCw, Link2 } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

/**
 * Tamper-Evident Assurance Ledger verification panel.
 *
 * Displays ONLY the verification result returned by the backend ledger API.
 * The frontend performs no local hash-chain calculation and never claims the
 * ledger is valid on its own.
 */
export const LedgerAuditPanel: React.FC = () => {
  const { ledgerVerification, refreshLedgerVerification, backendOnline } = useInvestigation();
  const [busy, setBusy] = React.useState(false);

  const handleRefresh = async () => {
    setBusy(true);
    try {
      await refreshLedgerVerification();
    } finally {
      setBusy(false);
    }
  };

  const state: 'VALID' | 'INVALID' | 'UNAVAILABLE' =
    ledgerVerification?.valid === true ? 'VALID'
      : ledgerVerification?.valid === false ? 'INVALID'
      : 'UNAVAILABLE';

  const rows: Array<[string, string]> = [
    ['Verification status', state],
    ['Events checked', ledgerVerification ? String(ledgerVerification.events_checked) : 'UNAVAILABLE'],
    ['Last verified sequence', ledgerVerification ? String(ledgerVerification.last_verified_sequence) : 'UNAVAILABLE'],
    ['First invalid sequence', ledgerVerification?.first_invalid_sequence != null ? String(ledgerVerification.first_invalid_sequence) : 'NONE / UNAVAILABLE'],
    ['Failure reason', ledgerVerification?.failure_reason ?? 'NONE / UNAVAILABLE'],
  ];

  return (
    <section
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        padding: '1.5rem',
        boxShadow: 'var(--card-shadow)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Link2 size={18} style={{ color: 'var(--accent-text)' }} />
          <h3
            style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.04em', textTransform: 'uppercase', margin: 0 }}
            className="font-display"
          >
            Tamper-Evident Assurance Ledger
          </h3>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {state === 'VALID' && (
            <Badge variant="success" size="sm" icon={<ShieldCheck size={12} />}>BACKEND: VALID</Badge>
          )}
          {state === 'INVALID' && (
            <Badge variant="critical" size="sm" icon={<ShieldX size={12} />}>BACKEND: INVALID</Badge>
          )}
          {state === 'UNAVAILABLE' && (
            <Badge variant="warning" size="sm">UNAVAILABLE</Badge>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={busy}
            icon={busy ? <Loader2 size={13} /> : <RefreshCw size={13} />}
          >
            {busy ? 'VERIFYING…' : 'RE-VERIFY CHAIN'}
          </Button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }} className="font-mono">
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', fontSize: '0.75rem' }}>
            <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.6875rem' }}>{label}</span>
            <span
              style={{
                color: value.includes('UNAVAILABLE')
                  ? 'var(--warning-text)'
                  : state === 'INVALID'
                  ? 'var(--critical-text)'
                  : 'var(--text-primary)',
                wordBreak: 'break-all',
                textAlign: 'right',
              }}
            >
              {value}
            </span>
          </div>
        ))}
      </div>

      <div
        style={{
          padding: '0.75rem 1rem',
          backgroundColor: 'var(--surface-elevated)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '0.375rem',
          fontSize: '0.75rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
        }}
      >
        {state === 'UNAVAILABLE'
          ? backendOnline
            ? 'The backend ledger has not been verified for this investigation. No validity claim is made by this client.'
            : 'Ledger verification UNAVAILABLE — the backend is unreachable. No validity claim is made by this client.'
          : 'Verification performed by the backend hash-chain auditor (ECDSA SECP256R1 / SHA-256). The frontend reproduces none of this logic.'}
      </div>
    </section>
  );
};
