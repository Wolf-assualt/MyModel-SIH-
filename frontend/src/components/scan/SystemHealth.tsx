import React from 'react';
import { Cpu, HardDrive, ShieldCheck, Zap, Database, Server, AlertTriangle } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';

export const SystemHealth: React.FC = () => {
  const { backendOnline, backendOverview } = useInvestigation();

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
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '16px',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '12px',
        }}
      >
        <h3
          style={{
            fontSize: '0.875rem',
            fontWeight: 600,
            color: 'var(--text-primary)',
            margin: 0,
          }}
        >
          Forensic Host Telemetry
        </h3>
        <span
          style={{
            fontSize: '12px',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <span
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              backgroundColor: backendOnline ? 'var(--success)' : 'var(--warning)',
              display: 'inline-block',
            }}
            aria-hidden="true"
          />
          {backendOnline ? 'Backend live' : 'Air-gap enclave'}
        </span>
      </div>

      {/* Hardware Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
        {/* CPU */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Cpu size={13} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />
              AVX-512 CPU cores
            </span>
            <span className="font-mono" style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>
              42% load
            </span>
          </div>
          <div style={{ height: '4px', backgroundColor: 'var(--surface-active)', borderRadius: '2px', overflow: 'hidden' }}>
            <div style={{ width: '42%', height: '100%', backgroundColor: 'var(--accent)' }} />
          </div>
        </div>

        {/* Memory */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <HardDrive size={13} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />
              ECC memory enclave
            </span>
            <span className="font-mono" style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>
              3.8 / 16 GB
            </span>
          </div>
          <div style={{ height: '4px', backgroundColor: 'var(--surface-active)', borderRadius: '2px', overflow: 'hidden' }}>
            <div style={{ width: '24%', height: '100%', backgroundColor: 'var(--accent)', opacity: 0.6 }} />
          </div>
        </div>

        {/* Hardware Acceleration */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Zap size={13} strokeWidth={1.5} style={{ color: 'var(--text-muted)' }} />
              SHA-NI crypto engine
            </span>
            <span className="font-mono" style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>
              3.2 GB/s
            </span>
          </div>
          <div style={{ height: '4px', backgroundColor: 'var(--surface-active)', borderRadius: '2px', overflow: 'hidden' }}>
            <div style={{ width: '78%', height: '100%', backgroundColor: 'var(--accent)', opacity: 0.6 }} />
          </div>
        </div>
      </div>

      {/* Live Backend Overview (only shown when backend is online) */}
      {backendOnline && backendOverview && (
        <div
          style={{
            marginTop: '16px',
            paddingTop: '16px',
            borderTop: '1px solid var(--border-subtle)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: '12px',
          }}
        >
          {/* Datasets */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Database size={14} strokeWidth={1.5} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
                Datasets
              </div>
              <div className="font-mono" style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {backendOverview.total_datasets}
              </div>
            </div>
          </div>

          {/* Models */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={14} strokeWidth={1.5} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
                Models
              </div>
              <div className="font-mono" style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {backendOverview.total_models}
              </div>
            </div>
          </div>

          {/* Quarantined */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={14} strokeWidth={1.5} style={{ color: backendOverview.quarantined_assets > 0 ? 'var(--warning-text)' : 'var(--text-muted)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
                Quarantined
              </div>
              <div
                className="font-mono"
                style={{
                  fontSize: '0.875rem',
                  fontWeight: 500,
                  color: backendOverview.quarantined_assets > 0 ? 'var(--warning-text)' : 'var(--text-primary)',
                }}
              >
                {backendOverview.quarantined_assets}
              </div>
            </div>
          </div>

          {/* System Status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={14} strokeWidth={1.5} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
                Integrity
              </div>
              <div
                style={{
                  fontSize: '12px',
                  fontWeight: 500,
                  color:
                    backendOverview.system_integrity_status === 'OPERATIONAL'
                      ? 'var(--success-text)'
                      : backendOverview.system_integrity_status === 'ELEVATED_RISK'
                      ? 'var(--warning-text)'
                      : 'var(--critical-text)',
                }}
              >
                {backendOverview.system_integrity_status}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
