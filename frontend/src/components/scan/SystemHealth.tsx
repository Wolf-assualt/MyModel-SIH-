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
          paddingBottom: '0.625rem',
        }}
      >
        <h3
          style={{
            fontSize: '0.875rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            margin: 0,
          }}
          className="font-display"
        >
          Forensic Host Telemetry
        </h3>
        <span
          style={{
            fontSize: '0.6875rem',
            color: backendOnline ? 'var(--success-text)' : 'var(--warning-text)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
          className="font-mono"
        >
          <ShieldCheck size={13} style={{ color: backendOnline ? 'var(--success-text)' : 'var(--warning-text)' }} />
          {backendOnline ? 'BACKEND LIVE' : 'AIR-GAP ENCLAVE'}
        </span>
      </div>

      {/* Hardware Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
        {/* CPU */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.375rem' }} className="font-mono">
              <Cpu size={13} style={{ color: 'var(--accent-text)' }} />
              AVX-512 CPU Cores
            </span>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }} className="font-mono">
              42% LOAD
            </span>
          </div>
          <div style={{ height: '6px', backgroundColor: 'var(--surface-active)', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{ width: '42%', height: '100%', backgroundColor: 'var(--accent)' }} />
          </div>
        </div>

        {/* Memory */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.375rem' }} className="font-mono">
              <HardDrive size={13} style={{ color: 'var(--info-text)' }} />
              ECC Memory Enclave
            </span>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }} className="font-mono">
              3.8 / 16 GB
            </span>
          </div>
          <div style={{ height: '6px', backgroundColor: 'var(--surface-active)', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{ width: '24%', height: '100%', backgroundColor: 'var(--info)' }} />
          </div>
        </div>

        {/* Hardware Acceleration */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.375rem' }} className="font-mono">
              <Zap size={13} style={{ color: 'var(--success-text)' }} />
              SHA-NI Crypto Engine
            </span>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--success-text)' }} className="font-mono">
              3.2 GB/s ACTIVE
            </span>
          </div>
          <div style={{ height: '6px', backgroundColor: 'var(--surface-active)', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{ width: '78%', height: '100%', backgroundColor: 'var(--success)' }} />
          </div>
        </div>
      </div>

      {/* Live Backend Overview (only shown when backend is online) */}
      {backendOnline && backendOverview && (
        <div
          style={{
            marginTop: '1rem',
            paddingTop: '0.875rem',
            borderTop: '1px solid var(--border-subtle)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: '0.75rem',
          }}
        >
          {/* Datasets */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Database size={14} style={{ color: 'var(--accent-text)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', letterSpacing: '0.04em' }} className="font-mono">
                DATASETS
              </div>
              <div style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }} className="font-mono">
                {backendOverview.total_datasets}
              </div>
            </div>
          </div>

          {/* Models */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Server size={14} style={{ color: 'var(--success-text)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', letterSpacing: '0.04em' }} className="font-mono">
                MODELS
              </div>
              <div style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }} className="font-mono">
                {backendOverview.total_models}
              </div>
            </div>
          </div>

          {/* Quarantined */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={14} style={{ color: backendOverview.quarantined_assets > 0 ? 'var(--critical-text)' : 'var(--text-muted)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', letterSpacing: '0.04em' }} className="font-mono">
                QUARANTINED
              </div>
              <div
                style={{
                  fontSize: '0.875rem',
                  fontWeight: 700,
                  color: backendOverview.quarantined_assets > 0 ? 'var(--critical-text)' : 'var(--success-text)',
                }}
                className="font-mono"
              >
                {backendOverview.quarantined_assets}
              </div>
            </div>
          </div>

          {/* System Status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={14} style={{ color: 'var(--success-text)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', letterSpacing: '0.04em' }} className="font-mono">
                INTEGRITY
              </div>
              <div
                style={{
                  fontSize: '0.6875rem',
                  fontWeight: 700,
                  color: backendOverview.system_integrity_status === 'OPERATIONAL'
                    ? 'var(--success-text)'
                    : backendOverview.system_integrity_status === 'ELEVATED_RISK'
                    ? 'var(--warning-text)'
                    : 'var(--critical-text)',
                }}
                className="font-mono"
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
