import React from 'react';
import { ShieldCheck, Database, Cpu, Binary } from 'lucide-react';
import { Badge } from '../ui/Badge';

export const HeroSection: React.FC = () => {
  return (
    <section
      style={{
        padding: '2.5rem 0 2rem 0',
        textAlign: 'center',
        position: 'relative',
      }}
    >
      <div style={{ display: 'inline-flex', marginBottom: '1rem' }}>
        <Badge variant="accent" size="md" pulse>
          FORENSIC INTEGRITY ASSURANCE PROTOCOL
        </Badge>
      </div>

      <h1
        style={{
          fontSize: '2.75rem',
          fontWeight: 700,
          color: 'var(--text-primary)',
          letterSpacing: '0.02em',
          lineHeight: 1.15,
          marginBottom: '1rem',
        }}
        className="font-display"
      >
        Establish Trust Before Inference.
      </h1>

      <p
        style={{
          fontSize: '1.0625rem',
          color: 'var(--text-secondary)',
          maxWidth: '780px',
          margin: '0 auto 1.75rem auto',
          lineHeight: 1.6,
        }}
      >
        Inspect computer-vision datasets, neural network weights, and inference outputs for
        clean-label poisoning, trigger backdoors, adversarial tampering, and evidence-chain inconsistencies
        before deployment to mission-critical systems.
      </p>

      {/* Zero-Trust Pillars */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            backgroundColor: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
          }}
        >
          <Database size={15} style={{ color: 'var(--accent-text)' }} />
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
            Dataset Poisoning & OOD
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            backgroundColor: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
          }}
        >
          <Cpu size={15} style={{ color: 'var(--success-text)' }} />
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
            Weight Hash Verification
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            backgroundColor: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
          }}
        >
          <Binary size={15} style={{ color: 'var(--warning-text)' }} />
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
            Inference Anomaly Probe
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            backgroundColor: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
          }}
        >
          <ShieldCheck size={15} style={{ color: 'var(--accent-text)' }} />
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
            Directed Evidence Graph
          </span>
        </div>
      </div>
    </section>
  );
};
