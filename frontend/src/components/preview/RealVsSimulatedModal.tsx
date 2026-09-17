import React from 'react';
import { X, CheckCircle2, AlertTriangle, Shield, Cpu, Binary, Eye } from 'lucide-react';

interface RealVsSimulatedModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const RealVsSimulatedModal: React.FC<RealVsSimulatedModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(3, 7, 18, 0.82)',
        backdropFilter: 'blur(8px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem',
      }}
      onClick={onClose}
    >
      <div
        style={{
          backgroundColor: '#090e1a',
          border: '1px solid #1e293b',
          borderRadius: '0.75rem',
          maxWidth: '740px',
          width: '100%',
          maxHeight: '90vh',
          overflowY: 'auto',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 242, 255, 0.1)',
          padding: '1.75rem',
          color: '#e2e8f0',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '0.5rem',
                backgroundColor: 'rgba(0, 242, 255, 0.12)',
                border: '1px solid rgba(0, 242, 255, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#00f2ff',
              }}
            >
              <Shield size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>
                TRUST-CV Architecture: Real vs. Simulated
              </h2>
              <span style={{ fontSize: '0.8125rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                Air-Gapped Client-Side Execution Details
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '0.25rem',
              borderRadius: '0.25rem',
              display: 'flex',
            }}
          >
            <X size={20} />
          </button>
        </div>

        <p style={{ fontSize: '0.875rem', color: '#cbd5e1', lineHeight: 1.6, marginBottom: '1.5rem' }}>
          This browser preview runs a standalone cryptographic and forensic verification engine locally in your browser
          without sending any imagery, models, or telemetry outside your machine.
        </p>

        {/* Comparison Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.25rem' }}>
          {/* Real Locally-Computed */}
          <div
            style={{
              backgroundColor: 'rgba(16, 185, 129, 0.05)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              borderRadius: '0.5rem',
              padding: '1.25rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.875rem' }}>
              <CheckCircle2 size={18} color="#10b981" />
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#34d399', margin: 0 }}>
                100% Real Locally-Computed
              </h3>
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8125rem', color: '#cbd5e1' }}>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <Binary size={15} color="#10b981" style={{ minWidth: '15px', marginTop: '2px' }} />
                <span><strong>SHA-256 Checksums:</strong> Web Crypto API executes cryptographic digests on dataset files, models, and inputs.</span>
              </li>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <Eye size={15} color="#10b981" style={{ minWidth: '15px', marginTop: '2px' }} />
                <span><strong>Laplacian Blur Analysis:</strong> Canvas pixel convolution 3x3 Laplacian edge kernel calculates true variance (&sigma;<sup>2</sup>).</span>
              </li>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <Binary size={15} color="#10b981" style={{ minWidth: '15px', marginTop: '2px' }} />
                <span><strong>Perceptual Difference Hashing (dHash):</strong> 8x8 discrete grayscale gradients detect exact and near-duplicate frames.</span>
              </li>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <Cpu size={15} color="#10b981" style={{ minWidth: '15px', marginTop: '2px' }} />
                <span><strong>Contributor Aggregation:</strong> Extracts <code>contributor__filename</code> prefixes to build contributor risk attributions.</span>
              </li>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <Shield size={15} color="#10b981" style={{ minWidth: '15px', marginTop: '2px' }} />
                <span><strong>Hash-Chained Audit Ledger:</strong> Sequential append-only blocks H<sub>i</sub> = SHA256(i || ts || digest || H<sub>i-1</sub>) with live tamper detection.</span>
              </li>
            </ul>
          </div>

          {/* Simulated or Unavailable */}
          <div
            style={{
              backgroundColor: 'rgba(239, 68, 68, 0.05)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              borderRadius: '0.5rem',
              padding: '1.25rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.875rem' }}>
              <AlertTriangle size={18} color="#ef4444" />
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#f87171', margin: 0 }}>
                Simulated / Requires Full GPU Backend
              </h3>
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.8125rem', color: '#cbd5e1' }}>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <span style={{ color: '#ef4444', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[SIM]</span>
                <span><strong>Model Behavioral Fingerprinting:</strong> Deterministic synthetic probe battery on GPU (requires full ONNX Runtime / PyTorch).</span>
              </li>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <span style={{ color: '#ef4444', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[SIM]</span>
                <span><strong>Live Target Detection Inference:</strong> Forward pass bounding box regression and class probability vectors.</span>
              </li>
              <li style={{ display: 'flex', gap: '0.5rem' }}>
                <span style={{ color: '#ef4444', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[SIM]</span>
                <span><strong>Distribution-Shift Drift Analysis:</strong> Wasserstein and Kolmogorov-Smirnov distance matrix over large spatial tensor corpora.</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div style={{ marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid #1e293b', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            onClick={onClose}
            style={{
              backgroundColor: '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: '0.375rem',
              padding: '0.5rem 1.25rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Acknowledge & Close
          </button>
        </div>
      </div>
    </div>
  );
};
