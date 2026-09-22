import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { X, ShieldCheck, Server, Keyboard, SunMoon } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

/** Lightweight settings/about dialog opened from the command palette. */
export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const { backendOnline, sessionId, theme, toggleTheme } = useInvestigation();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const rows: Array<[string, string]> = [
    ['Session ID', sessionId],
    ['Backend status', backendOnline ? 'Connected (FastAPI)' : 'Air-gapped / offline'],
    ['Appearance', theme === 'dark' ? 'Dark' : 'Light'],
    ['Version', 'TRUST-CV v2.4 (Offline SOC Defense)'],
  ];

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 10001,
        backgroundColor: 'rgba(5, 6, 8, 0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
      }}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.18, ease: 'easeOut' }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-label="Settings"
        className="glass-card"
        style={{
          width: '100%',
          maxWidth: '480px',
          borderRadius: '12px',
          overflow: 'hidden',
          borderColor: 'var(--border-strong)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '16px 20px',
            borderBottom: '1px solid var(--border)',
          }}
        >
          <h2 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            Settings
          </h2>
          <button
            onClick={onClose}
            aria-label="Close settings"
            style={{
              background: 'transparent',
              border: '1px solid var(--border)',
              borderRadius: '0.375rem',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              padding: '0.375rem',
              display: 'flex',
            }}
          >
            <X size={16} strokeWidth={1.5} />
          </button>
        </div>

        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {rows.map(([label, value]) => (
            <div
              key={label}
              style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', fontSize: '13px' }}
            >
              <span style={{ color: 'var(--text-muted)' }}>{label}</span>
              <span
                className={label === 'Session ID' ? 'font-mono' : undefined}
                style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}
              >
                {value}
              </span>
            </div>
          ))}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '12px',
              backgroundColor: 'var(--surface-elevated)',
              border: '1px solid var(--border)',
              borderRadius: '0.375rem',
              fontSize: '12px',
              color: 'var(--text-secondary)',
            }}
          >
            <Keyboard size={14} strokeWidth={1.5} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
            <span>
              Press <kbd className="font-mono">⌘K</kbd> / <kbd className="font-mono">Ctrl+K</kbd> anywhere to open the
              command palette.
            </span>
          </div>

          <div style={{ display: 'flex', gap: '8px', marginTop: '4px' }}>
            <button
              onClick={toggleTheme}
              style={{
                flex: 1,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                padding: '0.5rem',
                background: 'var(--surface-elevated)',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
                color: 'var(--text-primary)',
                cursor: 'pointer',
                fontSize: '12px',
                fontWeight: 500,
              }}
            >
              <SunMoon size={13} strokeWidth={1.5} />
              Toggle {theme === 'dark' ? 'light' : 'dark'} mode
            </button>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '12px',
              color: 'var(--text-muted)',
            }}
          >
            {backendOnline ? (
              <Server size={12} strokeWidth={1.5} style={{ color: 'var(--success-text)' }} />
            ) : (
              <ShieldCheck size={12} strokeWidth={1.5} style={{ color: 'var(--warning-text)' }} />
            )}
            All verdicts are produced by the backend assurance pipeline — this dialog displays session metadata only.
          </div>
        </div>
      </motion.div>
    </div>
  );
};
