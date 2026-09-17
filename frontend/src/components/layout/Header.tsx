import React from 'react';
import { ShieldAlert, Sun, Moon } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { Badge } from '../ui/Badge';
import { BackendStatus } from '../ui/BackendStatus';

export const Header: React.FC = () => {
  const { phase, setPhase, theme, toggleTheme, sessionId, isScanning, backendOnline } = useInvestigation();

  return (
    <header
      style={{
        backgroundColor: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        padding: '0.75rem 2rem',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        backdropFilter: 'blur(12px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1.5rem',
      }}
    >
      {/* Brand Identity */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div
          style={{
            width: '40px',
            height: '40px',
            borderRadius: '0.5rem',
            background: 'linear-gradient(135deg, var(--accent), #1d4ed8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--accent-glow)',
            color: '#ffffff',
          }}
        >
          <ShieldAlert size={22} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span
              style={{
                fontSize: '1.125rem',
                fontWeight: 700,
                color: 'var(--accent-text)',
                letterSpacing: '0.05em',
              }}
              className="font-mono"
            >
              TRUST-CV
            </span>
            <Badge variant="accent" size="sm">
              DEFENSE SOC
            </Badge>
            <span
              style={{
                fontSize: '0.75rem',
                color: 'var(--text-muted)',
              }}
              className="font-mono"
            >
              {sessionId}
            </span>
          </div>
          <p
            style={{
              fontSize: '0.75rem',
              color: 'var(--text-tertiary)',
              letterSpacing: '-0.01em',
              margin: 0,
            }}
          >
            Zero-Trust Computer Vision Integrity Assurance & Forensic Platform
          </p>
        </div>
      </div>

      {/* Center: Phase Navigation Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          backgroundColor: 'var(--surface-elevated)',
          border: '1px solid var(--border)',
          borderRadius: '0.5rem',
          padding: '0.25rem',
          gap: '0.25rem',
        }}
      >
        <button
          onClick={() => setPhase('launch')}
          style={{
            padding: '0.375rem 0.875rem',
            borderRadius: '0.375rem',
            border: 'none',
            fontSize: '0.8125rem',
            fontWeight: phase === 'launch' ? 600 : 500,
            backgroundColor: phase === 'launch' ? 'var(--accent-surface)' : 'transparent',
            color: phase === 'launch' ? 'var(--accent-text)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
          className="font-mono"
        >
          <span style={{ opacity: 0.6 }}>01</span> LAUNCH
        </button>

        <span style={{ color: 'var(--border-strong)', fontSize: '0.75rem' }}>/</span>

        <button
          onClick={() => setPhase('scan')}
          style={{
            padding: '0.375rem 0.875rem',
            borderRadius: '0.375rem',
            border: 'none',
            fontSize: '0.8125rem',
            fontWeight: phase === 'scan' ? 600 : 500,
            backgroundColor: phase === 'scan' ? 'var(--accent-surface)' : 'transparent',
            color: phase === 'scan' ? 'var(--accent-text)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
          className="font-mono"
        >
          <span style={{ opacity: 0.6 }}>02</span> SCAN
          {isScanning && (
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: 'var(--accent)',
                display: 'inline-block',
                animation: 'ping-subtle 1.2s infinite ease-in-out',
              }}
            />
          )}
        </button>

        <span style={{ color: 'var(--border-strong)', fontSize: '0.75rem' }}>/</span>

        <button
          onClick={() => setPhase('results')}
          style={{
            padding: '0.375rem 0.875rem',
            borderRadius: '0.375rem',
            border: 'none',
            fontSize: '0.8125rem',
            fontWeight: phase === 'results' ? 600 : 500,
            backgroundColor: phase === 'results' ? 'var(--accent-surface)' : 'transparent',
            color: phase === 'results' ? 'var(--accent-text)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
          className="font-mono"
        >
          <span style={{ opacity: 0.6 }}>03</span> RESULTS
        </button>
      </div>

      {/* Right Controls: Air-Gap Indicator + Theme Switcher */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {/* Backend Status Indicator */}
        <BackendStatus online={backendOnline} />

        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.45rem 0.75rem',
            backgroundColor: 'var(--surface-elevated)',
            border: '1px solid var(--border)',
            borderRadius: '0.375rem',
            color: 'var(--text-primary)',
            cursor: 'pointer',
            fontSize: '0.8125rem',
            transition: 'all 0.2s ease',
          }}
          className="font-mono"
          aria-label="Toggle Light and Dark Theme"
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
        >
          {theme === 'dark' ? (
            <>
              <Sun size={15} style={{ color: '#fbbf24' }} />
              <span style={{ fontWeight: 600 }}>LIGHT</span>
            </>
          ) : (
            <>
              <Moon size={15} style={{ color: '#0284c7' }} />
              <span style={{ fontWeight: 600 }}>DARK</span>
            </>
          )}
        </button>
      </div>
    </header>
  );
};
