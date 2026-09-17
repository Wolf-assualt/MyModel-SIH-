import React, { useState, useEffect, useRef } from 'react';
import { Terminal, ArrowDown } from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import type { TerminalLog as LogType } from '../../types/investigation';

export const TerminalLog: React.FC = () => {
  const { terminalLogs } = useInvestigation();
  const [filterLevel, setFilterLevel] = useState<'ALL' | 'INFO' | 'WARN' | 'CRIT' | 'PASS'>('ALL');
  const [autoScroll, setAutoScroll] = useState(true);
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLogs, autoScroll]);

  const filteredLogs = terminalLogs.filter(log => {
    if (filterLevel === 'ALL') return true;
    return log.level === filterLevel;
  });

  const getLevelBadge = (level: LogType['level']) => {
    switch (level) {
      case 'CRIT':
        return (
          <span
            style={{
              padding: '1px 5px',
              backgroundColor: 'var(--critical-surface)',
              border: '1px solid var(--critical-border)',
              color: 'var(--critical-text)',
              fontSize: '10px',
              fontWeight: 700,
              borderRadius: '2px',
            }}
          >
            CRIT
          </span>
        );
      case 'WARN':
        return (
          <span
            style={{
              padding: '1px 5px',
              backgroundColor: 'var(--warning-surface)',
              border: '1px solid var(--warning-border)',
              color: 'var(--warning-text)',
              fontSize: '10px',
              fontWeight: 700,
              borderRadius: '2px',
            }}
          >
            WARN
          </span>
        );
      case 'PASS':
        return (
          <span
            style={{
              padding: '1px 5px',
              backgroundColor: 'var(--success-surface)',
              border: '1px solid var(--success-border)',
              color: 'var(--success-text)',
              fontSize: '10px',
              fontWeight: 700,
              borderRadius: '2px',
            }}
          >
            PASS
          </span>
        );
      case 'INFO':
      default:
        return (
          <span
            style={{
              padding: '1px 5px',
              backgroundColor: 'var(--accent-surface)',
              border: '1px solid var(--accent-border)',
              color: 'var(--accent-text)',
              fontSize: '10px',
              fontWeight: 700,
              borderRadius: '2px',
            }}
          >
            INFO
          </span>
        );
    }
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--terminal-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.625rem',
        boxShadow: 'var(--card-shadow)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        height: '380px',
      }}
    >
      {/* Terminal Title Bar */}
      <div
        style={{
          padding: '0.625rem 1rem',
          backgroundColor: 'var(--surface-elevated)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Terminal size={14} style={{ color: 'var(--accent-text)' }} />
          <span
            style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '0.04em',
            }}
            className="font-mono"
          >
            LIVE FORENSIC AUDIT TELEMETRY STREAM
          </span>
          <span
            style={{
              fontSize: '0.6875rem',
              color: 'var(--text-muted)',
            }}
            className="font-mono"
          >
            ({terminalLogs.length} events logged)
          </span>
        </div>

        {/* Level Filters */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
          {(['ALL', 'CRIT', 'WARN', 'PASS', 'INFO'] as const).map(lvl => (
            <button
              key={lvl}
              onClick={() => setFilterLevel(lvl)}
              style={{
                padding: '0.15rem 0.5rem',
                fontSize: '0.625rem',
                border: '1px solid',
                borderColor: filterLevel === lvl ? 'var(--accent)' : 'var(--border)',
                backgroundColor: filterLevel === lvl ? 'var(--accent-surface)' : 'transparent',
                color: filterLevel === lvl ? 'var(--accent-text)' : 'var(--text-secondary)',
                borderRadius: '0.25rem',
                cursor: 'pointer',
                fontWeight: 600,
              }}
              className="font-mono"
            >
              {lvl}
            </button>
          ))}

          <button
            onClick={() => setAutoScroll(prev => !prev)}
            style={{
              padding: '0.15rem 0.5rem',
              fontSize: '0.625rem',
              border: '1px solid var(--border)',
              backgroundColor: autoScroll ? 'var(--surface-active)' : 'transparent',
              color: autoScroll ? 'var(--text-primary)' : 'var(--text-muted)',
              borderRadius: '0.25rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.25rem',
            }}
            className="font-mono"
            title="Toggle Auto-Scroll"
          >
            <ArrowDown size={10} />
            AUTO
          </button>
        </div>
      </div>

      {/* Log Feed */}
      <div
        style={{
          padding: '0.875rem 1.25rem',
          overflowY: 'auto',
          flex: 1,
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '0.75rem',
          lineHeight: '1.6',
          color: 'var(--terminal-text)',
        }}
      >
        {filteredLogs.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', padding: '1rem 0' }}>
            Awaiting kernel initialization events...
          </div>
        ) : (
          filteredLogs.map(log => (
            <div
              key={log.id}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.625rem',
                marginBottom: '0.35rem',
              }}
            >
              <span style={{ color: 'var(--text-muted)', userSelect: 'none', minWidth: '55px' }}>
                [{log.timestamp}]
              </span>
              {getLevelBadge(log.level)}
              <span
                style={{
                  color:
                    log.level === 'CRIT'
                      ? 'var(--critical-text)'
                      : log.level === 'WARN'
                      ? 'var(--warning-text)'
                      : log.level === 'PASS'
                      ? 'var(--success-text)'
                      : 'var(--terminal-text)',
                }}
              >
                {log.message}
              </span>
            </div>
          ))
        )}
        <div ref={terminalEndRef} />
      </div>
    </div>
  );
};
