import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Rocket,
  ScanLine,
  FileSearch,
  RotateCcw,
  SunMoon,
  Settings,
  Search,
  CornerDownLeft,
} from 'lucide-react';
import { useInvestigation } from '../../state/investigationStore';
import { SettingsModal } from './SettingsModal';

interface CommandItem {
  id: string;
  label: string;
  hint: string;
  icon: React.ReactNode;
  keywords: string;
  action: () => void;
}

export const CommandPalette: React.FC = () => {
  const { setPhase, resetInvestigation, toggleTheme, theme } = useInvestigation();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const close = useCallback(() => {
    setOpen(false);
    setQuery('');
    setActiveIndex(0);
  }, []);

  // Global ⌘K / Ctrl+K shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen(prev => !prev);
      }
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [close]);

  // Focus the input when opened
  useEffect(() => {
    if (open) {
      // Defer so the palette DOM exists before focusing
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const commands: CommandItem[] = useMemo(
    () => [
      {
        id: 'go-launch',
        label: 'Go to Launch',
        hint: 'Phase 01',
        icon: <Rocket size={15} />,
        keywords: 'phase launch upload artifacts dataset',
        action: () => setPhase('launch'),
      },
      {
        id: 'go-scan',
        label: 'Go to Scan',
        hint: 'Phase 02',
        icon: <ScanLine size={15} />,
        keywords: 'phase scan analyze pipeline monitor',
        action: () => setPhase('scan'),
      },
      {
        id: 'go-results',
        label: 'Go to Results',
        hint: 'Phase 03',
        icon: <FileSearch size={15} />,
        keywords: 'phase results verdict evidence findings',
        action: () => setPhase('results'),
      },
      {
        id: 'reset',
        label: 'Reset Investigation',
        hint: 'Clear state',
        icon: <RotateCcw size={15} />,
        keywords: 'reset clear artifacts session restart',
        action: () => resetInvestigation(),
      },
      {
        id: 'toggle-theme',
        label: 'Toggle Theme',
        hint: theme === 'dark' ? 'Switch to Light' : 'Switch to Dark',
        icon: <SunMoon size={15} />,
        keywords: 'theme dark light appearance toggle',
        action: () => toggleTheme(),
      },
      {
        id: 'settings',
        label: 'Open Settings',
        hint: 'About & info',
        icon: <Settings size={15} />,
        keywords: 'settings preferences about configuration',
        action: () => setSettingsOpen(true),
      },
    ],
    [setPhase, resetInvestigation, toggleTheme, theme],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(
      c => c.label.toLowerCase().includes(q) || c.keywords.includes(q),
    );
  }, [commands, query]);

  const runCommand = useCallback(
    (item: CommandItem) => {
      close();
      item.action();
    },
    [close],
  );

  // Keyboard navigation
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex(i => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex(i => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filtered[activeIndex]) runCommand(filtered[activeIndex]);
    }
  };

  // Keep active item in view
  useEffect(() => {
    const el = listRef.current?.querySelector('[data-active="true"]');
    el?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  return (
    <>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            onClick={close}
            style={{
              position: 'fixed',
              inset: 0,
              zIndex: 10000,
              backgroundColor: 'rgba(5, 6, 10, 0.7)',
              backdropFilter: 'blur(6px)',
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'center',
              paddingTop: '14vh',
              padding: '14vh 1.5rem 1.5rem 1.5rem',
            }}
          >
            <motion.div
              initial={{ opacity: 0, y: -10, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.98 }}
              transition={{ duration: 0.18, ease: 'easeOut' }}
              onClick={e => e.stopPropagation()}
              role="dialog"
              aria-label="Command palette"
              className="glass-card"
              style={{
                width: '100%',
                maxWidth: '560px',
                borderRadius: '0.75rem',
                overflow: 'hidden',
                borderColor: 'var(--border-strong)',
              }}
            >
              {/* Search input */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.625rem',
                  padding: '0.875rem 1rem',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <Search size={16} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                <input
                  ref={inputRef}
                  value={query}
                  onChange={e => {
                    setQuery(e.target.value);
                    setActiveIndex(0);
                  }}
                  onKeyDown={onKeyDown}
                  placeholder="Type a command or search…"
                  aria-label="Command palette search"
                  className="command-palette__input"
                  style={{
                    flex: 1,
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    color: 'var(--text-primary)',
                    fontSize: '0.9375rem',
                    fontFamily: 'inherit',
                  }}
                />
                <kbd
                  className="font-mono"
                  style={{
                    fontSize: '0.625rem',
                    color: 'var(--text-muted)',
                    border: '1px solid var(--border)',
                    borderRadius: '0.25rem',
                    padding: '0.125rem 0.375rem',
                  }}
                >
                  ESC
                </kbd>
              </div>

              {/* Command list */}
              <div ref={listRef} style={{ padding: '0.375rem', maxHeight: '320px', overflowY: 'auto' }}>
                {filtered.length === 0 && (
                  <div
                    className="font-mono"
                    style={{ padding: '1rem', fontSize: '0.8125rem', color: 'var(--text-muted)', textAlign: 'center' }}
                  >
                    NO MATCHING COMMANDS
                  </div>
                )}
                {filtered.map((item, i) => (
                  <button
                    key={item.id}
                    data-active={i === activeIndex}
                    onClick={() => runCommand(item)}
                    onMouseEnter={() => setActiveIndex(i)}
                    style={{
                      width: '100%',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.625rem 0.75rem',
                      background:
                        i === activeIndex
                          ? 'var(--accent-surface)'
                          : 'transparent',
                      border: 'none',
                      borderRadius: '0.375rem',
                      color: i === activeIndex ? 'var(--accent-text)' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <span style={{ display: 'inline-flex', flexShrink: 0 }}>{item.icon}</span>
                    <span style={{ flex: 1, fontSize: '0.875rem', fontWeight: 500 }}>{item.label}</span>
                    <span
                      className="font-mono"
                      style={{ fontSize: '0.625rem', color: 'var(--text-muted)', letterSpacing: '0.05em' }}
                    >
                      {item.hint}
                    </span>
                    {i === activeIndex && <CornerDownLeft size={12} style={{ opacity: 0.6 }} />}
                  </button>
                ))}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <SettingsModal isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </>
  );
};
