import React from 'react';

interface EmptyStateProps {
  title: string;
  description: string;
}

/** Simple inline SVG illustration — radar sweep with a question mark center. */
const EmptyStateIllustration: React.FC = () => (
  <svg
    width="96"
    height="96"
    viewBox="0 0 96 96"
    fill="none"
    aria-hidden="true"
    style={{ opacity: 0.85 }}
  >
    <circle cx="48" cy="48" r="44" stroke="var(--border-strong)" strokeWidth="1" strokeDasharray="4 4" />
    <circle cx="48" cy="48" r="30" stroke="var(--border)" strokeWidth="1" />
    <circle cx="48" cy="48" r="16" stroke="var(--border)" strokeWidth="1" />
    <line x1="48" y1="4" x2="48" y2="92" stroke="var(--border)" strokeWidth="1" />
    <line x1="4" y1="48" x2="92" y2="48" stroke="var(--border)" strokeWidth="1" />
    <path d="M48 48 L48 6 A42 42 0 0 1 84 30 Z" fill="var(--accent-surface)" />
    <circle cx="48" cy="48" r="5" fill="var(--accent)" opacity="0.9" />
  </svg>
);

export const EmptyState: React.FC<EmptyStateProps> = ({ title, description }) => (
  <div
    className="glass-card"
    style={{
      borderRadius: '0.625rem',
      padding: '3rem 2rem',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '1rem',
      textAlign: 'center',
    }}
  >
    <EmptyStateIllustration />
    <div>
      <h3
        className="font-display"
        style={{
          fontSize: '1rem',
          fontWeight: 700,
          letterSpacing: '0.05em',
          color: 'var(--text-secondary)',
          margin: 0,
          textTransform: 'uppercase',
        }}
      >
        {title}
      </h3>
      <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: '0.375rem 0 0 0', maxWidth: '460px', lineHeight: 1.5 }}>
        {description}
      </p>
    </div>
  </div>
);

export default EmptyState;
