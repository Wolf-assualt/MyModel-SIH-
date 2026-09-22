import React from 'react';

interface EmptyStateProps {
  title: string;
  description: string;
}

/** Minimal line illustration — concentric target, neutral palette. */
const EmptyStateIllustration: React.FC = () => (
  <svg
    width="88"
    height="88"
    viewBox="0 0 96 96"
    fill="none"
    aria-hidden="true"
    style={{ opacity: 0.9 }}
  >
    <circle cx="48" cy="48" r="44" stroke="var(--border-strong)" strokeWidth="1" />
    <circle cx="48" cy="48" r="28" stroke="var(--border)" strokeWidth="1" />
    <circle cx="48" cy="48" r="4" fill="var(--border-strong)" />
  </svg>
);

export const EmptyState: React.FC<EmptyStateProps> = ({ title, description }) => (
  <div
    className="glass-card"
    style={{
      padding: '48px 24px',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '16px',
      textAlign: 'center',
    }}
  >
    <EmptyStateIllustration />
    <div>
      <h3
        style={{
          fontSize: '15px',
          fontWeight: 600,
          color: 'var(--text-primary)',
          margin: 0,
        }}
      >
        {title}
      </h3>
      <p style={{ fontSize: '14px', color: 'var(--text-muted)', margin: '8px 0 0 0', maxWidth: '460px', lineHeight: 1.5 }}>
        {description}
      </p>
    </div>
  </div>
);

export default EmptyState;
