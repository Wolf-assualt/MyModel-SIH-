import React from 'react';

export type BadgeVariant =
  | 'default'
  | 'accent'
  | 'success'
  | 'warning'
  | 'danger'
  | 'critical'
  | 'info';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  icon?: React.ReactNode;
  size?: 'sm' | 'md';
  /** Accepted for API compatibility; dots are static. */
  pulse?: boolean;
  className?: string;
}

/**
 * Quiet status pill: small static dot + label in sentence case.
 * No pulse animation, no tinted backgrounds, no uppercase tracking.
 */
export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  icon,
  size = 'md',
  className = '',
}) => {
  const getColor = (): string => {
    switch (variant) {
      case 'accent':
        return 'var(--accent-text)';
      case 'success':
        return 'var(--success-text)';
      case 'warning':
        return 'var(--warning-text)';
      case 'danger':
      case 'critical':
        return 'var(--critical-text)';
      case 'info':
        return 'var(--info-text)';
      default:
        return 'var(--text-secondary)';
    }
  };

  const color = getColor();

  const sizeStyles: React.CSSProperties =
    size === 'sm'
      ? { padding: '2px 8px', fontSize: '11px' }
      : { padding: '3px 10px', fontSize: '12px' };

  return (
    <span
      className={`inline-flex items-center rounded-full border font-medium ${className}`}
      style={{
        ...sizeStyles,
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.375rem',
        borderColor: 'var(--border)',
        backgroundColor: 'var(--surface-elevated)',
        color,
        borderWidth: '1px',
        borderStyle: 'solid',
        lineHeight: 1.4,
      }}
    >
      {/* Small static status dot — color communicates state, motion does not */}
      <span
        style={{
          width: '5px',
          height: '5px',
          borderRadius: '50%',
          backgroundColor: 'currentColor',
          display: 'inline-block',
          flexShrink: 0,
        }}
        aria-hidden="true"
      />
      {icon && <span style={{ display: 'inline-flex' }}>{icon}</span>}
      {children}
    </span>
  );
};
