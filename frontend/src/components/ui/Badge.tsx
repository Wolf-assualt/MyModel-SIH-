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
  pulse?: boolean;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  icon,
  size = 'md',
  pulse = false,
  className = '',
}) => {
  const getStyles = (): React.CSSProperties => {
    switch (variant) {
      case 'accent':
        return {
          backgroundColor: 'var(--accent-surface)',
          borderColor: 'var(--accent-border)',
          color: 'var(--accent-text)',
        };
      case 'success':
        return {
          backgroundColor: 'var(--success-surface)',
          borderColor: 'var(--success-border)',
          color: 'var(--success-text)',
        };
      case 'warning':
        return {
          backgroundColor: 'var(--warning-surface)',
          borderColor: 'var(--warning-border)',
          color: 'var(--warning-text)',
        };
      case 'danger':
        return {
          backgroundColor: 'var(--danger-surface)',
          borderColor: 'var(--danger-border)',
          color: 'var(--danger-text)',
        };
      case 'critical':
        return {
          backgroundColor: 'var(--critical-surface)',
          borderColor: 'var(--critical-border)',
          color: 'var(--critical-text)',
        };
      case 'info':
        return {
          backgroundColor: 'var(--info-surface)',
          borderColor: 'var(--info-border)',
          color: 'var(--info-text)',
        };
      default:
        return {
          backgroundColor: 'var(--surface-elevated)',
          borderColor: 'var(--border)',
          color: 'var(--text-secondary)',
        };
    }
  };

  const sizeStyles: React.CSSProperties =
    size === 'sm'
      ? { padding: '2px 6px', fontSize: '11px' }
      : { padding: '3px 9px', fontSize: '12px' };

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-medium rounded border uppercase tracking-wider ${className}`}
      style={{
        ...getStyles(),
        ...sizeStyles,
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.375rem',
        borderRadius: '0.25rem',
        borderWidth: '1px',
        borderStyle: 'solid',
        lineHeight: 1.2,
      }}
    >
      {pulse && (
        <span
          style={{
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            backgroundColor: 'currentColor',
            display: 'inline-block',
            animation: 'ping-subtle 1.8s infinite ease-in-out',
          }}
        />
      )}
      {icon && <span style={{ display: 'inline-flex' }}>{icon}</span>}
      {children}
    </span>
  );
};
