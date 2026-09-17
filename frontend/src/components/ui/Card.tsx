import React from 'react';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  glow?: 'accent' | 'critical' | 'warning' | 'success' | 'none';
  interactive?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  glow = 'none',
  interactive = false,
  className = '',
  style,
  ...props
}) => {
  const getGlowStyles = (): React.CSSProperties => {
    switch (glow) {
      case 'accent':
        return {
          boxShadow: 'var(--accent-glow)',
          borderColor: 'var(--accent)',
        };
      case 'critical':
        return {
          boxShadow: 'var(--critical-glow)',
          borderColor: 'var(--critical)',
        };
      case 'warning':
        return {
          boxShadow: 'var(--warning-glow)',
          borderColor: 'var(--warning)',
        };
      case 'success':
        return {
          boxShadow: 'var(--success-glow)',
          borderColor: 'var(--success)',
        };
      default:
        return {};
    }
  };

  return (
    <div
      style={{
        backgroundColor: 'var(--surface)',
        borderColor: 'var(--border)',
        borderWidth: '1px',
        borderStyle: 'solid',
        borderRadius: '0.625rem',
        boxShadow: 'var(--card-shadow)',
        transition: 'border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease',
        cursor: interactive ? 'pointer' : 'default',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        ...getGlowStyles(),
        ...style,
      }}
      className={`surface-card ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};

export const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  style,
  className = '',
  ...props
}) => (
  <div
    style={{
      padding: '1.25rem 1.5rem',
      borderBottom: '1px solid var(--border-subtle)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '1rem',
      ...style,
    }}
    className={className}
    {...props}
  >
    {children}
  </div>
);

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  children,
  style,
  className = '',
  ...props
}) => (
  <h3
    style={{
      fontSize: '1rem',
      fontWeight: 600,
      color: 'var(--text-primary)',
      letterSpacing: '0.03em',
      textTransform: 'uppercase',
      margin: 0,
      ...style,
    }}
    className={`font-display ${className}`}
    {...props}
  >
    {children}
  </h3>
);

export const CardDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  children,
  style,
  className = '',
  ...props
}) => (
  <p
    style={{
      fontSize: '0.8125rem',
      color: 'var(--text-muted)',
      marginTop: '0.25rem',
      margin: 0,
      ...style,
    }}
    className={className}
    {...props}
  >
    {children}
  </p>
);

export const CardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  style,
  className = '',
  ...props
}) => (
  <div
    style={{
      padding: '1.25rem 1.5rem',
      flex: 1,
      ...style,
    }}
    className={className}
    {...props}
  >
    {children}
  </div>
);

export const CardFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  style,
  className = '',
  ...props
}) => (
  <div
    style={{
      padding: '1rem 1.5rem',
      borderTop: '1px solid var(--border-subtle)',
      backgroundColor: 'var(--surface-elevated)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      ...style,
    }}
    className={className}
    {...props}
  >
    {children}
  </div>
);
