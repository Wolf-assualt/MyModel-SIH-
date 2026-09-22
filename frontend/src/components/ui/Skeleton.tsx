import React from 'react';

interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  style?: React.CSSProperties;
}

/** Base shimmer block. */
export const Skeleton: React.FC<SkeletonProps> = ({ width = '100%', height = '0.875rem', style }) => (
  <span className="skeleton" style={{ display: 'block', width, height, ...style }} />
);

/** Multi-line skeleton commonly used to replace plain "Loading..." text. */
export const SkeletonText: React.FC<{ lines?: number }> = ({ lines = 3 }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', width: '100%' }}>
    {Array.from({ length: lines }).map((_, i) => (
      <Skeleton key={i} width={i === lines - 1 ? '60%' : '100%'} height="0.75rem" />
    ))}
  </div>
);
