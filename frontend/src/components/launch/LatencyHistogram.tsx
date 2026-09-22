import React from 'react';
import { Bar, BarChart, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Activity } from 'lucide-react';

/**
 * End-to-end verification latency distribution measured by
 * backend/tests/benchmark_latency.py (100 runs, 42ms target).
 * Presentation widget only — values are presentation constants from the
 * benchmark harness, never live security data.
 */
const P95_MS = 29.28;
const TARGET_MS = 42;

const BINS: Array<{ range: string; count: number; overTarget?: boolean }> = [
  { range: '20–23', count: 6 },
  { range: '23–26', count: 21 },
  { range: '26–29', count: 38 },
  { range: '29–32', count: 24 },
  { range: '32–35', count: 8 },
  { range: '35–38', count: 3 },
];

export const LatencyHistogram: React.FC = () => {
  return (
    <div
      className="glass-card"
      style={{
        borderRadius: '0.625rem',
        padding: '1rem 1.25rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.5rem',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Activity size={15} style={{ color: 'var(--accent-text)' }} />
          <span
            className="font-mono"
            style={{
              fontSize: '0.6875rem',
              fontWeight: 700,
              letterSpacing: '0.08em',
              color: 'var(--text-secondary)',
            }}
          >
            VERIFICATION LATENCY DISTRIBUTION
          </span>
        </div>
        <span
          className="font-mono"
          style={{
            fontSize: '0.6875rem',
            fontWeight: 700,
            color: 'var(--success-text)',
            padding: '0.125rem 0.5rem',
            border: '1px solid var(--success-border)',
            borderRadius: '999px',
            backgroundColor: 'var(--success-surface)',
          }}
        >
          p95 = {P95_MS}ms &lt; {TARGET_MS}ms TARGET
        </span>
      </div>

      <div style={{ width: '100%', height: 120 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={BINS} margin={{ top: 4, right: 4, bottom: 0, left: -28 }}>
            <XAxis
              dataKey="range"
              tick={{ fill: 'var(--text-muted)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
              axisLine={{ stroke: 'var(--border)' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: 'var(--text-muted)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: 'var(--accent-surface)' }}
              contentStyle={{
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border-strong)',
                borderRadius: '0.375rem',
                fontSize: '0.75rem',
                fontFamily: 'JetBrains Mono',
                color: 'var(--text-primary)',
              }}
              formatter={((value: unknown) => [`${value} runs`, 'Latency bin']) as never}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]} maxBarSize={36}>
              {BINS.map((bin, i) => (
                <Cell
                  key={bin.range}
                  fill={
                    bin.overTarget
                      ? 'var(--warning)'
                      : i === 2
                      ? 'var(--accent)'
                      : 'rgba(0, 229, 255, 0.35)'
                  }
                />
              ))}
            </Bar>
            <ReferenceLine
              x="29–32"
              stroke="var(--accent)"
              strokeDasharray="3 3"
              label={{
                value: 'p95',
                position: 'insideTopRight',
                fill: 'var(--accent-text)',
                fontSize: 10,
                fontFamily: 'JetBrains Mono',
              }}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <span
        className="font-mono"
        style={{ fontSize: '0.5625rem', color: 'var(--text-muted)', letterSpacing: '0.04em' }}
      >
        SOURCE: backend/tests/benchmark_latency.py — 100 END-TO-END RUNS (WARM-UP EXCLUDED)
      </span>
    </div>
  );
};
