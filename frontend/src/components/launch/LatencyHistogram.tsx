import React from 'react';
import { Bar, BarChart, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

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
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
        }}
      >
        <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
          Verification latency distribution
        </h3>
        <span
          className="font-mono"
          style={{
            fontSize: '11px',
            color: 'var(--text-secondary)',
            padding: '2px 8px',
            border: '1px solid var(--border)',
            borderRadius: '999px',
            backgroundColor: 'var(--surface-elevated)',
          }}
        >
          p95 {P95_MS}ms · target {TARGET_MS}ms
        </span>
      </div>

      <div style={{ width: '100%', height: 120 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={BINS} margin={{ top: 4, right: 4, bottom: 0, left: -28 }}>
            <XAxis
              dataKey="range"
              tick={{ fill: 'var(--text-muted)', fontSize: 10, fontFamily: 'Inter, sans-serif' }}
              axisLine={{ stroke: 'var(--border)' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: 'var(--text-muted)', fontSize: 10, fontFamily: 'Inter, sans-serif' }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: 'var(--surface-hover)' }}
              contentStyle={{
                backgroundColor: 'var(--surface-elevated)',
                border: '1px solid var(--border-strong)',
                borderRadius: '0.375rem',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
              }}
              formatter={((value: unknown) => [`${value} runs`, 'Latency bin']) as never}
            />
            <Bar dataKey="count" radius={[2, 2, 0, 0]} maxBarSize={36}>
              {BINS.map((bin, i) => (
                <Cell
                  key={bin.range}
                  fill={i === 2 ? 'var(--accent)' : 'var(--surface-active)'}
                />
              ))}
            </Bar>
            <ReferenceLine
              x="29–32"
              stroke="var(--accent-text)"
              strokeDasharray="3 3"
              label={{
                value: 'p95',
                position: 'insideTopRight',
                fill: 'var(--text-secondary)',
                fontSize: 10,
              }}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
        Source: <span className="font-mono">backend/tests/benchmark_latency.py</span> — 100 end-to-end runs (warm-up excluded)
      </span>
    </div>
  );
};
