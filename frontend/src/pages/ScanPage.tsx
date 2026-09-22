import React from 'react';
import { ScanHeader } from '../components/scan/ScanHeader';
import { ScanProgress } from '../components/scan/ScanProgress';
import { SystemHealth } from '../components/scan/SystemHealth';
import { PipelineStages } from '../components/scan/PipelineStages';
import { LiveMetrics } from '../components/scan/LiveMetrics';
import { TerminalLog } from '../components/scan/TerminalLog';
import { SignalMap } from '../components/scan/SignalMap';

export const ScanPage: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      <ScanHeader />

      {/* Progress + Health */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 340px) 1fr', gap: '24px' }}>
        <ScanProgress />
        <SystemHealth />
      </div>

      {/* 11 Pipeline Stages */}
      <PipelineStages />

      {/* Live Metrics Counters */}
      <LiveMetrics />

      {/* Terminal Telemetry + Signal Map */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <TerminalLog />
        <SignalMap />
      </div>
    </div>
  );
};
