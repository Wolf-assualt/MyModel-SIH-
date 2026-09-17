import React from 'react';
import { VerdictCard } from '../components/results/VerdictCard';
import { SummaryCards } from '../components/results/SummaryCards';
import { TrustScoreCard } from '../components/results/TrustScoreCard';
import { FindingsTable } from '../components/results/FindingsTable';
import { FindingDrawer } from '../components/results/FindingDrawer';
import { EvidenceGraph } from '../components/results/EvidenceGraph';
import { Recommendations } from '../components/results/Recommendations';
import { ExportActions } from '../components/results/ExportActions';
import { ImageAssessments } from '../components/results/ImageAssessments';

export const ResultsPage: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* 1. Large Verdict Card */}
      <VerdictCard />

      {/* 2. Executive Summary Metrics */}
      <SummaryCards />

      {/* 3. Trust Score Breakdown */}
      <TrustScoreCard />

      <ImageAssessments />

      {/* 4. Forensic Findings Table */}
      <FindingsTable />

      {/* 5. Directed Evidence & Lineage Graph */}
      <EvidenceGraph />

      {/* 6. Actionable Recommendations */}
      <Recommendations />

      {/* 7. Export & Workflow Actions */}
      <ExportActions />

      {/* Modal Drawer for clicked finding */}
      <FindingDrawer />
    </div>
  );
};
