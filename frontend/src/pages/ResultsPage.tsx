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
import { LedgerAuditPanel } from '../components/results/LedgerAuditPanel';
import { AnalystDecisionPanel } from '../components/results/AnalystDecisionPanel';
import { BackendErrorBanner } from '../components/results/BackendErrorBanner';

export const ResultsPage: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Backend failures/partial states are surfaced, never hidden. */}
      <BackendErrorBanner />

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

      {/* 6. Tamper-Evident Ledger Verification (backend authoritative) */}
      <LedgerAuditPanel />

      {/* 7. Analyst disposition — separate from the system assessment */}
      <AnalystDecisionPanel />

      {/* 8. Actionable Recommendations */}
      <Recommendations />

      {/* 9. Export & Workflow Actions */}
      <ExportActions />

      {/* Modal Drawer for clicked finding */}
      <FindingDrawer />
    </div>
  );
};
