import React, { useState } from 'react';
import { InvestigationProvider, useInvestigation } from './state/investigationStore';
import { Header } from './components/layout/Header';
import { PhaseStepper } from './components/layout/PhaseStepper';
import { Footer } from './components/layout/Footer';
import { LaunchPage } from './pages/LaunchPage';
import { ScanPage } from './pages/ScanPage';
import { ResultsPage } from './pages/ResultsPage';
import { TrustCvPreviewLayout } from './components/preview/TrustCvPreviewLayout';
import './theme/globals.css';

const MultiPhaseSocView: React.FC = () => {
  const { phase } = useInvestigation();

  return (
    <div className="app-container bg-tactical-grid">
      <Header />

      <main className="content-wrapper">
        <PhaseStepper />

        {phase === 'launch' && <LaunchPage />}
        {phase === 'scan' && <ScanPage />}
        {phase === 'results' && <ResultsPage />}
      </main>

      <Footer />
    </div>
  );
};

export function App() {
  // Default to the Single-Screen Preview matching the user's reference image
  const [viewMode, setViewMode] = useState<'preview' | 'soc'>('preview');

  return (
    <InvestigationProvider>
      <div style={{ position: 'relative' }}>
        {/* Quick View Mode Switcher floating tag */}
        <div
          style={{
            position: 'fixed',
            bottom: '12px',
            right: '12px',
            zIndex: 9999,
            backgroundColor: '#0c1322',
            border: '1px solid #1e293b',
            borderRadius: '9999px',
            padding: '4px 6px',
            display: 'flex',
            gap: '4px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
          }}
        >
          <button
            onClick={() => setViewMode('preview')}
            style={{
              border: 'none',
              borderRadius: '9999px',
              padding: '4px 10px',
              fontSize: '11px',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              backgroundColor: viewMode === 'preview' ? '#0284c7' : 'transparent',
              color: viewMode === 'preview' ? '#ffffff' : '#94a3b8',
              transition: 'all 0.15s ease',
            }}
          >
            REFERENCE VIEW
          </button>
          <button
            onClick={() => setViewMode('soc')}
            style={{
              border: 'none',
              borderRadius: '9999px',
              padding: '4px 10px',
              fontSize: '11px',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              backgroundColor: viewMode === 'soc' ? '#0284c7' : 'transparent',
              color: viewMode === 'soc' ? '#ffffff' : '#94a3b8',
              transition: 'all 0.15s ease',
            }}
          >
            MULTI-PHASE SOC
          </button>
        </div>

        {viewMode === 'preview' ? <TrustCvPreviewLayout /> : <MultiPhaseSocView />}
      </div>
    </InvestigationProvider>
  );
}

export default App;
