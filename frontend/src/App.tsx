import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { InvestigationProvider, useInvestigation } from './state/investigationStore';
import { Header } from './components/layout/Header';
import { PhaseStepper } from './components/layout/PhaseStepper';
import { LaunchPage } from './pages/LaunchPage';
import { ScanPage } from './pages/ScanPage';
import { ResultsPage } from './pages/ResultsPage';
import './theme/globals.css';

const MultiPhaseSocView: React.FC = () => {
  const { phase } = useInvestigation();

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col font-sans text-slate-200">
      <Header />
      <PhaseStepper />

      <main className="flex-1 overflow-x-hidden overflow-y-auto w-full relative">
        <div className="w-full max-w-[1600px] mx-auto min-h-full">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={phase}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25, ease: 'easeOut' }}
            >
              {phase === 'launch' && <LaunchPage />}
              {phase === 'scan' && <ScanPage />}
              {phase === 'results' && <ResultsPage />}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
};

export default function App() {
  return (
    <InvestigationProvider>
      <MultiPhaseSocView />
    </InvestigationProvider>
  );
}
