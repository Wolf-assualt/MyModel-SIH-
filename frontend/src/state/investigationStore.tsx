import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { apiService, type ScanSession } from '../services/api';
import type { SystemHealthOverview, ImageAssessment } from '../services/api';
import type {
  Phase,
  ArtifactItem,
  PipelineStage,
  TerminalLog,
  LiveMetrics,
  SignalPoint,
  Finding,
  FindingCategory,
  TrustScore,
  Recommendation,
} from '../types/investigation';
import {
  INITIAL_ARTIFACTS,
  PIPELINE_STAGES,
  INITIAL_METRICS,
  CLEAN_TRUST_SCORE,
} from '../data/mockScenario';

export type Theme = 'dark' | 'light';

interface InvestigationContextType {
  phase: Phase;
  setPhase: (phase: Phase) => void;
  theme: Theme;
  toggleTheme: () => void;
  sessionId: string;
  backendOnline: boolean;
  backendOverview: SystemHealthOverview | null;
  fusedAssessmentId: string | null;
  currentScanId: string | null;
  scanSession: ScanSession | null;
  artifacts: ArtifactItem[];
  clearArtifacts: () => void;
  updateArtifactWithFile: (artifactId: string, file: File) => Promise<void>;
  verifyArtifact: (artifactId: string) => void;
  isReadyToScan: boolean;
  validationChecklist: any;
  isScanning: boolean;
  isScanCompleted: boolean;
  scanProgress: number;
  currentOperation: string;
  elapsedSeconds: number;
  speedMultiplier: number;
  setSpeedMultiplier: (mult: number) => void;
  stages: PipelineStage[];
  terminalLogs: TerminalLog[];
  liveMetrics: LiveMetrics;
  signalPoints: SignalPoint[];
  startScan: () => void;
  pauseScan: () => void;
  resumeScan: () => void;
  skipScanToEnd: () => void;
  findings: Finding[];
  setFindings: React.Dispatch<React.SetStateAction<Finding[]>>;
  selectedCategory: FindingCategory;
  setSelectedCategory: (cat: FindingCategory) => void;
  selectedSeverity: string;
  setSelectedSeverity: (sev: string) => void;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  selectedFinding: Finding | null;
  setSelectedFinding: (finding: Finding | null) => void;
  trustScore: TrustScore;
  setTrustScore: React.Dispatch<React.SetStateAction<TrustScore>>;
  recommendations: Recommendation[];
  setRecommendations: React.Dispatch<React.SetStateAction<Recommendation[]>>;
  imageResults: ImageAssessment[];
  quarantineImage: (sampleId: string) => Promise<void>;
  graphNodes: any[];
  graphEdges: any[];
  graphDigest: string;
  selectedGraphNode: any | null;
  setSelectedGraphNode: (node: any | null) => void;
  focusNodeInGraph: (nodeId: string) => void;
  resetInvestigation: () => void;
  exportReport: () => void;
  exportEvidencePackage: () => void;
}

const InvestigationContext = createContext<InvestigationContextType | null>(null);

export const InvestigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setTheme] = useState<Theme>('dark');
  const [backendOnline, setBackendOnline] = useState(false);
  const [backendOverview, setBackendOverview] = useState<SystemHealthOverview | null>(null);
  const [fusedAssessmentId] = useState<string | null>(null);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [scanSession, setScanSession] = useState<ScanSession | null>(null);
  const [imageResults, setImageResults] = useState<ImageAssessment[]>([]);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));

  useEffect(() => {
    let cancelled = false;
    const probe = async () => {
      const online = await apiService.isBackendAvailable();
      if (!cancelled) {
        setBackendOnline(online);
        if (online) {
          const overview = await apiService.fetchOverview();
          if (!cancelled && overview) setBackendOverview(overview);
        }
      }
    };
    probe();
    const interval = window.setInterval(probe, 15_000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  const [phase, setPhaseState] = useState<Phase>('launch');
  const setPhase = useCallback((newPhase: Phase) => {
    setPhaseState(newPhase);
    window.history.pushState({}, '', `/${newPhase}`);
  }, []);

  const sessionId = 'TCV-2026-8891B';
  const [artifacts, setArtifacts] = useState<ArtifactItem[]>(INITIAL_ARTIFACTS);

  const updateArtifactWithFile = async (artifactId: string, file: File) => {
    const isDataset = artifacts.find(artifact => artifact.id === artifactId)?.type === 'dataset';
    if (isDataset) {
      try {
        const session = await apiService.uploadAndScanDataset(file);
        setCurrentScanId(session.scan_id);
        setScanSession(session);
        setArtifacts(prev => prev.map(art => art.id === artifactId ? {
          ...art, filename: file.name, size: '0', hash: '', status: 'verified', progress: 100, metadata: { format: 'Backend scan initiated' }
        } : art));
      } catch (error) {
        console.error(error);
        setArtifacts(prev => prev.map(art => art.id === artifactId ? {
          ...art, filename: file.name, status: 'error', progress: 0
        } : art));
      }
      return;
    }
  };

  const verifyArtifact = (_artifactId?: string) => {};
  const clearArtifacts = () => setArtifacts(INITIAL_ARTIFACTS);
  const quarantineImage = async (_sampleId?: string) => {};

  const datasetVerified = artifacts.find(a => a.type === 'dataset')?.status === 'verified';
  const validationChecklist = { datasetDetected: datasetVerified, configValidated: true };
  const isReadyToScan = datasetVerified;

  const [isScanning, setIsScanning] = useState(false);
  const [isScanCompleted, setIsScanCompleted] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentOperation, setCurrentOperation] = useState('System ready');
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [speedMultiplier, setSpeedMultiplier] = useState(1);
  const [stages, setStages] = useState<PipelineStage[]>(PIPELINE_STAGES);
  const [terminalLogs] = useState<TerminalLog[]>([]);
  const [liveMetrics] = useState<LiveMetrics>(INITIAL_METRICS);
  const [signalPoints] = useState<SignalPoint[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<FindingCategory>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [trustScore, setTrustScore] = useState<TrustScore>(CLEAN_TRUST_SCORE);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [graphNodes] = useState<any[]>([]);
  const [graphEdges] = useState<any[]>([]);
  const [graphDigest] = useState('');
  const [selectedGraphNode, setSelectedGraphNode] = useState<any | null>(null);

  const focusNodeInGraph = (_nodeId?: string) => {};
  const resetInvestigation = () => {};
  const exportReport = () => {};
  const exportEvidencePackage = () => {};

  const scanIntervalRef = useRef<number | null>(null);
  const timerIntervalRef = useRef<number | null>(null);

  useEffect(() => {
    if (isScanning) {
      timerIntervalRef.current = window.setInterval(() => setElapsedSeconds(prev => prev + 1), 1000);
    } else {
      if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
    }
    return () => { if (timerIntervalRef.current) clearInterval(timerIntervalRef.current); };
  }, [isScanning]);

  const completeScan = useCallback(() => {
    if (scanIntervalRef.current) clearInterval(scanIntervalRef.current);
    setScanProgress(100);
    setIsScanning(false);
    setIsScanCompleted(true);
    setCurrentOperation('INTEGRITY ANALYSIS COMPLETE');
    setTimeout(() => setPhase('results'), 1800);
  }, [setPhase]);

  const runScanSimulation = useCallback(() => {
    if (scanIntervalRef.current) clearInterval(scanIntervalRef.current);
    scanIntervalRef.current = window.setInterval(async () => {
      if (!currentScanId) return;
      try {
        const session = await apiService.getScanSession(currentScanId);
        setScanSession(session);
        setScanProgress(session.progress * 100);
        setCurrentOperation(`Stage: ${session.stage}`);
        
        setStages(prev => prev.map((s) => {
           const componentState = session.stage_results?.[s.code];
           if (componentState) {
              return { ...s, status: componentState.status as any, summary: componentState.explanation || s.summary };
           }
           // Fallback logic if stage_results isn't populated for this stage yet
           const currentStageIndex = Math.floor(session.progress * 10);
           const idx = prev.findIndex(x => x.code === s.code);
           if (idx === currentStageIndex && session.status !== 'COMPLETED' && session.status !== 'FAILED') {
               return { ...s, status: 'RUNNING', progress: 50 };
           }
           return { ...s, status: 'WAITING', progress: 0 };
        }));

        if (session.status === 'COMPLETED' || session.status === 'FAILED') {
          clearInterval(scanIntervalRef.current!);
          if (session.assessment) {
            setTrustScore({
              overall: session.assessment.assuranceScore * 100,
              dataIntegrity: session.assessment.dataRiskScore * 100,
              modelIntegrity: 0,
              inferenceIntegrity: 0,
              pipelineIntegrity: session.assessment.assuranceScore * 100,
              verdict: session.assessment.disposition,
              headline: 'Authoritative Backend Scan Completed',
              summary: `Analyzed ${session.assessment.totalSamples} samples`
            });
            setImageResults(session.assessment.imageResults || []);
            setFindings((session.findings || []).map((f: any) => ({
              id: f.finding_id,
              title: f.check_type,
              category: 'DATA POISONING',
              severity: f.severity,
              affectedArtifact: 'Uploaded dataset',
              evidenceSummary: f.description,
              confidence: f.metric_score * 100,
              status: 'Confirmed',
              detectionMethod: 'Backend Engine',
              expectedValue: 'Clean',
              observedValue: f.description,
              sha256Proof: 'N/A',
              recommendedAction: 'Quarantine'
            })));
          }
          completeScan();
        }
      } catch (err) {
        console.error('Scan polling error', err);
      }
    }, 1000);
  }, [currentScanId, completeScan]);

  const startScan = useCallback(() => {
    setIsScanning(true);
    setIsScanCompleted(false);
    setScanProgress(0);
    setPhase('scan');
    runScanSimulation();
  }, [runScanSimulation, setPhase]);

  const pauseScan = () => setIsScanning(false);
  const resumeScan = () => setIsScanning(true);
  const skipScanToEnd = () => completeScan();

  return (
    <InvestigationContext.Provider value={{
      phase, setPhase, theme, toggleTheme, sessionId, backendOnline, backendOverview,
      fusedAssessmentId, currentScanId, scanSession, artifacts, clearArtifacts,
      updateArtifactWithFile, verifyArtifact, isReadyToScan, validationChecklist,
      isScanning, isScanCompleted, scanProgress, currentOperation, elapsedSeconds,
      speedMultiplier, setSpeedMultiplier, stages, terminalLogs, liveMetrics, signalPoints,
      startScan, pauseScan, resumeScan, skipScanToEnd, findings, setFindings,
      selectedCategory, setSelectedCategory, selectedSeverity, setSelectedSeverity,
      searchQuery, setSearchQuery, selectedFinding, setSelectedFinding, trustScore,
      setTrustScore, recommendations, setRecommendations, imageResults, quarantineImage,
      graphNodes, graphEdges, graphDigest, selectedGraphNode, setSelectedGraphNode,
      focusNodeInGraph, resetInvestigation, exportReport, exportEvidencePackage
    }}>
      {children}
    </InvestigationContext.Provider>
  );
};

export const useInvestigation = () => {
  const context = useContext(InvestigationContext);
  if (!context) throw new Error('useInvestigation must be used within an InvestigationProvider');
  return context;
};
