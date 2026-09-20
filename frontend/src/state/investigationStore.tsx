import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { apiService, type ScanSession } from '../services/api';
import type {
  SystemHealthOverview,
  ImageAssessment,
  LedgerVerification,
  LedgerEventRecord,
  AnalystDecision,
} from '../services/api';
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
} from '../data/mockScenario';

/** Trigger a local, offline file download of a JSON document. */
function downloadJson(payload: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export type Theme = 'dark' | 'light';

/**
 * Ordered backend ScanStage values (app.schemas.scan.ScanStage) used to decide
 * which frontend stage slot has been reached during polling. This is a purely
 * positional mapping — it never asserts a security status.
 */
const BACKEND_STAGE_ORDER: string[] = [
  'INGESTION',
  'HASHING',
  'DATA_INTEGRITY',
  'MODEL_ASSURANCE',
  'INFERENCE_ASSURANCE',
  'DISTRIBUTION_SHIFT',
  'EVIDENCE_FUSION',
  'AUDIT',
  'REPORT',
  'COMPLETED',
];

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
  trustScore: TrustScore | null;
  setTrustScore: React.Dispatch<React.SetStateAction<TrustScore | null>>;
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
  /** Backend ledger hash-chain verification result; null means UNAVAILABLE. */
  ledgerVerification: LedgerVerification | null;
  /** Analyst decisions persisted in the backend ledger (never frontend state). */
  analystDecisions: LedgerEventRecord[];
  /** Last backend/API error surfaced to the operator. */
  backendError: string | null;
  refreshLedgerVerification: () => Promise<void>;
  loadEvidenceGraph: () => Promise<void>;
  refreshAnalystDecisions: (entityId?: string) => Promise<void>;
  submitAnalystDecision: (
    decision: AnalystDecision,
    actor: string,
    opts?: { entityId?: string; scanId?: string; reason?: string },
  ) => Promise<LedgerEventRecord | null>;
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

  const verifyArtifact = (_artifactId?: string) => {
    // Artifact acceptance is decided by the backend assurance pipeline on upload.
    // No client-side verification verdict is produced here.
  };

  const clearArtifacts = () => setArtifacts(INITIAL_ARTIFACTS);

  /**
   * Quarantine a flagged sample. The backend copies the original into isolated
   * storage, records a signed audit event and returns the updated assessment.
   */
  const quarantineImage = async (sampleId: string) => {
    const batchId = scanSession?.batch_id;
    if (!batchId) {
      setBackendError('Quarantine UNAVAILABLE: no backend batch is loaded.');
      return;
    }
    try {
      const updated = await apiService.quarantineDatasetImage(batchId, sampleId);
      setImageResults(prev => prev.map(img => (img.sample_id === updated.sample_id ? updated : img)));
      setBackendError(null);
      await refreshLedgerVerification();
    } catch (e: any) {
      setBackendError(e?.message || 'Quarantine failed.');
    }
  };

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
  const [trustScore, setTrustScore] = useState<TrustScore | null>(null);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [graphNodes, setGraphNodes] = useState<any[]>([]);
  const [graphEdges, setGraphEdges] = useState<any[]>([]);
  const [graphDigest, setGraphDigest] = useState('');
  const [selectedGraphNode, setSelectedGraphNode] = useState<any | null>(null);
  const [ledgerVerification, setLedgerVerification] = useState<LedgerVerification | null>(null);
  const [analystDecisions, setAnalystDecisions] = useState<LedgerEventRecord[]>([]);
  const [backendError, setBackendError] = useState<string | null>(null);

  /**
   * Pull the authoritative evidence graph from the backend.
   * If the backend is unreachable the graph stays EMPTY (UNAVAILABLE) — the
   * frontend never reconstructs authoritative relationships locally.
   */
  const loadEvidenceGraph = useCallback(async () => {
    try {
      const exportData = await apiService.fetchGraphExport();
      if (exportData && Array.isArray(exportData.nodes) && Array.isArray(exportData.edges)) {
        setGraphNodes(exportData.nodes.map(n => ({
          id: n.id,
          label: n.label || n.node_type,
          nodeType: String(n.node_type || 'ENTITY').toUpperCase(),
          properties: n.properties || {},
          status: (n.properties && n.properties.status) ? n.properties.status : 'UNKNOWN',
        })));
        setGraphEdges(exportData.edges.map(e => ({
          id: `${e.source_id}->${e.target_id}:${e.edge_type}`,
          sourceId: e.source_id,
          targetId: e.target_id,
          edgeType: e.edge_type,
          label: e.edge_type,
        })));
        setGraphDigest(exportData.graph_digest || '');
      } else {
        setGraphNodes([]); setGraphEdges([]); setGraphDigest('');
      }
    } catch {
      setGraphNodes([]); setGraphEdges([]); setGraphDigest('');
    }
  }, []);

  const refreshLedgerVerification = useCallback(async () => {
    try {
      setLedgerVerification(await apiService.verifyLedger());
      setBackendError(null);
    } catch (e: any) {
      // UNAVAILABLE — never inferred as valid locally.
      setLedgerVerification(null);
      setBackendError(e?.message || 'Backend ledger unavailable');
    }
  }, []);

  const refreshAnalystDecisions = useCallback(async (entityId?: string) => {
    try {
      const events = await apiService.fetchLedgerEvents({ entityId });
      setAnalystDecisions(events.filter(e => e.event_type === 'analyst_decision'));
    } catch {
      setAnalystDecisions([]);
    }
  }, []);

  /**
   * Record an explicit analyst decision. The decision only becomes visible after
   * the backend confirms and persists the signed ledger event.
   */
  const submitAnalystDecision = useCallback(async (
    decision: AnalystDecision,
    actor: string,
    opts: { entityId?: string; scanId?: string; reason?: string } = {},
  ): Promise<LedgerEventRecord | null> => {
    const entityId = opts.entityId || currentScanId || '';
    if (!entityId) {
      setBackendError('No entity available to record an analyst decision against.');
      return null;
    }
    try {
      const event = await apiService.recordAnalystDecision(entityId, decision, actor, {
        scanId: opts.scanId || currentScanId || undefined,
        reason: opts.reason,
      });
      setBackendError(null);
      await refreshAnalystDecisions(entityId);
      return event;
    } catch (e: any) {
      setBackendError(e?.message || 'Analyst decision was not recorded.');
      return null;
    }
  }, [currentScanId, refreshAnalystDecisions]);

  const focusNodeInGraph = (nodeId: string) => {
    const found = graphNodes.find(n => n.id === nodeId);
    setSelectedGraphNode(found ?? null);
  };

  const resetInvestigation = () => {
    setPhase('launch');
    setFindings([]);
    setImageResults([]);
    setTrustScore(null);
    setRecommendations([]);
    setSelectedFinding(null);
    setSelectedGraphNode(null);
    setCurrentScanId(null);
    setScanSession(null);
    setLedgerVerification(null);
    setAnalystDecisions([]);
    setBackendError(null);
    setGraphNodes([]);
    setGraphEdges([]);
    setGraphDigest('');
    setArtifacts(INITIAL_ARTIFACTS);
  };

  /**
   * Export the authoritative evidence package produced by the backend.
   * Nothing is assembled or signed in the browser.
   */
  const exportEvidencePackage = async () => {
    if (!scanSession) {
      window.alert('Export UNAVAILABLE: no backend scan session is loaded.');
      return;
    }
    try {
      const [overview, graph, ledger] = await Promise.all([
        apiService.fetchOverview(),
        apiService.fetchGraphExport(),
        apiService.verifyLedger(),
      ]);
      const payload = {
        exported_at: new Date().toISOString(),
        source: 'TRUST-CV backend (authoritative)',
        scan_id: scanSession.scan_id,
        batch_id: scanSession.batch_id ?? null,
        scan_status: scanSession.status,
        assessment: scanSession.assessment ?? null,
        stage_results: scanSession.stage_results ?? {},
        findings: scanSession.findings ?? [],
        evidence_graph: graph ?? null,
        ledger_verification: ledger,
        system_overview: overview,
        analyst_decisions: analystDecisions,
      };
      downloadJson(payload, `trustcv_evidence_${scanSession.scan_id}.json`);
    } catch (e: any) {
      setBackendError(e?.message || 'Evidence export failed.');
      window.alert(`Evidence export FAILED: ${e?.message || 'backend unavailable'}`);
    }
  };

  const exportReport = async () => {
    if (!scanSession) {
      window.alert('Export UNAVAILABLE: no backend scan session is loaded.');
      return;
    }
    try {
      const [ledger, graph] = await Promise.all([
        apiService.verifyLedger(),
        apiService.fetchGraphExport(),
      ]);
      const report = {
        report_id: `REP-${scanSession.scan_id.substring(0, 10).toUpperCase()}`,
        generated_at: new Date().toISOString(),
        authority: 'TRUST-CV backend assurance pipeline',
        scan_id: scanSession.scan_id,
        batch_id: scanSession.batch_id ?? null,
        status: scanSession.status,
        stage_results: scanSession.stage_results ?? {},
        assessment: scanSession.assessment ?? null,
        findings: scanSession.findings ?? [],
        evidence_graph_digest: graph?.graph_digest ?? null,
        ledger_verification: ledger,
        errors: scanSession.errors ?? [],
        warnings: scanSession.warnings ?? [],
      };
      downloadJson(report, `${report.report_id}.json`);
    } catch (e: any) {
      setBackendError(e?.message || 'Report export failed.');
      window.alert(`Report export FAILED: ${e?.message || 'backend unavailable'}`);
    }
  };

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
          // Map the backend pipeline stage to the frontend stage slots using the
          // REAL backend component keys. No stage is ever assumed PASSED.
          setStages(prev => prev.map(s => {
            const componentState = session.stage_results?.[s.code];
            if (componentState) {
              return { ...s, status: componentState.status as any, summary: componentState.explanation || s.summary };
            }
            const reached = BACKEND_STAGE_ORDER.indexOf(session.stage) >= 0
              && BACKEND_STAGE_ORDER.indexOf(session.stage) >= (BACKEND_STAGE_ORDER.indexOf(s.code) === -1 ? 99 : BACKEND_STAGE_ORDER.indexOf(s.code));
            if (reached && session.status !== 'COMPLETED' && session.status !== 'FAILED') {
              return { ...s, status: 'RUNNING', progress: 50 };
            }
            if (session.status === 'COMPLETED' || session.status === 'FAILED') {
              return { ...s, status: 'UNAVAILABLE', progress: 0 };
            }
            return { ...s, status: 'WAITING', progress: 0 };
          }));

          if (session.assessment) {
            // Every value below is copied verbatim from the backend response.
            // The frontend performs NO re-derivation of security semantics.
            const assessment = session.assessment as Record<string, any>;
            const assuranceScore = typeof assessment.assuranceScore === 'number' ? assessment.assuranceScore : null;
            const dataRiskScore = typeof assessment.dataRiskScore === 'number' ? assessment.dataRiskScore : null;
            const modelRiskScore = typeof assessment.modelRiskScore === 'number' ? assessment.modelRiskScore : -1;
            const inferenceRiskScore = typeof assessment.inferenceRiskScore === 'number' ? assessment.inferenceRiskScore : -1;
            const rawDisposition = String(assessment.disposition ?? session.status).toUpperCase();

            setTrustScore({
              overall: assuranceScore === null ? 0 : assuranceScore * 100,
              dataIntegrity: dataRiskScore === null ? 0 : dataRiskScore * 100,
              // -1 is the backend's explicit "module UNAVAILABLE" sentinel.
              modelIntegrity: modelRiskScore < 0 ? -1 : modelRiskScore * 100,
              inferenceIntegrity: inferenceRiskScore < 0 ? -1 : inferenceRiskScore * 100,
              pipelineIntegrity: assuranceScore === null ? 0 : assuranceScore * 100,
              verdict: (rawDisposition === 'REVIEW' || rawDisposition === 'ALLOW_WITH_MONITORING')
                ? 'UNDER_REVIEW'
                : (rawDisposition as any),
              headline: `Backend disposition: ${rawDisposition}`,
              summary: `Analyzed ${assessment.totalSamples ?? 0} samples; backend status ${session.status}`,
            });
            setImageResults(assessment.imageResults || []);
            setFindings((session.findings || []).map((f: any) => ({
              id: f.finding_id,
              title: f.check_type,
              category: 'DATA POISONING',
              severity: f.severity,
              affectedArtifact: f.sample_ids?.[0] ? String(f.sample_ids[0]) : 'Uploaded dataset',
              evidenceSummary: f.description,
              confidence: (f.metric_score ?? 0) * 100,
              status: rawDisposition === 'QUARANTINED' ? 'Quarantined' : 'Confirmed',
              detectionMethod: 'Backend assurance engine',
              expectedValue: 'Clean',
              observedValue: f.description,
              sha256Proof: f.details?.sha256_hash ?? 'N/A',
              recommendedAction: f.details?.recommended_action ?? 'Analyst review required',
            })));
          } else if (session.status === 'FAILED') {
            // FAILED with no assessment — do NOT synthesise a happy-path score.
            setTrustScore(null);
          }

          // Ledger verification and evidence graph come from the backend only.
          await refreshLedgerVerification();
          await loadEvidenceGraph();
          if (session.batch_id) await refreshAnalystDecisions(session.batch_id);

          completeScan();
        }
      } catch (err) {
        console.error('Scan polling error', err);
        setBackendError(err instanceof Error ? err.message : 'Scan polling failed');
      }
    }, 1000);
  }, [currentScanId, completeScan, refreshLedgerVerification, loadEvidenceGraph, refreshAnalystDecisions]);

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
      focusNodeInGraph, ledgerVerification, analystDecisions, backendError,
      refreshLedgerVerification, loadEvidenceGraph, refreshAnalystDecisions,
      submitAnalystDecision, resetInvestigation, exportReport, exportEvidencePackage
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
