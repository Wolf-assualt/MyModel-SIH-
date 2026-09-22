/**
 * Phase 8 Integration Tests — Frontend ↔ Backend Assurance Integration
 *
 * Verifies:
 * 1. The investigation store initialises in the correct idle state.
 * 2. After a dataset upload the store holds the scan_id from the backend.
 * 3. startScan() refuses to proceed when no scan_id exists.
 * 4. Stage codes in PIPELINE_STAGES match the keys the backend writes into
 *    ScanSession.stage_results (critical for the polling mapper to work).
 * 5. The VerdictCard renders UNAVAILABLE when no assessment is present.
 * 6. clearArtifacts also clears scan state.
 *
 * These tests use the controllable mock API from test/mockApi.ts so no real
 * network calls are made.  The tests verify behaviour, not presentation details.
 */
import { render, screen, act, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { InvestigationProvider, useInvestigation } from '../state/investigationStore';
import { PIPELINE_STAGES } from '../data/mockScenario';
import { createMockApiService } from './mockApi';

// ── Backend stage_results keys written by app/api/scan.py ─────────────────
const BACKEND_STAGE_RESULT_KEYS = new Set([
  'DATA_INGESTION',
  'HASH_VERIFICATION',
  'DATASET_ANALYSIS',
  'DUPLICATE_DETECTION',
  'LABEL_INTEGRITY',
  'QUALITY_ANALYSIS',
  'TRIGGER_CANDIDATE_ANALYSIS',
  'OOD_DETECTION',
  'MODEL_INTEGRITY',
  'BACKDOOR_ANALYSIS',
  'INFERENCE_VALIDATION',
  'DISTRIBUTION_SHIFT',
  'EVIDENCE_FUSION',
  'EVIDENCE_GRAPH',
  'FINAL_VERDICT',
]);

// ── Mock API setup ──────────────────────────────────────────────────────────

let mockApiModule: ReturnType<typeof createMockApiService>;

/**
 * Replace the production apiService singleton with the controllable mock.
 */
vi.mock('../services/api', async (importOriginal) => {
  const original = await importOriginal<typeof import('../services/api')>();
  return {
    ...original,
    apiService: new Proxy({} as typeof original.apiService, {
      get(_target, prop: string) {
        // Delegate to the current mock instance so individual tests can override.
        return (mockApiModule?.mock as Record<string, unknown>)?.[prop];
      },
    }),
  };
});

beforeEach(() => {
  mockApiModule = createMockApiService();
});

afterEach(() => {
  vi.clearAllMocks();
});

// ── 1. PIPELINE_STAGES code alignment ───────────────────────────────────────

describe('PIPELINE_STAGES stage code alignment', () => {
  it('every stage code exists in the backend stage_results key set', () => {
    const mismatches = PIPELINE_STAGES.filter(
      s => !BACKEND_STAGE_RESULT_KEYS.has(s.code),
    );
    expect(mismatches).toEqual([]);
  });

  it('all stage IDs are unique', () => {
    const ids = PIPELINE_STAGES.map(s => s.id);
    expect(new Set(ids).size).toBe(PIPELINE_STAGES.length);
  });

  it('all stage codes are unique', () => {
    const codes = PIPELINE_STAGES.map(s => s.code);
    expect(new Set(codes).size).toBe(PIPELINE_STAGES.length);
  });

  it('all stages initialize as WAITING', () => {
    const nonWaiting = PIPELINE_STAGES.filter(s => s.status !== 'WAITING');
    expect(nonWaiting).toEqual([]);
  });
});

// ── 2. Helper component ─────────────────────────────────────────────────────

function StoreInspector({
  onRender,
}: {
  onRender: (state: ReturnType<typeof useInvestigation>) => void;
}) {
  const state = useInvestigation();
  onRender(state);
  return null;
}

// ── 3. Initial store state ───────────────────────────────────────────────────

describe('InvestigationStore initial state', () => {
  it('starts with phase=launch and no scan session', async () => {
    let capturedState: ReturnType<typeof useInvestigation> | null = null;

    await act(async () => {
      render(
        <InvestigationProvider>
          <StoreInspector onRender={s => { capturedState = s; }} />
        </InvestigationProvider>,
      );
    });

    expect(capturedState).not.toBeNull();
    expect(capturedState!.phase).toBe('launch');
    expect(capturedState!.currentScanId).toBeNull();
    expect(capturedState!.isScanning).toBe(false);
    expect(capturedState!.isScanCompleted).toBe(false);
    expect(capturedState!.isReadyToScan).toBe(false);
    expect(capturedState!.trustScore).toBeNull();
    expect(capturedState!.findings).toHaveLength(0);
  });
});

// ── 4. startScan guard — must not proceed without scan_id ──────────────────

describe('startScan guard', () => {
  it('sets backendError when called without a scan_id', async () => {
    let capturedState: ReturnType<typeof useInvestigation> | null = null;

    await act(async () => {
      render(
        <InvestigationProvider>
          <StoreInspector onRender={s => { capturedState = s; }} />
        </InvestigationProvider>,
      );
    });

    // isReadyToScan must be false (no upload yet)
    expect(capturedState!.isReadyToScan).toBe(false);
    expect(capturedState!.currentScanId).toBeNull();

    await act(async () => {
      capturedState!.startScan();
    });

    // Should have set a backend error, not transitioned to scan phase.
    expect(capturedState!.backendError).not.toBeNull();
    expect(capturedState!.phase).toBe('launch');
    expect(capturedState!.isScanning).toBe(false);
  });
});

// ── 5. Upload sets scan_id from backend response ────────────────────────────

describe('updateArtifactWithFile — dataset upload', () => {
  it('stores the scan_id returned by the backend after successful upload', async () => {
    let capturedState: ReturnType<typeof useInvestigation> | null = null;

    await act(async () => {
      render(
        <InvestigationProvider>
          <StoreInspector onRender={s => { capturedState = s; }} />
        </InvestigationProvider>,
      );
    });

    const file = new File(['pixel data'], 'dataset.jpg', { type: 'image/jpeg' });

    await act(async () => {
      await capturedState!.updateArtifactWithFile('art-dataset', file);
    });

    await waitFor(() => {
      expect(capturedState!.currentScanId).toBe('scan-mock-001');
    });

    expect(capturedState!.scanSession?.batch_id).toBe('batch-mock-001');
    expect(capturedState!.isReadyToScan).toBe(true);

    // Artifact card should reflect upload state
    const datasetArtifact = capturedState!.artifacts.find(a => a.id === 'art-dataset');
    expect(datasetArtifact?.status).toBe('verified');
    expect(datasetArtifact?.filename).toBe('dataset.jpg');
  });

  it('sets backendError and status=error on upload failure', async () => {
    // Override the mock to simulate upload failure
    (mockApiModule.mock as Record<string, unknown>).uploadAndScanDataset = () =>
      Promise.reject(new Error('Upload failed: server error'));

    let capturedState: ReturnType<typeof useInvestigation> | null = null;

    await act(async () => {
      render(
        <InvestigationProvider>
          <StoreInspector onRender={s => { capturedState = s; }} />
        </InvestigationProvider>,
      );
    });

    const file = new File(['pixel data'], 'bad.jpg', { type: 'image/jpeg' });

    await act(async () => {
      await capturedState!.updateArtifactWithFile('art-dataset', file);
    });

    await waitFor(() => {
      expect(capturedState!.backendError).toContain('Upload failed');
    });

    const datasetArtifact = capturedState!.artifacts.find(a => a.id === 'art-dataset');
    expect(datasetArtifact?.status).toBe('error');
    expect(capturedState!.currentScanId).toBeNull();
    expect(capturedState!.isReadyToScan).toBe(false);
  });
});

// ── 6. VerdictCard UNAVAILABLE state ───────────────────────────────────────

describe('VerdictCard — no assessment', () => {
  it('never invents a verdict when trustScore is null', async () => {
    const { VerdictCard } = await import('../components/results/VerdictCard');

    await act(async () => {
      render(
        <InvestigationProvider>
          <VerdictCard />
        </InvestigationProvider>,
      );
    });

    // Should display the UNAVAILABLE placeholder, not any security verdict.
    expect(screen.getByText(/UNAVAILABLE/i)).toBeTruthy();
    expect(screen.queryByText(/^TRUSTED$/i)).toBeNull();
    expect(screen.queryByText(/^CLEAN$/i)).toBeNull();
  });
});

// ── 7. clearArtifacts also clears scan state ────────────────────────────────

describe('clearArtifacts', () => {
  it('resets scan_id and session when artifacts are cleared', async () => {
    let capturedState: ReturnType<typeof useInvestigation> | null = null;

    await act(async () => {
      render(
        <InvestigationProvider>
          <StoreInspector onRender={s => { capturedState = s; }} />
        </InvestigationProvider>,
      );
    });

    // Upload to create a session
    const file = new File(['data'], 'test.jpg', { type: 'image/jpeg' });
    await act(async () => {
      await capturedState!.updateArtifactWithFile('art-dataset', file);
    });

    await waitFor(() => expect(capturedState!.currentScanId).toBe('scan-mock-001'));

    // Clear should reset everything
    await act(async () => {
      capturedState!.clearArtifacts();
    });

    expect(capturedState!.currentScanId).toBeNull();
    expect(capturedState!.scanSession).toBeNull();
    expect(capturedState!.isReadyToScan).toBe(false);
  });
});
