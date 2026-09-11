/**
 * TRUST-CV: Centralized REST API Client
 * Connects directly to FastAPI backend routes with error handling and envelopes.
 * 100% Offline / Air-Gapped / Zero Remote Telemetry.
 */

const API_BASE = '/api/v1';

class TrustCVAPI {
  static async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const defaultHeaders = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };

    const config = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    };

    try {
      const response = await fetch(url, config);
      if (!response.ok) {
        let errDetail = `HTTP ${response.status} ${response.statusText}`;
        try {
          const errData = await response.json();
          if (errData.detail) errDetail = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
          else if (errData.error) errDetail = errData.error;
        } catch (_) {}
        throw new Error(errDetail);
      }

      const envelope = await response.json();
      return envelope.data !== undefined ? envelope.data : envelope;
    } catch (error) {
      console.error(`[API Error] ${endpoint}:`, error);
      throw error;
    }
  }

  // System & Health
  static async getHealth() {
    return this.request('/system/health');
  }

  static async getReadiness() {
    return this.request('/system/readiness');
  }

  static async getOverview() {
    return this.request('/dashboard/overview');
  }

  // Datasets
  static async listDatasets() {
    return this.request('/datasets');
  }

  static async ingestDataset(payload) {
    return this.request('/datasets/ingest', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static async verifyDataset(batchId) {
    return this.request(`/datasets/${batchId}/verify`, {
      method: 'POST',
    });
  }

  // Models
  static async listModels() {
    return this.request('/models');
  }

  static async registerModel(payload) {
    return this.request('/models/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static async verifyModelAgainstBaseline(modelId, baselineId) {
    return this.request(`/models/${modelId}/verify-against-baseline/${baselineId}`, {
      method: 'POST',
    });
  }

  // Behavioral Fingerprinting
  static async fingerprintModel(modelId, seed = 42) {
    return this.request(`/fingerprint/${modelId}?seed=${seed}`, {
      method: 'POST',
    });
  }

  // Runtime Inference DNA
  static async createInferenceDNA(payload) {
    return this.request('/inference/dna', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static async verifyInferenceChain(payload) {
    return this.request('/inference/verify-chain', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Distribution Drift
  static async evaluateDrift(payload) {
    return this.request('/drift/evaluate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Evidence Fusion & Hard-Veto Gatekeeper
  static async fuseEvidence(payload) {
    return this.request('/fusion/fuse', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Provenance Graph & Blast Radius
  static async getLineage(entityId) {
    return this.request(`/graph/lineage/${entityId}`);
  }

  static async getBlastRadius(entityId) {
    return this.request(`/graph/blast-radius/${entityId}`);
  }

  static async getFullGraph() {
    return this.request('/graph');
  }

  // Forensic Assurance Reports
  static async generateReport(payload) {
    return this.request('/reports/generate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static async verifyReport(reportPayload) {
    return this.request('/reports/verify', {
      method: 'POST',
      body: JSON.stringify(reportPayload),
    });
  }

  static async getReport(reportId) {
    return this.request(`/reports/${reportId}`);
  }

  // Red Team Scenario Runner
  static async runRedTeamScenario(scenarioId) {
    return this.request('/redteam/run', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: scenarioId }),
    });
  }
}

class TrustCvApiClient extends TrustCVAPI {}
window.TrustCVAPI = TrustCVAPI;
window.TrustCvApi = TrustCVAPI;
window.TrustCvApiClient = TrustCvApiClient;
