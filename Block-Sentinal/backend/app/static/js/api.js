/**
 * TRUST-CV API Client Wrapper
 * Handles asynchronous REST communication with FastAPI backend endpoints.
 */
class TrustCvApiClient {
  constructor(baseUrl = "/api/v1") {
    this.baseUrl = baseUrl;
  }

  async _request(path, options = {}) {
    const url = `${this.baseUrl}${path}`;
    const defaultHeaders = {
      "Accept": "application/json",
      "Content-Type": "application/json",
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...defaultHeaders,
          ...(options.headers || {}),
        },
      });

      if (!response.ok) {
        let errMessage = `HTTP error ${response.status}: ${response.statusText}`;
        try {
          const errData = await response.json();
          if (errData.error) errMessage = errData.error;
          else if (errData.detail) errMessage = errData.detail;
        } catch (_) {}
        throw new Error(errMessage);
      }

      const envelope = await response.json();
      return envelope.data !== undefined ? envelope.data : envelope;
    } catch (error) {
      console.error(`[API Error] ${options.method || "GET"} ${path}:`, error);
      throw error;
    }
  }

  /* SOC Dashboard & Overview */
  async getOverview() {
    return this._request("/dashboard/overview");
  }

  async getTimeline(limit = 25) {
    return this._request(`/dashboard/timeline?limit=${limit}`);
  }

  async getContributors() {
    return this._request("/dashboard/contributors");
  }

  async investigateEntity(entityId) {
    return this._request(`/dashboard/investigate/${encodeURIComponent(entityId)}`);
  }

  /* Evidence & Lineage Graph */
  async getGraph() {
    return this._request("/graph/export");
  }

  async traceLineage(entityId) {
    return this._request(`/graph/trace/${encodeURIComponent(entityId)}`);
  }

  async getContributorRisk(contributorId, name = "Unknown") {
    return this._request(`/graph/contributor/${encodeURIComponent(contributorId)}/risk?name=${encodeURIComponent(name)}`);
  }

  /* Red-Team Adversarial Lab */
  async executeAttack(attackType, targetEntityId, intensity = 0.5, customPayload = {}) {
    return this._request("/redteam/attack/execute", {
      method: "POST",
      body: JSON.stringify({
        attack_type: attackType,
        target_entity_id: targetEntityId,
        intensity: parseFloat(intensity),
        custom_payload: customPayload,
      }),
    });
  }

  async verifyAttack(attackResult) {
    return this._request("/redteam/attack/verify", {
      method: "POST",
      body: JSON.stringify(attackResult),
    });
  }

  /* System Hardening & Cryptographic Audit */
  async auditChain() {
    return this._request("/hardening/audit/chain");
  }

  async getOfflineStatus() {
    return this._request("/hardening/audit/offline");
  }

  async getBenchmarkMetrics() {
    return this._request("/hardening/benchmark");
  }

  /* Assurance Reports */
  async getReport(reportId, format = "JSON_MANIFEST") {
    return this._request(`/reports/${encodeURIComponent(reportId)}?format=${format}`);
  }

  async verifyReport(report) {
    return this._request("/reports/verify", {
      method: "POST",
      body: JSON.stringify({ report }),
    });
  }
  /* Dataset Upload & Ingestion */
  async uploadDataset(formData) {
    const url = `${this.baseUrl}/datasets/upload`;
    try {
      const response = await fetch(url, {
        method: "POST",
        body: formData,
      });
      if (!response.ok) {
        let errMessage = `HTTP error ${response.status}: ${response.statusText}`;
        try {
          const errData = await response.json();
          if (errData.error) errMessage = errData.error;
          else if (errData.detail) errMessage = errData.detail;
        } catch (_) {}
        throw new Error(errMessage);
      }
      const envelope = await response.json();
      return envelope.data !== undefined ? envelope.data : envelope;
    } catch (error) {
      console.error("[API Error] POST /datasets/upload:", error);
      throw error;
    }
  }

  async getReadiness() {
    return this._request("/system/readiness");
  }
}

// Attach aliases to window for global access
window.TrustCvApiClient = TrustCvApiClient;
window.TrustCvApi = new TrustCvApiClient();
window.TrustCVAPI = window.TrustCvApi;
