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

  /**
   * Cryptographically verify a sealed assurance report against the backend.
   * Returns the authoritative VerifyReportResponse, or null when the backend
   * cannot be reached (never fabricates a PASS/FAIL verdict client-side).
   */
  async auditReportSignature(report) {
    if (!report || typeof report !== "object") return null;
    try {
      return await this.verifyReport(report);
    } catch (error) {
      console.warn("[API] Report signature audit unavailable:", error);
      return null;
    }
  }

  /**
   * Ask the backend to cryptographically re-audit a report whose payload was
   * deliberately mutated. The verdict is produced by backend crypto only.
   * Returns null if no report was supplied or the backend is unreachable.
   */
  async probeTamperedReport(report) {
    if (!report || typeof report !== "object") return null;
    const mutated = JSON.parse(JSON.stringify(report));
    mutated.overall_verdict = "ACCEPTED";
    mutated.report_digest = "0".repeat(64);
    try {
      return await this.verifyReport(mutated);
    } catch (error) {
      console.warn("[API] Report tamper probe unavailable:", error);
      return null;
    }
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

  async getDatasetManifest(batchId) {
    return this._request(`/datasets/manifest/${encodeURIComponent(batchId)}`);
  }

  async verifyDatasetManifest(batchId) {
    return this._request(`/datasets/manifest/${encodeURIComponent(batchId)}/verify`);
  }

  /* Scan Pipeline (authoritative backend execution) */
  async startScan(batchId) {
    return this._request(`/scan/start/${encodeURIComponent(batchId)}`, {
      method: "POST",
    });
  }

  async getScan(scanId) {
    return this._request(`/scan/${encodeURIComponent(scanId)}`);
  }

  /* Tamper-Evident Assurance Ledger */
  async verifyLedger() {
    return this._request("/ledger/verify");
  }

  async listLedgerEvents(limit) {
    const qs = limit !== undefined ? `?limit=${Number(limit)}` : "";
    return this._request(`/ledger/events${qs}`);
  }

  async listLedgerEventsByScan(scanId) {
    return this._request(`/ledger/events/scan/${encodeURIComponent(scanId)}`);
  }

  async listLedgerEventsByEntity(entityId) {
    return this._request(`/ledger/events/entity/${encodeURIComponent(entityId)}`);
  }

  async recordAnalystDecision(entityId, decision, actor, opts = {}) {
    const qs = new URLSearchParams();
    qs.set("entity_id", entityId);
    qs.set("decision", String(decision).toUpperCase());
    qs.set("actor", actor || "operator_ground_station");
    if (opts.scan_id) qs.set("scan_id", opts.scan_id);
    if (opts.reason) qs.set("reason", opts.reason);
    return this._request(`/ledger/decision?${qs.toString()}`, {
      method: "POST",
    });
  }

  /** Read back the persisted analyst decisions recorded for an entity. */
  async listAnalystDecisions(entityId) {
    const events = await this.listLedgerEventsByEntity(entityId);
    if (!Array.isArray(events)) return [];
    return events.filter(e => e && e.event_type === "analyst_decision");
  }

  async getReadiness() {
    return this._request("/system/readiness");
  }
}

// Attach aliases to window for global access
window.TrustCvApiClient = TrustCvApiClient;
window.TrustCvApi = new TrustCvApiClient();
window.TrustCVAPI = window.TrustCvApi;
