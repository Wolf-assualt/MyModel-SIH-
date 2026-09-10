/**
 * TRUST-CV Defense SOC Command Center Application Controller
 * Handles real-time telemetry polling, red-team simulation, intercept modals, and reports.
 */

let graphRenderer = null;
let currentOverview = null;
let pollingTimer = null;

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", async () => {
  console.log("[TRUST-CV] Initializing Defense SOC Command Center...");

  // 1. Initialize Lucide Icons
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // 2. Initialize Provenance Graph Renderer
  graphRenderer = new ProvenanceGraphRenderer("graph-canvas", "inspector-drawer");

  // 3. Attach UI Event Listeners
  initEventListeners();

  // 4. Initial Data Fetch
  await refreshAllData();

  // 5. Start Telemetry Polling (Every 3 seconds)
  pollingTimer = setInterval(pollTelemetry, 3000);
});

function initEventListeners() {
  // Drawer close button
  const drawerCloseBtn = document.getElementById("drawer-close-btn");
  if (drawerCloseBtn) {
    drawerCloseBtn.addEventListener("click", () => {
      if (graphRenderer) graphRenderer.closeInspector();
    });
  }

  // Reset Graph View button
  const resetGraphBtn = document.getElementById("btn-reset-graph");
  if (resetGraphBtn) {
    resetGraphBtn.addEventListener("click", () => {
      if (graphRenderer) graphRenderer.resetView();
    });
  }

  // Refresh Graph button
  const refreshGraphBtn = document.getElementById("btn-refresh-graph");
  if (refreshGraphBtn) {
    refreshGraphBtn.addEventListener("click", async () => {
      refreshGraphBtn.classList.add("animate-spin");
      await loadGraph();
      setTimeout(() => refreshGraphBtn.classList.remove("animate-spin"), 600);
    });
  }

  // Red Team Quick Attack Buttons
  const btnAttackBackdoor = document.getElementById("btn-attack-backdoor");
  if (btnAttackBackdoor) {
    btnAttackBackdoor.addEventListener("click", () => triggerAttack("BACKDOOR_TRIGGER", "dataset_recon_alpha", 0.8));
  }

  const btnAttackWeights = document.getElementById("btn-attack-weights");
  if (btnAttackWeights) {
    btnAttackWeights.addEventListener("click", () => triggerAttack("MODEL_WEIGHT_TAMPERING", "model_yolo_tactical_v4", 0.75));
  }

  const btnAttackReplay = document.getElementById("btn-attack-replay");
  if (btnAttackReplay) {
    btnAttackReplay.addEventListener("click", () => triggerAttack("INFERENCE_REPLAY", "inf_rec_uav_patrol_01", 0.6));
  }

  // Air-Gap Badge Click
  const airgapBadge = document.getElementById("badge-airgap");
  if (airgapBadge) {
    airgapBadge.addEventListener("click", verifyOfflineReadiness);
  }

  // Copy Chain Tip Button
  const copyChainTipBtn = document.getElementById("btn-copy-chain-tip");
  if (copyChainTipBtn) {
    copyChainTipBtn.addEventListener("click", copyChainTip);
  }

  // Modal Close Buttons
  const interceptModalClose = document.getElementById("modal-intercept-close");
  if (interceptModalClose) {
    interceptModalClose.addEventListener("click", closeInterceptModal);
  }

  const reportModalClose = document.getElementById("modal-report-close");
  if (reportModalClose) {
    reportModalClose.addEventListener("click", closeReportModal);
  }
}

async function refreshAllData() {
  try {
    await Promise.allSettled([
      loadOverview(),
      loadGraph(),
      loadTimeline(),
      loadAuditStatus(),
    ]);
  } catch (err) {
    console.error("[SOC] Error during initial data load:", err);
  }
}

async function pollTelemetry() {
  try {
    await Promise.allSettled([
      loadOverview(true),
      loadTimeline(true),
    ]);
  } catch (err) {
    console.warn("[SOC] Telemetry polling hiccup:", err);
  }
}

async function loadOverview(isPolling = false) {
  if (!window.TrustCvApi) return;
  try {
    const data = await window.TrustCvApi.getOverview();
    currentOverview = data;
    renderOverviewMetrics(data);
  } catch (err) {
    if (!isPolling) console.error("[SOC] Failed to load overview:", err);
  }
}

function renderOverviewMetrics(overview) {
  if (!overview) return;

  // Total Assets = Models + Datasets + Inferences
  const totalAssets = (overview.total_models || 0) + (overview.total_datasets || 0) + (overview.total_inferences || 0);
  const totalAssetsEl = document.getElementById("stat-total-assets");
  if (totalAssetsEl) totalAssetsEl.textContent = totalAssets;

  // Quarantines
  const quarantinedEl = document.getElementById("stat-quarantined");
  if (quarantinedEl) {
    quarantinedEl.textContent = overview.quarantined_assets || 0;
    if (overview.quarantined_assets > 0) {
      quarantinedEl.parentElement.classList.add("border-rose-500/60");
    } else {
      quarantinedEl.parentElement.classList.remove("border-rose-500/60");
    }
  }

  // Threat Vectors
  const threatsEl = document.getElementById("stat-threats");
  if (threatsEl) {
    threatsEl.textContent = overview.active_threats_count || 0;
  }

  // Chain Tip Hash
  const chainTipEl = document.getElementById("stat-chain-head");
  if (chainTipEl && overview.chain_head_hash) {
    const raw = overview.chain_head_hash;
    chainTipEl.textContent = raw.length > 20 ? `${raw.slice(0, 10)}...${raw.slice(-8)}` : raw;
    chainTipEl.setAttribute("data-full-hash", raw);
  }

  // System Status Pill
  const statusPill = document.getElementById("system-status-pill");
  if (statusPill) {
    const status = overview.system_integrity_status || "OPERATIONAL";
    statusPill.textContent = status;
    if (status === "OPERATIONAL") {
      statusPill.className = "px-2.5 py-1 text-xs font-mono font-bold rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-500/50 flex items-center gap-1.5";
    } else if (status === "ELEVATED_RISK") {
      statusPill.className = "px-2.5 py-1 text-xs font-mono font-bold rounded-full bg-amber-950/80 text-amber-400 border border-amber-500/50 flex items-center gap-1.5";
    } else {
      statusPill.className = "px-2.5 py-1 text-xs font-mono font-bold rounded-full bg-rose-950/80 text-rose-400 border border-rose-500/50 animate-pulse flex items-center gap-1.5";
    }
  }
}

async function loadGraph() {
  if (!window.TrustCvApi || !graphRenderer) return;
  try {
    const exportData = await window.TrustCvApi.getGraph();
    if (exportData) {
      graphRenderer.loadGraphData(exportData);
      const nodeCountEl = document.getElementById("graph-node-count");
      const edgeCountEl = document.getElementById("graph-edge-count");
      if (nodeCountEl) nodeCountEl.textContent = `${exportData.node_count || 0} Nodes`;
      if (edgeCountEl) edgeCountEl.textContent = `${exportData.edge_count || 0} Edges`;
    }
  } catch (err) {
    console.error("[SOC] Failed to load graph data:", err);
  }
}

async function loadTimeline(isPolling = false) {
  if (!window.TrustCvApi) return;
  try {
    const timeline = await window.TrustCvApi.getTimeline(15);
    const container = document.getElementById("activity-feed-container");
    if (!container || !timeline) return;

    if (timeline.length === 0) {
      container.innerHTML = `<div class="text-xs text-slate-500 py-4 text-center">No recent security events recorded.</div>`;
      return;
    }

    const html = timeline.map((item) => {
      const severityColor = {
        CRITICAL: "bg-rose-950 text-rose-300 border-rose-600",
        HIGH: "bg-orange-950 text-orange-300 border-orange-600",
        MEDIUM: "bg-amber-950 text-amber-300 border-amber-600",
        LOW: "bg-slate-800 text-slate-300 border-slate-600",
        INFO: "bg-cyan-950 text-cyan-300 border-cyan-600",
      }[item.severity] || "bg-slate-800 text-slate-300 border-slate-600";

      const timeStr = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : "--:--:--";

      return `
        <div class="p-2.5 bg-slate-900/60 rounded border border-slate-800/80 hover:border-slate-700 transition flex flex-col gap-1 text-xs">
          <div class="flex items-center justify-between">
            <span class="font-mono text-cyan-400 font-semibold">${item.event_type}</span>
            <div class="flex items-center gap-1.5">
              <span class="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase border ${severityColor}">${item.severity}</span>
              <span class="text-slate-500 font-mono text-[11px]">${timeStr}</span>
            </div>
          </div>
          <p class="text-slate-300">${escapeHtml(item.description)}</p>
          <div class="flex items-center gap-2 text-[10px] font-mono text-slate-500 mt-0.5">
            <span>ID: <span class="text-slate-400">${item.entity_id}</span></span>
            ${item.actor ? `<span>• ACTOR: <span class="text-slate-400">${item.actor}</span></span>` : ""}
          </div>
        </div>
      `;
    }).join("");

    container.innerHTML = html;
  } catch (err) {
    if (!isPolling) console.error("[SOC] Failed to load timeline:", err);
  }
}

async function loadAuditStatus() {
  if (!window.TrustCvApi) return;
  try {
    const [chainAudit, offlineStatus] = await Promise.allSettled([
      window.TrustCvApi.auditChain(),
      window.TrustCvApi.getOfflineStatus(),
    ]);

    const chainAuditEl = document.getElementById("audit-chain-status");
    if (chainAuditEl && chainAudit.status === "fulfilled") {
      const data = chainAudit.value;
      const isValid = data.valid;
      chainAuditEl.innerHTML = isValid
        ? `<span class="text-emerald-400 font-mono">SEALED (BLOCKS: ${data.total_blocks})</span>`
        : `<span class="text-rose-400 font-mono">TAMPER DETECTED (BLOCK: ${data.broken_index})</span>`;
    }

    const offlineStatusEl = document.getElementById("audit-offline-status");
    if (offlineStatusEl && offlineStatus.status === "fulfilled") {
      const data = offlineStatus.value;
      offlineStatusEl.innerHTML = data.air_gap_verified
        ? `<span class="text-cyan-400 font-mono">AIR-GAPPED 100%</span>`
        : `<span class="text-amber-400 font-mono">EXTERNAL LINK ACTIVE</span>`;
    }
  } catch (err) {
    console.error("[SOC] Failed to load audit status:", err);
  }
}

/* Red Team Simulation Handler */
async function triggerAttack(attackType, targetEntityId, intensity = 0.7) {
  const modal = document.getElementById("modal-intercept");
  if (!modal || !window.TrustCvApi) return;

  const btnTrigger = event?.currentTarget;
  if (btnTrigger) {
    btnTrigger.disabled = true;
    btnTrigger.classList.add("opacity-50");
  }

  showToast(`Simulating ${attackType} vector...`, "info");

  try {
    // 1. Execute attack inside quarantine sandbox
    const result = await window.TrustCvApi.executeAttack(attackType, targetEntityId, intensity);

    // 2. Pass result to defense detection verification
    const verification = await window.TrustCvApi.verifyAttack(result);

    // 3. Display Intercept Modal
    renderInterceptModal(attackType, targetEntityId, result, verification);

    // 4. Refresh telemetry and graph immediately
    await refreshAllData();
  } catch (err) {
    showToast(`Simulation failed: ${err.message}`, "error");
    console.error("[SOC] Attack execution error:", err);
  } finally {
    if (btnTrigger) {
      btnTrigger.disabled = false;
      btnTrigger.classList.remove("opacity-50");
    }
  }
}

function renderInterceptModal(attackType, targetId, result, verification) {
  const modal = document.getElementById("modal-intercept");
  if (!modal) return;

  const typeEl = document.getElementById("intercept-attack-type");
  const targetEl = document.getElementById("intercept-target");
  const verdictBadge = document.getElementById("intercept-verdict-badge");
  const summaryEl = document.getElementById("intercept-summary");
  const detailsEl = document.getElementById("intercept-details");

  if (typeEl) typeEl.textContent = attackType;
  if (targetEl) targetEl.textContent = targetId;

  const isDetected = verification ? verification.detected : true;
  if (verdictBadge) {
    verdictBadge.textContent = isDetected ? "CONTAINED & QUARANTINED" : "EVASION INVESTIGATION";
    verdictBadge.className = isDetected
      ? "px-2.5 py-1 text-xs font-mono font-bold rounded bg-rose-950 text-rose-300 border border-rose-500"
      : "px-2.5 py-1 text-xs font-mono font-bold rounded bg-amber-950 text-amber-300 border border-amber-500";
  }

  if (summaryEl) {
    summaryEl.textContent = verification && verification.verdict_summary
      ? verification.verdict_summary
      : `Adversarial attempt against ${targetId} was flagged and intercepted by zero-trust validation engines.`;
  }

  if (detailsEl) {
    const violations = verification?.findings || result?.evidence_generated || [];
    const violationsHtml = violations.length
      ? violations.map((v) => `
          <div class="py-1.5 border-b border-slate-800 text-xs flex items-start gap-2">
            <span class="text-rose-400 font-mono font-bold">VIOLATION:</span>
            <span class="text-slate-300 font-mono">${escapeHtml(typeof v === "object" ? v.description || JSON.stringify(v) : String(v))}</span>
          </div>
        `).join("")
      : `<div class="text-xs text-slate-400">Cryptographic hash mismatch triggered quarantine.</div>`;

    detailsEl.innerHTML = `
      <div class="space-y-3">
        <div>
          <span class="text-xs font-bold uppercase tracking-wider text-cyan-400 block mb-1">Triggered Defense Sensors</span>
          <div class="bg-slate-950 p-2 rounded border border-slate-800">
            ${violationsHtml}
          </div>
        </div>
        <div class="grid grid-cols-2 gap-2 text-xs">
          <div class="bg-slate-950 p-2 rounded border border-slate-800">
            <span class="text-slate-400 block text-[10px]">EXECUTION RUN ID</span>
            <span class="font-mono text-cyan-300 break-all text-[11px]">${result.run_id || "RUN-" + Date.now()}</span>
          </div>
          <div class="bg-slate-950 p-2 rounded border border-slate-800">
            <span class="text-slate-400 block text-[10px]">ENFORCEMENT STATUS</span>
            <span class="font-mono text-rose-400 font-bold text-[11px]">ISOLATED IN QUARANTINE</span>
          </div>
        </div>
      </div>
    `;
  }

  modal.classList.remove("hidden");
  modal.classList.add("flex");
}

function closeInterceptModal() {
  const modal = document.getElementById("modal-intercept");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
  }
}

function closeReportModal() {
  const modal = document.getElementById("modal-report");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
  }
}

async function verifyOfflineReadiness() {
  if (!window.TrustCvApi) return;
  try {
    const res = await window.TrustCvApi.getOfflineStatus();
    if (res.air_gap_verified) {
      showToast("AIR-GAP AUDIT PASSED: Zero external socket bindings detected.", "success");
    } else {
      showToast("AIR-GAP ALERT: Active external sockets discovered!", "error");
    }
  } catch (err) {
    showToast("Audit check error: " + err.message, "error");
  }
}

function copyChainTip() {
  const chainTipEl = document.getElementById("stat-chain-head");
  if (!chainTipEl) return;
  const hash = chainTipEl.getAttribute("data-full-hash") || chainTipEl.textContent;
  navigator.clipboard.writeText(hash);
  showToast("Chain Head Hash copied to clipboard!", "info");
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  const bgClass = {
    info: "bg-cyan-950 text-cyan-200 border-cyan-500",
    success: "bg-emerald-950 text-emerald-200 border-emerald-500",
    error: "bg-rose-950 text-rose-200 border-rose-500",
  }[type] || "bg-slate-900 text-slate-200 border-slate-500";

  toast.className = `fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded shadow-2xl border text-xs font-mono flex items-center gap-2 transition-all duration-300 transform translate-y-2 opacity-0 ${bgClass}`;
  toast.innerHTML = `
    <span class="w-2 h-2 rounded-full ${type === 'error' ? 'bg-rose-400' : type === 'success' ? 'bg-emerald-400' : 'bg-cyan-400'} animate-ping"></span>
    <span>${escapeHtml(message)}</span>
  `;

  document.body.appendChild(toast);
  requestAnimationFrame(() => {
    toast.classList.remove("translate-y-2", "opacity-0");
  });

  setTimeout(() => {
    toast.classList.add("translate-y-2", "opacity-0");
    setTimeout(() => toast.remove(), 350);
  }, 3000);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
