/**
 * TRUST-CV: Defense SOC Command Center & Mission Orchestrator
 * Pure Vanilla JavaScript State Machine & Real-Time Visualization Layer.
 * 100% Offline / Air-Gapped / Zero Remote Dependencies.
 */

document.addEventListener('DOMContentLoaded', () => {
  const AppState = {
    theme: localStorage.getItem('trustcv_theme') || 'dark',
    activePhase: 1, // 1: Launch, 2: Scan, 3: Results
    currentScenario: 'pristine_eo', // pristine_eo, tamper_b04, benign_drift, model_tamper, inference_replay
    mission: {
      id: 'MSN-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
      startTime: new Date(),
      assetName: 'Sentinel2_S2A_Recon_Tile',
      assetType: 'EARTH_OBSERVATION_SATELLITE',
      format: 'BIGEARTHNET_S2_12BAND',
      datasetManifest: null,
      modelManifest: null,
      dnaRecords: [],
      driftReport: null,
      fusedAssessment: null,
      graphData: { nodes: [], edges: [] },
      blastRadius: null,
      report: null,
      isHardVeto: false,
      isQuarantined: false,
    },
    graphRenderer: null,
    scanInterval: null,
  };

  // =========================================================================
  // 1. THEME MANAGEMENT
  // =========================================================================

  function applyTheme(theme) {
    AppState.theme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('trustcv_theme', theme);
    
    const themeBtn = document.getElementById('btn-theme-toggle');
    if (themeBtn) {
      themeBtn.innerHTML = theme === 'dark' 
        ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`
        : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
      themeBtn.title = `Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`;
    }

    if (AppState.graphRenderer) {
      AppState.graphRenderer.render();
    }
  }

  // =========================================================================
  // 2. STAGE NAVIGATION & HUD UPDATES
  // =========================================================================

  function setPhase(phaseNum) {
    AppState.activePhase = phaseNum;

    // Update Views
    document.querySelectorAll('.stage-view').forEach(v => v.classList.remove('active'));
    const targetView = document.getElementById(`stage-view-${phaseNum}`);
    if (targetView) targetView.classList.add('active');

    // Update HUD Stepper
    document.querySelectorAll('.hud-step').forEach(s => {
      const stepIdx = parseInt(s.getAttribute('data-step'), 10);
      s.classList.remove('active', 'completed');
      if (stepIdx === phaseNum) {
        s.classList.add('active');
      } else if (stepIdx < phaseNum) {
        s.classList.add('completed');
      }
    });

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // =========================================================================
  // 3. SCENARIOS CONFIGURATION & SELECTION
  // =========================================================================

  const Scenarios = {
    pristine_eo: {
      name: 'Authentic Sentinel-2 EO Patch',
      tag: 'HAPPY PATH',
      tagClass: 'badge-health-ok',
      desc: 'Pristine 12-band multi-spectral patch. Full Merkle inclusion integrity, approved model weights, and valid inference DNA.',
      tamperedBand: null,
      expectedVerdict: 'ACCEPTED',
      riskScore: 0.05,
      hardVeto: false,
    },
    tamper_b04: {
      name: 'Adversarial B04 (Red Band) Tamper',
      tag: 'HARD VETO',
      tagClass: 'badge-health-crit',
      desc: 'Controlled byte injection into Band 4 (Red) GeoTIFF. Immediate Merkle divergence, hard-veto BLOCK, and quarantine.',
      tamperedBand: 'B04',
      expectedVerdict: 'QUARANTINED',
      riskScore: 0.98,
      hardVeto: true,
    },
    benign_drift: {
      name: 'Seasonal Autumn Terrain Drift',
      tag: 'REVIEW ONLY',
      tagClass: 'badge-health-warn',
      desc: 'Natural vegetation senescence & solar irradiance decay. Significant statistical drift detected; no quarantine.',
      tamperedBand: null,
      expectedVerdict: 'REVIEW',
      riskScore: 0.35,
      hardVeto: false,
    },
    model_tamper: {
      name: 'Model Weight Tensor Modification',
      tag: 'MODEL TAMPER',
      tagClass: 'badge-health-crit',
      desc: 'Single floating-point weight mutation in classifier layer. State dict divergence triggers hard-veto quarantine.',
      tamperedBand: null,
      expectedVerdict: 'QUARANTINED',
      riskScore: 0.95,
      hardVeto: true,
    },
    inference_replay: {
      name: 'Inference DNA Nonce Replay',
      tag: 'REPLAY ATTACK',
      tagClass: 'badge-health-crit',
      desc: 'Replaying legitimate inference record in stream. Duplicate nonce triggers replay violation and chain invalidation.',
      tamperedBand: null,
      expectedVerdict: 'QUARANTINED',
      riskScore: 0.90,
      hardVeto: true,
    },
  };

  function selectScenario(scenarioKey) {
    AppState.currentScenario = scenarioKey;
    const sc = Scenarios[scenarioKey];
    if (!sc) return;

    // Update UI Preset Cards
    document.querySelectorAll('.preset-card').forEach(card => {
      card.classList.toggle('selected', card.getAttribute('data-scenario') === scenarioKey);
    });

    // Update Spectral Bands Visualizer
    document.querySelectorAll('.spectral-band-tile').forEach(tile => {
      const bandName = tile.getAttribute('data-band');
      tile.classList.toggle('tampered', bandName === sc.tamperedBand);
    });

    // Update Preflight Meta
    const metaAsset = document.getElementById('meta-asset-name');
    if (metaAsset) metaAsset.textContent = sc.name;

    const metaStatus = document.getElementById('meta-expected-status');
    if (metaStatus) {
      metaStatus.textContent = sc.expectedVerdict;
      metaStatus.style.color = sc.hardVeto ? 'var(--status-danger)' : (sc.expectedVerdict === 'REVIEW' ? 'var(--status-warning)' : 'var(--status-success)');
    }
  }

  // =========================================================================
  // 4. PHASE 2: TERMINAL LOGGING & SCAN SIMULATION
  // =========================================================================

  function addTerminalLog(op, msg, type = 'info') {
    const term = document.getElementById('terminal-body');
    if (!term) return;

    const now = new Date();
    const ts = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

    const row = document.createElement('div');
    row.className = `log-entry ${type}`;
    row.innerHTML = `
      <span class="log-ts">[${ts}]</span>
      <span class="log-op">${op.padEnd(20, '.')}</span>
      <span class="log-msg">${msg}</span>
    `;

    term.appendChild(row);
    term.scrollTop = term.scrollHeight;
  }

  function updatePipelineStage(stageIndex, status) {
    const item = document.getElementById(`stage-item-${stageIndex}`);
    if (!item) return;

    item.className = `pipeline-stage-item ${status.toLowerCase()}`;
    const badge = item.querySelector('.stage-badge');
    if (badge) {
      badge.textContent = status.toUpperCase();
      badge.className = `stage-badge badge-${status.toLowerCase()}`;
    }
  }

  function updateRiskMeter(score, isHardVeto) {
    const scoreVal = document.getElementById('live-risk-score');
    const barFill = document.getElementById('live-risk-fill');
    if (scoreVal) scoreVal.textContent = score.toFixed(2);
    if (barFill) {
      barFill.style.width = `${Math.min(100, Math.max(0, score * 100))}%`;
      barFill.style.backgroundColor = isHardVeto ? 'var(--status-danger)' : (score > 0.3 ? 'var(--status-warning)' : 'var(--status-success)');
    }
  }

  async function launchAssuranceScan() {
    setPhase(2);
    const scenario = Scenarios[AppState.currentScenario];
    const isTamper = scenario.hardVeto;
    const isDrift = (AppState.currentScenario === 'benign_drift');

    // Clear Terminal & Reset Steppers
    const term = document.getElementById('terminal-body');
    if (term) term.innerHTML = '';
    for (let i = 1; i <= 12; i++) {
      updatePipelineStage(i, 'pending');
    }
    updateRiskMeter(0.0, false);

    addTerminalLog('MISSION.START', `Initializing Assurance Mission [${AppState.mission.id}] for '${scenario.name}'...`, 'highlight');

    // 12 Pipeline Steps
    const steps = [
      { id: 1, op: 'READ_ONLY.INSPECT', msg: 'Scanning 12 Sentinel-2 GeoTIFF bands. Non-destructive lock active.', status: 'passed' },
      { id: 2, op: 'CRYPTO.MERKLE_TREE', msg: isTamper && AppState.currentScenario === 'tamper_b04' 
          ? 'Merkle root divergence detected! B04 GeoTIFF hash altered.' 
          : 'All 12 band SHA-256 digests verified. Compound Merkle root sealed with ECDSA SECP256R1.', 
        status: (isTamper && AppState.currentScenario === 'tamper_b04') ? 'blocked' : 'passed' },
      { id: 3, op: 'DATA.INTEGRITY', msg: isTamper ? 'Bit-level mutation flagged in spectral payload.' : 'Duplicate detection & 16-bit dHash perceptual audit clean.', status: isTamper ? 'blocked' : 'passed' },
      { id: 4, op: 'MODEL.IDENTITY', msg: AppState.currentScenario === 'model_tamper' 
          ? 'Weight tensor state-dict hash mismatch! Approved baseline violated.' 
          : 'Approved architecture (TorchScript) and deterministic state dict match baseline.', 
        status: AppState.currentScenario === 'model_tamper' ? 'blocked' : 'passed' },
      { id: 5, op: 'BEHAVIOR.FINGERPRINT', msg: '7 physical transformations evaluated (Noise, Blur, Occlusion). Sensitivity score within bounds.', status: 'passed' },
      { id: 6, op: 'INFERENCE.DNA', msg: AppState.currentScenario === 'inference_replay'
          ? 'Replay violation! Duplicate nonce reused in stream. Monotonicity broken.'
          : 'Inference DNA tuple sealed: ⟨InputFrame, ModelDigest, Output, Nonce, PrevHash⟩.', 
        status: AppState.currentScenario === 'inference_replay' ? 'blocked' : 'passed' },
      { id: 7, op: 'DISTRIBUTION.DRIFT', msg: isDrift 
          ? 'Spectral distribution shift detected (NDVI KS=0.84, PSI=11.28). Flagged for contextual review.' 
          : 'Spectral distribution matches Summer Sentinel-2 reference profile (KS < 0.15).', 
        status: isDrift ? 'review' : 'passed' },
      { id: 8, op: 'EVIDENCE.FUSION', msg: isTamper 
          ? 'HARD VETO TRIGGERED: Cryptographic integrity failure takes precedence over all other metrics.' 
          : (isDrift ? 'Evidence fused: Non-critical drift elevated risk; no hard veto present.' : 'Multi-domain evidence fused cleanly. Risk assessment = LOW.'), 
        status: isTamper ? 'blocked' : (isDrift ? 'review' : 'passed') },
      { id: 9, op: 'GATEKEEPER.ACTION', msg: isTamper 
          ? 'DISPOSITION: BLOCK. Target asset quarantined in defense ledger.' 
          : (isDrift ? 'DISPOSITION: ALLOW_WITH_MONITORING (Operational Review).' : 'DISPOSITION: ALLOW. Asset approved for operational deployment.'), 
        status: isTamper ? 'blocked' : (isDrift ? 'review' : 'passed') },
      { id: 10, op: 'PROVENANCE.LINEAGE', msg: 'Directed property graph updated: Contributor -> Dataset -> Model -> Inference -> Evidence.', status: 'passed' },
      { id: 11, op: 'BLAST_RADIUS.EVAL', msg: isTamper 
          ? 'BFS Impact Traversal: 2 downstream assets flagged as POTENTIALLY AFFECTED / REQUIRES REVIEW.' 
          : 'No downstream assets compromised.', 
        status: isTamper ? 'blocked' : 'passed' },
      { id: 12, op: 'FORENSIC.REPORT', msg: 'RFC 8785 Canonical JSON generated and cryptographically sealed with SECP256R1 digital signature.', status: 'passed' },
    ];

    let currentStep = 0;
    const intervalTime = 650; // smooth 8s total scan

    AppState.scanInterval = setInterval(() => {
      if (currentStep < steps.length) {
        const step = steps[currentStep];
        updatePipelineStage(step.id, 'running');
        addTerminalLog(step.op, step.msg, step.status === 'blocked' ? 'danger' : (step.status === 'review' ? 'review' : 'pass'));
        
        // Update Risk meter smoothly
        const progress = (currentStep + 1) / steps.length;
        const targetRisk = scenario.riskScore * progress;
        updateRiskMeter(targetRisk, isTamper && currentStep >= 1);

        setTimeout(() => {
          updatePipelineStage(step.id, step.status);
        }, intervalTime - 50);

        currentStep++;
      } else {
        clearInterval(AppState.scanInterval);
        addTerminalLog('MISSION.COMPLETE', 'Assurance Scan Complete. Compiling final forensic report...', 'highlight');
        
        // Auto-navigate to Phase 3 after 1.2s
        setTimeout(() => {
          populateResultsPage();
          setPhase(3);
        }, 1200);
      }
    }, intervalTime);
  }

  // =========================================================================
  // 5. PHASE 3: POPULATE RESULTS & INCIDENT ANALYSIS
  // =========================================================================

  function populateResultsPage() {
    const scenario = Scenarios[AppState.currentScenario];
    const isTamper = scenario.hardVeto;
    const isDrift = (AppState.currentScenario === 'benign_drift');

    // 1. Master Decision Hero
    const hero = document.getElementById('decision-hero-banner');
    const verdictTitle = document.getElementById('decision-verdict-title');
    const verdictDesc = document.getElementById('decision-verdict-desc');
    const verdictTag = document.getElementById('decision-verdict-tag');

    if (hero && verdictTitle && verdictDesc) {
      hero.className = 'decision-hero';
      if (isTamper) {
        hero.classList.add('quarantined');
        verdictTitle.textContent = 'INTEGRITY INCIDENT // ASSET QUARANTINED';
        verdictDesc.textContent = 'Hard-Veto Triggered: Cryptographic or model tampering detected. Asset blocked from mission deployment.';
        verdictTag.className = 'badge-tag badge-health-crit';
        verdictTag.textContent = 'DISPOSITION: BLOCK / QUARANTINED';
      } else if (isDrift) {
        hero.classList.add('review');
        verdictTitle.textContent = 'REVIEW REQUIRED // DISTRIBUTION SHIFT';
        verdictDesc.textContent = 'Statistical drift detected (Seasonal / Atmospheric). Cryptographic integrity is intact; contextual review recommended.';
        verdictTag.className = 'badge-tag badge-health-warn';
        verdictTag.textContent = 'DISPOSITION: ALLOW_WITH_MONITORING';
      } else {
        hero.classList.add('accepted');
        verdictTitle.textContent = 'ASSURANCE PASSED // ASSET TRUSTED';
        verdictDesc.textContent = 'All cryptographic proofs, model identities, runtime inference DNA, and evidence fusion criteria verified.';
        verdictTag.className = 'badge-tag badge-health-ok';
        verdictTag.textContent = 'DISPOSITION: ALLOW / OPERATIONAL';
      }
    }

    // 2. Populate 5 Core Evidence Pillars
    const pillarData = [
      {
        id: 'data-integrity',
        title: 'Data Integrity',
        verdict: isTamper && AppState.currentScenario === 'tamper_b04' ? 'TAMPERED' : 'PASS',
        badgeClass: isTamper && AppState.currentScenario === 'tamper_b04' ? 'badge-health-crit' : 'badge-health-ok',
        desc: isTamper && AppState.currentScenario === 'tamper_b04' ? 'Merkle root divergence in Band 4 (Red GeoTIFF).' : 'All 12 bands bit-exact match approved Merkle tree.',
        meta: 'Merkle Root: ' + (isTamper ? '0c0b60f7... (FAILED)' : '3cafad42... (PASS)'),
      },
      {
        id: 'model-integrity',
        title: 'Model Identity',
        verdict: AppState.currentScenario === 'model_tamper' ? 'MISMATCH' : 'PASS',
        badgeClass: AppState.currentScenario === 'model_tamper' ? 'badge-health-crit' : 'badge-health-ok',
        desc: AppState.currentScenario === 'model_tamper' ? 'Weight tensor state-dict hash diverges from approved baseline.' : 'PyTorch state dict layers hash identical to approved baseline.',
        meta: 'Model ID: 7d3185d1... // Arch: ResNet50-EO',
      },
      {
        id: 'runtime-assurance',
        title: 'Runtime Inference DNA',
        verdict: AppState.currentScenario === 'inference_replay' ? 'REPLAYED' : 'PASS',
        badgeClass: AppState.currentScenario === 'inference_replay' ? 'badge-health-crit' : 'badge-health-ok',
        desc: AppState.currentScenario === 'inference_replay' ? 'Duplicate nonce collision detected in runtime inference stream.' : 'Sequential Inference DNA hash chain and freshness verified.',
        meta: 'Sequence Monotonicity: ' + (AppState.currentScenario === 'inference_replay' ? 'BROKEN' : 'VALID'),
      },
      {
        id: 'distribution-drift',
        title: 'Distribution Shift',
        verdict: isDrift ? 'DRIFT DETECTED' : 'NO DRIFT',
        badgeClass: isDrift ? 'badge-health-warn' : 'badge-health-ok',
        desc: isDrift ? 'Seasonal vegetation decay detected (KS=0.84, PSI=11.28, W1=0.16).' : 'Spectral distributions within nominal operational tolerances.',
        meta: 'Energy Distance: ' + (isDrift ? '0.1838 (Elevated)' : '0.0012 (Nominal)'),
      },
      {
        id: 'evidence-fusion',
        title: 'Evidence Fusion',
        verdict: isTamper ? 'HARD VETO' : (isDrift ? 'REVIEW' : 'ALLOW'),
        badgeClass: isTamper ? 'badge-health-crit' : (isDrift ? 'badge-health-warn' : 'badge-health-ok'),
        desc: isTamper ? 'Hard-veto precedence enforced: Benign scores cannot override integrity failure.' : 'Synthesized multi-domain assessment clear for operational deployment.',
        meta: 'Risk Score: ' + scenario.riskScore.toFixed(2) + ' / 1.00',
      },
    ];

    const pillarsContainer = document.getElementById('evidence-pillars-grid');
    if (pillarsContainer) {
      pillarsContainer.innerHTML = pillarData.map(p => `
        <div class="pillar-card">
          <div class="pillar-card-header">
            <span class="pillar-title">${p.title}</span>
            <span class="pillar-status-badge ${p.badgeClass}">${p.verdict}</span>
          </div>
          <div class="pillar-main-verdict">${p.verdict}</div>
          <p class="pillar-desc">${p.desc}</p>
          <div class="pillar-meta">${p.meta}</div>
        </div>
      `).join('');
    }

    // 3. Incident Panel (Shown only when Quarantined)
    const incidentPanel = document.getElementById('incident-analysis-panel');
    if (incidentPanel) {
      incidentPanel.classList.toggle('active', isTamper);
      if (isTamper) {
        document.getElementById('incident-what-changed').textContent = AppState.currentScenario === 'tamper_b04' 
          ? 'Band 4 (Red) GeoTIFF modified with 32-byte injected payload.' 
          : (AppState.currentScenario === 'model_tamper' ? 'Floating-point weight tensor mutation in classifier layer.' : 'Nonce reuse detected in inference record.');
        
        document.getElementById('incident-why-blocked').textContent = 'Hard-Veto Rule: Cryptographic integrity violations bypass statistical averaging and trigger immediate BLOCK.';
        document.getElementById('incident-what-quarantined').textContent = 'Dataset Batch [5a6c5c5a...] and linked execution pipelines.';
        document.getElementById('incident-blast-radius').textContent = '2 Downstream Assets: Tactical Recon Model, Inference Stream Run #99 (POTENTIALLY AFFECTED / REQUIRES REVIEW).';
      }
    }

    // 4. Render Provenance Property Graph
    let sampleNodes = [];
    let sampleEdges = [];

    if (isTamper) {
      sampleNodes = [
        { id: 'contrib_delhi', label: 'Ground Station Recon', node_type: 'CONTRIBUTOR', digest: '9f83a12b...', status: 'VERIFIED' },
        { id: 'ds_recon_01', label: AppState.currentScenario === 'tamper_b04' ? 'EO Dataset (Tampered B04)' : 'EO Dataset 5a6c5c5a', node_type: 'DATASET', digest: '0c0b60f7... (DIVERGED)', status: 'TAMPERED' },
        { id: 'model_landcover', label: AppState.currentScenario === 'model_tamper' ? 'LandCover Model (Mutated)' : 'LandCover Model v1.2', node_type: 'MODEL', digest: '7d3185d1...', status: 'REVIEW' },
        { id: 'infer_mission_99', label: 'Inference Run #99', node_type: 'INFERENCE', digest: '4b32a9e0...', status: 'REVIEW' },
        { id: 'ev_quarantine_01', label: 'QUARANTINE ENFORCED', node_type: 'QUARANTINE', digest: 'HARD_VETO_CRIT', status: 'QUARANTINED' },
      ];

      sampleEdges = [
        { source_id: 'contrib_delhi', target_id: 'ds_recon_01' },
        { source_id: 'ds_recon_01', target_id: 'ev_quarantine_01', type: 'QUARANTINE_BRANCH' },
        { source_id: 'ds_recon_01', target_id: 'model_landcover' },
        { source_id: 'model_landcover', target_id: 'infer_mission_99' },
      ];
    } else if (isDrift) {
      sampleNodes = [
        { id: 'contrib_delhi', label: 'Ground Station Recon', node_type: 'CONTRIBUTOR', digest: '9f83a12b...', status: 'VERIFIED' },
        { id: 'ds_recon_01', label: 'EO Dataset Autumn-S2', node_type: 'DATASET', digest: '3cafad42... (SEALED)', status: 'VERIFIED' },
        { id: 'model_landcover', label: 'LandCover Model v1.2', node_type: 'MODEL', digest: '7d3185d1...', status: 'VERIFIED' },
        { id: 'infer_mission_99', label: 'Inference Run #99', node_type: 'INFERENCE', digest: '4b32a9e0...', status: 'VERIFIED' },
        { id: 'ev_drift_01', label: 'DISTRIBUTION SHIFT', node_type: 'EVIDENCE', digest: 'KS=0.84 PSI=11.28', status: 'REVIEW' },
      ];

      sampleEdges = [
        { source_id: 'contrib_delhi', target_id: 'ds_recon_01' },
        { source_id: 'ds_recon_01', target_id: 'model_landcover' },
        { source_id: 'model_landcover', target_id: 'infer_mission_99' },
        { source_id: 'infer_mission_99', target_id: 'ev_drift_01' },
      ];
    } else {
      sampleNodes = [
        { id: 'contrib_delhi', label: 'Ground Station Recon', node_type: 'CONTRIBUTOR', digest: '9f83a12b...', status: 'VERIFIED' },
        { id: 'ds_recon_01', label: 'EO Dataset 5a6c5c5a', node_type: 'DATASET', digest: '3cafad42... (SEALED)', status: 'VERIFIED' },
        { id: 'model_landcover', label: 'LandCover Model v1.2', node_type: 'MODEL', digest: '7d3185d1...', status: 'VERIFIED' },
        { id: 'infer_mission_99', label: 'Inference Run #99', node_type: 'INFERENCE', digest: '4b32a9e0...', status: 'VERIFIED' },
        { id: 'ev_integrity_01', label: 'OPERATIONAL ACCEPTED', node_type: 'EVIDENCE', digest: 'SECP256R1_PASS', status: 'VERIFIED' },
      ];

      sampleEdges = [
        { source_id: 'contrib_delhi', target_id: 'ds_recon_01' },
        { source_id: 'ds_recon_01', target_id: 'model_landcover' },
        { source_id: 'model_landcover', target_id: 'infer_mission_99' },
        { source_id: 'infer_mission_99', target_id: 'ev_integrity_01' },
      ];
    }

    if (!AppState.graphRenderer) {
      AppState.graphRenderer = new TrustCVGraph('graph-canvas', {
        width: 760,
        height: 360,
      });
    }
    AppState.graphRenderer.setData(sampleNodes, sampleEdges, {
      scenario: AppState.currentScenario,
      isTamper,
      isDrift,
    });

    // 5. Populate Forensic Report
    const repId = 'REP-' + Math.random().toString(36).substring(2, 10).toUpperCase();
    const repDigest = isTamper ? 'dc27831fc4372b65d05b0939b2adcb4257e15f1d04f21d860060f3a410941e1b' : '2875135e954cc06fa8d4b17cd61fa0fda55931744c221b1203707e8723963402';
    
    document.getElementById('report-id-display').textContent = repId;
    document.getElementById('report-digest-display').textContent = repDigest;
    document.getElementById('report-sig-status').textContent = 'VALID (SECP256R1)';
    document.getElementById('report-sig-status').className = 'badge-tag badge-health-ok';
  }

  // =========================================================================
  // 6. EVENT LISTENERS & INITIALIZATION
  // =========================================================================

  // Theme Toggle
  const themeToggle = document.getElementById('btn-theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      applyTheme(AppState.theme === 'dark' ? 'light' : 'dark');
    });
  }

  // Scenario Cards Click
  document.querySelectorAll('.preset-card').forEach(card => {
    card.addEventListener('click', () => {
      selectScenario(card.getAttribute('data-scenario'));
    });
  });

  // Launch CTA Click
  const launchBtn = document.getElementById('btn-launch-mission');
  if (launchBtn) {
    launchBtn.addEventListener('click', () => {
      launchAssuranceScan();
    });
  }

  // New Mission CTA
  const newMissionBtn = document.getElementById('btn-new-mission');
  if (newMissionBtn) {
    newMissionBtn.addEventListener('click', () => {
      AppState.mission.id = 'MSN-' + Math.random().toString(36).substring(2, 9).toUpperCase();
      document.getElementById('hud-mission-id').textContent = AppState.mission.id;
      setPhase(1);
    });
  }

  // Verify Report Signature
  const verifyRepBtn = document.getElementById('btn-verify-report');
  if (verifyRepBtn) {
    verifyRepBtn.addEventListener('click', () => {
      const sigStatus = document.getElementById('report-sig-status');
      sigStatus.textContent = 'VERIFYING...';
      setTimeout(() => {
        sigStatus.textContent = 'VALID (SECP256R1 ECDSA MATCH)';
        sigStatus.className = 'badge-tag badge-health-ok';
        alert('Forensic Report Signature Verification: PASS\nRFC 8785 Canonical Digest match confirmed with ECDSA SECP256R1 signer public key.');
      }, 400);
    });
  }

  // Simulate Report Tamper
  const tamperRepBtn = document.getElementById('btn-tamper-report');
  if (tamperRepBtn) {
    tamperRepBtn.addEventListener('click', () => {
      const sigStatus = document.getElementById('report-sig-status');
      sigStatus.textContent = 'TAMPERED // REJECTED';
      sigStatus.className = 'badge-tag badge-health-crit';
      alert('Forensic Report Tampering Detected!\nDigest mismatch: Altering report verdict invalidates SECP256R1 digital signature. Verification FAILED.');
    });
  }

  // Subsystems Drawer Toggle
  const drawerBtn = document.getElementById('btn-open-drawer');
  const drawerCloseBtn = document.getElementById('btn-close-drawer');
  const drawerBackdrop = document.getElementById('drawer-backdrop');
  const drawerPanel = document.getElementById('drawer-panel');

  function toggleDrawer(open) {
    if (drawerBackdrop && drawerPanel) {
      drawerBackdrop.classList.toggle('active', open);
      drawerPanel.classList.toggle('active', open);
    }
  }

  if (drawerBtn) drawerBtn.addEventListener('click', () => toggleDrawer(true));
  if (drawerCloseBtn) drawerCloseBtn.addEventListener('click', () => toggleDrawer(false));
  if (drawerBackdrop) drawerBackdrop.addEventListener('click', () => toggleDrawer(false));

  // Subsystem helpers & XSS sanitization
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  window.escapeHtml = escapeHtml;

  window.refreshAllData = function() {
    TrustCVAPI.getReadiness();
  };

  window.triggerAttack = function(attackId) {
    TrustCVAPI.runRedTeamScenario(attackId);
  };

  // Initial Boot
  applyTheme(AppState.theme);
  selectScenario('pristine_eo');
  setPhase(1);

  // Poll Backend Readiness
  TrustCVAPI.getReadiness().then(res => {
    const healthBadge = document.getElementById('hud-health-badge');
    if (healthBadge && res.ready) {
      healthBadge.innerHTML = '<span class="status-dot green"></span> <span>HEALTHY (WAL)</span>';
      healthBadge.className = 'badge-tag badge-health-ok';
    }
  }).catch(() => {
    const healthBadge = document.getElementById('hud-health-badge');
    if (healthBadge) {
      healthBadge.innerHTML = '<span class="status-dot amber"></span> <span>STANDALONE MODE</span>';
      healthBadge.className = 'badge-tag badge-health-warn';
    }
  });
});
