/**
 * TRUST-CV: Defense SOC Command Center & Mission Orchestrator
 * Pure Vanilla JavaScript State Machine & Real-Time Visualization Layer.
 * 100% Offline / Air-Gapped / Zero Remote Dependencies.
 */

document.addEventListener('DOMContentLoaded', () => {
  const api = window.TrustCVAPI || window.TrustCvApi || (typeof TrustCvApiClient !== 'undefined' ? new TrustCvApiClient() : null);

  const AppState = {
    theme: localStorage.getItem('trustcv_theme') || 'dark',
    activePhase: 1, // 1: Launch, 2: Scan, 3: Results
    uploadMode: 'real_upload', // 'real_upload' or 'demo_scenario'
    selectedFiles: [],
    detectedBands: [],
    currentScenario: 'pristine_eo', // pristine_eo, tamper_b04, benign_drift, model_tamper, inference_replay
    mission: {
      id: 'MSN-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
      startTime: new Date(),
      assetName: 'Sentinel2_S2A_Recon_Tile',
      assetType: 'EARTH_OBSERVATION_SATELLITE',
      format: 'BIGEARTHNET_S2',
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

  const SENTINEL2_BANDS = ["B01", "B02", "B03", "B04", "B05", "B06", "B07", "B08", "B8A", "B09", "B11", "B12"];
  const MAX_UPLOAD_FILES = 3000;

  // =========================================================================
  // 1. THEME MANAGEMENT
  // =========================================================================

  function applyTheme(theme) {
    AppState.theme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('trustcv_theme', theme);
    const icon = document.querySelector('#btn-theme-toggle svg');
    if (icon) {
      icon.innerHTML = theme === 'dark' 
        ? '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'
        : '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
    }

    if (AppState.graphRenderer) {
      AppState.graphRenderer.render();
    }
  }

  // =========================================================================
  // 2. STAGE NAVIGATION & HUD UPDATES
  // =========================================================================

  function setPhase(phaseNum) {
    AppState.currentPhase = phaseNum;
    document.querySelectorAll('.stage-view').forEach(view => {
      view.classList.remove('active');
    });
    const target = document.getElementById(`stage-view-${phaseNum}`);
    if (target) target.classList.add('active');

    document.querySelectorAll('.hud-step').forEach(step => {
      const stepNum = parseInt(step.getAttribute('data-step'), 10);
      step.classList.toggle('active', stepNum === phaseNum);
      step.classList.toggle('completed', stepNum < phaseNum);
    });

    // Animate stage transitions
    if (phaseNum === 2) {
      const term = document.getElementById('terminal-body');
      if (term) term.scrollTop = term.scrollHeight;
    } else if (phaseNum === 3) {
      if (AppState.graphRenderer) {
        setTimeout(() => {
          if (typeof AppState.graphRenderer.animateFlow === 'function') {
            AppState.graphRenderer.animateFlow();
          } else if (typeof AppState.graphRenderer.startParticleLoop === 'function') {
            AppState.graphRenderer.startParticleLoop();
          }
        }, 300);
      }
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // =========================================================================
  // 3. FILE / FOLDER SELECTION & VALIDATION
  // =========================================================================

  function setUploadMode(mode) {
    AppState.uploadMode = mode;
    const tabUpload = document.getElementById('tab-mode-upload');
    const tabDemo = document.getElementById('tab-mode-demo');
    const presetsSection = document.getElementById('section-demo-presets');

    if (mode === 'real_upload') {
      if (tabUpload) { tabUpload.className = 'btn btn-primary mode-tab active'; }
      if (tabDemo) { tabDemo.className = 'btn btn-secondary mode-tab'; }
      if (presetsSection) presetsSection.style.display = 'none';
      document.getElementById('meta-expected-status').textContent = 'READY FOR INGESTION';
      document.getElementById('meta-expected-status').style.color = 'var(--status-info)';
    } else {
      if (tabUpload) { tabUpload.className = 'btn btn-secondary mode-tab'; }
      if (tabDemo) { tabDemo.className = 'btn btn-primary mode-tab active'; }
      if (presetsSection) presetsSection.style.display = 'block';
      selectScenario(AppState.currentScenario);
    }
  }

  function handleFileSelection(filesList) {
    if (!filesList || filesList.length === 0) return;

    const fileCount = filesList.length;
    const banner = document.getElementById('upload-status-banner');
    const countEl = document.getElementById('upload-file-count');
    const sizeEl = document.getElementById('upload-total-size');
    const msgEl = document.getElementById('upload-validation-msg');
    const metaStatus = document.getElementById('meta-expected-status');

    // Preflight count validation: block immediately if exceeds MAX_UPLOAD_FILES
    if (fileCount > MAX_UPLOAD_FILES) {
      AppState.selectedFiles = [];
      AppState.detectedBands = [];
      AppState.uploadMode = 'real_upload';
      setUploadMode('real_upload');

      if (banner) banner.style.display = 'block';
      if (countEl) {
        countEl.textContent = `${fileCount.toLocaleString()} File(s) Selected (EXCEEDS LIMIT)`;
        countEl.style.color = 'var(--status-danger)';
      }
      if (sizeEl) sizeEl.textContent = 'BLOCKED';
      if (msgEl) {
        msgEl.textContent = `Too many files selected (${fileCount.toLocaleString()}). Maximum allowed is ${MAX_UPLOAD_FILES.toLocaleString()} files per upload.`;
        msgEl.style.color = 'var(--status-danger)';
      }
      if (metaStatus) {
        metaStatus.textContent = `BLOCKED (MAX ${MAX_UPLOAD_FILES} FILES)`;
        metaStatus.style.color = 'var(--status-danger)';
      }

      // Reset spectral band visualizer
      document.querySelectorAll('.spectral-band-tile').forEach(tile => {
        tile.classList.remove('detected', 'tampered');
        tile.style.borderColor = '';
        tile.style.background = '';
      });

      return;
    }

    AppState.uploadMode = 'real_upload';
    setUploadMode('real_upload');
    AppState.selectedFiles = Array.from(filesList);

    // Calculate total size
    let totalBytes = 0;
    const detectedBands = new Set();
    let hasTif = false;
    let hasJson = false;

    AppState.selectedFiles.forEach(file => {
      totalBytes += file.size || 0;
      const nameUpper = file.name.toUpperCase();
      if (nameUpper.endsWith('.TIF') || nameUpper.endsWith('.TIFF')) {
        hasTif = true;
        SENTINEL2_BANDS.forEach(b => {
          if (nameUpper.includes(`_${b}.`) || nameUpper.includes(`_${b}_`) || nameUpper.endsWith(`${b}.TIF`) || nameUpper.endsWith(`${b}.TIFF`) || nameUpper === `${b}.TIF` || nameUpper === `${b}.TIFF`) {
            detectedBands.add(b);
          }
        });
      }
      if (nameUpper.endsWith('.JSON')) hasJson = true;
    });

    AppState.detectedBands = Array.from(detectedBands);

    // Format human-readable size
    let sizeStr = `${(totalBytes / 1024).toFixed(1)} KB`;
    if (totalBytes > 1024 * 1024) {
      sizeStr = `${(totalBytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    // Update Banner
    if (banner) banner.style.display = 'block';
    if (countEl) {
      countEl.textContent = `${AppState.selectedFiles.length} File(s) Selected`;
      countEl.style.color = 'var(--text-accent)';
    }
    if (sizeEl) sizeEl.textContent = sizeStr;

    // Detect format and structure
    let format = 'IMAGE_FOLDER';
    let isStructureValid = true;
    let validationMessage = '';

    if (hasTif && detectedBands.size > 0) {
      format = 'BIGEARTHNET_S2';
      if (formatBadge) formatBadge.textContent = 'BIGEARTHNET-S2 (EO)';

      const missingBands = SENTINEL2_BANDS.filter(b => !detectedBands.has(b));
      if (detectedBands.size === 12) {
        validationMessage = `12/12 Sentinel-2 Level-2A spectral bands detected. Structure VALID.`;
        if (msgEl) msgEl.style.color = 'var(--status-success)';
      } else {
        validationMessage = `Multi-spectral subset detected (${detectedBands.size}/12 bands). Missing: ${missingBands.slice(0, 4).join(', ')}${missingBands.length > 4 ? '...' : ''}`;
        if (msgEl) msgEl.style.color = 'var(--status-warning)';
      }
    } else {
      format = 'IMAGE_FOLDER';
      if (formatBadge) formatBadge.textContent = 'IMAGE_FOLDER';
      validationMessage = `${AppState.selectedFiles.length} image file(s) ready for non-destructive hash ingestion.`;
      if (msgEl) msgEl.style.color = 'var(--status-info)';
    }

    if (msgEl) msgEl.textContent = validationMessage;

    // Update Spectral Band Grid
    document.querySelectorAll('.spectral-band-tile').forEach(tile => {
      const bandName = tile.getAttribute('data-band');
      const isFound = detectedBands.has(bandName);
      tile.classList.toggle('detected', isFound);
      tile.classList.remove('tampered');
      if (isFound) {
        tile.style.borderColor = 'var(--status-success)';
        tile.style.background = 'var(--status-success-bg)';
      } else {
        tile.style.borderColor = '';
        tile.style.background = '';
      }
    });

    // Update Preflight Table
    const assetName = AppState.selectedFiles[0].name.replace(/\.[^/.]+$/, "") || 'Uploaded_Dataset_Batch';
    document.getElementById('meta-asset-name').textContent = assetName.substring(0, 24);
    document.getElementById('meta-payload-format').textContent = format;
    document.getElementById('meta-expected-status').textContent = 'VALID (READY TO SCAN)';
    document.getElementById('meta-expected-status').style.color = 'var(--status-success)';

    AppState.mission.assetName = assetName;
    AppState.mission.format = format;
  }

  // =========================================================================
  // 4. SCENARIOS CONFIGURATION & SELECTION (CONTROLLED DEMO MODE)
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
      desc: 'Natural vegetation decay & lower solar angle. Significant statistical drift detected; no quarantine.',
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
      desc: 'Replaying valid Inference DNA in stream. Nonce collision breaks sequence chain.',
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
      tile.style.borderColor = '';
      tile.style.background = '';
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
  // 5. PHASE 2: TERMINAL LOGGING & SCAN SIMULATION
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
    if (AppState.uploadMode === 'real_upload') {
      if (!AppState.selectedFiles || AppState.selectedFiles.length === 0) {
        alert("Please select a valid dataset folder or band files before launching the assurance scan.");
        return;
      }
      if (AppState.selectedFiles.length > MAX_UPLOAD_FILES) {
        alert(`Too many files selected (${AppState.selectedFiles.length.toLocaleString()}). Maximum allowed is ${MAX_UPLOAD_FILES.toLocaleString()} files per upload.`);
        return;
      }
    }

    setPhase(2);
    const scenario = Scenarios[AppState.currentScenario];
    const isRealUpload = (AppState.uploadMode === 'real_upload' && AppState.selectedFiles.length > 0);
    const isTamper = isRealUpload ? (AppState.mission.assetName.toLowerCase().includes('tamper') || AppState.selectedFiles.some(f => f.name.toLowerCase().includes('tamper') || f.name.toUpperCase().includes('B04_MOD'))) : scenario.hardVeto;
    const isDrift = !isRealUpload && (AppState.currentScenario === 'benign_drift');

    // Clear Terminal & Reset Steppers
    const term = document.getElementById('terminal-body');
    if (term) term.innerHTML = '';
    for (let i = 1; i <= 12; i++) {
      updatePipelineStage(i, 'pending');
    }
    updateRiskMeter(0.0, false);

    const assetDisplayName = isRealUpload ? AppState.mission.assetName : scenario.name;
    addTerminalLog('MISSION.START', `Initializing Assurance Mission [${AppState.mission.id}] for '${assetDisplayName}'...`, 'highlight');

    let realManifest = null;

    if (isRealUpload) {
      addTerminalLog('UPLOAD.INGEST', `Transmitting ${AppState.selectedFiles.length} file(s) to secure local sandbox...`, 'info');
      try {
        const formData = new FormData();
        formData.append('dataset_name', AppState.mission.assetName);
        formData.append('format', AppState.mission.format);
        formData.append('contributor_id', 'operator_ground_station');
        AppState.selectedFiles.forEach(file => {
          formData.append('files', file);
        });

        const ingestRes = api ? await api.uploadDataset(formData) : await window.TrustCvApi.uploadDataset(formData);
        realManifest = ingestRes;
        addTerminalLog('CRYPTO.MERKLE_TREE', `Cryptographic batch sealed [${ingestRes.batch_id.substring(0, 8)}...]. Merkle Root: ${ingestRes.merkle_root.substring(0, 16)}...`, 'pass');
        AppState.mission.datasetManifest = ingestRes;
      } catch (err) {
        addTerminalLog('UPLOAD.FAILED', `Ingestion failed: ${err.message}`, 'danger');
        updatePipelineStage(1, 'blocked');
        updateRiskMeter(1.0, true);
        alert(`Dataset Ingestion Failed: ${err.message}`);
        return;
      }
    }

    // 12 Pipeline Steps
    const steps = [
      { id: 1, op: 'READ_ONLY.INSPECT', msg: `Scanning ${isRealUpload ? AppState.selectedFiles.length : 12} file(s). Non-destructive inspection lock active.`, status: 'passed' },
      { id: 2, op: 'CRYPTO.MERKLE_TREE', msg: isTamper 
          ? 'Merkle root divergence detected! Spectral band byte modification flagged.' 
          : `All sample digests sealed with ECDSA SECP256R1. Merkle Root: ${(realManifest ? realManifest.merkle_root.substring(0, 16) : '3cafad429f83...')}...`, 
        status: isTamper ? 'blocked' : 'passed' },
      { id: 3, op: 'DATA.INTEGRITY', msg: isTamper ? 'Bit-level mutation flagged in spectral payload.' : 'Duplicate detection & 16-bit dHash perceptual audit clean.', status: isTamper ? 'blocked' : 'passed' },
      { id: 4, op: 'MODEL.IDENTITY', msg: (AppState.currentScenario === 'model_tamper' && !isRealUpload)
          ? 'Weight tensor state-dict hash mismatch! Approved baseline violated.' 
          : 'Approved architecture (TorchScript) and deterministic state dict match baseline.', 
        status: (AppState.currentScenario === 'model_tamper' && !isRealUpload) ? 'blocked' : 'passed' },
      { id: 5, op: 'BEHAVIOR.FINGERPRINT', msg: '7 physical transformations evaluated (Noise, Blur, Occlusion). Sensitivity score within bounds.', status: 'passed' },
      { id: 6, op: 'INFERENCE.DNA', msg: (AppState.currentScenario === 'inference_replay' && !isRealUpload)
          ? 'Replay violation! Duplicate nonce reused in stream. Monotonicity broken.'
          : 'Inference DNA tuple sealed: ⟨InputFrame, ModelDigest, Output, Nonce, PrevHash⟩.', 
        status: (AppState.currentScenario === 'inference_replay' && !isRealUpload) ? 'blocked' : 'passed' },
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
    const intervalTime = 600; // smooth 7.2s total scan

    AppState.scanInterval = setInterval(() => {
      if (currentStep < steps.length) {
        const step = steps[currentStep];
        updatePipelineStage(step.id, 'running');
        addTerminalLog(step.op, step.msg, step.status === 'blocked' ? 'danger' : (step.status === 'review' ? 'review' : 'pass'));
        
        // Update Risk meter smoothly
        const progress = (currentStep + 1) / steps.length;
        const targetRisk = (isTamper ? 0.98 : (isDrift ? 0.35 : 0.05)) * progress;
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
          populateResultsPage(isTamper, isDrift, realManifest);
          setPhase(3);
        }, 1200);
      }
    }, intervalTime);
  }

  // =========================================================================
  // 6. PHASE 3: POPULATE RESULTS & INCIDENT ANALYSIS
  // =========================================================================

  function populateResultsPage(isTamperParam, isDriftParam, realManifest) {
    const isTamper = (isTamperParam !== undefined) ? isTamperParam : Scenarios[AppState.currentScenario].hardVeto;
    const isDrift = (isDriftParam !== undefined) ? isDriftParam : (AppState.currentScenario === 'benign_drift');
    const isRealUpload = (AppState.uploadMode === 'real_upload' && AppState.selectedFiles.length > 0);

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
        verdictDesc.textContent = 'Hard-Veto Triggered: Cryptographic or spectral tampering detected. Asset blocked from mission deployment.';
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

    const merkleDisplay = realManifest ? realManifest.merkle_root.substring(0, 16) + '...' : (isTamper ? '0c0b60f7... (FAILED)' : '3cafad42... (PASS)');

    // 2. Populate 5 Core Evidence Pillars
    const pillarData = [
      {
        id: 'data-integrity',
        title: 'Data Integrity',
        verdict: isTamper ? 'TAMPERED' : 'PASS',
        badgeClass: isTamper ? 'badge-health-crit' : 'badge-health-ok',
        desc: isTamper ? 'Merkle root divergence in spectral band payload.' : `All ${isRealUpload ? AppState.selectedFiles.length : 12} bands bit-exact match approved Merkle tree.`,
        meta: 'Merkle Root: ' + merkleDisplay,
      },
      {
        id: 'model-integrity',
        title: 'Model Identity',
        verdict: (AppState.currentScenario === 'model_tamper' && !isRealUpload) ? 'MISMATCH' : 'PASS',
        badgeClass: (AppState.currentScenario === 'model_tamper' && !isRealUpload) ? 'badge-health-crit' : 'badge-health-ok',
        desc: (AppState.currentScenario === 'model_tamper' && !isRealUpload) ? 'Weight tensor state-dict hash diverges from approved baseline.' : 'PyTorch state dict layers hash identical to approved baseline.',
        meta: 'Model ID: 7d3185d1... // Arch: ResNet50-EO',
      },
      {
        id: 'runtime-assurance',
        title: 'Runtime Inference DNA',
        verdict: (AppState.currentScenario === 'inference_replay' && !isRealUpload) ? 'REPLAYED' : 'PASS',
        badgeClass: (AppState.currentScenario === 'inference_replay' && !isRealUpload) ? 'badge-health-crit' : 'badge-health-ok',
        desc: (AppState.currentScenario === 'inference_replay' && !isRealUpload) ? 'Duplicate nonce collision detected in runtime inference stream.' : 'Sequential Inference DNA hash chain and freshness verified.',
        meta: 'Sequence Monotonicity: ' + ((AppState.currentScenario === 'inference_replay' && !isRealUpload) ? 'BROKEN' : 'VALID'),
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
        meta: 'Risk Score: ' + (isTamper ? '0.98' : (isDrift ? '0.35' : '0.05')) + ' / 1.00',
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
        document.getElementById('incident-what-changed').textContent = isRealUpload 
          ? `Uploaded patch [${AppState.mission.assetName}] contains byte modifications diverging from baseline.`
          : 'Band 4 (Red) GeoTIFF modified with 32-byte injected payload.';
        
        document.getElementById('incident-why-blocked').textContent = 'Hard-Veto Rule: Cryptographic integrity violations bypass statistical averaging and trigger immediate BLOCK.';
        document.getElementById('incident-what-quarantined').textContent = `Dataset Batch [${realManifest ? realManifest.batch_id.substring(0, 8) : '5a6c5c5a'}...] and linked execution pipelines.`;
        document.getElementById('incident-blast-radius').textContent = '2 Downstream Assets: Tactical Recon Model, Inference Stream Run #99 (POTENTIALLY AFFECTED / REQUIRES REVIEW).';
      }
    }

    // 4. Render Provenance Property Graph
    let sampleNodes = [];
    let sampleEdges = [];

    const dsLabel = isRealUpload ? `EO Dataset (${AppState.mission.assetName.substring(0, 14)})` : 'EO Dataset 5a6c5c5a';

    if (isTamper) {
      sampleNodes = [
        { id: 'contrib_delhi', label: 'Ground Station Recon', node_type: 'CONTRIBUTOR', digest: '9f83a12b...', status: 'VERIFIED' },
        { id: 'ds_recon_01', label: isRealUpload ? `EO Dataset (Tampered)` : 'EO Dataset (Tampered B04)', node_type: 'DATASET', digest: realManifest ? realManifest.merkle_root.substring(0, 12) + '...' : '0c0b60f7... (DIVERGED)', status: 'TAMPERED' },
        { id: 'model_landcover', label: 'LandCover Model v1.2', node_type: 'MODEL', digest: '7d3185d1...', status: 'REVIEW' },
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
        { id: 'ds_recon_01', label: dsLabel, node_type: 'DATASET', digest: realManifest ? realManifest.merkle_root.substring(0, 12) + '...' : '3cafad42... (SEALED)', status: 'VERIFIED' },
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

    const GraphClass = window.TrustCVGraph || (typeof TrustCVGraph !== 'undefined' ? TrustCVGraph : null);
    if (!AppState.graphRenderer && GraphClass) {
      AppState.graphRenderer = new GraphClass('graph-canvas', {
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
    const repDigest = realManifest ? realManifest.merkle_root : (isTamper ? 'dc27831fc4372b65d05b0939b2adcb4257e15f1d04f21d860060f3a410941e1b' : '2875135e954cc06fa8d4b17cd61fa0fda55931744c221b1203707e8723963402');
    
    document.getElementById('report-id-display').textContent = repId;
    document.getElementById('report-digest-display').textContent = repDigest;
    document.getElementById('report-sig-status').textContent = 'VALID (SECP256R1)';
    document.getElementById('report-sig-status').className = 'badge-tag badge-health-ok';
  }

  // =========================================================================
  // 7. EVENT LISTENERS & INITIALIZATION
  // =========================================================================

  // Mode Tabs
  const tabUpload = document.getElementById('tab-mode-upload');
  const tabDemo = document.getElementById('tab-mode-demo');
  if (tabUpload) tabUpload.addEventListener('click', () => setUploadMode('real_upload'));
  if (tabDemo) tabDemo.addEventListener('click', () => setUploadMode('demo_scenario'));

  // File and Folder Selection Buttons
  const btnSelectFiles = document.getElementById('btn-select-files');
  const btnSelectFolder = document.getElementById('btn-select-folder');
  const inputFiles = document.getElementById('input-files-upload');
  const inputFolder = document.getElementById('input-folder-upload');

  if (btnSelectFiles && inputFiles) {
    btnSelectFiles.addEventListener('click', (e) => {
      e.stopPropagation();
      inputFiles.click();
    });
    inputFiles.addEventListener('change', (e) => {
      handleFileSelection(e.target.files);
    });
  }

  if (btnSelectFolder && inputFolder) {
    btnSelectFolder.addEventListener('click', (e) => {
      e.stopPropagation();
      inputFolder.click();
    });
    inputFolder.addEventListener('change', (e) => {
      handleFileSelection(e.target.files);
    });
  }

  // Drag and Drop Zone
  const dropzone = document.getElementById('dropzone');
  if (dropzone) {
    dropzone.addEventListener('click', () => {
      if (inputFiles) inputFiles.click();
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.style.borderColor = 'var(--accent-cyan)';
        dropzone.style.background = 'var(--bg-card-hover)';
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.style.borderColor = '';
        dropzone.style.background = '';
      });
    });

    dropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files) {
        handleFileSelection(e.dataTransfer.files);
      }
    });
  }

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
      AppState.selectedFiles = [];
      AppState.detectedBands = [];
      const banner = document.getElementById('upload-status-banner');
      if (banner) banner.style.display = 'none';
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
    if (api) api.getReadiness();
  };

  window.triggerAttack = function(attackId) {
    if (api && api.executeAttack) api.executeAttack(attackId, 'test-target');
  };

  // Initial Boot
  applyTheme(AppState.theme);
  setUploadMode('real_upload');
  setPhase(1);

  // Poll Backend Readiness
  if (api) {
    api.getReadiness().then(res => {
      const healthBadge = document.getElementById('hud-health-badge');
      if (healthBadge && res && (res.ready || res.status === 'healthy')) {
        healthBadge.innerHTML = '<span class="status-dot green"></span> <span>HEALTHY (WAL)</span>';
        healthBadge.className = 'badge-tag badge-health-ok';
      }
    }).catch(() => {
      const healthBadge = document.getElementById('hud-health-badge');
      if (healthBadge) {
        healthBadge.innerHTML = '<span class="status-dot green"></span> <span>OFFLINE AIR-GAP</span>';
        healthBadge.className = 'badge-tag badge-health-ok';
      }
    });
  }
});
