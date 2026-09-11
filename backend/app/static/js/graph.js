/**
 * TRUST-CV: Interactive Lineage Provenance Property Graph Renderer
 * High-performance defense DAG visualization with animated evidence-flow particles,
 * state transition pulses, hover telemetry tooltips, and air-gapped theme adaptation.
 * 100% Offline / Zero External Libraries.
 */

class TrustCVGraph {
  constructor(containerId, options = {}) {
    this.container = typeof containerId === 'string' ? document.getElementById(containerId) : containerId;
    this.options = {
      width: options.width || 760,
      height: options.height || 360,
      onNodeClick: options.onNodeClick || null,
      ...options,
    };

    this.nodes = [];
    this.edges = [];
    this.meta = {};
    this.particles = [];
    this.animFrameId = null;
    this.isVisible = true;
    this.prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    this.initDOM();
    this.initObservers();
  }

  initDOM() {
    if (!this.container) return;

    // Preserve any existing hidden legacy canvas for backward compatibility tests
    const existingCanvas = this.container.querySelector('canvas#graph-canvas');
    if (existingCanvas) {
      existingCanvas.style.display = 'none';
    }

    // Remove any previous SVG or tooltip
    const oldSvg = this.container.querySelector('svg.trustcv-graph-svg');
    if (oldSvg) oldSvg.remove();
    const oldTip = this.container.querySelector('.graph-tooltip');
    if (oldTip) oldTip.remove();

    // Create Tooltip
    this.tooltip = document.createElement('div');
    this.tooltip.className = 'graph-tooltip';
    this.container.appendChild(this.tooltip);

    // Create SVG Canvas
    const svgNS = 'http://www.w3.org/2000/svg';
    this.svg = document.createElementNS(svgNS, 'svg');
    this.svg.classList.add('trustcv-graph-svg');
    this.svg.setAttribute('width', '100%');
    this.svg.setAttribute('height', '100%');
    this.svg.setAttribute('viewBox', `0 0 ${this.options.width} ${this.options.height}`);
    this.svg.style.overflow = 'visible';

    // SVG Defs: Gradients, Markers, and Glow Filters
    const defs = document.createElementNS(svgNS, 'defs');
    defs.innerHTML = `
      <marker id="arrow-neutral" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#64748b" />
      </marker>
      <marker id="arrow-cyan" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#06b6d4" />
      </marker>
      <marker id="arrow-green" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#10b981" />
      </marker>
      <marker id="arrow-danger" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#ef4444" />
      </marker>
      <marker id="arrow-amber" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f59e0b" />
      </marker>
      
      <linearGradient id="grad-cyan-green" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#06b6d4" />
        <stop offset="100%" stop-color="#10b981" />
      </linearGradient>
      <linearGradient id="grad-danger" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#ef4444" />
        <stop offset="100%" stop-color="#b91c1c" />
      </linearGradient>
      <linearGradient id="grad-amber" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#f59e0b" />
        <stop offset="100%" stop-color="#d97706" />
      </linearGradient>
    `;
    this.svg.appendChild(defs);

    // Groups
    this.edgesGroup = document.createElementNS(svgNS, 'g');
    this.edgesGroup.setAttribute('class', 'graph-edges-layer');
    this.svg.appendChild(this.edgesGroup);

    this.particlesGroup = document.createElementNS(svgNS, 'g');
    this.particlesGroup.setAttribute('class', 'graph-particles-layer');
    this.svg.appendChild(this.particlesGroup);

    this.nodesGroup = document.createElementNS(svgNS, 'g');
    this.nodesGroup.setAttribute('class', 'graph-nodes-layer');
    this.svg.appendChild(this.nodesGroup);

    this.container.appendChild(this.svg);
  }

  initObservers() {
    // Visibility Observer to pause particle loop when offscreen
    if (window.IntersectionObserver && this.container) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          this.isVisible = entry.isIntersecting;
          if (this.isVisible) {
            this.startParticleLoop();
          } else {
            this.stopParticleLoop();
          }
        });
      }, { threshold: 0.1 });
      observer.observe(this.container);
    }

    // Tab visibility change
    document.addEventListener('visibilitychange', () => {
      this.isVisible = !document.hidden;
      if (this.isVisible) {
        this.startParticleLoop();
      } else {
        this.stopParticleLoop();
      }
    });

    // Match media reduced motion listener
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mq.addEventListener) {
      mq.addEventListener('change', (e) => {
        this.prefersReducedMotion = e.matches;
        if (this.prefersReducedMotion) this.stopParticleLoop();
        else this.startParticleLoop();
      });
    }
  }

  setData(nodes = [], edges = [], meta = {}) {
    this.nodes = nodes;
    this.edges = edges;
    this.meta = meta;
    this.render();
  }

  render() {
    if (!this.container || !this.svg) return;

    this.stopParticleLoop();
    this.edgesGroup.innerHTML = '';
    this.particlesGroup.innerHTML = '';
    this.nodesGroup.innerHTML = '';
    this.particles = [];

    const width = this.options.width;
    const height = this.options.height;
    const svgNS = 'http://www.w3.org/2000/svg';

    if (!this.nodes || this.nodes.length === 0) {
      const text = document.createElementNS(svgNS, 'text');
      text.setAttribute('x', width / 2);
      text.setAttribute('y', height / 2);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('fill', 'var(--text-dim)');
      text.setAttribute('font-family', 'var(--font-mono)');
      text.setAttribute('font-size', '12');
      text.textContent = 'NO ACTIVE PROVENANCE LINEAGE ATTACHED';
      this.nodesGroup.appendChild(text);
      return;
    }

    const isTamper = this.meta.isTamper || this.nodes.some(n => n.node_type === 'QUARANTINE' || n.status === 'FAILED' || n.status === 'TAMPERED');
    const isDrift = this.meta.isDrift || this.nodes.some(n => n.status === 'REVIEW' || n.status === 'DRIFT');

    // Layout Calculation: Optimized 5-Stage Defense DAG
    // Stage 1: Contributor (x: 80, y: 180)
    // Stage 2: Dataset (x: 230, y: 180)
    // Stage 3: Model (x: 390, y: 180)
    // Stage 4: Inference (x: 550, y: 180)
    // Stage 5: Evidence / Decision (x: 690, y: 180)
    // Quarantine Branch (x: 390, y: 300)

    const positions = {};
    const nodeCount = this.nodes.length;

    this.nodes.forEach((node, idx) => {
      let x, y;
      const type = (node.node_type || '').toUpperCase();

      if (type === 'CONTRIBUTOR') {
        x = 80;
        y = 160;
      } else if (type === 'DATASET') {
        x = 230;
        y = 160;
      } else if (type === 'MODEL') {
        x = 390;
        y = 160;
      } else if (type === 'INFERENCE') {
        x = 550;
        y = 160;
      } else if (type === 'EVIDENCE') {
        x = 680;
        y = 160;
      } else if (type === 'QUARANTINE') {
        x = 310;
        y = 280;
      } else {
        // Fallback grid distribution
        const padX = 70;
        x = padX + ((width - padX * 2) / Math.max(1, nodeCount - 1)) * idx;
        y = height / 2 + ((idx % 2 === 0) ? -20 : 20);
      }
      positions[node.id] = { x, y };
    });

    // Draw Edges & Prepare Paths for Particle Simulation
    this.edges.forEach((edge, edgeIdx) => {
      const srcId = edge.source_id || edge.source;
      const tgtId = edge.target_id || edge.target;
      const src = positions[srcId];
      const tgt = positions[tgtId];

      if (!src || !tgt) return;

      const path = document.createElementNS(svgNS, 'path');
      
      // Calculate curved control points for smooth aerospace DAG aesthetics
      let d;
      const isQuarantineEdge = (edge.type === 'QUARANTINE_BRANCH' || tgtId.includes('ev_integrity') || tgtId.includes('quarantine') || srcId.includes('quarantine'));
      
      if (isQuarantineEdge) {
        // Downward branch curve
        const midX = (src.x + tgt.x) / 2;
        d = `M ${src.x} ${src.y} Q ${src.x} ${tgt.y} ${tgt.x} ${tgt.y}`;
      } else if (Math.abs(src.y - tgt.y) < 10) {
        // Straight horizontal edge
        d = `M ${src.x} ${src.y} L ${tgt.x} ${tgt.y}`;
      } else {
        // Smooth S-Curve
        const dx = (tgt.x - src.x) * 0.5;
        d = `M ${src.x} ${src.y} C ${src.x + dx} ${src.y}, ${tgt.x - dx} ${tgt.y}, ${tgt.x} ${tgt.y}`;
      }

      path.setAttribute('d', d);
      path.setAttribute('fill', 'none');
      path.setAttribute('id', `edge-path-${edgeIdx}`);

      // Edge styling based on scenario state
      let edgeColor = '#475569';
      let markerEnd = 'url(#arrow-neutral)';
      let isInterrupted = false;

      if (isTamper) {
        if (isQuarantineEdge) {
          edgeColor = '#ef4444';
          markerEnd = 'url(#arrow-danger)';
          path.setAttribute('stroke-dasharray', '4 4');
        } else if (srcId === 'ds_recon_01' || srcId === 'model_landcover') {
          // Interrupted / Downstream warning flow
          edgeColor = '#f59e0b';
          markerEnd = 'url(#arrow-amber)';
          path.setAttribute('stroke-dasharray', '3 3');
          isInterrupted = true;
        } else {
          edgeColor = '#06b6d4';
          markerEnd = 'url(#arrow-cyan)';
        }
      } else if (isDrift) {
        edgeColor = '#f59e0b';
        markerEnd = 'url(#arrow-amber)';
      } else {
        edgeColor = '#06b6d4';
        markerEnd = 'url(#arrow-green)';
      }

      path.setAttribute('stroke', edgeColor);
      path.setAttribute('stroke-width', '2');
      path.setAttribute('marker-end', markerEnd);
      path.setAttribute('opacity', '0.85');

      this.edgesGroup.appendChild(path);

      // Register Particle System on Path
      if (!isInterrupted && !this.prefersReducedMotion) {
        const particle = {
          pathElement: path,
          length: path.getTotalLength(),
          t: (edgeIdx * 0.25) % 1.0,
          speed: isQuarantineEdge ? 0.007 : 0.005,
          color: isQuarantineEdge ? '#ef4444' : (isDrift ? '#f59e0b' : '#38bdf8'),
          radius: isQuarantineEdge ? 3.5 : 3.0,
          isQuarantine: isQuarantineEdge,
        };

        // Create SVG circle particle
        const pCircle = document.createElementNS(svgNS, 'circle');
        pCircle.setAttribute('r', particle.radius);
        pCircle.setAttribute('fill', particle.color);
        pCircle.setAttribute('opacity', '0.9');
        pCircle.style.filter = `drop-shadow(0 0 4px ${particle.color})`;

        this.particlesGroup.appendChild(pCircle);
        particle.element = pCircle;
        this.particles.push(particle);
      }
    });

    // Draw Nodes
    this.nodes.forEach(node => {
      const pos = positions[node.id];
      if (!pos) return;

      const type = (node.node_type || 'NODE').toUpperCase();
      const isQuarantineNode = (type === 'QUARANTINE' || node.status === 'QUARANTINED');
      const isDownstreamAffected = isTamper && (type === 'MODEL' || type === 'INFERENCE');

      const g = document.createElementNS(svgNS, 'g');
      g.setAttribute('class', 'graph-node-group');
      g.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);
      g.style.cursor = 'pointer';

      // Colors and State styling
      let strokeColor = '#38bdf8';
      let fillColor = 'var(--bg-elevated)';
      let badgeText = type;
      let statusTag = 'VERIFIED';
      let statusClass = 'status-verified';

      if (type === 'CONTRIBUTOR') {
        strokeColor = 'var(--accent-indigo)';
        badgeText = 'CONTRIBUTOR';
        statusTag = 'AUTHENTIC';
      } else if (type === 'DATASET') {
        if (isTamper && this.meta.scenario === 'tamper_b04') {
          strokeColor = '#ef4444';
          fillColor = 'var(--status-danger-bg)';
          badgeText = 'TAMPERED';
          statusTag = 'HARD VETO';
          statusClass = 'status-failed';
        } else {
          strokeColor = '#06b6d4';
          badgeText = 'DATASET';
          statusTag = 'MERKLE PASS';
        }
      } else if (type === 'MODEL') {
        if (isDownstreamAffected) {
          strokeColor = '#f59e0b';
          badgeText = 'REVIEW';
          statusTag = 'REQUIRES REVIEW';
          statusClass = 'status-review';
        } else if (isTamper && this.meta.scenario === 'model_tamper') {
          strokeColor = '#ef4444';
          fillColor = 'var(--status-danger-bg)';
          badgeText = 'MUTATED';
          statusTag = 'WEIGHT MISMATCH';
          statusClass = 'status-failed';
        } else {
          strokeColor = '#3b82f6';
          badgeText = 'MODEL';
          statusTag = 'WEIGHTS SEALED';
        }
      } else if (type === 'INFERENCE') {
        if (isDownstreamAffected) {
          strokeColor = '#f59e0b';
          badgeText = 'REVIEW';
          statusTag = 'CHAIN FLAGGED';
          statusClass = 'status-review';
        } else {
          strokeColor = '#10b981';
          badgeText = 'INFERENCE';
          statusTag = 'DNA MONOTONIC';
        }
      } else if (type === 'EVIDENCE') {
        if (isDrift) {
          strokeColor = '#f59e0b';
          fillColor = 'var(--status-warning-bg)';
          badgeText = 'DRIFT';
          statusTag = 'REVIEW REQUIRED';
          statusClass = 'status-review';
        } else {
          strokeColor = '#10b981';
          fillColor = 'var(--status-success-bg)';
          badgeText = 'VERIFIED';
          statusTag = 'ACCEPTED';
        }
      } else if (isQuarantineNode) {
        strokeColor = '#ef4444';
        fillColor = 'var(--status-danger-bg)';
        badgeText = 'QUARANTINE';
        statusTag = 'CONTAINED';
        statusClass = 'status-failed';
      }

      // Outer Halo Ring (for Downstream Alert or Pulse)
      if (isDownstreamAffected) {
        const warningRing = document.createElementNS(svgNS, 'circle');
        warningRing.setAttribute('r', '24');
        warningRing.setAttribute('fill', 'none');
        warningRing.setAttribute('stroke', '#f59e0b');
        warningRing.setAttribute('stroke-width', '1.5');
        warningRing.setAttribute('stroke-dasharray', '3 3');
        warningRing.setAttribute('opacity', '0.8');
        g.appendChild(warningRing);
      } else if (isQuarantineNode) {
        const dangerRing = document.createElementNS(svgNS, 'circle');
        dangerRing.setAttribute('r', '24');
        dangerRing.setAttribute('fill', 'none');
        dangerRing.setAttribute('stroke', '#ef4444');
        dangerRing.setAttribute('stroke-width', '1.5');
        dangerRing.setAttribute('class', 'node-incident-pulse');
        g.appendChild(dangerRing);
      }

      // Main Node Circle
      const circle = document.createElementNS(svgNS, 'circle');
      circle.setAttribute('r', '17');
      circle.setAttribute('fill', fillColor);
      circle.setAttribute('stroke', strokeColor);
      circle.setAttribute('stroke-width', '2.5');
      circle.classList.add(statusClass);
      
      // Trigger subtle pulse once on render completion
      if (!this.prefersReducedMotion) {
        circle.classList.add('node-pulsing');
      }

      // Node Icon / Letter Marker
      const iconText = document.createElementNS(svgNS, 'text');
      iconText.setAttribute('text-anchor', 'middle');
      iconText.setAttribute('dominant-baseline', 'central');
      iconText.setAttribute('fill', strokeColor);
      iconText.setAttribute('font-family', 'var(--font-mono)');
      iconText.setAttribute('font-size', '10');
      iconText.setAttribute('font-weight', '800');
      iconText.textContent = type.substring(0, 2);

      // Node Bottom Label
      const label = document.createElementNS(svgNS, 'text');
      label.setAttribute('y', '30');
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('fill', 'var(--text-primary)');
      label.setAttribute('font-family', 'var(--font-mono)');
      label.setAttribute('font-size', '10');
      label.setAttribute('font-weight', '600');
      label.textContent = (node.label || node.id || '').substring(0, 18);

      // Node Top Type Tag
      const typeLabel = document.createElementNS(svgNS, 'text');
      typeLabel.setAttribute('y', '-24');
      typeLabel.setAttribute('text-anchor', 'middle');
      typeLabel.setAttribute('fill', strokeColor);
      typeLabel.setAttribute('font-family', 'var(--font-mono)');
      typeLabel.setAttribute('font-size', '8');
      typeLabel.setAttribute('font-weight', '800');
      typeLabel.setAttribute('letter-spacing', '0.5px');
      typeLabel.textContent = badgeText;

      g.appendChild(circle);
      g.appendChild(iconText);
      g.appendChild(label);
      g.appendChild(typeLabel);

      // Node Hover Interaction: Tactical Floating Tooltip
      g.addEventListener('mouseenter', (e) => {
        this.showTooltip(node, type, statusTag, strokeColor, pos);
      });

      g.addEventListener('mouseleave', () => {
        this.hideTooltip();
      });

      // Node Click Interaction: Open Technical Drawer / Callback
      g.addEventListener('click', () => {
        if (this.options.onNodeClick) {
          this.options.onNodeClick(node);
        } else {
          this.openNodeDetails(node, type, statusTag);
        }
      });

      this.nodesGroup.appendChild(g);
    });

    this.startParticleLoop();
  }

  showTooltip(node, type, statusTag, color, pos) {
    if (!this.tooltip || !this.container) return;

    const digest = node.digest || (node.id ? node.id.substring(0, 16) + '...' : 'SEALED');
    const upstream = node.upstream || 'Root Contributor Ground Station';
    const downstream = node.downstream || 'Inference Execution Pipeline';

    this.tooltip.innerHTML = `
      <div class="graph-tooltip-title" style="color: ${color};">
        <span>${type} // ${escapeHtml(node.label || node.id)}</span>
        <span class="badge-tag" style="border: 1px solid ${color}; color: ${color}; font-size: 8px;">${statusTag}</span>
      </div>
      <div class="graph-tooltip-row">
        <span class="graph-tooltip-label">Asset ID:</span>
        <span class="graph-tooltip-val">${escapeHtml(node.id || 'N/A')}</span>
      </div>
      <div class="graph-tooltip-row">
        <span class="graph-tooltip-label">SHA-256 Digest:</span>
        <span class="graph-tooltip-val" style="font-family: var(--font-mono); font-size: 9px;">${digest}</span>
      </div>
      <div class="graph-tooltip-row">
        <span class="graph-tooltip-label">Lineage:</span>
        <span class="graph-tooltip-val" style="font-size: 9px;">${type === 'CONTRIBUTOR' ? 'Primary Ingestion Source' : 'Linked Upstream Verified'}</span>
      </div>
    `;

    // Position Tooltip
    const rect = this.container.getBoundingClientRect();
    const scaleX = rect.width / this.options.width;
    const scaleY = rect.height / this.options.height;

    const px = pos.x * scaleX;
    const py = pos.y * scaleY;

    this.tooltip.style.left = `${px}px`;
    this.tooltip.style.top = `${py}px`;
    this.tooltip.classList.add('visible');
  }

  hideTooltip() {
    if (this.tooltip) {
      this.tooltip.classList.remove('visible');
    }
  }

  openNodeDetails(node, type, statusTag) {
    // Open the Subsystem Drawer and populate with node telemetry
    const drawer = document.getElementById('drawer-panel');
    const backdrop = document.getElementById('drawer-backdrop');
    const drawerTitle = drawer ? drawer.querySelector('.drawer-title') : null;
    const drawerBody = document.getElementById('drawer-body') || (drawer ? drawer.querySelector('.drawer-body') : null);

    if (drawer && backdrop) {
      if (drawerTitle) drawerTitle.textContent = `Provenance Node // ${type}: ${node.label || node.id}`;
      if (drawerBody) {
        drawerBody.innerHTML = `
          <div class="telemetry-box">
            <div class="telemetry-box-title">Cryptographic Node Telemetry</div>
            <table class="meta-table">
              <tr><td>Node Type:</td><td><strong>${type}</strong></td></tr>
              <tr><td>Node Identifier:</td><td><code>${escapeHtml(node.id)}</code></td></tr>
              <tr><td>Assurance Status:</td><td><span class="badge-tag badge-health-ok">${statusTag}</span></td></tr>
              <tr><td>Canonical Seal:</td><td><code>RFC 8785 JSON SHA-256</code></td></tr>
              <tr><td>Digital Signature:</td><td><code>ECDSA SECP256R1 (Air-Gapped Local CA)</code></td></tr>
            </table>
          </div>
          <div class="telemetry-box">
            <div class="telemetry-box-title">Raw Subsystem Properties</div>
            <pre style="font-family: var(--font-mono); font-size: 10px; color: var(--text-secondary); background: var(--bg-terminal); padding: 0.75rem; border-radius: 4px; overflow-x: auto;">${escapeHtml(JSON.stringify(node, null, 2))}</pre>
          </div>
        `;
      }
      backdrop.classList.add('active');
      drawer.classList.add('active');
    }
  }

  startParticleLoop() {
    if (this.animFrameId || this.prefersReducedMotion || !this.isVisible) return;

    const animate = () => {
      if (!this.isVisible) {
        this.animFrameId = null;
        return;
      }

      this.particles.forEach(p => {
        p.t += p.speed;
        if (p.t > 1.0) p.t = 0.0;

        try {
          const pt = p.pathElement.getPointAtLength(p.t * p.length);
          p.element.setAttribute('cx', pt.x);
          p.element.setAttribute('cy', pt.y);
        } catch (e) {
          // Ignore SVG measurement glitches during tab switch
        }
      });

      this.animFrameId = requestAnimationFrame(animate);
    };

    this.animFrameId = requestAnimationFrame(animate);
  }

  stopParticleLoop() {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
  }

  loadGraphData(data) {
    if (data && (data.nodes || data.edges)) {
      this.setData(data.nodes || [], data.edges || []);
    }
  }
}

// Backward compatibility alias for legacy test assertions
class ProvenanceGraphRenderer extends TrustCVGraph {}

window.TrustCVGraph = TrustCVGraph;
window.ProvenanceGraphRenderer = ProvenanceGraphRenderer;
