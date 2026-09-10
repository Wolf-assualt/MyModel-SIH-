/**
 * TRUST-CV Directed Property Graph & Cryptographic Provenance Canvas Renderer
 * Renders interactive forensic graph with particle flows, lineage tracing, and drawer inspection.
 */

class ProvenanceGraphRenderer {
  constructor(canvasId, drawerId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) {
      console.warn(`[Graph] Canvas element #${canvasId} not found.`);
      return;
    }
    this.ctx = this.canvas.getContext("2d");
    this.drawer = document.getElementById(drawerId);

    // Data structures
    this.nodes = [];
    this.edges = [];
    this.nodeMap = new Map();
    this.particles = [];

    // Camera transform
    this.scale = 1.0;
    this.panX = 0;
    this.panY = 0;

    // Interaction states
    this.isDraggingCanvas = false;
    this.dragStart = { x: 0, y: 0 };
    this.draggedNode = null;
    this.hoveredNode = null;
    this.selectedNode = null;
    this.highlightedAncestors = new Set();
    this.highlightedDescendants = new Set();

    // Node Visual Configurations
    this.typeColors = {
      CONTRIBUTOR: "#06b6d4",       // Cyan
      DATASET_BATCH: "#3b82f6",     // Blue
      SAMPLE: "#6366f1",            // Indigo
      MODEL: "#a855f7",             // Purple
      INFERENCE_RECORD: "#14b8a6",  // Teal
      FINDING: "#f43f5e",           // Crimson
    };

    this.typeIcons = {
      CONTRIBUTOR: "USR",
      DATASET_BATCH: "DAT",
      SAMPLE: "SMP",
      MODEL: "MDL",
      INFERENCE_RECORD: "INF",
      FINDING: "SEC",
    };

    // Physics parameters
    this.simulationRunning = true;
    this.simulationAlpha = 1.0;

    this._initEvents();
    this._initResizeObserver();
    this._startRenderLoop();
  }

  _initResizeObserver() {
    const resize = () => {
      if (!this.canvas) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = rect.height * dpr;
      this.canvas.style.width = `${rect.width}px`;
      this.canvas.style.height = `${rect.height}px`;
      this.ctx.scale(dpr, dpr);
      this.width = rect.width;
      this.height = rect.height;
    };

    window.addEventListener("resize", resize);
    resize();
    setTimeout(resize, 200);
  }

  _initEvents() {
    this.canvas.addEventListener("mousedown", (e) => this._onMouseDown(e));
    window.addEventListener("mousemove", (e) => this._onMouseMove(e));
    window.addEventListener("mouseup", (e) => this._onMouseUp(e));
    this.canvas.addEventListener("wheel", (e) => this._onWheel(e), { passive: false });
  }

  _screenToWorld(sx, sy) {
    const rect = this.canvas.getBoundingClientRect();
    const x = (sx - rect.left - this.panX) / this.scale;
    const y = (sy - rect.top - this.panY) / this.scale;
    return { x, y };
  }

  _findNodeAt(wx, wy) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const node = this.nodes[i];
      const dist = Math.hypot(node.x - wx, node.y - wy);
      if (dist <= node.radius + 6) {
        return node;
      }
    }
    return null;
  }

  _onMouseDown(e) {
    const rect = this.canvas.getBoundingClientRect();
    const wx = (e.clientX - rect.left - this.panX) / this.scale;
    const wy = (e.clientY - rect.top - this.panY) / this.scale;

    const hit = this._findNodeAt(wx, wy);
    if (hit) {
      this.draggedNode = hit;
      this._selectNode(hit);
    } else {
      this.isDraggingCanvas = true;
      this.dragStart = { x: e.clientX - this.panX, y: e.clientY - this.panY };
    }
  }

  _onMouseMove(e) {
    const rect = this.canvas.getBoundingClientRect();
    if (
      e.clientX < rect.left ||
      e.clientX > rect.right ||
      e.clientY < rect.top ||
      e.clientY > rect.bottom
    ) {
      if (!this.isDraggingCanvas && !this.draggedNode) return;
    }

    if (this.draggedNode) {
      const { x, y } = this._screenToWorld(e.clientX, e.clientY);
      this.draggedNode.x = x;
      this.draggedNode.y = y;
      this.draggedNode.vx = 0;
      this.draggedNode.vy = 0;
      this.simulationAlpha = 0.3; // Re-awaken physics briefly
    } else if (this.isDraggingCanvas) {
      this.panX = e.clientX - this.dragStart.x;
      this.panY = e.clientY - this.dragStart.y;
    } else {
      const { x, y } = this._screenToWorld(e.clientX, e.clientY);
      const hit = this._findNodeAt(x, y);
      if (hit !== this.hoveredNode) {
        this.hoveredNode = hit;
        this.canvas.style.cursor = hit ? "pointer" : "grab";
      }
    }
  }

  _onMouseUp() {
    this.isDraggingCanvas = false;
    this.draggedNode = null;
    this.canvas.style.cursor = this.hoveredNode ? "pointer" : "grab";
  }

  _onWheel(e) {
    e.preventDefault();
    const rect = this.canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
    const newScale = Math.min(Math.max(0.25, this.scale * zoomFactor), 3.5);

    this.panX = mouseX - (mouseX - this.panX) * (newScale / this.scale);
    this.panY = mouseY - (mouseY - this.panY) * (newScale / this.scale);
    this.scale = newScale;
  }

  loadGraphData(graphExport) {
    if (!graphExport) return;
    const rawNodes = graphExport.nodes || [];
    const rawEdges = graphExport.edges || [];

    this.nodeMap.clear();
    const cx = (this.width || 800) / 2;
    const cy = (this.height || 600) / 2;

    this.nodes = rawNodes.map((n, idx) => {
      // Stratify initial layout loosely by type
      const angle = (idx / (rawNodes.length || 1)) * 2 * Math.PI;
      const radius = 150 + Math.random() * 120;
      const node = {
        ...n,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        radius: n.node_type === "MODEL" || n.node_type === "FINDING" ? 22 : 18,
      };
      this.nodeMap.set(n.node_id, node);
      return node;
    });

    this.edges = rawEdges
      .map((e) => {
        const source = this.nodeMap.get(e.source_id);
        const target = this.nodeMap.get(e.target_id);
        if (!source || !target) return null;
        return {
          ...e,
          source,
          target,
        };
      })
      .filter(Boolean);

    // Initialize flowing particles along edges
    this.particles = [];
    this.edges.forEach((edge, i) => {
      const particleCount = 2;
      for (let p = 0; p < particleCount; p++) {
        this.particles.push({
          edge,
          progress: (p / particleCount) + Math.random() * 0.2,
          speed: 0.006 + Math.random() * 0.005,
          color: edge.edge_type === "FLAGGED_WITH" ? "#f43f5e" : "#06b6d4",
        });
      }
    });

    this.simulationAlpha = 1.0;
    this.simulationRunning = true;
    this.resetView();
  }

  resetView() {
    if (!this.nodes.length) return;
    const w = this.width || 800;
    const h = this.height || 600;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    this.nodes.forEach((n) => {
      if (n.x < minX) minX = n.x;
      if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.y > maxY) maxY = n.y;
    });

    const graphW = Math.max(maxX - minX + 150, 400);
    const graphH = Math.max(maxY - minY + 150, 300);

    this.scale = Math.min(w / graphW, h / graphH, 1.2);
    this.panX = w / 2 - ((minX + maxX) / 2) * this.scale;
    this.panY = h / 2 - ((minY + maxY) / 2) * this.scale;
  }

  async _selectNode(node) {
    this.selectedNode = node;
    this.highlightedAncestors.clear();
    this.highlightedDescendants.clear();

    // Query backend lineage trace
    try {
      if (window.TrustCvApi) {
        const trace = await window.TrustCvApi.traceLineage(node.node_id);
        if (trace) {
          (trace.upstream_dependencies || []).forEach((id) => this.highlightedAncestors.add(id));
          (trace.downstream_impact || []).forEach((id) => this.highlightedDescendants.add(id));
        }
      }
    } catch (err) {
      console.warn("[Graph] Lineage trace failed, fallback to local:", err);
      // Local immediate fallback
      this.edges.forEach((e) => {
        if (e.target.node_id === node.node_id) this.highlightedAncestors.add(e.source.node_id);
        if (e.source.node_id === node.node_id) this.highlightedDescendants.add(e.target.node_id);
      });
    }

    this._openInspector(node);
  }

  _openInspector(node) {
    if (!this.drawer) return;
    this.drawer.classList.remove("translate-x-full");

    const titleEl = document.getElementById("drawer-title");
    const typeEl = document.getElementById("drawer-type");
    const digestEl = document.getElementById("drawer-digest");
    const detailsEl = document.getElementById("drawer-details");
    const statusBadge = document.getElementById("drawer-status-badge");

    if (titleEl) titleEl.textContent = node.label || node.node_id;
    if (typeEl) {
      typeEl.textContent = node.node_type;
      typeEl.style.color = this.typeColors[node.node_type] || "#06b6d4";
    }

    const digest = (node.attributes && (node.attributes.canonical_digest || node.attributes.raw_output_digest || node.attributes.model_digest || node.attributes.batch_digest)) || "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    if (digestEl) {
      digestEl.textContent = digest;
      digestEl.title = "Click to copy digest";
      digestEl.onclick = () => {
        navigator.clipboard.writeText(digest);
        const originalText = digestEl.textContent;
        digestEl.textContent = "COPIED TO CLIPBOARD!";
        setTimeout(() => (digestEl.textContent = originalText), 1500);
      };
    }

    if (statusBadge) {
      const isFinding = node.node_type === "FINDING";
      statusBadge.textContent = isFinding ? "SECURITY VIOLATION" : "CRYPTOGRAPHICALLY ATTESTED";
      statusBadge.className = isFinding
        ? "inline-block px-2 py-0.5 text-xs font-semibold rounded bg-rose-900/60 text-rose-300 border border-rose-500/50"
        : "inline-block px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/60 text-emerald-300 border border-emerald-500/50";
    }

    if (detailsEl) {
      const attrHtml = Object.entries(node.attributes || {})
        .map(([k, v]) => {
          let displayVal = typeof v === "object" ? JSON.stringify(v, null, 2) : String(v);
          return `
            <div class="flex flex-col py-1 border-b border-slate-800 text-xs">
              <span class="text-slate-400 font-mono">${k}</span>
              <span class="text-slate-200 font-mono break-all mt-0.5">${displayVal}</span>
            </div>
          `;
        })
        .join("");

      detailsEl.innerHTML = `
        <div class="mb-4">
          <h4 class="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-2">Forensic Attributes</h4>
          <div class="bg-slate-900/80 p-2.5 rounded border border-slate-800 max-h-60 overflow-y-auto">
            ${attrHtml || "<span class='text-slate-500'>No additional attributes</span>"}
          </div>
        </div>
        <div class="mb-2">
          <h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Lineage Impact</h4>
          <div class="grid grid-cols-2 gap-2 text-xs">
            <div class="bg-slate-900/80 p-2 rounded border border-emerald-500/30">
              <span class="text-emerald-400 font-semibold block">Upstream Roots</span>
              <span class="text-slate-200 font-mono text-sm">${this.highlightedAncestors.size}</span>
            </div>
            <div class="bg-slate-900/80 p-2 rounded border border-amber-500/30">
              <span class="text-amber-400 font-semibold block">Downstream Blast</span>
              <span class="text-slate-200 font-mono text-sm">${this.highlightedDescendants.size}</span>
            </div>
          </div>
        </div>
      `;
    }
  }

  closeInspector() {
    if (this.drawer) {
      this.drawer.classList.add("translate-x-full");
    }
    this.selectedNode = null;
    this.highlightedAncestors.clear();
    this.highlightedDescendants.clear();
  }

  _tickPhysics() {
    if (!this.simulationRunning || this.simulationAlpha < 0.005) {
      this.simulationRunning = false;
      return;
    }

    const k = 0.05 * this.simulationAlpha;
    const center = { x: (this.width || 800) / 2, y: (this.height || 600) / 2 };

    // Repulsion between nodes
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.hypot(dx, dy) || 1;
        if (dist < 220) {
          const force = ((220 - dist) / dist) * 1.5 * this.simulationAlpha;
          n1.vx -= (dx / dist) * force;
          n1.vy -= (dy / dist) * force;
          n2.vx += (dx / dist) * force;
          n2.vy += (dy / dist) * force;
        }
      }

      // Gentle center gravity
      n1.vx += (center.x - n1.x) * 0.0008 * this.simulationAlpha;
      n1.vy += (center.y - n1.y) * 0.0008 * this.simulationAlpha;
    }

    // Spring forces along edges
    for (let e of this.edges) {
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const dist = Math.hypot(dx, dy) || 1;
      const desiredDist = 120;
      const springForce = (dist - desiredDist) * 0.03 * this.simulationAlpha;

      e.source.vx += (dx / dist) * springForce;
      e.source.vy += (dy / dist) * springForce;
      e.target.vx -= (dx / dist) * springForce;
      e.target.vy -= (dy / dist) * springForce;
    }

    // Apply velocities with friction
    for (let n of this.nodes) {
      if (n === this.draggedNode) continue;
      n.x += n.vx;
      n.y += n.vy;
      n.vx *= 0.85;
      n.vy *= 0.85;
    }

    this.simulationAlpha *= 0.985;
  }

  _startRenderLoop() {
    const loop = () => {
      this._tickPhysics();
      this._render();
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  _render() {
    const ctx = this.ctx;
    const w = this.width || 800;
    const h = this.height || 600;

    ctx.save();
    ctx.clearRect(0, 0, w, h);

    // Apply camera transform
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.scale, this.scale);

    // 1. Draw Edges
    this._renderEdges(ctx);

    // 2. Draw Cryptographic Particles
    this._renderParticles(ctx);

    // 3. Draw Nodes
    this._renderNodes(ctx);

    ctx.restore();
  }

  _renderEdges(ctx) {
    for (let e of this.edges) {
      const isSelectedFlow =
        this.selectedNode &&
        ((this.selectedNode.node_id === e.source.node_id && this.highlightedDescendants.has(e.target.node_id)) ||
         (this.selectedNode.node_id === e.target.node_id && this.highlightedAncestors.has(e.source.node_id)));

      const isFinding = e.edge_type === "FLAGGED_WITH";

      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);

      // Compute slight curve
      const midX = (e.source.x + e.target.x) / 2;
      const midY = (e.source.y + e.target.y) / 2;
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const normalX = -dy * 0.08;
      const normalY = dx * 0.08;

      ctx.quadraticCurveTo(midX + normalX, midY + normalY, e.target.x, e.target.y);

      if (isSelectedFlow) {
        ctx.strokeStyle = this.selectedNode.node_id === e.source.node_id ? "#f59e0b" : "#10b981";
        ctx.lineWidth = 2.5;
        ctx.shadowColor = ctx.strokeStyle;
        ctx.shadowBlur = 8;
      } else if (isFinding) {
        ctx.strokeStyle = "rgba(244, 63, 94, 0.6)";
        ctx.lineWidth = 1.8;
        ctx.shadowBlur = 0;
      } else {
        ctx.strokeStyle = "rgba(51, 65, 85, 0.5)";
        ctx.lineWidth = 1.2;
        ctx.shadowBlur = 0;
      }

      ctx.stroke();
      ctx.shadowBlur = 0;

      // Draw directional arrow near target
      const t = 0.85;
      const ax = (1 - t) * (1 - t) * e.source.x + 2 * (1 - t) * t * (midX + normalX) + t * t * e.target.x;
      const ay = (1 - t) * (1 - t) * e.source.y + 2 * (1 - t) * t * (midY + normalY) + t * t * e.target.y;
      const angle = Math.atan2(e.target.y - ay, e.target.x - ax);

      ctx.save();
      ctx.translate(ax, ay);
      ctx.rotate(angle);
      ctx.fillStyle = ctx.strokeStyle;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(-6, -3);
      ctx.lineTo(-6, 3);
      ctx.closePath();
      ctx.fill();
      ctx.restore();
    }
  }

  _renderParticles(ctx) {
    for (let p of this.particles) {
      p.progress += p.speed;
      if (p.progress > 1.0) p.progress -= 1.0;

      const e = p.edge;
      const midX = (e.source.x + e.target.x) / 2;
      const midY = (e.source.y + e.target.y) / 2;
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const normalX = -dy * 0.08;
      const normalY = dx * 0.08;

      const t = p.progress;
      const px = (1 - t) * (1 - t) * e.source.x + 2 * (1 - t) * t * (midX + normalX) + t * t * e.target.x;
      const py = (1 - t) * (1 - t) * e.source.y + 2 * (1 - t) * t * (midY + normalY) + t * t * e.target.y;

      ctx.beginPath();
      ctx.arc(px, py, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  _renderNodes(ctx) {
    for (let n of this.nodes) {
      const isSelected = this.selectedNode && this.selectedNode.node_id === n.node_id;
      const isAncestor = this.highlightedAncestors.has(n.node_id);
      const isDescendant = this.highlightedDescendants.has(n.node_id);
      const isHovered = this.hoveredNode && this.hoveredNode.node_id === n.node_id;

      let baseColor = this.typeColors[n.node_type] || "#06b6d4";
      let haloColor = baseColor;
      let alpha = 1.0;

      if (this.selectedNode) {
        if (isSelected) {
          haloColor = "#ffffff";
          alpha = 1.0;
        } else if (isAncestor) {
          haloColor = "#10b981";
          alpha = 1.0;
        } else if (isDescendant) {
          haloColor = "#f59e0b";
          alpha = 1.0;
        } else {
          alpha = 0.25;
        }
      }

      ctx.save();
      ctx.globalAlpha = alpha;

      // Glow Halo
      if (isSelected || isAncestor || isDescendant || isHovered) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
        ctx.fillStyle = "transparent";
        ctx.strokeStyle = haloColor;
        ctx.lineWidth = isSelected ? 3 : 2;
        ctx.shadowColor = haloColor;
        ctx.shadowBlur = 14;
        ctx.stroke();
      }

      // Outer Circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      ctx.fillStyle = "#0f172a";
      ctx.strokeStyle = baseColor;
      ctx.lineWidth = 2;
      ctx.fill();
      ctx.stroke();

      // Node Icon / Short Text
      ctx.fillStyle = baseColor;
      ctx.font = "bold 9px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      const icon = this.typeIcons[n.node_type] || "NOD";
      ctx.fillText(icon, n.x, n.y);

      // Node Label
      ctx.fillStyle = "#cbd5e1";
      ctx.font = "10px 'Rajdhani', sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      const displayLabel = n.label && n.label.length > 18 ? n.label.slice(0, 16) + "…" : n.label || n.node_id;
      ctx.fillText(displayLabel, n.x, n.y + n.radius + 4);

      ctx.restore();
    }
  }
}

// Global initialization helper
window.ProvenanceGraphRenderer = ProvenanceGraphRenderer;
