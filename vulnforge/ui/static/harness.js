/**
 * Harness mode — live agent graph + Ralph loop profile picker.
 * Graph supports pan (drag) and zoom (wheel / buttons).
 */
(function () {
  const $ = (sel, el = document) => el.querySelector(sel);

  let lastGraph = null;
  let profiles = [];
  let selectedProfileId =
    (typeof localStorage !== "undefined" &&
      localStorage.getItem("vf_loop_profile_id")) ||
    "default-campaign";
  let typeView = false;
  let activated = false;

  // Viewport: pan/zoom over graph content coordinates
  let view = { x: 0, y: 0, k: 1 };
  let contentSize = { w: 800, h: 400 };
  let dragging = false;
  let dragMoved = false;
  let dragStart = { x: 0, y: 0, vx: 0, vy: 0 };
  let suppressClick = false;

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function stateColor(state) {
    const s = String(state || "");
    if (s === "succeeded") return "var(--good)";
    if (s === "leased") return "var(--info)";
    if (s === "queued") return "var(--muted)";
    if (s === "failed_task" || s === "deadletter" || s === "failed_infra")
      return "var(--bad)";
    if (s === "blocked" || s === "cancelled") return "var(--warn)";
    return "var(--border)";
  }

  async function api(path, opts) {
    if (typeof window.api === "function") return window.api(path, opts);
    const r = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts?.headers || {}) },
      ...opts,
    });
    if (!r.ok) {
      const t = await r.text();
      throw new Error(t || r.statusText);
    }
    return r.json();
  }

  function runKey() {
    return (
      window.currentKey ||
      document.body.getAttribute("data-run-key") ||
      ""
    );
  }

  async function loadProfiles() {
    try {
      const data = await api("/api/loop-profiles");
      profiles = data.profiles || [];
      const sel = $("#harness-loop-select");
      if (!sel) return;
      if (!profiles.some((p) => p.id === selectedProfileId) && profiles[0]) {
        selectedProfileId = profiles[0].id;
      }
      sel.innerHTML = profiles
        .map(
          (p) =>
            `<option value="${esc(p.id)}" ${
              p.id === selectedProfileId ? "selected" : ""
            }>${esc(p.title || p.id)}</option>`
        )
        .join("");
      renderLoopDetail();
    } catch (e) {
      console.warn("loop profiles", e);
    }
  }

  function renderLoopDetail() {
    const el = $("#harness-loop-detail");
    if (!el) return;
    const p = profiles.find((x) => x.id === selectedProfileId);
    if (!p) {
      el.textContent = "No profile selected.";
      return;
    }
    const loop = p.loop || {};
    el.innerHTML = `
      <div><strong>${esc(p.title || p.id)}</strong> <code>${esc(p.id)}</code></div>
      <div>max_tasks: ${esc(loop.max_tasks)} · iterations: ${esc(
      loop.max_iterations
    )}</div>
      <div>task_timeout: ${esc(loop.task_timeout_s)}s · workers: ${esc(
      loop.workers
    )}</div>
      <div class="controls-hint" style="margin-top:0.35rem">Used on Start / Resume from this page.</div>
    `;
  }

  function renderRunner(runner) {
    const el = $("#harness-runner");
    if (!el) return;
    const r = runner || {};
    const meta = r.meta || {};
    el.innerHTML = `
      <div class="harness-runner-row"><span>State</span><strong>${esc(
        r.state || "—"
      )}</strong></div>
      <div class="harness-runner-row"><span>Workers</span><strong>${esc(
        r.workers_alive ?? r.workers ?? "—"
      )} / ${esc(meta.workers ?? r.workers ?? "—")}</strong></div>
      <div class="harness-runner-row"><span>PIDs</span><code>${esc(
        (r.pids || []).join(", ") || "—"
      )}</code></div>
      <div class="harness-runner-row"><span>Profile</span><code>${esc(
        meta.loop_profile_id || "—"
      )}</code></div>
      <div class="harness-runner-row"><span>max_tasks</span><code>${esc(
        meta.max_tasks ?? "—"
      )}</code></div>
      <div class="harness-runner-row"><span>timeout</span><code>${esc(
        meta.task_timeout ?? "—"
      )}s</code></div>
    `;
  }

  function measureLabel(text, maxChars) {
    const s = String(text || "");
    if (s.length <= maxChars) return s;
    return s.slice(0, Math.max(4, maxChars - 1)) + "…";
  }

  function wrapLabel(text, maxWidthChars) {
    const s = String(text || "");
    if (s.length <= maxWidthChars) return [s];
    const words = s.split(/[\s·|/]+/).filter(Boolean);
    if (words.length <= 1) {
      return [measureLabel(s, maxWidthChars)];
    }
    const lines = [];
    let cur = "";
    for (const w of words) {
      const next = cur ? cur + " " + w : w;
      if (next.length > maxWidthChars && cur) {
        lines.push(cur);
        cur = w;
        if (lines.length >= 3) break;
      } else {
        cur = next;
      }
    }
    if (cur && lines.length < 3) lines.push(measureLabel(cur, maxWidthChars));
    return lines.length ? lines : [measureLabel(s, maxWidthChars)];
  }

  function layoutNodes(nodes) {
    const kindOrder = [
      "recon",
      "hunt",
      "validate_mech",
      "validate_llm",
      "develop_poc",
      "render",
      "tool_gaps",
      "generate_skill",
      "generate_run_skills",
    ];
    const rank = (k) => {
      const i = kindOrder.indexOf(String(k));
      return i >= 0 ? i : kindOrder.length;
    };
    const sorted = [...nodes].sort((a, b) => {
      const dr = rank(a.kind) - rank(b.kind);
      if (dr) return dr;
      return (a.task_id || 0) - (b.task_id || 0);
    });
    const cols = {};
    sorted.forEach((n) => {
      const c = rank(n.kind);
      if (!cols[c]) cols[c] = [];
      cols[c].push(n);
    });
    const nodeW = 168;
    const nodeH = 52;
    const colW = nodeW + 48;
    const rowH = nodeH + 20;
    const padX = 48;
    const padY = 40;
    const positions = {};
    Object.keys(cols)
      .map(Number)
      .sort((a, b) => a - b)
      .forEach((c, ci) => {
        cols[c].forEach((n, ri) => {
          positions[n.id] = {
            x: padX + ci * colW,
            y: padY + ri * rowH,
            w: nodeW,
            h: nodeH,
          };
        });
      });
    const maxCol = Math.max(0, ...Object.keys(cols).map(Number));
    const maxRows = Math.max(1, ...Object.values(cols).map((a) => a.length));
    return {
      positions,
      nodeW,
      nodeH,
      width: padX * 2 + (maxCol + 1) * colW,
      height: padY * 2 + maxRows * rowH,
    };
  }

  function applyViewTransform() {
    const g = $("#harness-viewport");
    if (!g) return;
    g.setAttribute(
      "transform",
      `translate(${view.x},${view.y}) scale(${view.k})`
    );
    const zlab = $("#harness-zoom-label");
    if (zlab) zlab.textContent = `${Math.round(view.k * 100)}%`;
  }

  function fitView(host) {
    if (!host) return;
    const rect = host.getBoundingClientRect();
    const vw = Math.max(200, rect.width - 8);
    const vh = Math.max(160, rect.height - 8);
    const cw = Math.max(1, contentSize.w);
    const ch = Math.max(1, contentSize.h);
    const k = Math.min(1.2, Math.max(0.25, Math.min(vw / cw, vh / ch) * 0.92));
    view.k = k;
    view.x = (vw - cw * k) / 2;
    view.y = (vh - ch * k) / 2;
    applyViewTransform();
  }

  function zoomAt(clientX, clientY, factor, host) {
    const rect = host.getBoundingClientRect();
    const mx = clientX - rect.left;
    const my = clientY - rect.top;
    const prev = view.k;
    const next = Math.min(3, Math.max(0.2, prev * factor));
    if (next === prev) return;
    // Keep point under cursor stable
    view.x = mx - (mx - view.x) * (next / prev);
    view.y = my - (my - view.y) * (next / prev);
    view.k = next;
    applyViewTransform();
  }

  function bindZoomButtons(host) {
    $("#harness-zoom-in")?.addEventListener("click", () => {
      const r = host.getBoundingClientRect();
      zoomAt(r.left + r.width / 2, r.top + r.height / 2, 1.15, host);
    });
    $("#harness-zoom-out")?.addEventListener("click", () => {
      const r = host.getBoundingClientRect();
      zoomAt(r.left + r.width / 2, r.top + r.height / 2, 1 / 1.15, host);
    });
    $("#harness-zoom-fit")?.addEventListener("click", () => fitView(host));
  }

  function bindViewport(host) {
    if (!host) return;
    host.style.cursor = "grab";
    host.tabIndex = 0;
    // Zoom controls are recreated each render
    bindZoomButtons(host);
    if (host.dataset.panBound === "1") return;
    host.dataset.panBound = "1";

    host.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        const factor = e.deltaY > 0 ? 0.9 : 1.1;
        zoomAt(e.clientX, e.clientY, factor, host);
      },
      { passive: false }
    );

    host.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      // Don't pan when starting on toolbar buttons
      if (e.target.closest?.(".harness-graph-toolbar")) return;
      dragging = true;
      dragMoved = false;
      dragStart = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
      host.setPointerCapture?.(e.pointerId);
      host.style.cursor = "grabbing";
    });
    host.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      const dx = e.clientX - dragStart.x;
      const dy = e.clientY - dragStart.y;
      if (Math.hypot(dx, dy) > 4) dragMoved = true;
      view.x = dragStart.vx + dx;
      view.y = dragStart.vy + dy;
      applyViewTransform();
    });
    const endDrag = (e) => {
      if (!dragging) return;
      dragging = false;
      host.style.cursor = "grab";
      if (dragMoved) {
        suppressClick = true;
        setTimeout(() => {
          suppressClick = false;
        }, 0);
      }
      try {
        host.releasePointerCapture?.(e.pointerId);
      } catch (_) {}
    };
    host.addEventListener("pointerup", endDrag);
    host.addEventListener("pointercancel", endDrag);
  }

  function renderGraph(graph) {
    const host = $("#harness-graph");
    if (!host) return;
    lastGraph = graph;
    const useType = typeView && (graph.type_nodes || []).length;
    const nodes = useType ? graph.type_nodes : graph.nodes || [];
    const edges = useType ? graph.type_edges || [] : graph.edges || [];

    if (!nodes.length) {
      host.innerHTML =
        '<p class="empty controls-hint">No tasks yet. Init a run and Start Ralph to populate the graph.</p>';
      renderKindSummary(graph);
      renderRunner(graph.runner);
      return;
    }

    const norm = nodes.map((n) => {
      if (useType) {
        return {
          id: n.id,
          label: `${n.kind} (${n.count})`,
          state: Object.keys(n.states || {})[0] || "queued",
          kind: n.kind,
          task_id: null,
        };
      }
      return n;
    });

    const { positions, nodeW, nodeH, width, height } = layoutNodes(norm);
    contentSize = { w: width, h: height };

    const edgeSvg = edges
      .map((e) => {
        const a = positions[e.source];
        const b = positions[e.target];
        if (!a || !b) return "";
        const x1 = a.x + (a.w || nodeW);
        const y1 = a.y + (a.h || nodeH) / 2;
        const x2 = b.x;
        const y2 = b.y + (b.h || nodeH) / 2;
        return `<path d="M${x1},${y1} C${x1 + 36},${y1} ${x2 - 36},${y2} ${x2},${y2}" class="harness-edge" data-type="${esc(
          e.type || ""
        )}" />`;
      })
      .join("");

    const nodeSvg = norm
      .map((n) => {
        const p = positions[n.id] || { x: 0, y: 0, w: nodeW, h: nodeH };
        const w = p.w || nodeW;
        const h = p.h || nodeH;
        const fill = stateColor(n.state);
        const clickable = n.task_id != null ? " harness-node-click" : "";
        const kindLine = measureLabel(String(n.kind || ""), 22);
        const lines = wrapLabel(n.label || n.id || "", 22);
        const lineEls = lines
          .map(
            (ln, i) =>
              `<tspan x="10" dy="${i === 0 ? 0 : 13}">${esc(ln)}</tspan>`
          )
          .join("");
        return `<g class="harness-node${clickable}" data-task-id="${esc(
          n.task_id ?? ""
        )}" transform="translate(${p.x},${p.y})">
          <title>${esc(n.label || n.id || "")}</title>
          <rect width="${w}" height="${h}" rx="8" ry="8" fill="var(--panel)" stroke="${fill}" stroke-width="2" />
          <text x="10" y="16" class="harness-node-kind">${esc(kindLine)}</text>
          <text x="10" y="34" class="harness-node-label">${lineEls}</text>
        </g>`;
      })
      .join("");

    // Keep panBound flag across re-renders (listeners on host stay attached)
    const wasBound = host.dataset.panBound === "1";
    host.innerHTML = `
      <div class="harness-graph-toolbar">
        <span class="controls-hint">Scroll = zoom · Drag = pan · Click node = step I/O</span>
        <div class="harness-zoom-btns">
          <button type="button" class="btn btn-sm" id="harness-zoom-out" title="Zoom out">−</button>
          <span id="harness-zoom-label" class="harness-zoom-label">100%</span>
          <button type="button" class="btn btn-sm" id="harness-zoom-in" title="Zoom in">+</button>
          <button type="button" class="btn btn-sm" id="harness-zoom-fit" title="Fit graph">Fit</button>
        </div>
      </div>
      <svg class="harness-svg" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="harness-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="var(--muted)" />
          </marker>
        </defs>
        <g id="harness-viewport">
          <g class="harness-edges" marker-end="url(#harness-arrow)">${edgeSvg}</g>
          <g class="harness-nodes">${nodeSvg}</g>
        </g>
      </svg>`;
    if (wasBound) host.dataset.panBound = "1";
    bindViewport(host);
    fitView(host);

    host.querySelectorAll(".harness-node-click").forEach((g) => {
      g.addEventListener("click", (ev) => {
        if (suppressClick || dragMoved) {
          ev.preventDefault();
          ev.stopPropagation();
          return;
        }
        const id = g.getAttribute("data-task-id");
        if (!id) return;
        if (typeof window.openStepIO === "function") {
          window.openStepIO(id);
        } else if (typeof window.openTranscript === "function") {
          window.openTranscript(id);
        }
      });
    });

    renderKindSummary(graph);
    renderRunner(graph.runner);
  }

  function renderKindSummary(graph) {
    const el = $("#harness-kind-summary");
    if (!el) return;
    const types = graph?.type_nodes || [];
    if (!types.length) {
      el.innerHTML = '<p class="empty">—</p>';
      return;
    }
    el.innerHTML = `<ul class="harness-kind-list">${types
      .map((t) => {
        const st = Object.entries(t.states || {})
          .map(([k, v]) => `${k}:${v}`)
          .join(" · ");
        return `<li><strong>${esc(t.kind)}</strong> ×${esc(
          t.count
        )} <span class="controls-hint">${esc(st)}</span></li>`;
      })
      .join("")}</ul>`;
  }

  async function refreshGraph() {
    const key = runKey();
    if (!key || !key.includes("/")) return;
    const [target_id, run_id] = key.split("/");
    try {
      const graph = await api(
        `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(
          run_id
        )}/graph`
      );
      renderGraph(graph);
    } catch (e) {
      const host = $("#harness-graph");
      if (host)
        host.innerHTML = `<p class="empty" style="color:var(--bad)">${esc(
          e.message || e
        )}</p>`;
    }
  }

  function getSelectedLoopProfileId() {
    return selectedProfileId || "default-campaign";
  }

  function activate() {
    if (!activated) {
      activated = true;
      $("#harness-refresh")?.addEventListener("click", () => refreshGraph());
      $("#harness-loop-select")?.addEventListener("change", (e) => {
        selectedProfileId = e.target.value;
        try {
          localStorage.setItem("vf_loop_profile_id", selectedProfileId);
        } catch (_) {}
        renderLoopDetail();
      });
      $("#harness-type-view")?.addEventListener("change", (e) => {
        typeView = !!e.target.checked;
        if (lastGraph) renderGraph(lastGraph);
      });
    }
    loadProfiles();
    refreshGraph();
  }

  window.VulnForgeHarness = {
    activate,
    refreshGraph,
    getSelectedLoopProfileId,
    loadProfiles,
  };
})();
