/**
 * Harness mode — live agent graph + Ralph loop profile picker.
 * Graph: pan (drag empty or background), zoom (wheel / buttons), click node → step I/O.
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
  let shellReady = false;

  // Viewport: pan/zoom over graph content coordinates
  let view = { x: 0, y: 0, k: 1 };
  let contentSize = { w: 800, h: 400 };
  let hasUserView = false; // after pan/zoom, don't auto-fit on refresh
  let dragging = false;
  let dragMoved = false;
  let dragStart = { x: 0, y: 0, vx: 0, vy: 0 };
  let suppressClick = false;
  let spacePan = false;

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

  function edgeColor(type) {
    const t = String(type || "");
    if (t === "finding" || t === "parent") return "var(--info)";
    if (t === "split" || t === "spawn" || t === "requeue") return "var(--warn)";
    if (t === "enqueue_hunt" || t === "pipeline") return "var(--muted)";
    return "var(--muted)";
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
    const nodeW = 172;
    const nodeH = 56;
    const colW = nodeW + 56;
    const rowH = nodeH + 24;
    const padX = 56;
    const padY = 48;
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

  function ensureShell(host) {
    if (!host) return null;
    if (shellReady && host.querySelector(".harness-svg")) {
      return host.querySelector("#harness-world");
    }
    host.innerHTML = `
      <div class="harness-graph-toolbar">
        <span class="controls-hint">Drag empty space or hold <kbd>Space</kbd> + drag to pan · Scroll to zoom · Click node for step I/O</span>
        <div class="harness-zoom-btns">
          <button type="button" class="btn btn-sm" id="harness-zoom-out" title="Zoom out">−</button>
          <span id="harness-zoom-label" class="harness-zoom-label">100%</span>
          <button type="button" class="btn btn-sm" id="harness-zoom-in" title="Zoom in">+</button>
          <button type="button" class="btn btn-sm" id="harness-zoom-fit" title="Fit graph">Fit</button>
        </div>
      </div>
      <svg class="harness-svg" width="100%" height="100%">
        <defs>
          <marker id="harness-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L6,3 L0,6 Z" fill="var(--muted)" />
          </marker>
          <marker id="harness-arrow-info" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L6,3 L0,6 Z" fill="var(--info)" />
          </marker>
        </defs>
        <rect class="harness-svg-bg" x="0" y="0" width="100%" height="100%" fill="transparent" />
        <g id="harness-viewport">
          <g id="harness-world"></g>
        </g>
      </svg>
      <div id="harness-graph-meta" class="harness-graph-meta controls-hint"></div>`;
    shellReady = true;
    bindViewport(host);
    return host.querySelector("#harness-world");
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

  function fitView(host, force) {
    if (!host) return;
    const rect = host.getBoundingClientRect();
    const vw = Math.max(200, rect.width - 8);
    const vh = Math.max(160, rect.height - 8);
    const cw = Math.max(1, contentSize.w);
    const ch = Math.max(1, contentSize.h);
    const k = Math.min(1.25, Math.max(0.2, Math.min(vw / cw, vh / ch) * 0.9));
    view.k = k;
    view.x = (vw - cw * k) / 2;
    view.y = (vh - ch * k) / 2 + 12; // leave room for toolbar
    applyViewTransform();
    if (force) hasUserView = false;
  }

  function zoomAt(clientX, clientY, factor, host) {
    const rect = host.getBoundingClientRect();
    const mx = clientX - rect.left;
    const my = clientY - rect.top;
    const prev = view.k;
    const next = Math.min(3, Math.max(0.15, prev * factor));
    if (next === prev) return;
    view.x = mx - (mx - view.x) * (next / prev);
    view.y = my - (my - view.y) * (next / prev);
    view.k = next;
    hasUserView = true;
    applyViewTransform();
  }

  function bindViewport(host) {
    if (!host || host.dataset.panBound === "1") {
      // Re-bind zoom buttons if shell was recreated without clearing flag
      if (host && host.dataset.panBound === "1") {
        wireZoomButtons(host);
      }
      return;
    }
    host.dataset.panBound = "1";
    host.style.cursor = "grab";
    host.tabIndex = 0;

    wireZoomButtons(host);

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
      if (e.target.closest?.(".harness-graph-toolbar")) return;
      if (e.target.closest?.(".harness-zoom-btns")) return;

      const onNode = e.target.closest?.(".harness-node-click");
      // Pan: empty background, or Space+drag, or middle-button-like force on node via Alt
      const wantPan = !onNode || spacePan || e.altKey;
      if (!wantPan) {
        // node click only — no pan start
        return;
      }

      dragging = true;
      dragMoved = false;
      dragStart = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
      try {
        host.setPointerCapture(e.pointerId);
      } catch (_) {}
      host.classList.add("is-panning");
      host.style.cursor = "grabbing";
      e.preventDefault();
    });

    host.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      const dx = e.clientX - dragStart.x;
      const dy = e.clientY - dragStart.y;
      if (Math.hypot(dx, dy) > 3) dragMoved = true;
      view.x = dragStart.vx + dx;
      view.y = dragStart.vy + dy;
      hasUserView = true;
      applyViewTransform();
    });

    const endDrag = (e) => {
      if (!dragging) return;
      dragging = false;
      host.classList.remove("is-panning");
      host.style.cursor = spacePan ? "grab" : "grab";
      if (dragMoved) {
        suppressClick = true;
        setTimeout(() => {
          suppressClick = false;
        }, 50);
      }
      try {
        host.releasePointerCapture(e.pointerId);
      } catch (_) {}
    };
    host.addEventListener("pointerup", endDrag);
    host.addEventListener("pointercancel", endDrag);
    host.addEventListener("lostpointercapture", endDrag);

    // Space to pan over nodes
    window.addEventListener("keydown", (e) => {
      if (e.code === "Space" && !e.repeat && !e.target.matches?.("input,textarea,select")) {
        spacePan = true;
        host.style.cursor = "grab";
      }
    });
    window.addEventListener("keyup", (e) => {
      if (e.code === "Space") {
        spacePan = false;
        if (!dragging) host.style.cursor = "grab";
      }
    });
  }

  function wireZoomButtons(host) {
    const zin = $("#harness-zoom-in");
    const zout = $("#harness-zoom-out");
    const zfit = $("#harness-zoom-fit");
    if (zin && !zin.dataset.bound) {
      zin.dataset.bound = "1";
      zin.addEventListener("click", (e) => {
        e.stopPropagation();
        const r = host.getBoundingClientRect();
        zoomAt(r.left + r.width / 2, r.top + r.height / 2, 1.15, host);
      });
    }
    if (zout && !zout.dataset.bound) {
      zout.dataset.bound = "1";
      zout.addEventListener("click", (e) => {
        e.stopPropagation();
        const r = host.getBoundingClientRect();
        zoomAt(r.left + r.width / 2, r.top + r.height / 2, 1 / 1.15, host);
      });
    }
    if (zfit && !zfit.dataset.bound) {
      zfit.dataset.bound = "1";
      zfit.addEventListener("click", (e) => {
        e.stopPropagation();
        hasUserView = false;
        fitView(host, true);
      });
    }
  }

  function renderGraph(graph) {
    const host = $("#harness-graph");
    if (!host) return;
    lastGraph = graph;
    const useType = typeView && (graph.type_nodes || []).length;
    const nodes = useType ? graph.type_nodes : graph.nodes || [];
    const edges = useType ? graph.type_edges || [] : graph.edges || [];

    if (!nodes.length) {
      shellReady = false;
      host.dataset.panBound = "";
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

    const world = ensureShell(host);
    if (!world) return;

    const edgeSvg = edges
      .map((e) => {
        const a = positions[e.source];
        const b = positions[e.target];
        if (!a || !b) return "";
        const x1 = a.x + (a.w || nodeW);
        const y1 = a.y + (a.h || nodeH) / 2;
        const x2 = b.x;
        const y2 = b.y + (b.h || nodeH) / 2;
        const stroke = edgeColor(e.type);
        const marker =
          e.type === "finding" || e.type === "parent"
            ? "url(#harness-arrow-info)"
            : "url(#harness-arrow)";
        return `<path d="M${x1},${y1} C${x1 + 40},${y1} ${x2 - 40},${y2} ${x2},${y2}" class="harness-edge" data-type="${esc(
          e.type || ""
        )}" style="stroke:${stroke}" marker-end="${marker}" />`;
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
          <title>${esc(n.label || n.id || "")} · ${esc(n.state || "")}</title>
          <rect width="${w}" height="${h}" rx="8" ry="8" fill="var(--panel)" stroke="${fill}" stroke-width="2" />
          <circle cx="12" cy="12" r="4" fill="${fill}" />
          <text x="22" y="16" class="harness-node-kind">${esc(kindLine)}</text>
          <text x="10" y="36" class="harness-node-label">${lineEls}</text>
        </g>`;
      })
      .join("");

    world.innerHTML = `
      <rect class="harness-world-pad" x="-200" y="-200" width="${
        width + 400
      }" height="${height + 400}" fill="transparent" />
      <g class="harness-edges">${edgeSvg}</g>
      <g class="harness-nodes">${nodeSvg}</g>`;

    const meta = $("#harness-graph-meta");
    if (meta) {
      const ec = (graph.edges || []).length;
      const nc = (graph.nodes || []).length;
      meta.textContent = useType
        ? `Type view · ${(graph.type_nodes || []).length} kinds`
        : `${nc} tasks · ${ec} links`;
    }

    if (!hasUserView) {
      fitView(host);
    } else {
      applyViewTransform();
    }

    world.querySelectorAll(".harness-node-click").forEach((g) => {
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
      if (host) {
        shellReady = false;
        host.dataset.panBound = "";
        host.innerHTML = `<p class="empty" style="color:var(--bad)">${esc(
          e.message || e
        )}</p>`;
      }
    }
  }

  function getSelectedLoopProfileId() {
    return selectedProfileId || "default-campaign";
  }

  function activate() {
    if (!activated) {
      activated = true;
      $("#harness-refresh")?.addEventListener("click", () => {
        // Manual refresh keeps view unless Fit was last intent
        refreshGraph();
      });
      $("#harness-loop-select")?.addEventListener("change", (e) => {
        selectedProfileId = e.target.value;
        try {
          localStorage.setItem("vf_loop_profile_id", selectedProfileId);
        } catch (_) {}
        renderLoopDetail();
      });
      $("#harness-type-view")?.addEventListener("change", (e) => {
        typeView = !!e.target.checked;
        hasUserView = false; // re-fit when switching view mode
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
