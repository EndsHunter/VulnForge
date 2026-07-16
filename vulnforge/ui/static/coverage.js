/* VulnForge Coverage mode — residual-risk matrix cockpit */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  let covFilter = "all"; // all | residual | shallow | none | aborted | has_finding
  let covSelected = null; // { area, class }
  let covCache = null;
  let selectFormOpen = false;
  /** @type {{path: string, is_dir: boolean}[]} */
  let customPathTargets = [];
  let pathPickerBrowse = ".";

  const RESIDUAL_DEPTHS = new Set(["", "planned", "shallow", "none", "aborted"]);
  const FINDING_DEPTHS = new Set(["candidate", "confirmed", "needs_human"]);

  function esc(s) {
    if (typeof window.esc === "function") return window.esc(s);
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badge(state) {
    if (typeof window.badge === "function") return window.badge(state);
    return `<span class="badge">${esc(state)}</span>`;
  }

  function toast(msg, err) {
    if (typeof window.toast === "function") window.toast(msg, err);
  }

  function runApiBase() {
    if (typeof window.runApiBase === "function") return window.runApiBase();
    const key = window.currentKey || "";
    const [target_id, run_id] = key.split("/");
    return `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}`;
  }

  function api(path, opts) {
    if (typeof window.api === "function") return window.api(path, opts);
    return fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts?.headers || {}) },
      ...opts,
    }).then(async (res) => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || data.error || res.statusText);
      return data;
    });
  }

  function normDepth(d) {
    return String(d || "").toLowerCase().trim();
  }

  function effectiveDepth(cell) {
    if (!cell) return "";
    return normDepth(cell.last_depth);
  }

  function isResidual(depth) {
    return RESIDUAL_DEPTHS.has(normDepth(depth));
  }

  function isHasFinding(depth) {
    return FINDING_DEPTHS.has(normDepth(depth));
  }

  function covDepthClass(d) {
    const x = normDepth(d);
    if (x === "shallow") return "cov-shallow";
    if (x === "none") return "cov-none";
    if (x === "candidate" || x === "confirmed" || x === "needs_human") return "cov-candidate";
    if (x === "aborted") return "cov-aborted";
    if (x === "planned") return "cov-planned";
    return "cov-empty";
  }

  function cellMatchesFilter(cell, filter) {
    const ftr = (filter || "all").toLowerCase();
    const d = effectiveDepth(cell);
    if (ftr === "all") return true;
    if (ftr === "residual") return isResidual(d);
    if (ftr === "shallow") return d === "shallow";
    if (ftr === "none") return d === "none";
    if (ftr === "aborted") return d === "aborted";
    if (ftr === "has_finding") return isHasFinding(d);
    return true;
  }

  function summaryCounts(cov) {
    const cells = cov?.cells || [];
    const areas = cov?.areas || [];
    const classes = cov?.classes || [];
    const map = cellMap(cov);
    let residual = 0;
    let shallow = 0;
    let none = 0;
    let aborted = 0;
    let hasFinding = 0;
    let empty = 0;
    let planned = 0;
    // Count full matrix (including missing cells as empty residual)
    for (const a of areas) {
      for (const cl of classes) {
        const cell = map[`${a}\0${cl}`];
        const d = cell ? effectiveDepth(cell) : "";
        if (!cell || d === "" || d === "planned") {
          residual++;
          if (!cell || d === "") empty++;
          if (d === "planned") planned++;
        } else if (d === "shallow") {
          residual++;
          shallow++;
        } else if (d === "none") {
          residual++;
          none++;
        } else if (d === "aborted") {
          residual++;
          aborted++;
        } else if (isHasFinding(d)) {
          hasFinding++;
        } else {
          residual++;
        }
      }
    }
    // Prefer cell list totals when matrix empty of area/class axes
    if (!areas.length && !classes.length) {
      for (const c of cells) {
        const d = effectiveDepth(c);
        if (d === "shallow") {
          residual++;
          shallow++;
        } else if (d === "none") {
          residual++;
          none++;
        } else if (d === "aborted") {
          residual++;
          aborted++;
        } else if (isHasFinding(d)) hasFinding++;
        else residual++;
      }
    }
    const total =
      areas.length && classes.length
        ? areas.length * classes.length
        : cells.length || residual + hasFinding;
    return {
      total,
      residual,
      shallow,
      none,
      aborted,
      has_finding: hasFinding,
      empty,
      planned,
    };
  }

  function cellMap(cov) {
    const map = {};
    for (const c of cov?.cells || []) {
      map[`${c.area}\0${c.class}`] = c;
    }
    return map;
  }

  /**
   * Ensure matrix axes include every hunt class/area actually used in this run
   * (task payloads), not only what coverage_facts rolled up — domain packs etc.
   */
  function enrichCoverageAxes(cov, snap) {
    const base = cov && typeof cov === "object" ? cov : { areas: [], classes: [], cells: [] };
    const areas = new Set((base.areas || []).map(String).filter(Boolean));
    const classes = new Set((base.classes || []).map(String).filter(Boolean));
    const cells = [...(base.cells || [])];
    const map = cellMap(base);

    const cat = snap?.hunt_classes || window.__VF_hunt_classes || {};
    const catalogOrder = [
      ...(cat.active || []),
      ...(cat.all || []),
      ...(cat.default || []),
    ];
    const orderIdx = new Map(catalogOrder.map((c, i) => [String(c), i]));

    const tasks = snap?.tasks || window.__VF_last_snap?.tasks || [];
    for (const t of tasks) {
      if ((t.kind || "") !== "hunt") continue;
      const p = t.payload || {};
      const a = String(p.area || "").trim();
      const c = String(p.class || p.attack_class || "").trim();
      if (a) areas.add(a);
      if (c) classes.add(c);
      if (a && c) {
        const key = `${a}\0${c}`;
        if (!map[key]) {
          const cell = {
            area: a,
            class: c,
            visit_count: 0,
            last_depth: "planned",
          };
          map[key] = cell;
          cells.push(cell);
        }
      }
    }

    const sortClasses = (set) =>
      [...set].sort((a, b) => {
        const ia = orderIdx.has(a) ? orderIdx.get(a) : 10_000;
        const ib = orderIdx.has(b) ? orderIdx.get(b) : 10_000;
        return ia - ib || a.localeCompare(b);
      });

    return {
      ...base,
      areas: [...areas].sort((a, b) => a.localeCompare(b)),
      classes: sortClasses(classes),
      cells,
    };
  }

  function residualCells(cov, depths) {
    const want = depths || ["", "planned", "shallow", "aborted"];
    const wantSet = new Set(want.map(normDepth));
    const areas = cov?.areas || [];
    const classes = cov?.classes || [];
    const map = cellMap(cov);
    const out = [];
    for (const a of areas) {
      for (const cl of classes) {
        const cell = map[`${a}\0${cl}`];
        const d = cell ? effectiveDepth(cell) : "";
        if (wantSet.has(d)) {
          out.push({
            area: a,
            class: cl,
            last_depth: d || "empty",
            visit_count: cell?.visit_count || 0,
          });
        }
      }
    }
    return out;
  }

  function depthLabel(d, visits) {
    const x = normDepth(d);
    const name =
      !x || x === "planned"
        ? x === "planned"
          ? "planned"
          : "empty"
        : x;
    const v = Number(visits) || 0;
    if (name === "empty") return { main: "—", sub: "0", full: "No visits yet" };
    return {
      main: name,
      sub: String(v),
      full: `${name} · ${v} visit${v === 1 ? "" : "s"}`,
    };
  }

  function renderLegend() {
    const el = $("#coverage-legend");
    if (!el) return;
    const items = [
      { cls: "cov-empty", label: "Empty / planned", tip: "Not visited or only enqueued" },
      { cls: "cov-shallow", label: "Shallow", tip: "Hunt ended without real read/grep depth" },
      { cls: "cov-none", label: "None", tip: "Honest miss (submit_none) — still not proof of safety" },
      { cls: "cov-aborted", label: "Aborted", tip: "Hunt aborted — re-queue recommended" },
      { cls: "cov-candidate", label: "Has finding", tip: "Candidate / needs_human / confirmed filed" },
    ];
    el.innerHTML = items
      .map(
        (it) =>
          `<span class="cov-legend-item" title="${esc(it.tip)}"><span class="cov-legend-swatch ${it.cls}"></span>${esc(it.label)}</span>`
      )
      .join("");
  }

  function renderSummary(cov) {
    const el = $("#coverage-summary");
    if (!el) return;
    const c = summaryCounts(cov);
    // Only three primary filters — depth breakdown is a hint line, not more tabs
    const allowed = new Set(["all", "residual", "has_finding"]);
    if (!allowed.has((covFilter || "all").toLowerCase())) covFilter = "all";
    const ftr = (covFilter || "all").toLowerCase();
    const active = (key) => (ftr === key ? " active" : "");
    const emptyPlanned = (c.empty || 0) + (c.planned || 0);
    el.innerHTML = `
      <div class="coverage-summary-grid">
        <button type="button" class="stat info stat-link${active("all")}" data-cov-filter="all" title="Show all cells" aria-pressed="${ftr === "all"}">
          <div class="label">All</div><div class="value">${c.total}</div>
        </button>
        <button type="button" class="stat warn stat-link${active("residual")}" data-cov-filter="residual" title="Empty, planned, shallow, none, aborted — work queue" aria-pressed="${ftr === "residual"}">
          <div class="label">Residual</div><div class="value">${c.residual}</div>
        </button>
        <button type="button" class="stat good stat-link${active("has_finding")}" data-cov-filter="has_finding" title="Cells where a finding was filed" aria-pressed="${ftr === "has_finding"}">
          <div class="label">Has finding</div><div class="value">${c.has_finding}</div>
        </button>
      </div>
      <p class="controls-hint coverage-breakdown" title="Breakdown of residual cells (not separate filters)">
        Residual mix:
        empty/planned ${emptyPlanned}
        · shallow ${c.shallow}
        · none ${c.none}
        · aborted ${c.aborted}
      </p>`;
    el.querySelectorAll("[data-cov-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        covFilter = btn.getAttribute("data-cov-filter") || "all";
        paintMatrix();
        renderSummary(covCache);
        renderActions();
      });
    });
  }

  function renderActions() {
    const el = $("#coverage-actions");
    if (!el) return;
    const residual = residualCells(covCache, ["", "planned", "shallow", "aborted"]);
    const withNone = residualCells(covCache, ["", "planned", "shallow", "aborted", "none"]);
    el.innerHTML = `
      <div class="coverage-actions-row">
        <button type="button" class="btn btn-primary" id="cov-bulk-residual" ${residual.length ? "" : "disabled"}
          title="Re-queue empty, planned, shallow, and aborted cells">
          Re-queue residual (${residual.length})
        </button>
        <button type="button" class="btn" id="cov-bulk-residual-none" ${withNone.length ? "" : "disabled"}
          title="Also re-queue honest none cells">
          Include none (${withNone.length})
        </button>
        <span class="controls-hint">Bulk uses existing path hints when available. Ralph must be running to drain the queue.</span>
      </div>`;
    $("#cov-bulk-residual")?.addEventListener("click", () => bulkRequeue(false));
    $("#cov-bulk-residual-none")?.addEventListener("click", () => bulkRequeue(true));
  }

  async function bulkRequeue(includeNone) {
    const depths = includeNone
      ? ["", "planned", "shallow", "aborted", "none"]
      : ["", "planned", "shallow", "aborted"];
    const cells = residualCells(covCache, depths);
    if (!cells.length) {
      toast("No residual cells to re-queue");
      return;
    }
    const label = includeNone
      ? `Re-queue ${cells.length} residual cell(s) including honest none?`
      : `Re-queue ${cells.length} residual cell(s) (empty / planned / shallow / aborted)?`;
    if (!window.confirm(label)) return;
    let ok = 0;
    let fail = 0;
    const notes = "bulk residual re-queue from Coverage";
    for (const cell of cells) {
      try {
        await api(`${runApiBase()}/coverage/requeue`, {
          method: "POST",
          body: JSON.stringify({
            area: cell.area,
            class: cell.class,
            force_depth: true,
            reason: "operator_bulk_residual",
            operator_notes: notes,
          }),
        });
        ok++;
      } catch {
        fail++;
      }
    }
    toast(
      fail
        ? `Re-queued ${ok}; ${fail} failed`
        : `Re-queued ${ok} hunt(s)`,
      fail > 0
    );
    if (typeof window.loadRunFull === "function") await window.loadRunFull();
  }

  function knownAreas() {
    const fromCov = covCache?.areas || [];
    const snap = window.__VF_last_snap || {};
    const arch = snap.architecture || {};
    const fromArch = [];
    const parts = arch.partitions || arch.areas || [];
    if (Array.isArray(parts)) {
      for (const p of parts) {
        if (typeof p === "string") fromArch.push(p);
        else if (p && (p.name || p.area)) fromArch.push(p.name || p.area);
      }
    }
    const comps = snap.architecture_summary?.components || arch.components || [];
    if (Array.isArray(comps)) {
      for (const c of comps) {
        if (typeof c === "string") fromArch.push(c);
        else if (c && (c.name || c.id)) fromArch.push(c.name || c.id);
      }
    }
    return [...new Set([...fromCov, ...fromArch].map(String).filter(Boolean))].sort();
  }

  function knownClasses() {
    const catalog = window.__VF_hunt_classes || {};
    const fromCat = [
      ...(catalog.active || []),
      ...(catalog.all || []),
      ...(catalog.default || []),
    ];
    const fromCov = covCache?.classes || [];
    const pol = window.__VF_cov_policy?.classes || [];
    return [...new Set([...fromCat, ...fromCov, ...pol].map(String).filter(Boolean))];
  }

  function activeClassesList() {
    const cat = window.__VF_hunt_classes || {};
    if (Array.isArray(cat.active) && cat.active.length) return cat.active.map(String);
    if (Array.isArray(cat.default) && cat.default.length) return cat.default.map(String);
    return knownClasses();
  }

  /** Operator run.max_tasks ceiling (Coverage estimates / confirm dialogs). */
  function maxTasksCap() {
    const snap = window.__VF_last_snap;
    const n = Number(
      window.__VF_max_tasks ??
        snap?.run?.max_tasks ??
        snap?.max_tasks ??
        snap?.config?.run?.max_tasks ??
        50
    );
    return Math.max(1, Number.isFinite(n) && n > 0 ? n : 50);
  }

  function modeStatusCopy(mode, policy) {
    const p = policy || {};
    const cap = maxTasksCap();
    if (mode === "all") {
      return {
        badge: "all",
        title: "Bulk: all architecture areas",
        detail:
          `Last action filled the queue with active hunt skills × known areas (capped at ${cap}). Ralph drains those hunts while it runs.`,
      };
    }
    if (mode === "select") {
      const nA = (p.areas || []).length;
      const nC = (p.classes || []).length;
      const areaHint = nA
        ? `${nA} area${nA === 1 ? "" : "s"}`
        : "architecture areas";
      const classHint = nC
        ? `${nC} class${nC === 1 ? "" : "es"}`
        : "active classes";
      return {
        badge: "custom",
        title: "Custom enqueue",
        detail: `Last custom queue used ${areaHint} × ${classHint}. Open the builder below to queue another batch.`,
      };
    }
    return {
      badge: "recon",
      title: "Following recon plan",
      detail:
        "No bulk override. Recon and residual re-queues decide what gets hunted. Use the buttons only when you want to flood the queue yourself.",
    };
  }

  function estimateAllAreasJobs() {
    const nAreas = Math.max(knownAreas().length, 1);
    const nCore = activeClassesList().length || 5;
    const raw = nAreas * nCore;
    const cap = maxTasksCap();
    return { raw, capped: Math.min(raw, cap), nAreas, nCore, cap };
  }

  function joinPath(base, name) {
    const b = (base || ".").replace(/\\/g, "/");
    if (!b || b === ".") return name;
    return `${b.replace(/\/$/, "")}/${name}`;
  }

  function parentPath(path) {
    const p = (path || ".").replace(/\\/g, "/");
    if (!p || p === ".") return ".";
    const parts = p.split("/").filter(Boolean);
    parts.pop();
    return parts.length ? parts.join("/") : ".";
  }

  function pathPickerBreadcrumb(path) {
    const p = (path || ".").replace(/\\/g, "/");
    const parts = !p || p === "." ? [] : p.split("/").filter(Boolean);
    let acc = [];
    let html = `<button type="button" class="bc-seg cov-picker-bc" data-ppath="." title="Target root">target</button>`;
    for (const seg of parts) {
      acc.push(seg);
      const full = acc.join("/");
      html += `<span class="bc-sep">/</span><button type="button" class="bc-seg cov-picker-bc" data-ppath="${esc(full)}">${esc(seg)}</button>`;
    }
    return html;
  }

  function addPathTarget(path, isDir) {
    const rel = String(path || "").replace(/\\/g, "/").replace(/^\//, "");
    if (!rel || rel === ".") {
      // Allow targeting root as a folder
      if (!customPathTargets.some((t) => t.path === "." && t.is_dir)) {
        customPathTargets.push({ path: ".", is_dir: true });
      }
      return;
    }
    if (customPathTargets.some((t) => t.path === rel)) return;
    customPathTargets.push({ path: rel, is_dir: !!isDir });
  }

  function removePathTarget(path) {
    customPathTargets = customPathTargets.filter((t) => t.path !== path);
  }

  function renderPathTargetChips() {
    const box = $("#cov-path-targets");
    if (!box) return;
    if (!customPathTargets.length) {
      box.innerHTML = `<span class="controls-hint">No path targets yet — browse below and click <strong>Add folder</strong> or <strong>Add file</strong>.</span>`;
      return;
    }
    box.innerHTML = customPathTargets
      .map(
        (t) =>
          `<span class="cov-path-chip-item" title="${esc(t.is_dir ? "Folder" : "File")}: ${esc(t.path)}">
            <span class="mono">${esc(t.path === "." ? "target root" : t.path)}</span>
            <span class="controls-hint">${t.is_dir ? "folder" : "file"}</span>
            <button type="button" class="btn btn-ghost btn-sm cov-path-remove" data-rm-path="${esc(t.path)}" title="Remove">×</button>
          </span>`
      )
      .join("");
    box.querySelectorAll(".cov-path-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        removePathTarget(btn.getAttribute("data-rm-path"));
        renderPathTargetChips();
        updateSelectEstimate();
      });
    });
  }

  async function loadPathPicker(el) {
    const list = $("#cov-path-picker-list");
    const crumb = $("#cov-path-picker-bc");
    if (!list) return;
    if (crumb) crumb.innerHTML = pathPickerBreadcrumb(pathPickerBrowse);
    list.innerHTML = `<div class="controls-hint" style="padding:0.4rem">Loading…</div>`;
    try {
      const data = await api(
        `${runApiBase()}/target/list?path=${encodeURIComponent(pathPickerBrowse || ".")}&max_entries=200`
      );
      if (!data.ok) {
        list.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(data.error || "list failed")}</div>`;
        return;
      }
      const entries = data.entries || [];
      if (!entries.length) {
        list.innerHTML = `<div class="controls-hint" style="padding:0.4rem">Empty folder</div>`;
      } else {
        list.innerHTML = entries
          .map((e) => {
            const full = joinPath(pathPickerBrowse, e.name);
            const isDir = !!e.is_dir;
            return `<div class="cov-picker-row">
              <button type="button" class="cov-picker-name mono ${isDir ? "is-dir" : "is-file"}" data-open-path="${esc(full)}" data-is-dir="${isDir ? "1" : "0"}" title="${esc(full)}">
                ${isDir ? "📁" : "📄"} ${esc(e.name)}
              </button>
              <button type="button" class="btn btn-sm cov-picker-add" data-add-path="${esc(full)}" data-is-dir="${isDir ? "1" : "0"}">
                ${isDir ? "Add folder" : "Add file"}
              </button>
            </div>`;
          })
          .join("");
      }
      // Bind once on container via event delegation if needed — rebind after each load
      list.querySelectorAll("[data-open-path]").forEach((btn) => {
        btn.addEventListener("click", () => {
          if (btn.getAttribute("data-is-dir") === "1") {
            pathPickerBrowse = btn.getAttribute("data-open-path") || ".";
            loadPathPicker(el);
          }
        });
      });
      list.querySelectorAll("[data-add-path]").forEach((btn) => {
        btn.addEventListener("click", () => {
          addPathTarget(
            btn.getAttribute("data-add-path"),
            btn.getAttribute("data-is-dir") === "1"
          );
          renderPathTargetChips();
          updateSelectEstimate();
          toast(`Added ${btn.getAttribute("data-add-path")}`);
        });
      });
      crumb?.querySelectorAll(".cov-picker-bc").forEach((btn) => {
        btn.addEventListener("click", () => {
          pathPickerBrowse = btn.getAttribute("data-ppath") || ".";
          loadPathPicker(el);
        });
      });
    } catch (e) {
      list.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message || e)}</div>`;
    }
  }

  function countSelectAreas(el) {
    const named = el.querySelectorAll("[data-cov-area]:checked").length;
    const extra = ($("#cov-extra-areas")?.value || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean).length;
    const paths = customPathTargets.length;
    const total = named + extra + paths;
    if (total > 0) return total;
    return knownAreas().length || 1;
  }

  function updateSelectEstimate() {
    const estEl = $("#cov-select-estimate");
    const form = $("#cov-select-form");
    if (!estEl || !form) return;
    const nA = countSelectAreas(form.closest(".cov-plan-card") || document);
    const nC = form.querySelectorAll("[data-cov-class]:checked").length || 0;
    const raw = nA * nC;
    const cap = maxTasksCap();
    const capped = Math.min(raw, cap);
    const pathN = customPathTargets.length;
    estEl.textContent = nC
      ? `About ${capped} hunt${capped === 1 ? "" : "s"} will be queued` +
        (pathN ? ` (${pathN} path target${pathN === 1 ? "" : "s"})` : "") +
        (raw > cap ? ` (capped at ${cap})` : "") +
        "."
      : "Select at least one hunt class.";
  }

  function renderModeBar(policy) {
    const el = $("#coverage-mode-bar");
    if (!el) return;
    const p = policy || window.__VF_cov_policy || { mode: "auto", areas: [], classes: [] };
    const mode = p.mode || "auto";
    const status = modeStatusCopy(mode, p);
    const est = estimateAllAreasJobs();

    // Restore path targets from policy when opening form first time
    if (selectFormOpen && !customPathTargets.length && (p.path_targets || []).length) {
      customPathTargets = (p.path_targets || [])
        .filter((t) => t && t.path)
        .map((t) => ({ path: String(t.path), is_dir: !!t.is_dir }));
    }

    const areas = knownAreas();
    const classes = knownClasses();
    const activeClasses = activeClassesList();
    const pathSet = new Set(customPathTargets.map((t) => t.path));
    const selAreas = new Set(
      (p.areas || []).map(String).filter((a) => !pathSet.has(a))
    );
    const selClasses = new Set((p.classes || []).map(String));
    if (!selClasses.size && activeClasses.length) {
      for (const c of activeClasses) selClasses.add(c);
    }

    const areaChecks = areas.length
      ? areas
          .filter((a) => !pathSet.has(a))
          .map(
            (a) =>
              `<label class="cov-check"><input type="checkbox" data-cov-area value="${esc(a)}" ${selAreas.has(a) ? "checked" : ""}/> <span class="mono">${esc(a)}</span></label>`
          )
          .join("")
      : `<span class="controls-hint">No architecture areas yet — use the path picker or type names.</span>`;

    const classBlock = (title, list) => {
      if (!list.length) return "";
      const checks = list
        .map(
          (c) =>
            `<label class="cov-check"><input type="checkbox" data-cov-class value="${esc(c)}" ${selClasses.has(c) ? "checked" : ""}/> <span class="mono">${esc(c)}</span></label>`
        )
        .join("");
      return `<div class="cov-class-group"><div class="cov-select-subhead">${esc(title)}</div><div class="cov-check-grid cov-check-grid-sm">${checks}</div></div>`;
    };

    const optionalList = classes.filter((c) => !activeClasses.includes(c));
    const classGroups =
      classBlock("Active skills", activeClasses) +
      classBlock("Optional skills", optionalList);

    el.innerHTML = `
      <div class="cov-plan-card">
        <div class="cov-plan-head">
          <div>
            <div class="cov-plan-kicker">Hunt planning</div>
            <div class="cov-plan-status">
              <span class="cov-plan-badge cov-plan-badge-${esc(status.badge)}">${esc(status.title)}</span>
            </div>
            <p class="controls-hint cov-plan-detail">${esc(status.detail)}</p>
          </div>
        </div>

        <div class="cov-plan-actions" role="group" aria-label="Queue more hunts">
          <button type="button" class="cov-plan-action ${mode === "auto" && !selectFormOpen ? "is-current" : ""}" data-cov-mode="auto" id="cov-plan-auto">
            <span class="cov-plan-action-title">Follow recon only</span>
            <span class="cov-plan-action-desc">Clear bulk override. Do not enqueue a new batch — leave planning to recon and cell re-queues.</span>
          </button>
          <button type="button" class="cov-plan-action ${mode === "all" && !selectFormOpen ? "is-current" : ""}" data-cov-mode="all" id="cov-plan-all">
            <span class="cov-plan-action-title">Cover all areas (active)</span>
            <span class="cov-plan-action-desc">Queue about ${est.capped} hunt${est.capped === 1 ? "" : "s"}: ${est.nCore} active skills × ${est.nAreas} area${est.nAreas === 1 ? "" : "s"}${est.raw > est.cap ? ` (capped at ${est.cap})` : ""}. Starts work immediately if Ralph is running.</span>
          </button>
          <button type="button" class="cov-plan-action ${selectFormOpen || mode === "select" ? "is-current" : ""}" data-cov-mode="select" id="cov-plan-custom">
            <span class="cov-plan-action-title">Custom areas &amp; classes…</span>
            <span class="cov-plan-action-desc">Pick architecture areas and/or folders/files from the target tree, then choose hunt classes.</span>
          </button>
        </div>

        ${
          selectFormOpen
            ? `<div class="cov-select-form" id="cov-select-form">
                <div class="cov-select-form-title">Custom hunt queue</div>
                <p class="controls-hint" style="margin:0 0 0.65rem">
                  Combine architecture areas and <strong>path targets</strong> (folder or file) with hunt classes.
                  Path targets seed path hints from that location. Cap is ${maxTasksCap()} hunts per batch (run.max_tasks).
                </p>

                <div class="cov-select-heading">Path targets (from target tree)</div>
                <div id="cov-path-targets" class="cov-path-targets"></div>
                <div class="cov-path-picker" id="cov-path-picker">
                  <div class="cov-path-picker-toolbar">
                    <div id="cov-path-picker-bc" class="cov-path-picker-bc"></div>
                    <div class="cov-path-picker-btns">
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-picker-up">Up</button>
                      <button type="button" class="btn btn-sm" id="cov-picker-add-cwd" title="Use the folder you are browsing as an area">Add this folder</button>
                    </div>
                  </div>
                  <div id="cov-path-picker-list" class="cov-path-picker-list"></div>
                </div>

                <div class="cov-select-cols" style="margin-top:0.85rem">
                  <div>
                    <div class="cov-select-heading">Architecture areas</div>
                    <div class="cov-check-grid">${areaChecks}</div>
                    <label class="field-label" style="margin-top:0.5rem"><span class="label-text">Extra named areas (comma-separated)</span></label>
                    <input type="text" id="cov-extra-areas" class="cov-text-input" placeholder="e.g. api, worker" />
                    <div class="cov-select-quick">
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-areas-all">Select all areas</button>
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-areas-none">Clear areas</button>
                    </div>
                  </div>
                  <div>
                    <div class="cov-select-heading">Hunt classes</div>
                    ${classGroups || `<span class="controls-hint">No catalog</span>`}
                    <div class="cov-select-quick">
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-classes-core">Active only</button>
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-classes-all">All classes</button>
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-classes-none">Clear</button>
                    </div>
                  </div>
                </div>
                <div class="cov-select-actions">
                  <button type="button" class="btn btn-primary" id="cov-select-enqueue">Queue selected hunts</button>
                  <button type="button" class="btn" id="cov-select-cancel">Close</button>
                  <span class="controls-hint" id="cov-select-estimate"></span>
                </div>
              </div>`
            : ""
        }
      </div>`;

    const setChecks = (selector, on) => {
      el.querySelectorAll(selector).forEach((inp) => {
        inp.checked = !!on;
      });
      updateSelectEstimate();
    };

    el.querySelectorAll("[data-cov-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const m = btn.getAttribute("data-cov-mode");
        if (m === "select") {
          selectFormOpen = true;
          renderModeBar(p);
          return;
        }
        if (m === "all") {
          const e = estimateAllAreasJobs();
          if (
            !window.confirm(
              `Queue about ${e.capped} hunt(s)?\n\n` +
                `${e.nCore} core classes × ${e.nAreas} areas` +
                (e.raw > e.cap ? ` (capped at ${e.cap})` : "") +
                ".\n\nRalph must be running to work the queue."
            )
          ) {
            return;
          }
        }
        if (m === "auto" && mode !== "auto") {
          if (
            !window.confirm(
              "Switch back to following the recon plan only?\n\nThis does not cancel hunts already in the queue."
            )
          ) {
            return;
          }
        }
        selectFormOpen = false;
        applyCoverageMode(m);
      });
    });

    $("#cov-select-cancel")?.addEventListener("click", () => {
      selectFormOpen = false;
      renderModeBar(p);
    });
    $("#cov-areas-all")?.addEventListener("click", () => setChecks("[data-cov-area]", true));
    $("#cov-areas-none")?.addEventListener("click", () => setChecks("[data-cov-area]", false));
    $("#cov-classes-core")?.addEventListener("click", () => {
      el.querySelectorAll("[data-cov-class]").forEach((inp) => {
        inp.checked = activeClasses.includes(inp.value);
      });
      updateSelectEstimate();
    });
    $("#cov-classes-all")?.addEventListener("click", () => setChecks("[data-cov-class]", true));
    $("#cov-classes-none")?.addEventListener("click", () => setChecks("[data-cov-class]", false));
    el.querySelectorAll("[data-cov-area], [data-cov-class]").forEach((inp) => {
      inp.addEventListener("change", updateSelectEstimate);
    });
    $("#cov-extra-areas")?.addEventListener("input", updateSelectEstimate);

    if (selectFormOpen) {
      renderPathTargetChips();
      loadPathPicker(el);
      $("#cov-picker-up")?.addEventListener("click", () => {
        pathPickerBrowse = parentPath(pathPickerBrowse);
        loadPathPicker(el);
      });
      $("#cov-picker-add-cwd")?.addEventListener("click", () => {
        addPathTarget(pathPickerBrowse || ".", true);
        renderPathTargetChips();
        updateSelectEstimate();
        toast(
          `Added folder ${pathPickerBrowse === "." ? "target root" : pathPickerBrowse}`
        );
      });
      updateSelectEstimate();
    }

    $("#cov-select-enqueue")?.addEventListener("click", () => {
      const pickedAreas = [...el.querySelectorAll("[data-cov-area]:checked")].map(
        (i) => i.value
      );
      const extra = ($("#cov-extra-areas")?.value || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const pickedClasses = [...el.querySelectorAll("[data-cov-class]:checked")].map(
        (i) => i.value
      );
      const pathTargets = customPathTargets.map((t) => ({
        path: t.path,
        is_dir: !!t.is_dir,
      }));
      if (!pickedClasses.length) {
        toast("Pick at least one hunt class", true);
        return;
      }
      const nA =
        pickedAreas.length + extra.length + pathTargets.length ||
        knownAreas().length ||
        1;
      const raw = nA * pickedClasses.length;
      const cap = maxTasksCap();
      const capped = Math.min(raw, cap);
      const pathNote = pathTargets.length
        ? `\nPath targets: ${pathTargets.map((t) => t.path).join(", ")}`
        : "";
      if (
        !window.confirm(
          `Queue about ${capped} hunt(s) for your selection?` +
            (raw > cap ? ` (capped at ${cap})` : "") +
            pathNote
        )
      ) {
        return;
      }
      applyCoverageMode(
        "select",
        [...new Set([...pickedAreas, ...extra])],
        pickedClasses,
        pathTargets
      );
    });
  }

  async function applyCoverageMode(mode, areas, classes, pathTargets) {
    try {
      const body = { mode, enqueue: mode !== "auto" };
      if (mode === "select") {
        body.areas = areas || [];
        body.classes = classes || [];
        body.path_targets = pathTargets || customPathTargets || [];
      }
      const r = await api(`${runApiBase()}/coverage/mode`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      toast(
        mode === "auto"
          ? "Now following recon plan only"
          : `Queued ${r.enqueued_count || 0} hunt(s)`
      );
      window.__VF_cov_policy = r.policy;
      selectFormOpen = false;
      // keep path targets for next custom open if policy stored them
      if (mode === "select" && (r.path_targets || []).length) {
        customPathTargets = r.path_targets.map((t) => ({
          path: String(t.path),
          is_dir: !!t.is_dir,
        }));
      }
      renderModeBar(r.policy);
      if (typeof window.loadRunFull === "function") await window.loadRunFull();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function renderMatrixHtml(cov, opts = {}) {
    const interactive = opts.interactive !== false;
    const filter = opts.filter || "all";
    const selected = opts.selected || null;
    const snap = opts.snap || window.__VF_last_snap;
    cov = enrichCoverageAxes(cov, snap);

    if (!cov || (!(cov.cells || []).length && !(cov.areas || []).length)) {
      return `<div class="empty" style="padding:1rem">No coverage facts yet — appear after recon enqueues hunts.</div>`;
    }
    const areas = cov.areas || [];
    const classes = cov.classes || [];
    const map = cellMap(cov);
    if (!areas.length || !classes.length) {
      return `<div class="empty" style="padding:1rem">Coverage axes empty — wait for recon plan.</div>`;
    }

    const classLink = (c) =>
      `<a class="cov-class-link mono" href="/dev#hunt/${encodeURIComponent(c)}" target="_blank" rel="noopener">${esc(c)}</a>`;

    const classCaption = `<div class="coverage-class-caption controls-hint">
      <strong>${areas.length}</strong> areas × <strong>${classes.length}</strong> classes:
      ${classes.map((c) => `<span class="cov-class-pill">${classLink(c)}</span>`).join(" ")}
    </div>`;

    const head =
      `<tr><th class="row-head">Area \\ class</th>` +
      classes.map((c) => `<th title="${esc(c)}">${classLink(c)}</th>`).join("") +
      `</tr>`;

    const rows = areas
      .map((a) => {
        const cells = classes
          .map((cl) => {
            const cell = map[`${a}\0${cl}`] || {
              area: a,
              class: cl,
              last_depth: "",
              visit_count: 0,
            };
            const d = effectiveDepth(cell);
            const match = cellMatchesFilter(cell, filter);
            const dim = filter !== "all" && !match ? " cov-dim" : "";
            const sel =
              selected &&
              selected.area === a &&
              selected.class === cl
                ? " cov-selected"
                : "";
            const cls = covDepthClass(d);
            const lab = depthLabel(d, cell.visit_count);
            const tip = esc(
              (cell.depth_blurb || lab.full) + (match ? "" : " · hidden by filter")
            );
            if (!interactive) {
              return `<td class="${dim}"><span class="cov-cell ${cls}" title="${tip}"><span class="cov-main">${esc(lab.main)}</span><span class="cov-sub">${esc(lab.sub)}</span></span></td>`;
            }
            return `<td class="${dim}"><button type="button" class="cov-cell ${cls} cov-click${sel}" data-area="${esc(a)}" data-class="${esc(cl)}" title="${tip}"><span class="cov-main">${esc(lab.main)}</span><span class="cov-sub">${esc(lab.sub)}</span></button></td>`;
          })
          .join("");
        return `<tr><td class="row-head mono" title="${esc(a)}">${esc(a)}</td>${cells}</tr>`;
      })
      .join("");

    return `${classCaption}
      <div class="coverage-wrap"><table class="coverage-grid">${head}${rows}</table></div>
      <p class="controls-hint" style="margin-top:0.5rem">
        Click a cell for reasons and re-queue. Dimmed cells are outside the active filter.
        Scroll horizontally when many hunt classes are in play.
      </p>`;
  }

  function paintMatrix() {
    const panel = $("#coverage-panel");
    if (!panel || !covCache) return;
    covCache = enrichCoverageAxes(covCache, window.__VF_last_snap);
    panel.innerHTML = renderMatrixHtml(covCache, {
      interactive: true,
      filter: covFilter,
      selected: covSelected,
      snap: window.__VF_last_snap,
    });
    panel.querySelectorAll(".cov-click").forEach((btn) => {
      btn.addEventListener("click", () => {
        openCell(btn.getAttribute("data-area"), btn.getAttribute("data-class"));
      });
    });
  }

  function taskResultSummary(t) {
    const res = t.result || {};
    if (res.finding_id) return `filed #${res.finding_id}`;
    if (res.none_found) return `none: ${res.reason || "submit_none"}${res.shallow ? " (shallow)" : ""}`;
    if (res.error) return String(res.error);
    if (res.aborted_scope) return "aborted_scope";
    if (t.state === "queued") return "queued";
    if (t.state === "leased") return "running";
    if (t.state === "done") return "done";
    return t.state || "";
  }

  async function openCell(area, cls) {
    const detail = $("#coverage-detail");
    if (!detail) return;
    covSelected = { area, class: cls };
    paintMatrix();
    detail.hidden = false;
    detail.innerHTML = `<div class="empty">Loading <span class="mono">${esc(area)}</span> × <span class="mono">${esc(cls)}</span>…</div>`;
    try {
      const data = await api(
        `${runApiBase()}/coverage/cell?area=${encodeURIComponent(area)}&class=${encodeURIComponent(cls)}`
      );
      const d = normDepth(data.last_depth);
      const lab = depthLabel(d, data.visit_count);
      const reasons = (data.reasons || [])
        .map((r) => `<li>${esc(r)}</li>`)
        .join("");
      const paths = (data.path_hints || [])
        .map(
          (p) =>
            `<button type="button" class="path-chip cov-path-chip" data-path="${esc(p)}" title="Open in Explorer">${esc(p)}</button>`
        )
        .join("");
      const tasks = (data.tasks || [])
        .slice()
        .reverse()
        .slice(0, 10)
        .map((t) => {
          const sum = taskResultSummary(t);
          const hasT = !!t.has_transcript;
          const queued = String(t.state || "").toLowerCase() === "queued";
          return `<li class="cov-task-row">
            <span class="mono">#${t.id}</span> ${badge(t.state)}
            <span class="controls-hint">${esc(sum)}</span>
            ${
              hasT
                ? ""
                : t.id
                  ? `<button type="button" class="btn btn-ghost btn-sm cov-open-task" data-tid="${t.id}">Tasks</button>`
                  : ""
            }
            ${
              queued
                ? `<button type="button" class="btn btn-sm btn-bad cov-cancel-task" data-tid="${t.id}" title="Remove from queue">Remove</button>`
                : ""
            }
          </li>`;
        })
        .join("");
      const findings = (data.findings || [])
        .map((f) => {
          const title = f.title || f.stable_key || `Finding #${f.id}`;
          return `<li class="cov-finding-row">
            ${badge(f.state)}
            <button type="button" class="btn btn-ghost btn-sm cov-open-finding" data-fid="${f.id}">#${f.id} ${esc(title)}</button>
            ${
              f.evidence_id
                ? `<button type="button" class="btn btn-ghost btn-sm cov-open-ev" data-pack="${esc(String(f.evidence_id))}">Evidence</button>`
                : ""
            }
          </li>`;
        })
        .join("");

      detail.innerHTML = `
        <div class="coverage-detail-head">
          <div>
            <div class="cov-detail-title">
              <strong class="mono">${esc(area)}</strong>
              <span class="cov-times">×</span>
              <strong class="mono">${esc(cls)}</strong>
              <a class="cov-class-link controls-hint" href="/dev#hunt/${encodeURIComponent(cls)}" target="_blank" rel="noopener" style="margin-left:0.5rem;font-weight:500">Open in Dev</a>
            </div>
            <div class="cov-detail-meta">
              <span class="cov-cell ${covDepthClass(d)}" style="display:inline-flex;width:auto;padding:0.15rem 0.5rem">${esc(lab.main)}</span>
              <span class="controls-hint">${esc(lab.full)}</span>
            </div>
          </div>
          <div class="toolbar">
            <button type="button" class="btn btn-primary" id="cov-requeue">Re-queue hunt</button>
            <button type="button" class="btn" id="cov-detail-close">Close</button>
          </div>
        </div>
        <p class="depth-blurb">${esc(data.depth_blurb || "")}</p>
        <div class="field" style="margin:0.65rem 0">
          <label for="cov-op-notes"><span class="label-text">Notes for re-queue (optional)</span></label>
          <textarea id="cov-op-notes" class="op-notes" rows="3" placeholder="e.g. Focus on auth middleware; prior hunt missed rate limits."></textarea>
        </div>
        <h3>Why this depth</h3>
        <ul class="reason-list">${reasons || "<li class='controls-hint'>No detail</li>"}</ul>
        <h3>Path hints</h3>
        <div class="cov-path-chips">${paths || "<span class='controls-hint'>None stored</span>"}</div>
        <h3>Related hunts</h3>
        <ul class="task-mini cov-task-list">${tasks || "<li class='controls-hint'>No hunt tasks for this cell</li>"}</ul>
        <h3>Findings</h3>
        <ul class="cov-finding-list">${findings || "<li class='controls-hint'>None linked to this class</li>"}</ul>`;

      $("#cov-detail-close")?.addEventListener("click", () => {
        detail.hidden = true;
        covSelected = null;
        paintMatrix();
      });
      $("#cov-requeue")?.addEventListener("click", async () => {
        try {
          const operator_notes = ($("#cov-op-notes")?.value || "").trim();
          const r = await api(`${runApiBase()}/coverage/requeue`, {
            method: "POST",
            body: JSON.stringify({
              area,
              class: cls,
              path_hints: data.path_hints || [],
              force_depth: true,
              reason: "operator_requeue_ui",
              operator_notes,
            }),
          });
          toast(`Re-queued hunt task #${r.task_id}`);
          if (typeof window.loadRunFull === "function") await window.loadRunFull();
          openCell(area, cls);
        } catch (e) {
          toast(e.message || String(e), true);
        }
      });
      detail.querySelectorAll(".cov-path-chip").forEach((btn) => {
        btn.addEventListener("click", () => {
          const path = btn.getAttribute("data-path");
          if (window.VulnForgeModes?.goExplorer) {
            window.VulnForgeModes.goExplorer(path);
          } else if (window.VulnForgeExplorer?.reveal) {
            window.VulnForgeModes?.setMode?.("explorer");
            window.VulnForgeExplorer.reveal(path);
          }
        });
      });
      detail.querySelectorAll(".cov-open-finding").forEach((btn) => {
        btn.addEventListener("click", () => {
          const fid = btn.getAttribute("data-fid");
          window.VulnForgeModes?.setMode?.("report", "report");
          if (window.VulnForgeReport?.openFinding) {
            window.VulnForgeReport.openFinding(fid);
          } else {
            window.VulnForgeReport?.setFilter?.("all");
          }
        });
      });
      detail.querySelectorAll(".cov-open-ev").forEach((btn) => {
        btn.addEventListener("click", () => {
          const pack = btn.getAttribute("data-pack");
          window.VulnForgeModes?.goEvidence?.(pack);
        });
      });
      detail.querySelectorAll(".cov-open-task").forEach((btn) => {
        btn.addEventListener("click", () => {
          window.VulnForgeModes?.setMode?.("audit", "tasks");
          // Best-effort: highlight task if UI supports it later
          const tid = btn.getAttribute("data-tid");
          if (tid && typeof window.openTranscript === "function") {
            try {
              window.openTranscript(Number(tid));
            } catch {
              /* ignore */
            }
          }
        });
      });
      detail.querySelectorAll(".cov-cancel-task").forEach((btn) => {
        btn.addEventListener("click", async (ev) => {
          ev.stopPropagation();
          const tid = btn.getAttribute("data-tid");
          if (!tid || typeof window.cancelQueuedTask !== "function") return;
          const r = await window.cancelQueuedTask(tid);
          if (r && r.ok !== false) {
            openCell(area, cls);
          }
        });
      });
    } catch (e) {
      detail.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message || e)}</div>`;
    }
  }

  /**
   * Mission overview mini matrix (non-interactive).
   */
  function renderPreviewHtml(cov) {
    return renderMatrixHtml(cov, { interactive: false, filter: "all" });
  }

  /**
   * Full Coverage mode paint from snapshot.
   */
  function renderCoverage(snap) {
    if (!$("#coverage-panel") && !$("#coverage-summary")) return;
    window.__VF_cov_policy = snap?.coverage_policy || window.__VF_cov_policy;
    window.__VF_hunt_classes = snap?.hunt_classes || window.__VF_hunt_classes;
    const mt =
      snap?.max_tasks ??
      snap?.run?.max_tasks ??
      (snap?.config && snap.config.run && snap.config.run.max_tasks);
    if (mt != null && Number(mt) > 0) {
      window.__VF_max_tasks = Math.max(1, Number(mt));
    }
    covCache = enrichCoverageAxes(snap?.coverage || covCache, snap);

    renderLegend();
    renderSummary(covCache);
    renderModeBar(window.__VF_cov_policy);
    renderActions();
    paintMatrix();
    // Keep selection highlight; detail panel is user-driven (avoids wiping notes on refresh)
  }

  function setFilter(next) {
    covFilter = next || "all";
    if (covCache) {
      renderSummary(covCache);
      paintMatrix();
      renderActions();
    }
  }

  window.VulnForgeCoverage = {
    render: renderCoverage,
    renderPreviewHtml,
    setFilter,
    openCell,
    covDepthClass,
  };
  // Back-compat for app.js mission preview / older hooks
  window.renderCoverageHtml = function (cov, opts) {
    if (opts && opts.interactive === false) return renderPreviewHtml(cov);
    return renderMatrixHtml(cov, {
      interactive: opts?.interactive !== false,
      filter: covFilter,
      selected: covSelected,
    });
  };
  window.renderCoverageModeBar = renderModeBar;
  window.bindCoverageClicks = function (root) {
    (root || document).querySelectorAll(".cov-click").forEach((btn) => {
      btn.addEventListener("click", () => {
        openCell(btn.getAttribute("data-area"), btn.getAttribute("data-class"));
      });
    });
  };
  window.openCoverageCell = openCell;
  window.covDepthClass = covDepthClass;
})();
