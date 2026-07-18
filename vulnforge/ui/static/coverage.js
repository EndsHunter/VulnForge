/* VulnForge Coverage mode — residual-risk matrix cockpit */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  let covFilter = "all"; // all | residual | shallow | none | aborted | has_finding
  let covSelected = null; // { area, class }
  let covCache = null;
  let selectFormOpen = false;
  let maxHuntFormOpen = false;
  /** @type {{path: string, is_dir: boolean}[]} */
  let customPathTargets = [];
  /** Path targets for MAX Hunt (separate from custom queue picker). */
  /** @type {{path: string, is_dir: boolean}[]} */
  let maxHuntPathTargets = [];
  let pathPickerBrowse = ".";
  let maxPathPickerBrowse = ".";
  /** Draft fields preserved across MAX Hunt form re-renders / browse. */
  let maxHuntFormState = {
    scope: "all",
    maxFiles: null,
    activate: false,
    notes: "",
  };
  /** @type {object|null} last MAX Hunt dry-run preview */
  let maxHuntPreview = null;

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
   * Ensure matrix axes include every hunt skill/area actually used in this run
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
    // Full hunt skill catalog (all registered — seed, custom, generated, import)
    const catalog = window.__VF_hunt_classes || {};
    const fromCat = [
      ...(catalog.active || []),
      ...(catalog.all || []),
      ...(catalog.default || []),
    ];
    const fromProfiles = Array.isArray(catalog.profiles)
      ? catalog.profiles.map((p) => (p && p.id) || "").filter(Boolean)
      : [];
    const fromCov = covCache?.classes || [];
    const pol = window.__VF_cov_policy?.classes || [];
    return [
      ...new Set(
        [...fromCat, ...fromProfiles, ...fromCov, ...pol].map(String).filter(Boolean)
      ),
    ];
  }

  function activeClassesList() {
    const cat = window.__VF_hunt_classes || {};
    if (Array.isArray(cat.active) && cat.active.length) return cat.active.map(String);
    if (Array.isArray(cat.default) && cat.default.length) return cat.default.map(String);
    return knownClasses();
  }

  /** Group skill ids by provenance for Coverage custom picker. */
  function skillGroupsForPicker() {
    const cat = window.__VF_hunt_classes || {};
    const all = knownClasses();
    const active = new Set(activeClassesList());
    const bySource = cat.by_source || {};
    const generated = new Set(
      [...(bySource.generated || []), ...(bySource.custom || []), ...(bySource.import || [])].map(
        String
      )
    );
    // Prefer profiles[] when present (richer than by_source alone)
    if (Array.isArray(cat.profiles) && cat.profiles.length) {
      for (const p of cat.profiles) {
        if (!p || !p.id) continue;
        const src = String(p.source || "").toLowerCase();
        if (src === "generated" || src === "custom" || src === "import") {
          generated.add(String(p.id));
        }
      }
    }
    const activeList = all.filter((id) => active.has(id));
    const customGen = all.filter((id) => generated.has(id));
    const optionalSeed = all.filter((id) => !active.has(id) && !generated.has(id));
    return {
      active: activeList,
      allCustomGenerated: customGen,
      optionalSeed,
      all,
    };
  }

  /** True if operator free-text looks like a target path (file or folder). */
  function looksLikePath(s) {
    const t = String(s || "")
      .replace(/\\/g, "/")
      .trim();
    if (!t || t === "." || t === ".." || t.split("/").includes("..")) return false;
    if (t.includes("/")) return true;
    const base = t.split("/").pop() || t;
    if (base.includes(".") && !base.startsWith(".")) {
      const ext = base.split(".").pop() || "";
      if (ext.length >= 1 && ext.length <= 12 && /^[a-zA-Z0-9]+$/.test(ext)) return true;
    }
    return false;
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
          "Last action filled the queue with active hunt skills × all known areas (no max_tasks cap). Ralph drains those hunts while it runs.",
      };
    }
    if (mode === "select") {
      const nA = (p.areas || []).length;
      const nC = (p.classes || []).length;
      const areaHint = nA
        ? `${nA} area${nA === 1 ? "" : "s"}`
        : "architecture areas";
      const skillHint = nC
        ? `${nC} skill${nC === 1 ? "" : "s"}`
        : "active skills";
      return {
        badge: "custom",
        title: "Custom enqueue",
        detail: `Last custom queue used ${areaHint} × ${skillHint}. Open the builder below to queue another batch.`,
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
    // Cover-all is uncapped (no run.max_tasks ceiling)
    return { raw, capped: raw, nAreas, nCore, cap: null, uncapped: true };
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

  /**
   * @param {{path: string, is_dir: boolean}[]} targets
   * @param {string} path
   * @param {boolean} isDir
   * @returns {boolean} true if newly added
   */
  function pushPathTarget(targets, path, isDir) {
    const rel = String(path || "").replace(/\\/g, "/").replace(/^\//, "");
    if (!rel || rel === ".") {
      if (!targets.some((t) => t.path === "." && t.is_dir)) {
        targets.push({ path: ".", is_dir: true });
        return true;
      }
      return false;
    }
    if (targets.some((t) => t.path === rel)) return false;
    targets.push({ path: rel, is_dir: !!isDir });
    return true;
  }

  function addPathTarget(path, isDir) {
    pushPathTarget(customPathTargets, path, isDir);
  }

  function removePathTarget(path) {
    customPathTargets = customPathTargets.filter((t) => t.path !== path);
  }

  /**
   * @param {object} [opts]
   * @param {string} [opts.boxSel]
   * @param {{path: string, is_dir: boolean}[]} [opts.targets]
   * @param {(path: string) => void} [opts.onRemove]
   * @param {string} [opts.emptyMsg]
   */
  function renderPathTargetChips(opts = {}) {
    const boxSel = opts.boxSel || "#cov-path-targets";
    const box = $(boxSel);
    if (!box) return;
    const targets = opts.targets || customPathTargets;
    const emptyMsg =
      opts.emptyMsg ||
      `No path targets yet — browse below and click <strong>Add folder</strong> or <strong>Add file</strong>.`;
    if (!targets.length) {
      box.innerHTML = `<span class="controls-hint">${emptyMsg}</span>`;
      return;
    }
    box.innerHTML = targets
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
        const rm = btn.getAttribute("data-rm-path");
        if (typeof opts.onRemove === "function") {
          opts.onRemove(rm);
        } else {
          removePathTarget(rm);
          renderPathTargetChips(opts);
          updateSelectEstimate();
        }
      });
    });
  }

  function renderMaxPathTargetChips() {
    renderPathTargetChips({
      boxSel: "#cov-max-path-targets",
      targets: maxHuntPathTargets,
      emptyMsg:
        "No path targets yet — browse the tree and <strong>Add folder</strong> / <strong>Add file</strong>. Required when scope is <em>Path targets only</em>.",
      onRemove: (path) => {
        maxHuntPathTargets = maxHuntPathTargets.filter((t) => t.path !== path);
        renderMaxPathTargetChips();
        maxHuntPreview = null;
        const est = $("#cov-max-estimate");
        if (est) est.textContent = "Path list changed — click Preview to refresh estimate.";
      },
    });
  }

  /**
   * Browse target tree into a path-picker panel (custom queue or MAX Hunt).
   * @param {object} [opts]
   * @param {string} [opts.listSel]
   * @param {string} [opts.crumbSel]
   * @param {() => string} [opts.getBrowse]
   * @param {(p: string) => void} [opts.setBrowse]
   * @param {(path: string, isDir: boolean) => void} [opts.onAdd]
   */
  async function loadPathPicker(opts = {}) {
    const listSel = opts.listSel || "#cov-path-picker-list";
    const crumbSel = opts.crumbSel || "#cov-path-picker-bc";
    const list = $(listSel);
    const crumb = $(crumbSel);
    if (!list) return;

    const getBrowse =
      typeof opts.getBrowse === "function"
        ? opts.getBrowse
        : () => pathPickerBrowse;
    const setBrowse =
      typeof opts.setBrowse === "function"
        ? opts.setBrowse
        : (p) => {
            pathPickerBrowse = p;
          };
    const onAdd =
      typeof opts.onAdd === "function"
        ? opts.onAdd
        : (path, isDir) => {
            addPathTarget(path, isDir);
            renderPathTargetChips();
            updateSelectEstimate();
            toast(`Added ${path}`);
          };

    const browse = getBrowse() || ".";
    if (crumb) crumb.innerHTML = pathPickerBreadcrumb(browse);
    list.innerHTML = `<div class="controls-hint" style="padding:0.4rem">Loading…</div>`;
    try {
      // Request high entry cap so deep trees open fully (API max 500).
      const data = await api(
        `${runApiBase()}/target/list?path=${encodeURIComponent(browse)}&max_entries=500`
      );
      if (!data.ok) {
        list.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(data.error || "list failed")}</div>`;
        return;
      }
      const entries = data.entries || [];
      const truncated =
        data.truncated ||
        data.capped ||
        (typeof data.total === "number" && data.total > entries.length) ||
        entries.length >= 500;
      if (!entries.length) {
        list.innerHTML = `<div class="controls-hint" style="padding:0.4rem">Empty folder</div>`;
      } else {
        list.innerHTML =
          entries
            .map((e) => {
              const full = joinPath(browse, e.name);
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
            .join("") +
          (truncated
            ? `<div class="cov-picker-truncated">Showing first ${entries.length} entries — open a subfolder for the rest.</div>`
            : "");
      }
      // Scroll list into view and ensure the panel is fully visible
      try {
        list.scrollTop = 0;
        const picker = list.closest(".cov-path-picker");
        picker?.scrollIntoView({ block: "nearest", behavior: "smooth" });
      } catch (_) {}
      list.querySelectorAll("[data-open-path]").forEach((btn) => {
        btn.addEventListener("click", () => {
          if (btn.getAttribute("data-is-dir") === "1") {
            setBrowse(btn.getAttribute("data-open-path") || ".");
            loadPathPicker(opts);
          }
        });
      });
      list.querySelectorAll("[data-add-path]").forEach((btn) => {
        btn.addEventListener("click", () => {
          onAdd(
            btn.getAttribute("data-add-path"),
            btn.getAttribute("data-is-dir") === "1"
          );
        });
      });
      crumb?.querySelectorAll(".cov-picker-bc").forEach((btn) => {
        btn.addEventListener("click", () => {
          setBrowse(btn.getAttribute("data-ppath") || ".");
          loadPathPicker(opts);
        });
      });
    } catch (e) {
      list.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message || e)}</div>`;
    }
  }

  function maxPathPickerOpts() {
    return {
      listSel: "#cov-max-path-picker-list",
      crumbSel: "#cov-max-path-picker-bc",
      getBrowse: () => maxPathPickerBrowse,
      setBrowse: (p) => {
        maxPathPickerBrowse = p;
      },
      onAdd: (path, isDir) => {
        const added = pushPathTarget(maxHuntPathTargets, path, isDir);
        if (!added) {
          toast(`Already added: ${path}`);
          return;
        }
        // Selecting files/folders implies path scope
        maxHuntFormState.scope = "paths";
        const pathsRadio = document.querySelector(
          'input[name="cov-max-scope"][value="paths"]'
        );
        if (pathsRadio) pathsRadio.checked = true;
        renderMaxPathTargetChips();
        maxHuntPreview = null;
        const est = $("#cov-max-estimate");
        if (est) {
          est.textContent = `Added ${isDir ? "folder" : "file"} ${path === "." ? "target root" : path}. Click Preview to estimate.`;
        }
        toast(`Added ${isDir ? "folder" : "file"} ${path === "." ? "target root" : path}`);
      },
    };
  }

  function captureMaxHuntFormState() {
    const scope =
      document.querySelector('input[name="cov-max-scope"]:checked')?.value ||
      maxHuntFormState.scope ||
      "all";
    let maxFiles = parseInt($("#cov-max-files")?.value || "", 10);
    if (!Number.isFinite(maxFiles)) maxFiles = maxHuntFormState.maxFiles;
    maxHuntFormState = {
      scope: scope === "paths" ? "paths" : "all",
      maxFiles: Number.isFinite(maxFiles) ? maxFiles : maxHuntFormState.maxFiles,
      activate: !!$("#cov-max-activate")?.checked,
      notes: $("#cov-max-notes")?.value ?? maxHuntFormState.notes ?? "",
    };
  }

  function bindMaxHuntFormFieldCapture() {
    document.querySelectorAll('input[name="cov-max-scope"]').forEach((inp) => {
      inp.addEventListener("change", () => {
        captureMaxHuntFormState();
        maxHuntPreview = null;
      });
    });
    $("#cov-max-files")?.addEventListener("change", captureMaxHuntFormState);
    $("#cov-max-files")?.addEventListener("input", captureMaxHuntFormState);
    $("#cov-max-activate")?.addEventListener("change", captureMaxHuntFormState);
    $("#cov-max-notes")?.addEventListener("input", captureMaxHuntFormState);
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
    const checked = form.querySelectorAll("[data-cov-class]:checked").length || 0;
    const extraSkills = ($("#cov-extra-skills")?.value || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean).length;
    const nC = checked + extraSkills;
    const raw = nA * nC;
    const cap = maxTasksCap();
    const capped = Math.min(raw, cap);
    const extraPaths = ($("#cov-extra-areas")?.value || "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s && looksLikePath(s)).length;
    const pathN = customPathTargets.length + extraPaths;
    estEl.textContent = nC
      ? `About ${capped} hunt${capped === 1 ? "" : "s"} will be queued` +
        (pathN ? ` (${pathN} path target${pathN === 1 ? "" : "s"})` : "") +
        (raw > cap ? ` (capped at ${cap})` : "") +
        "."
      : "Select at least one hunt skill.";
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
    const activeClasses = activeClassesList();
    const groups = skillGroupsForPicker();
    const pathSet = new Set(customPathTargets.map((t) => t.path));
    const selAreas = new Set(
      (p.areas || []).map(String).filter((a) => !pathSet.has(a) && !looksLikePath(a))
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
      : `<span class="controls-hint">No architecture areas yet — use the path picker or type paths/names below.</span>`;

    const skillBlock = (title, list, hint) => {
      if (!list.length) return "";
      const checks = list
        .map((c) => {
          const isGen = groups.allCustomGenerated.includes(c);
          const badge = isGen
            ? ` <span class="cov-skill-src" title="Custom or generated skill">custom</span>`
            : "";
          return `<label class="cov-check"><input type="checkbox" data-cov-class value="${esc(c)}" ${selClasses.has(c) ? "checked" : ""}/> <span class="mono">${esc(c)}</span>${badge}</label>`;
        })
        .join("");
      return `<div class="cov-class-group"><div class="cov-select-subhead">${esc(title)}${hint ? ` <span class="controls-hint">${esc(hint)}</span>` : ""}</div><div class="cov-check-grid cov-check-grid-sm">${checks}</div></div>`;
    };

    const inactiveCustom = groups.allCustomGenerated.filter(
      (id) => !groups.active.includes(id)
    );
    const skillGroupsFinal =
      skillBlock("Active skills", groups.active) +
      skillBlock(
        "Custom & generated",
        inactiveCustom,
        inactiveCustom.length ? "not in active set — still queueable" : ""
      ) +
      (inactiveCustom.length
        ? ""
        : groups.allCustomGenerated.length
          ? `<div class="controls-hint cov-skill-note">Custom/generated skills appear under Active (marked custom).</div>`
          : `<div class="controls-hint cov-skill-note">No custom/generated skills yet — create or generate under Dev → Hunt skills.</div>`) +
      skillBlock("Optional seed skills", groups.optionalSeed);

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
          <button type="button" class="cov-plan-action ${mode === "auto" && !selectFormOpen && !maxHuntFormOpen ? "is-current" : ""}" data-cov-mode="auto" id="cov-plan-auto">
            <span class="cov-plan-action-title">Follow recon only</span>
            <span class="cov-plan-action-desc">Clear bulk override. Do not enqueue a new batch — leave planning to recon and cell re-queues.</span>
          </button>
          <button type="button" class="cov-plan-action ${mode === "all" && !selectFormOpen && !maxHuntFormOpen ? "is-current" : ""}" data-cov-mode="all" id="cov-plan-all">
            <span class="cov-plan-action-title">Cover all areas (active)</span>
            <span class="cov-plan-action-desc">Queue about ${est.raw} hunt${est.raw === 1 ? "" : "s"}: ${est.nCore} active skills × ${est.nAreas} area${est.nAreas === 1 ? "" : "s"} (no max_tasks cap). Starts work immediately if Ralph is running.</span>
          </button>
          <button type="button" class="cov-plan-action ${selectFormOpen || mode === "select" ? "is-current" : ""}" data-cov-mode="select" id="cov-plan-custom">
            <span class="cov-plan-action-title">Custom areas &amp; skills…</span>
            <span class="cov-plan-action-desc">Pick areas/paths and skills — or generate a new custom skill and queue it.</span>
          </button>
          <button type="button" class="cov-plan-action ${maxHuntFormOpen ? "is-current" : ""}" data-cov-mode="max_hunt" id="cov-plan-max">
            <span class="cov-plan-action-title">MAX Hunt…</span>
            <span class="cov-plan-action-desc">Per source file: generate a custom skill + queue a hunt. Scope to all files or pick folders/files in the explorer. Capped; costly LLM work — research only, not proof.</span>
          </button>
        </div>

        ${
          maxHuntFormOpen
            ? (() => {
                const mhScope =
                  maxHuntFormState.scope === "paths" ? "paths" : "all";
                const mhMaxFiles = Math.max(
                  1,
                  Math.min(
                    200,
                    Number.isFinite(maxHuntFormState.maxFiles)
                      ? maxHuntFormState.maxFiles
                      : Math.min(50, maxTasksCap())
                  )
                );
                const mhNotes = maxHuntFormState.notes || "";
                const mhAct = !!maxHuntFormState.activate;
                return `<div class="cov-select-form cov-max-hunt-form" id="cov-max-hunt-form">
                <div class="cov-select-form-title">MAX Hunt</div>
                <p class="controls-hint" style="margin:0 0 0.65rem">
                  Enqueues one <strong>generate_skill</strong> Ralph task per source file (each then queues one hunt).
                  Skills are saved as <strong>generated / inactive</strong> in Dev. Cap uses max files, run.max_tasks, and a hard ceiling of 200.
                  <strong>Not exploit proof</strong> — operator research only. Ralph must be Start/Resume.
                </p>
                <div class="cov-select-heading">Scope</div>
                <div class="strategy-list" role="radiogroup" aria-label="MAX Hunt scope">
                  <label class="cov-check"><input type="radio" name="cov-max-scope" value="all" ${mhScope === "all" ? "checked" : ""} /> All source files (priority-sorted)</label>
                  <label class="cov-check"><input type="radio" name="cov-max-scope" value="paths" ${mhScope === "paths" ? "checked" : ""} /> Path targets only (files/folders from the explorer below)</label>
                </div>
                <div class="cov-select-heading" style="margin-top:0.65rem">Path targets</div>
                <p class="controls-hint" style="margin:0 0 0.4rem">
                  Same tree browser as Custom areas &amp; skills. Click a folder name to open it; use <strong>Add folder</strong> / <strong>Add file</strong> to include it.
                  Folders expand to all source files under them. Used when scope is <em>Path targets only</em>.
                </p>
                <div id="cov-max-path-targets" class="cov-path-targets"></div>
                <div class="cov-path-picker" id="cov-max-path-picker">
                  <div class="cov-path-picker-toolbar">
                    <div id="cov-max-path-picker-bc" class="cov-path-picker-bc"></div>
                    <div class="cov-path-picker-btns">
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-max-picker-up">Up</button>
                      <button type="button" class="btn btn-sm" id="cov-max-picker-add-cwd" title="Add the folder you are browsing">Add this folder</button>
                    </div>
                  </div>
                  <div id="cov-max-path-picker-list" class="cov-path-picker-list"></div>
                </div>
                <div class="init-row-2" style="margin-top:0.75rem">
                  <div class="field">
                    <label class="field-label" for="cov-max-files"><span class="label-text">Max files</span></label>
                    <input type="number" id="cov-max-files" class="cov-text-input" value="${mhMaxFiles}" min="1" max="200" step="1" />
                  </div>
                  <div class="field" style="display:flex;align-items:flex-end">
                    <label class="cov-check" style="margin:0 0 0.4rem">
                      <input type="checkbox" id="cov-max-activate" ${mhAct ? "checked" : ""} /> Activate generated skills (not recommended)
                    </label>
                  </div>
                </div>
                <div class="field">
                  <label class="field-label" for="cov-max-notes"><span class="label-text">Operator notes (optional)</span></label>
                  <textarea id="cov-max-notes" class="cov-text-input op-notes" rows="2" placeholder="Extra guidance appended to every per-file skill brief…">${esc(mhNotes)}</textarea>
                </div>
                <p class="controls-hint" id="cov-max-estimate">Click Preview to estimate file count and cost.</p>
                <div class="cov-select-actions">
                  <button type="button" class="btn" id="cov-max-preview">Preview</button>
                  <button type="button" class="btn btn-primary" id="cov-max-start">Start MAX Hunt</button>
                  <button type="button" class="btn" id="cov-max-cancel">Close</button>
                </div>
              </div>`;
              })()
            : ""
        }

        ${
          selectFormOpen
            ? `<div class="cov-select-form" id="cov-select-form">
                <div class="cov-select-form-title">Custom hunt queue</div>
                <p class="controls-hint" style="margin:0 0 0.65rem">
                  Combine architecture areas and <strong>path targets</strong> (folder or file) with hunt <strong>skills</strong>
                  (seed, custom, or dynamically generated). Paths may also be typed under areas.
                  Cap is ${maxTasksCap()} hunts per batch (run.max_tasks).
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
                    <label class="field-label" style="margin-top:0.5rem"><span class="label-text">Extra areas or paths (comma-separated)</span></label>
                    <input type="text" id="cov-extra-areas" class="cov-text-input" placeholder="e.g. api, worker, src/auth.py, packages/api/" />
                    <p class="controls-hint init-hint" style="margin-top:0.25rem">File or folder paths become path targets with path hints.</p>
                    <div class="cov-select-quick">
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-areas-all">Select all areas</button>
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-areas-none">Clear areas</button>
                    </div>
                  </div>
                  <div>
                    <div class="cov-select-heading">Hunt skills</div>
                    ${skillGroupsFinal || `<span class="controls-hint">No catalog</span>`}
                    <label class="field-label" style="margin-top:0.5rem"><span class="label-text">Extra skill ids (comma-separated)</span></label>
                    <input type="text" id="cov-extra-skills" class="cov-text-input" placeholder="e.g. my-generated-skill" />
                    <div class="cov-select-quick">
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-classes-core">Active only</button>
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-classes-custom" title="Select all custom and generated skills">Custom &amp; generated</button>
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-classes-all">All skills</button>
                      <button type="button" class="btn btn-ghost btn-sm" id="cov-classes-none">Clear</button>
                    </div>
                  </div>
                </div>

                <div class="cov-generate-block" id="cov-generate-block">
                  <div class="cov-select-heading">Generate new skill</div>
                  <p class="controls-hint" style="margin:0 0 0.45rem">
                    Queues a Ralph <span class="mono">generate_skill</span> task (async LLM). Uses path targets / areas above as hunt focus when queue is on.
                  </p>
                  <div class="field">
                    <label class="field-label" for="cov-gen-brief"><span class="label-text">Brief (required)</span></label>
                    <textarea id="cov-gen-brief" class="cov-text-input op-notes" rows="3" placeholder="e.g. Hunt for IDOR in packages/api auth handlers; focus on tenant isolation."></textarea>
                  </div>
                  <div class="field">
                    <label class="field-label" for="cov-gen-id"><span class="label-text">Suggested skill id (optional)</span></label>
                    <input type="text" id="cov-gen-id" class="cov-text-input" placeholder="e.g. api-tenant-idor" />
                  </div>
                  <div class="cov-gen-opts">
                    <label class="cov-check"><input type="checkbox" id="cov-gen-queue" checked /> Queue hunt(s) after generate</label>
                    <label class="cov-check"><input type="checkbox" id="cov-gen-activate" /> Activate skill in Dev</label>
                  </div>
                  <div class="cov-select-actions" style="margin-top:0.5rem">
                    <button type="button" class="btn btn-primary" id="cov-gen-submit">Generate &amp; queue</button>
                    <span class="controls-hint">Requires Ralph running</span>
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
          maxHuntFormOpen = false;
          renderModeBar(p);
          return;
        }
        if (m === "max_hunt") {
          maxHuntFormOpen = true;
          selectFormOpen = false;
          maxHuntPreview = null;
          renderModeBar(p);
          return;
        }
        if (m === "all") {
          const e = estimateAllAreasJobs();
          if (
            !window.confirm(
              `Queue about ${e.raw} hunt(s)?\n\n` +
                `${e.nCore} active skills × ${e.nAreas} areas (no max_tasks cap).\n\n` +
                `This can be a large queue. Ralph must be running to work it.`
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
        maxHuntFormOpen = false;
        applyCoverageMode(m);
      });
    });

    $("#cov-select-cancel")?.addEventListener("click", () => {
      selectFormOpen = false;
      renderModeBar(p);
    });
    $("#cov-max-cancel")?.addEventListener("click", () => {
      maxHuntFormOpen = false;
      maxHuntPreview = null;
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
    $("#cov-classes-custom")?.addEventListener("click", () => {
      const customSet = new Set(groups.allCustomGenerated);
      el.querySelectorAll("[data-cov-class]").forEach((inp) => {
        inp.checked = customSet.has(inp.value);
      });
      updateSelectEstimate();
    });
    $("#cov-classes-all")?.addEventListener("click", () => setChecks("[data-cov-class]", true));
    $("#cov-classes-none")?.addEventListener("click", () => setChecks("[data-cov-class]", false));
    el.querySelectorAll("[data-cov-area], [data-cov-class]").forEach((inp) => {
      inp.addEventListener("change", updateSelectEstimate);
    });
    $("#cov-extra-areas")?.addEventListener("input", updateSelectEstimate);
    $("#cov-extra-skills")?.addEventListener("input", updateSelectEstimate);

    function collectCustomSelection() {
      const pickedAreas = [...el.querySelectorAll("[data-cov-area]:checked")].map(
        (i) => i.value
      );
      const extraRaw = ($("#cov-extra-areas")?.value || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const extraAreas = [];
      const typedPaths = [];
      for (const x of extraRaw) {
        if (looksLikePath(x))
          typedPaths.push(x.replace(/\\/g, "/").replace(/\/+$/, "") || x);
        else extraAreas.push(x);
      }
      const pathTargets = [
        ...customPathTargets.map((t) => ({
          path: t.path,
          is_dir: !!t.is_dir,
        })),
        ...typedPaths.map((p) => ({
          path: p,
          is_dir: !/\.[a-zA-Z0-9]{1,12}$/.test(p.split("/").pop() || ""),
        })),
      ];
      const seenP = new Set();
      const pathTargetsDedup = [];
      for (const t of pathTargets) {
        if (seenP.has(t.path)) continue;
        seenP.add(t.path);
        pathTargetsDedup.push(t);
      }
      return {
        areas: [...new Set([...pickedAreas, ...extraAreas])],
        pathTargets: pathTargetsDedup,
        typedPaths,
      };
    }

    if (selectFormOpen) {
      renderPathTargetChips();
      loadPathPicker();
      $("#cov-picker-up")?.addEventListener("click", () => {
        pathPickerBrowse = parentPath(pathPickerBrowse);
        loadPathPicker();
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

    if (maxHuntFormOpen) {
      bindMaxHuntFormFieldCapture();
      renderMaxPathTargetChips();
      loadPathPicker(maxPathPickerOpts());
      $("#cov-max-picker-up")?.addEventListener("click", () => {
        maxPathPickerBrowse = parentPath(maxPathPickerBrowse);
        loadPathPicker(maxPathPickerOpts());
      });
      $("#cov-max-picker-add-cwd")?.addEventListener("click", () => {
        maxPathPickerOpts().onAdd(maxPathPickerBrowse || ".", true);
      });
      if (maxHuntPreview) {
        const est = $("#cov-max-estimate");
        if (est) {
          const n =
            maxHuntPreview.estimated_generate_tasks ??
            maxHuntPreview.files?.length ??
            0;
          const total = maxHuntPreview.file_count ?? n;
          const cap = maxHuntPreview.capped_to ?? n;
          est.textContent =
            `About ${n} generate_skill task(s) (~${n} hunts). ` +
            `Matched ${total} source file(s); capped to ${cap}` +
            (maxHuntPreview.truncated ? " (truncated)." : ".") +
            (maxHuntPreview.files_sample?.length
              ? ` Sample: ${maxHuntPreview.files_sample.slice(0, 5).join(", ")}`
              : "") +
            " Start Ralph to run.";
        }
      }
    }

    function collectMaxHuntBody(dryRun) {
      captureMaxHuntFormState();
      const scope =
        maxHuntFormState.scope === "paths" ? "paths" : "all";
      let maxFiles = parseInt($("#cov-max-files")?.value || "50", 10);
      if (!Number.isFinite(maxFiles)) {
        maxFiles = Number.isFinite(maxHuntFormState.maxFiles)
          ? maxHuntFormState.maxFiles
          : 50;
      }
      maxFiles = Math.max(1, Math.min(200, maxFiles));
      const body = {
        scope,
        max_files: maxFiles,
        dry_run: !!dryRun,
        activate: !!maxHuntFormState.activate,
        operator_notes: (maxHuntFormState.notes || "").trim(),
      };
      if (scope === "paths") {
        body.path_targets = maxHuntPathTargets.map((t) => ({
          path: t.path,
          is_dir: !!t.is_dir,
        }));
        if (!body.path_targets.length) {
          toast(
            "Add path targets (files or folders) for Path targets only — or choose All source files",
            true
          );
          return null;
        }
      }
      return body;
    }

    async function runMaxHuntPreview() {
      const body = collectMaxHuntBody(true);
      if (!body) return null;
      try {
        const r = await api(`${runApiBase()}/coverage/max-hunt`, {
          method: "POST",
          body: JSON.stringify(body),
        });
        maxHuntPreview = r;
        const est = $("#cov-max-estimate");
        if (est) {
          const n = r.estimated_generate_tasks ?? (r.files || []).length;
          est.textContent =
            `About ${n} generate_skill task(s) (~${n} hunts after generation). ` +
            `Matched ${r.file_count ?? n} file(s); cap ${r.capped_to ?? n}` +
            (r.truncated ? " (truncated)." : ".") +
            (r.files_sample?.length
              ? ` Sample: ${r.files_sample.slice(0, 5).join(", ")}`
              : "");
        }
        return r;
      } catch (e) {
        toast(e.message || String(e), true);
        return null;
      }
    }

    $("#cov-max-preview")?.addEventListener("click", () => {
      runMaxHuntPreview();
    });

    $("#cov-max-start")?.addEventListener("click", async () => {
      let prev = maxHuntPreview;
      if (!prev) prev = await runMaxHuntPreview();
      if (!prev || !prev.ok) return;
      const n = prev.estimated_generate_tasks ?? (prev.files || []).length;
      if (!n) {
        toast("No source files matched", true);
        return;
      }
      const costNote =
        n > 10
          ? `\n\nThis will run ~${n} LLM skill authorings (then ~${n} hunts). Confirm you accept the cost.`
          : "";
      const scopeHint =
        prev.scope === "paths"
          ? `\nScope: path targets (${maxHuntPathTargets.length} selected).`
          : "\nScope: all source files.";
      if (
        !window.confirm(
          `Start MAX Hunt?\n\n` +
            `Enqueue ${n} generate_skill task(s) (≈ ${n} hunts after). ` +
            `Cap ${prev.capped_to}; matched ${prev.file_count}.` +
            scopeHint +
            costNote +
            `\n\nSkills default inactive. Not exploit proof. Ralph must be running.`
        )
      ) {
        return;
      }
      const body = collectMaxHuntBody(false);
      if (!body) return;
      try {
        const r = await api(`${runApiBase()}/coverage/max-hunt`, {
          method: "POST",
          body: JSON.stringify(body),
        });
        toast(r.message || `Queued ${r.enqueued_generate || 0} generate_skill task(s)`);
        maxHuntFormOpen = false;
        maxHuntPreview = null;
        if (typeof window.loadRunFull === "function") await window.loadRunFull();
        else renderModeBar(window.__VF_cov_policy || p);
      } catch (e) {
        toast(e.message || String(e), true);
      }
    });

    $("#cov-gen-submit")?.addEventListener("click", async () => {
      const brief = ($("#cov-gen-brief")?.value || "").trim();
      if (!brief) {
        toast("Brief is required to generate a skill", true);
        $("#cov-gen-brief")?.focus();
        return;
      }
      const sel = collectCustomSelection();
      const body = {
        brief,
        suggested_id: ($("#cov-gen-id")?.value || "").trim() || null,
        activate: !!$("#cov-gen-activate")?.checked,
        enqueue_hunts: $("#cov-gen-queue") ? !!$("#cov-gen-queue").checked : true,
        areas: sel.areas,
        path_targets: sel.pathTargets,
      };
      if (
        !window.confirm(
          "Queue generate_skill via Ralph?\n\n" +
            (body.enqueue_hunts
              ? "After the skill is authored, hunt(s) will be enqueued for selected paths/areas."
              : "Skill only — no hunts will be enqueued.") +
            "\n\nStart/Resume Ralph to run."
        )
      ) {
        return;
      }
      try {
        const r = await api(`${runApiBase()}/coverage/generate-skill`, {
          method: "POST",
          body: JSON.stringify(body),
        });
        toast(r.message || `Queued generate_skill #${r.task_id}`);
        if (typeof window.loadRunFull === "function") await window.loadRunFull();
      } catch (e) {
        toast(e.message || String(e), true);
      }
    });

    $("#cov-select-enqueue")?.addEventListener("click", () => {
      const sel = collectCustomSelection();
      const pickedClasses = [...el.querySelectorAll("[data-cov-class]:checked")].map(
        (i) => i.value
      );
      const extraSkills = ($("#cov-extra-skills")?.value || "")
        .split(",")
        .map((s) => s.trim().toLowerCase().replace(/_/g, "-"))
        .filter(Boolean);
      const skillSet = [...new Set([...pickedClasses, ...extraSkills])];
      if (!skillSet.length) {
        toast("Pick at least one hunt skill", true);
        return;
      }
      const nA =
        sel.areas.length + sel.pathTargets.length || knownAreas().length || 1;
      const raw = nA * skillSet.length;
      const cap = maxTasksCap();
      const capped = Math.min(raw, cap);
      const pathNote = sel.pathTargets.length
        ? `\nPath targets: ${sel.pathTargets.map((t) => t.path).join(", ")}`
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
        [...new Set([...sel.areas, ...sel.typedPaths])],
        skillSet,
        sel.pathTargets
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
      <strong>${areas.length}</strong> areas × <strong>${classes.length}</strong> skills:
      ${classes.map((c) => `<span class="cov-class-pill">${classLink(c)}</span>`).join(" ")}
    </div>`;

    const head =
      `<tr><th class="row-head">Area \\ skill</th>` +
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
        Scroll horizontally when many hunt skills are in play.
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
