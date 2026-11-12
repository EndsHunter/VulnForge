/*
 * Atlas page (Code Atlas) — mode id "explorer". Spec: docs/ui/REDESIGN.md → Atlas.
 * Contract: window.VFPages.atlas = { mount(el), render(snap), onShow(snap), onHide() }.
 * Data: "vf:snapshot" events (snap.architecture / architecture_summary / coverage /
 * findings / tasks / codemap). Pure helpers are exported for node --test.
 *
 * Honesty: shading shows open cells (not hunted / too shallow / aborted / nothing found). A
 * finding pin never means an area is safe or unsafe; it means a finding was filed.
 */
(function (root, factory) {
  const helpers = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = helpers;
  } else {
    root.AtlasHelpers = helpers;
    if (typeof document !== "undefined") mountPage(helpers);
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* Pure helpers                                                        */
  /* ------------------------------------------------------------------ */

  const RESIDUAL_STATES = new Set(["empty", "planned", "shallow", "none", "aborted"]);
  const GAP_STATES = new Set(["empty", "shallow", "aborted"]);
  const ACTIVE_TASK_STATES = new Set(["leased", "running"]);
  const SKILL_BAR_SIZE = 8;

  const ZONES = [
    { id: "exposed", label: "Internet-facing", hint: "An input surface lands in this area" },
    { id: "boundary", label: "Trust boundary", hint: "Named in a recon trust boundary" },
    { id: "internal", label: "Internal", hint: "No surface or boundary maps here" },
    { id: "other", label: "Other hunted areas", hint: "Hunted areas that are not recon components" },
  ];

  function normPath(p) {
    let s = String(p == null ? "" : p).trim().replace(/\\/g, "/");
    while (s.startsWith("./")) s = s.slice(2);
    s = s.replace(/\/+$/, "");
    return s === "." ? "" : s;
  }

  /** True when `path` is `hint` or lives under it. Empty hint never matches. */
  function pathUnder(path, hint) {
    const p = normPath(path);
    const h = normPath(hint);
    if (!h || !p) return false;
    return p === h || p.startsWith(h + "/");
  }

  /** Either path contains the other (a dir that holds a hint, or a file under a hint). */
  function pathsOverlap(a, b) {
    return pathUnder(a, b) || pathUnder(b, a);
  }

  function lc(s) {
    return String(s == null ? "" : s).toLowerCase();
  }

  function textMentions(text, name) {
    const t = lc(text);
    const n = lc(name).trim();
    if (!t || !n) return false;
    const idx = t.indexOf(n);
    if (idx < 0) return false;
    const before = idx === 0 ? "" : t[idx - 1];
    const after = t[idx + n.length] || "";
    const word = /[a-z0-9_]/;
    return !word.test(before) && !word.test(after);
  }

  /** Map a coverage cell's last_depth to a `.vf-cell--*` state key. */
  function cellState(depth) {
    const d = lc(depth).trim();
    if (d === "candidate" || d === "needs_human" || d === "confirmed") return "finding";
    if (d === "none") return "none";
    if (d === "shallow") return "shallow";
    if (d === "aborted") return "aborted";
    if (d === "planned") return "planned";
    if (d === "running") return "running";
    return "empty";
  }

  /* Shared cell vocabulary (MissionOverviewHelpers.CELL_STATES) so Atlas and
     Campaign word states the same; the literal below is the node/test fallback. */
  const SHARED_STATES =
    (typeof globalThis !== "undefined" && globalThis.MissionOverviewHelpers && globalThis.MissionOverviewHelpers.CELL_STATES) || null;
  const STATE_LABEL = SHARED_STATES
    ? Object.fromEntries(SHARED_STATES.map((st) => [st.id, st.label]))
    : {
        finding: "Finding filed",
        none: "Nothing found",
        shallow: "Too shallow",
        aborted: "Aborted",
        planned: "Queued",
        running: "Hunting now",
        empty: "Not hunted",
      };
  const STATE_TIP = SHARED_STATES ? Object.fromEntries(SHARED_STATES.map((st) => [st.id, st.tip])) : {};
  /** Legend order for cell states. */
  const STATE_ORDER = ["finding", "none", "shallow", "aborted", "planned", "running", "empty"];

  /** Counts of each state in an area's coverage, in legend order, zero counts dropped. */
  function stateCounts(cov) {
    const n = Object.create(null);
    for (const c of cov || []) n[c.state] = (n[c.state] || 0) + 1;
    return STATE_ORDER.filter((k) => n[k]).map((k) => ({ state: k, label: STATE_LABEL[k], count: n[k] }));
  }

  function surfaceName(s) {
    if (typeof s === "string") return s;
    if (s && typeof s === "object") return String(s.name || s.id || s.surface || "");
    return "";
  }

  function surfaceHints(s) {
    if (s && typeof s === "object") {
      const h = s.path_hints || s.paths;
      return Array.isArray(h) ? h.map(normPath).filter(Boolean) : [];
    }
    // A bare string surface may itself be a path ("api/routes.py" or "api/ GET /x").
    if (typeof s === "string") {
      const first = s.trim().split(/\s+/)[0] || "";
      if (/[/.]/.test(first) && !/[→>]/.test(first)) return [normPath(first)];
    }
    return [];
  }

  function boundaryText(b) {
    if (typeof b === "string") return b;
    if (b && typeof b === "object") return [b.name, b.id, b.description, b.role].filter(Boolean).join(" ");
    return "";
  }

  /**
   * Areas for the map: recon components first, then hunted coverage areas that do
   * not match a component (zone "other"). Each area: {name, role, path_hints, source}.
   */
  function buildAreas(snap) {
    const s = snap || {};
    const sum = s.architecture_summary || {};
    const arch = s.architecture && typeof s.architecture === "object" ? s.architecture : {};
    const rawComps = Array.isArray(sum.components) && sum.components.length
      ? sum.components
      : Array.isArray(arch.components) ? arch.components : [];
    const out = [];
    const seen = new Set();
    for (const c of rawComps) {
      const name = typeof c === "string" ? c.trim() : String((c && (c.name || c.id)) || "").trim();
      if (!name || seen.has(lc(name))) continue;
      seen.add(lc(name));
      const hints = c && typeof c === "object" && Array.isArray(c.path_hints) ? c.path_hints : [];
      out.push({
        name,
        role: c && typeof c === "object" ? String(c.role || c.description || "") : "",
        path_hints: hints.map(normPath).filter(Boolean),
        source: "recon",
      });
    }
    const covAreas = (s.coverage && Array.isArray(s.coverage.areas)) ? s.coverage.areas : [];
    const cellAreas = (s.coverage && Array.isArray(s.coverage.cells))
      ? s.coverage.cells.map((c) => c && c.area)
      : [];
    const taskAreas = (Array.isArray(s.tasks) ? s.tasks : [])
      .filter((t) => t && t.kind === "hunt")
      .map((t) => (t.payload || {}).area);
    for (const a of [...covAreas, ...cellAreas, ...taskAreas]) {
      const name = String(a || "").trim();
      if (!name || seen.has(lc(name))) continue;
      seen.add(lc(name));
      const hints = [];
      for (const t of Array.isArray(s.tasks) ? s.tasks : []) {
        const p = (t && t.payload) || {};
        if (t && t.kind === "hunt" && lc(p.area) === lc(name)) {
          for (const h of p.path_hints || []) {
            const n = normPath(h);
            if (n && !hints.includes(n)) hints.push(n);
          }
        }
      }
      out.push({ name, role: "", path_hints: hints.slice(0, 12), source: "coverage" });
    }
    return out;
  }

  /**
   * Zone per area from input surfaces and trust boundaries. Returns null when the
   * architecture has neither (the map then uses a plain grid).
   */
  function assignZones(areas, snap) {
    const s = snap || {};
    const sum = s.architecture_summary || {};
    const arch = s.architecture && typeof s.architecture === "object" ? s.architecture : {};
    const surfaces = Array.isArray(sum.input_surfaces) && sum.input_surfaces.length
      ? sum.input_surfaces
      : Array.isArray(arch.input_surfaces) ? arch.input_surfaces : [];
    const bounds = Array.isArray(sum.trust_boundaries) && sum.trust_boundaries.length
      ? sum.trust_boundaries
      : Array.isArray(arch.trust_boundaries) ? arch.trust_boundaries : [];
    const zones = {};
    const reconAreas = areas.filter((a) => a.source === "recon");
    if (!surfaces.length && !bounds.length) {
      for (const a of areas) zones[a.name] = a.source === "recon" ? null : "other";
      return reconAreas.length && areas.some((a) => a.source !== "recon") ? zones : null;
    }
    for (const a of areas) {
      if (a.source !== "recon") {
        zones[a.name] = "other";
        continue;
      }
      const exposed = surfaces.some((sf) => {
        const hints = surfaceHints(sf);
        if (hints.some((h) => a.path_hints.some((ah) => pathsOverlap(h, ah)))) return true;
        return textMentions(surfaceName(sf), a.name);
      });
      if (exposed) {
        zones[a.name] = "exposed";
        continue;
      }
      const boundary = bounds.some((b) => {
        const text = boundaryText(b);
        if (textMentions(text, a.name)) return true;
        return a.path_hints.some((h) => h && lc(text).includes(lc(h)));
      });
      zones[a.name] = boundary ? "boundary" : "internal";
    }
    return zones;
  }

  /** Skill columns: active catalog order first, then any class seen in coverage. */
  function skillColumns(snap) {
    const s = snap || {};
    const cat = s.hunt_classes || {};
    const out = [];
    const add = (c) => {
      const id = String(c || "").trim();
      if (id && !out.includes(id)) out.push(id);
    };
    (cat.active || cat.default || []).forEach(add);
    ((s.coverage && s.coverage.classes) || []).forEach(add);
    for (const c of (s.coverage && s.coverage.cells) || []) add(c && c.class);
    return out;
  }

  /** Active hunt tasks → set of "area\0class" plus live paths. */
  function liveWork(tasks) {
    const cells = new Set();
    const paths = [];
    const areas = new Set();
    for (const t of Array.isArray(tasks) ? tasks : []) {
      if (!t || t.kind !== "hunt" || !ACTIVE_TASK_STATES.has(lc(t.state))) continue;
      const p = t.payload || {};
      const area = String(p.area || "");
      const cls = String(p.class || p.attack_class || "");
      if (area) areas.add(lc(area));
      if (area && cls) cells.add(lc(area) + "\0" + lc(cls));
      for (const h of p.path_hints || []) {
        const n = normPath(h);
        if (n) paths.push(n);
      }
      if (p.path) paths.push(normPath(p.path));
    }
    return { cells, paths, areas };
  }

  /** Per-area coverage across `skills`: [{skill, state, depth, visits}] */
  function areaCoverage(areaName, snap, skills, live) {
    const s = snap || {};
    const cells = (s.coverage && s.coverage.cells) || [];
    const lw = live || liveWork(s.tasks);
    const byClass = {};
    for (const c of cells) {
      if (c && lc(c.area) === lc(areaName)) byClass[lc(c.class)] = c;
    }
    return (skills || []).map((skill) => {
      const cell = byClass[lc(skill)];
      let state = cellState(cell && cell.last_depth);
      if (lw.cells.has(lc(areaName) + "\0" + lc(skill))) state = "running";
      return {
        skill,
        state,
        label: STATE_LABEL[state],
        visits: (cell && cell.visit_count) || 0,
        blurb: (cell && cell.depth_blurb) || "",
      };
    });
  }

  function openCount(cov) {
    return (cov || []).filter((c) => RESIDUAL_STATES.has(c.state)).length;
  }

  function gapSkills(cov) {
    return (cov || []).filter((c) => GAP_STATES.has(c.state)).map((c) => c.skill);
  }

  /**
   * Composer preselection: cells a hunt already touched badly (shallow / aborted)
   * plus recon hunt_focus classes; if that is empty, the first `fallback` unhunted
   * skills in catalog order. Keeps a young run from preselecting every skill.
   */
  function suggestSkills(cov, focusClasses, fallback) {
    const focus = new Set((focusClasses || []).map(lc));
    const open = (cov || []).filter((c) => c.state !== "running" && c.state !== "planned");
    const picked = open
      .filter((c) => c.state === "shallow" || c.state === "aborted" || (focus.has(lc(c.skill)) && c.state !== "finding"))
      .map((c) => c.skill);
    if (picked.length) return picked;
    return open.filter((c) => c.state === "empty").slice(0, fallback == null ? 3 : fallback).map((c) => c.skill);
  }

  function findingPath(f) {
    const b = (f && f.body) || {};
    if (b.sink_path) return normPath(b.sink_path);
    for (const c of b.citations || []) if (c && c.path) return normPath(c.path);
    return "";
  }

  function findingLine(f) {
    const b = (f && f.body) || {};
    for (const c of b.citations || []) if (c && c.path) return c.start_line || null;
    return null;
  }

  const LIVE_FINDING_EXCLUDE = new Set(["superseded", "rejected_mech", "rejected_llm", "rejected_human"]);

  /** Findings that still matter on the map (not rejected / superseded). */
  function liveFindings(findings) {
    return (Array.isArray(findings) ? findings : []).filter(
      (f) => f && !LIVE_FINDING_EXCLUDE.has(lc(f.state))
    );
  }

  /** Assign each finding to an area: explicit body.area, else longest path-hint match. */
  function findingsByArea(findings, areas) {
    const out = {};
    for (const a of areas) out[a.name] = [];
    for (const f of liveFindings(findings)) {
      const b = f.body || {};
      const explicit = String(b.area || f.area || "").trim();
      let match = explicit ? areas.find((a) => lc(a.name) === lc(explicit)) : null;
      if (!match) {
        const p = findingPath(f);
        let best = -1;
        for (const a of areas) {
          for (const h of a.path_hints) {
            if (pathUnder(p, h) && h.length > best) {
              best = h.length;
              match = a;
            }
          }
        }
      }
      if (match) out[match.name].push(f);
    }
    return out;
  }

  /** Finding count for a tree entry (file exact, dir = everything under it). */
  function findingCountForPath(path, findings) {
    const p = normPath(path);
    let n = 0;
    for (const f of liveFindings(findings)) {
      const fp = findingPath(f);
      if (fp && (fp === p || (p && pathUnder(fp, p)) || !p)) n += 1;
    }
    return n;
  }

  /**
   * Tree badge for one entry: {findings, tag: "live"|"gap"|""}.
   * live = under an active hunt's paths. gap = a path hint of an area with gap cells
   * sits at or under this entry.
   */
  function treeBadge(path, ctx) {
    const p = normPath(path);
    const findings = findingCountForPath(p, ctx.findings);
    const live = (ctx.livePaths || []).some((lp) => pathsOverlap(lp, p));
    let gap = false;
    if (!live) {
      for (const a of ctx.areas || []) {
        if (!(ctx.gapAreas || new Set()).has(a.name)) continue;
        if (a.path_hints.some((h) => pathUnder(h, p))) {
          gap = true;
          break;
        }
      }
    }
    return { findings, tag: live ? "live" : gap ? "gap" : "" };
  }

  /**
   * Lay out nodes. With zones: one band per non-empty zone, in ZONES order.
   * Without: a single grid. Pure geometry so tests can pin it.
   */
  function layoutMap(areas, zones, opts) {
    const o = Object.assign({ width: 900, nodeW: 168, nodeH: 76, gapX: 20, gapY: 20, pad: 20, bandHead: 30 }, opts || {});
    const cols = Math.max(1, Math.floor((o.width - o.pad * 2 + o.gapX) / (o.nodeW + o.gapX)));
    const nodes = [];
    const bands = [];
    let y = o.pad;
    const groups = zones
      ? ZONES.map((z) => ({ zone: z, items: areas.filter((a) => (zones[a.name] || "internal") === z.id) }))
      : [{ zone: null, items: areas.slice() }];
    for (const g of groups) {
      if (!g.items.length) continue;
      const rows = Math.ceil(g.items.length / cols);
      const head = g.zone ? o.bandHead : 0;
      const bandH = head + rows * o.nodeH + (rows - 1) * o.gapY + (g.zone ? o.pad : 0);
      if (g.zone) {
        bands.push({ id: g.zone.id, label: g.zone.label, hint: g.zone.hint, x: o.pad / 2, y, w: o.width - o.pad, h: bandH });
      }
      g.items.forEach((a, i) => {
        const r = Math.floor(i / cols);
        const c = i % cols;
        nodes.push({
          name: a.name,
          zone: g.zone ? g.zone.id : null,
          x: o.pad + c * (o.nodeW + o.gapX),
          y: y + head + r * (o.nodeH + o.gapY),
          w: o.nodeW,
          h: o.nodeH,
        });
      });
      y += bandH + (g.zone ? o.gapY : 0);
    }
    const height = Math.max(y + (zones ? 0 : o.pad), o.nodeH + o.pad * 2);
    return { width: o.width, height, nodes, bands, cols };
  }

  /** SVG paths for relations whose ends are both on the map. */
  function edgePaths(relations, nodes) {
    const byName = {};
    for (const n of nodes) byName[lc(n.name)] = n;
    const out = [];
    for (const r of Array.isArray(relations) ? relations : []) {
      const a = byName[lc(r && r.from)];
      const b = byName[lc(r && r.to)];
      if (!a || !b || a === b) continue;
      const ax = a.x + a.w / 2;
      const bx = b.x + b.w / 2;
      let d;
      if (Math.abs(a.y - b.y) < 1) {
        // Same row: arc below the nodes so the line does not cross labels.
        const y0 = a.y + a.h;
        const dip = y0 + 14;
        d = `M${ax} ${y0} C${ax} ${dip} ${bx} ${dip} ${bx} ${y0}`;
      } else {
        const down = b.y > a.y;
        const y1 = down ? a.y + a.h : a.y;
        const y2 = down ? b.y : b.y + b.h;
        const my = (y1 + y2) / 2;
        d = `M${ax} ${y1} C${ax} ${my} ${bx} ${my} ${bx} ${y2}`;
      }
      out.push({ d, from: a.name, to: b.name, kind: String((r && r.kind) || "related"), note: String((r && r.note) || "") });
    }
    return out;
  }

  /** Node tone for the shading toggle. */
  function nodeTone(mode, cov, findingCount) {
    if (mode === "findings") return findingCount > 0 ? "hot" : "calm";
    const applicable = (cov || []).length;
    if (!applicable) return "calm";
    const ratio = openCount(cov) / applicable;
    if (ratio >= 0.75) return "hot";
    if (ratio >= 0.4) return "warm";
    return "calm";
  }

  /** Seed sinks (raw records keep path/line) under an area's hints. */
  function sinksForArea(area, snap) {
    const s = snap || {};
    const arch = s.architecture && typeof s.architecture === "object" ? s.architecture : {};
    const inv = arch.inventory && typeof arch.inventory === "object" ? arch.inventory : {};
    const raw = Array.isArray(arch.seed_sinks) ? arch.seed_sinks : Array.isArray(inv.seed_sinks) ? inv.seed_sinks : [];
    return raw.filter((k) => k && typeof k === "object" && area.path_hints.some((h) => pathUnder(k.path, h)));
  }

  function entrypointsForArea(area, snap) {
    const s = snap || {};
    const out = [];
    const sum = s.architecture_summary || {};
    for (const sf of sum.input_surfaces || []) {
      const hints = surfaceHints(sf);
      if (hints.some((h) => area.path_hints.some((ah) => pathsOverlap(h, ah))) || textMentions(surfaceName(sf), area.name)) {
        out.push({ label: surfaceName(sf) || hints[0] || "surface", path: hints[0] || "" });
      }
    }
    const eps = (s.codemap && s.codemap.entrypoints) || [];
    for (const e of eps) {
      if (e && area.path_hints.some((h) => pathUnder(e.path, h)) && !out.some((x) => x.path === normPath(e.path))) {
        out.push({ label: normPath(e.path), path: normPath(e.path) });
      }
    }
    return out;
  }

  function fileCountForArea(area, snap) {
    const mods = (snap && snap.codemap && snap.codemap.modules) || [];
    let n = 0;
    let any = false;
    for (const m of mods) {
      if (m && area.path_hints.some((h) => normPath(m.path) === h)) {
        n += Number(m.file_count) || 0;
        any = true;
      }
    }
    return any ? n : null;
  }

  return {
    ZONES,
    SKILL_BAR_SIZE,
    STATE_LABEL,
    STATE_TIP,
    STATE_ORDER,
    stateCounts,
    normPath,
    pathUnder,
    pathsOverlap,
    textMentions,
    cellState,
    buildAreas,
    assignZones,
    skillColumns,
    liveWork,
    areaCoverage,
    openCount,
    gapSkills,
    suggestSkills,
    findingPath,
    findingLine,
    liveFindings,
    findingsByArea,
    findingCountForPath,
    treeBadge,
    layoutMap,
    edgePaths,
    nodeTone,
    sinksForArea,
    entrypointsForArea,
    fileCountForArea,
  };
});

/* -------------------------------------------------------------------- */
/* Page (browser only)                                                   */
/* -------------------------------------------------------------------- */
function mountPage(H) {
  "use strict";

  const state = {
    root: null,
    built: false,
    snap: null,
    view: "map", // map | code
    shade: "risk", // risk | findings
    selected: null,
    composer: {}, // area -> {skills:Set, notes}
    expanded: new Set([""]),
    children: {}, // dir -> entries
    treeFilter: "",
    singleFile: false,
    editRaw: false,
  };

  const $ = (sel, el) => (el || document).querySelector(sel);

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function base() {
    if (typeof window.runApiBase === "function") return window.runApiBase();
    const key = document.body?.dataset?.runKey || "";
    const [t, r] = key.split("/");
    return `/api/runs/${encodeURIComponent(t)}/${encodeURIComponent(r)}`;
  }

  async function api(path, opts) {
    if (typeof window.api === "function") return window.api(path, opts);
    const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...(opts || {}) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || data.error || res.statusText);
    return data;
  }

  function toast(msg, err) {
    if (typeof window.toast === "function") window.toast(msg, err);
  }

  async function refresh() {
    if (typeof window.loadRunFull === "function") await window.loadRunFull();
  }

  /* ---------- derived model ---------- */

  function model(snap) {
    const s = snap || {};
    const areas = H.buildAreas(s);
    const zones = H.assignZones(areas, s);
    const skills = H.skillColumns(s);
    const live = H.liveWork(s.tasks);
    const byArea = H.findingsByArea(s.findings, areas);
    const cov = {};
    const gapAreas = new Set();
    for (const a of areas) {
      cov[a.name] = H.areaCoverage(a.name, s, skills, live);
      if (H.gapSkills(cov[a.name]).length) gapAreas.add(a.name);
    }
    const sum = s.architecture_summary || {};
    const hasArch = !!(sum.has_architecture || (s.architecture && Object.keys(s.architecture).length));
    return { areas, zones, skills, live, byArea, cov, gapAreas, hasArch, sum };
  }

  /* ---------- skeleton ---------- */

  function build() {
    const el = state.root;
    el.innerHTML = `
    <div class="atlas">
      <aside class="atlas-tree" aria-label="Target files">
        <label class="atlas-tree-search">
          <span class="visually-hidden">Filter files</span>
          <input type="search" id="atlas-tree-filter" placeholder="Filter loaded files…" autocomplete="off">
        </label>
        <ul class="atlas-tree-list" id="atlas-tree-list" role="tree" aria-label="Target tree"></ul>
        <p class="atlas-tree-foot vf-faint">Read-only target. <span class="atlas-legend-chip is-gap">gap</span> = an area with skills not hunted, too shallow or aborted. <span class="atlas-legend-chip is-live">live</span> = a hunt is running here.</p>
      </aside>

      <main class="atlas-main">
        <div class="atlas-head">
          <h1 class="atlas-title">Architecture</h1>
          <span class="atlas-meta" id="atlas-meta"></span>
          <span class="vf-spacer"></span>
          <div class="atlas-seg" role="group" aria-label="Map shading" id="atlas-shade-group">
            <button type="button" data-shade="risk" aria-pressed="true">Residual risk</button>
            <button type="button" data-shade="findings" aria-pressed="false">Findings</button>
          </div>
          <div class="atlas-seg" role="group" aria-label="View">
            <button type="button" data-view="map" aria-pressed="true">Map</button>
            <button type="button" data-view="code" aria-pressed="false">Code</button>
          </div>
        </div>

        <div class="atlas-view" id="atlas-map-view">
          <p class="atlas-summary" id="atlas-summary"></p>
          <div class="atlas-map-scroll" id="atlas-map-scroll"></div>
          <ul class="atlas-legend" id="atlas-legend" aria-label="Legend"></ul>
        </div>
        <div class="atlas-view atlas-code" id="atlas-code-view" hidden></div>

        <div class="atlas-folds">
          <details class="atlas-fold" id="atlas-fold-recon">
            <summary>Run recon with brief</summary>
            <div class="atlas-fold-body">
              <label class="atlas-field">Brief for the recon agents (optional)
                <textarea id="atlas-recon-notes" rows="3" placeholder="e.g. focus on the admin blueprint and the job queue"></textarea>
              </label>
              <div class="atlas-row">
                <button type="button" class="vf-btn vf-btn--primary" data-recon="hunts">Recon + plan hunts</button>
                <button type="button" class="vf-btn" data-recon="only">Recon only</button>
                <span class="vf-faint">Merges into the current map. Ralph must be running to execute.</span>
              </div>
            </div>
          </details>
          <details class="atlas-fold" id="atlas-fold-history">
            <summary>Architecture history</summary>
            <div class="atlas-fold-body" id="atlas-history"></div>
          </details>
          <details class="atlas-fold" id="atlas-fold-codemap">
            <summary>Codemap</summary>
            <div class="atlas-fold-body" id="atlas-codemap"></div>
          </details>
          <details class="atlas-fold" id="atlas-fold-raw">
            <summary>Raw architecture JSON</summary>
            <div class="atlas-fold-body" id="atlas-raw"></div>
          </details>
        </div>

        <form class="atlas-command" id="atlas-command">
          <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/></svg>
          <label class="atlas-command-label">
            <span class="visually-hidden">Ask the run AI</span>
            <input type="text" id="atlas-command-input" autocomplete="off" placeholder="Ask the run AI, e.g. “which areas have no authz hunts yet?”">
          </label>
          <span class="vf-kbd">⌘K</span>
          <button type="submit" class="vf-btn">Ask</button>
        </form>
      </main>

      <aside class="atlas-inspector" id="atlas-inspector" aria-label="Area inspector"></aside>
    </div>`;

    // Monaco viewer lives in #explorer-panel (explorer.js); host it in Code view.
    const explorer = document.getElementById("explorer-panel");
    if (explorer) $("#atlas-code-view", el).appendChild(explorer);

    el.addEventListener("click", onClick);
    el.addEventListener("change", onChange);
    $("#atlas-tree-filter", el).addEventListener("input", (e) => {
      state.treeFilter = e.target.value || "";
      paintTree();
    });
    $("#atlas-command", el).addEventListener("submit", (e) => {
      e.preventDefault();
      const input = $("#atlas-command-input", el);
      const text = (input.value || "").trim();
      const chat = window.VulnForgeChat;
      if (!chat) return;
      chat.openSheet?.();
      if (text) chat.prefill?.(text);
      input.value = "";
    });
    $("#atlas-fold-history", el).addEventListener("toggle", (e) => {
      if (e.target.open) loadHistory();
    });
    state.built = true;
    loadDir("");
  }

  /* ---------- events ---------- */

  function onClick(ev) {
    const t = ev.target;
    const shade = t.closest("[data-shade]");
    if (shade) {
      state.shade = shade.dataset.shade;
      paintMap();
      return;
    }
    const view = t.closest("[data-view]");
    if (view) {
      setView(view.dataset.view);
      return;
    }
    const node = t.closest("[data-area]");
    if (node && !t.closest(".atlas-inspector")) {
      select(node.dataset.area);
      return;
    }
    const tree = t.closest("[data-tree-path]");
    if (tree) {
      onTreeClick(tree.dataset.treePath, tree.dataset.dir === "1");
      return;
    }
    const reveal = t.closest("[data-reveal]");
    if (reveal) {
      openCode(reveal.dataset.reveal, reveal.dataset.line);
      return;
    }
    const finding = t.closest("[data-finding]");
    if (finding) {
      const id = Number(finding.dataset.finding);
      window.VulnForgeModes?.goReport?.("all");
      window.VulnForgeReport?.openFinding?.(id);
      return;
    }
    const skill = t.closest("[data-skill-toggle]");
    if (skill) {
      const c = composerFor(state.selected);
      const k = skill.dataset.skillToggle;
      if (c.skills.has(k)) c.skills.delete(k);
      else c.skills.add(k);
      paintInspector();
      return;
    }
    if (t.closest("#atlas-enqueue")) {
      enqueueArea();
      return;
    }
    const recon = t.closest("[data-recon]");
    if (recon) {
      runRecon(recon.dataset.recon === "hunts");
      return;
    }
    if (t.closest("[data-open-recon]")) {
      const fold = $("#atlas-fold-recon", state.root);
      fold.open = true;
      fold.scrollIntoView({ block: "nearest", behavior: "smooth" });
      $("#atlas-recon-notes", state.root)?.focus();
      return;
    }
    const rev = t.closest("[data-rev-view]");
    if (rev) {
      viewRevision(rev.dataset.revView);
      return;
    }
    const restore = t.closest("[data-rev-restore]");
    if (restore) {
      restoreRevision(restore.dataset.revRestore);
      return;
    }
    if (t.closest("#atlas-codemap-rebuild")) {
      rebuildCodemap();
      return;
    }
    if (t.closest("#atlas-raw-edit")) {
      state.editRaw = !state.editRaw;
      paintRaw();
      return;
    }
    if (t.closest("#atlas-raw-save")) {
      saveRaw();
    }
  }

  function onChange(ev) {
    const notes = ev.target.closest("#atlas-composer-notes");
    if (notes && state.selected) composerFor(state.selected).notes = notes.value;
  }

  function setView(v) {
    state.view = v === "code" ? "code" : "map";
    const root = state.root;
    $("#atlas-map-view", root).hidden = state.view !== "map";
    $("#atlas-code-view", root).hidden = state.view !== "code";
    $("#atlas-shade-group", root).hidden = state.view !== "map";
    root.querySelectorAll("[data-view]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.view === state.view)));
    if (state.view === "code") {
      const ex = window.VulnForgeExplorer;
      ex?.ensureMounted?.();
      setTimeout(() => ex?.layout?.(), 0);
    }
  }

  function openCode(path, line) {
    setView("code");
    window.VulnForgeExplorer?.reveal?.(path, line != null && line !== "" ? Number(line) : undefined);
    paintTree();
  }

  function select(name) {
    state.selected = name;
    paintMap();
    paintInspector();
  }

  function focusClassesFor(name, m) {
    return (m.sum.hunt_focus || [])
      .filter((f) => f && typeof f === "object" && String(f.area || "").toLowerCase() === String(name).toLowerCase())
      .map((f) => String(f.class || ""));
  }

  function composerFor(name) {
    if (!state.composer[name]) {
      const m = model(state.snap);
      state.composer[name] = {
        skills: new Set(H.suggestSkills(m.cov[name] || [], focusClassesFor(name, m))),
        notes: "",
      };
    }
    return state.composer[name];
  }

  /* ---------- tree ---------- */

  async function loadDir(path) {
    const ex = window.VulnForgeExplorer;
    try {
      const data = ex?.listDir
        ? await ex.listDir(path || ".")
        : await api(`${base()}/target/list?path=${encodeURIComponent(path || ".")}`);
      state.children[path] = data.entries || [];
      if (data.single_file) state.singleFile = true;
    } catch (e) {
      state.children[path] = [];
      toast(e.message, true);
    }
    paintTree();
  }

  function onTreeClick(path, isDir) {
    if (!isDir) {
      openCode(path);
      return;
    }
    if (state.expanded.has(path)) state.expanded.delete(path);
    else {
      state.expanded.add(path);
      if (!state.children[path]) loadDir(path);
    }
    // A dir that is an area root also selects that area on the map.
    const m = model(state.snap);
    const area = m.areas.find((a) => a.path_hints.includes(H.normPath(path)));
    if (area) {
      state.selected = area.name;
      paintInspector();
      paintMap();
    }
    paintTree();
  }

  function paintTree() {
    const list = state.root && $("#atlas-tree-list", state.root);
    if (!list) return;
    const m = model(state.snap);
    const ctx = {
      findings: (state.snap && state.snap.findings) || [],
      livePaths: m.live.paths,
      areas: m.areas,
      gapAreas: m.gapAreas,
    };
    const open = window.VulnForgeExplorer?.state?.openFile || "";
    const q = state.treeFilter.toLowerCase().trim();
    const rows = [];
    const walk = (dir, depth) => {
      const entries = state.children[dir];
      if (!entries) {
        if (depth === 0) rows.push(`<li class="vf-empty">Loading…</li>`);
        return;
      }
      for (const e of entries) {
        const full = dir ? `${dir}/${e.name}` : e.name;
        const isDir = !!e.is_dir;
        const match = !q || full.toLowerCase().includes(q);
        const expanded = isDir && state.expanded.has(full);
        if (match || isDir) {
          const b = H.treeBadge(full, ctx);
          const badges =
            (b.findings ? `<span class="atlas-badge is-finding" title="${b.findings} finding(s) cite this path">${b.findings}</span>` : "") +
            (b.tag ? `<span class="atlas-badge is-${b.tag}">${b.tag}</span>` : "");
          if (match || expanded) {
            rows.push(`<li role="treeitem"${isDir ? ` aria-expanded="${expanded}"` : ""}>
              <button type="button" class="atlas-tree-row${!isDir && H.normPath(open) === full ? " is-open" : ""}" data-tree-path="${esc(full)}" data-dir="${isDir ? 1 : 0}" style="padding-left:${8 + depth * 14}px">
                <span class="atlas-tree-caret" aria-hidden="true">${isDir ? (expanded ? "▾" : "▸") : ""}</span>
                <span class="atlas-tree-name">${esc(e.name)}${isDir ? "/" : ""}</span>${badges}
              </button></li>`);
          }
        }
        if (expanded) walk(full, depth + 1);
      }
      if (!entries.length && depth === 0) rows.push(`<li class="vf-empty">Empty target</li>`);
    };
    walk("", 0);
    list.innerHTML = rows.join("");
  }

  /* ---------- map ---------- */

  function paintMeta(m) {
    const s = state.snap || {};
    const sum = m.sum;
    const meta = $("#atlas-meta", state.root);
    const bits = [];
    const agents = Array.isArray(sum.recon_agents_run) ? sum.recon_agents_run : [];
    if (m.hasArch) {
      bits.push(`${m.areas.filter((a) => a.source === "recon").length} components`);
      if (agents.length) bits.push(`merged from ${agents.length} recon agent${agents.length === 1 ? "" : "s"}`);
    } else {
      bits.push("no architecture yet");
    }
    const reconRunning = (s.tasks || []).some((t) => t.kind === "recon" && ["leased", "running", "queued"].includes(String(t.state)));
    if (reconRunning) bits.push(`<span class="atlas-meta-live">recon in progress</span>`);
    meta.innerHTML = bits.join(" · ");
    const summ = $("#atlas-summary", state.root);
    const text = String(sum.summary || "").trim();
    summ.textContent = text;
    summ.hidden = !text;
  }

  function reconFailure() {
    const tasks = (state.snap && state.snap.tasks) || [];
    const failed = tasks
      .filter((t) => t.kind === "recon" && /^failed|deadletter/.test(String(t.state)))
      .sort((a, b) => b.id - a.id)[0];
    if (!failed) return "";
    const r = failed.result || {};
    const why = r.error || r.reason || failed.state;
    return `<p class="atlas-empty-warn">Last recon task #${esc(failed.id)} ended <b>${esc(failed.state)}</b>${why && why !== failed.state ? `: ${esc(String(why).slice(0, 240))}` : ""}.</p>`;
  }

  function paintMap() {
    const scroll = state.root && $("#atlas-map-scroll", state.root);
    if (!scroll) return;
    const m = model(state.snap);
    paintMeta(m);
    state.root.querySelectorAll("[data-shade]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.shade === state.shade)));

    if (!m.areas.length) {
      scroll.innerHTML = `<div class="atlas-empty">
        <h2>No architecture yet</h2>
        <p>Recon maps the target into components, input surfaces and trust boundaries. Hunts are planned from that map.</p>
        ${reconFailure()}
        <div class="atlas-row">
          <button type="button" class="vf-btn vf-btn--primary" data-open-recon="1">Run recon with brief</button>
          <button type="button" class="vf-btn" data-view="code">Browse code</button>
        </div>
      </div>`;
      $("#atlas-legend", state.root).innerHTML = "";
      return;
    }

    const width = Math.max(560, Math.min(1400, scroll.clientWidth - 2 || 900));
    const lay = H.layoutMap(m.areas, m.zones, { width });
    const rels = (m.sum.relations && m.sum.relations.length ? m.sum.relations : (state.snap.architecture || {}).relations) || [];
    const edges = H.edgePaths(rels, lay.nodes);
    if (!state.selected || !m.areas.some((a) => a.name === state.selected)) {
      const ranked = m.areas.slice().sort((a, b) => H.openCount(m.cov[b.name]) - H.openCount(m.cov[a.name]));
      state.selected = ranked[0].name;
    }

    const bandsHtml = lay.bands
      .map(
        (b) => `<div class="atlas-zone is-${b.id}" style="left:${b.x}px;top:${b.y}px;width:${b.w}px;height:${b.h}px" title="${esc(b.hint)}"><span class="atlas-zone-label">${esc(b.label)}</span></div>`
      )
      .join("");
    const edgesHtml = edges.length
      ? `<svg class="atlas-edges" width="${lay.width}" height="${lay.height}" aria-hidden="true">${edges
          .map((e) => `<path d="${e.d}"><title>${esc(`${e.from} → ${e.to} (${e.kind})${e.note ? ": " + e.note : ""}`)}</title></path>`)
          .join("")}</svg>`
      : "";
    const nodesHtml = lay.nodes
      .map((n) => {
        const area = m.areas.find((a) => a.name === n.name);
        const cov = m.cov[n.name] || [];
        const fcount = (m.byArea[n.name] || []).length;
        const tone = H.nodeTone(state.shade, cov, fcount);
        const bar = cov.slice(0, H.SKILL_BAR_SIZE)
          .map((c) => `<span class="vf-cell vf-cell--${c.state}" title="${esc(c.skill)}: ${esc(c.label)}"></span>`)
          .join("");
        const open = H.openCount(cov);
        const isLive = m.live.areas.has(n.name.toLowerCase());
        const kind = area.role ? area.role.split(/[.;\n]/)[0].slice(0, 42) : area.source === "recon" ? "component" : "hunted area";
        return `<button type="button" class="atlas-node is-${tone}${state.selected === n.name ? " is-selected" : ""}" data-area="${esc(n.name)}"
            style="left:${n.x}px;top:${n.y}px;width:${n.w}px;height:${n.h}px"
            aria-pressed="${state.selected === n.name}"
            aria-label="${esc(`${n.name}: ${open} of ${cov.length} skill cells open, ${fcount} finding${fcount === 1 ? "" : "s"}`)}">
          <span class="atlas-node-top"><span class="atlas-node-name">${esc(n.name)}</span>${isLive ? '<span class="atlas-node-live" title="Hunt running">●</span>' : ""}${fcount ? `<span class="atlas-pin" title="${fcount} finding(s) filed">${fcount}</span>` : ""}</span>
          <span class="atlas-node-kind">${esc(kind)}</span>
          <span class="atlas-skillbar" aria-hidden="true">${bar}</span>
        </button>`;
      })
      .join("");
    scroll.innerHTML = `<div class="atlas-map" style="width:${lay.width}px;height:${lay.height}px">${bandsHtml}${edgesHtml}${nodesHtml}</div>`;

    $("#atlas-legend", state.root).innerHTML =
      H.STATE_ORDER.map((k) => `<li title="${esc(H.STATE_TIP[k] || "")}"><span class="vf-cell vf-cell--${k}" aria-hidden="true"></span>${esc(H.STATE_LABEL[k])}</li>`).join("") +
      `<li class="vf-faint">${state.shade === "risk" ? "Shading = share of open cells (not hunted, too shallow, aborted or nothing found). Calm is not proof of safety." : "Shading = areas with filed findings. No pin is not proof of safety."}</li>`;
  }

  /* ---------- inspector ---------- */

  function paintInspector() {
    const el = state.root && $("#atlas-inspector", state.root);
    if (!el) return;
    const m = model(state.snap);
    const area = m.areas.find((a) => a.name === state.selected);
    if (!area) {
      el.innerHTML = `<p class="vf-empty">Select an area on the map to see its coverage, findings and hunts.</p>`;
      return;
    }
    const zone = m.zones ? H.ZONES.find((z) => z.id === (m.zones[area.name] || "internal")) : null;
    const cov = m.cov[area.name] || [];
    const findings = m.byArea[area.name] || [];
    const eps = H.entrypointsForArea(area, state.snap);
    const sinks = H.sinksForArea(area, state.snap);
    const files = H.fileCountForArea(area, state.snap);
    const c = composerFor(area.name);
    const focus = new Set(focusClassesFor(area.name, m));
    const hints = area.path_hints.length
      ? area.path_hints.map((h) => `<button type="button" class="atlas-path" data-reveal="${esc(h)}">${esc(h)}</button>`).join("")
      : `<span class="vf-faint">no path hints</span>`;
    const epHtml = eps.length
      ? eps.slice(0, 6).map((e) => e.path ? `<button type="button" class="atlas-path" data-reveal="${esc(e.path)}">${esc(e.label)}</button>` : `<span>${esc(e.label)}</span>`).join("")
      : `<span class="vf-faint">none mapped</span>`;
    const sinkHtml = sinks.length
      ? sinks.slice(0, 6).map((k) => `<button type="button" class="atlas-path" data-reveal="${esc(k.path)}" data-line="${esc(k.line || "")}">${esc(k.kind || "sink")} · ${esc(H.normPath(k.path))}${k.line ? ":" + esc(k.line) : ""}</button>`).join("") +
        (sinks.length > 6 ? `<span class="vf-faint">+${sinks.length - 6} more</span>` : "")
      : `<span class="vf-faint">none indexed</span>`;
    const grid = cov.length
      ? cov.map((x) => {
          const tip = `${x.skill}: ${x.label}${x.visits ? ` · ${x.visits} visit${x.visits === 1 ? "" : "s"}` : ""}. ${x.blurb || H.STATE_TIP[x.state] || ""}`.trim();
          return `<li><button type="button" class="atlas-cov vf-cell vf-cell--${x.state}${c.skills.has(x.skill) ? " is-picked" : ""}" data-skill-toggle="${esc(x.skill)}" aria-pressed="${c.skills.has(x.skill)}" aria-label="${esc(tip)}" title="${esc(tip)}">
          <span class="atlas-cov-name">${esc(x.skill)}</span>${focus.has(x.skill) ? '<span class="atlas-focus" aria-hidden="true">◆</span>' : ""}</button></li>`;
        }).join("")
      : `<li class="vf-empty">No hunt skills are active yet.</li>`;
    const fHtml = findings.length
      ? `<ul class="atlas-findings">${findings
          .map((f) => {
            const sev = String(f.severity || (f.body || {}).severity_claim || "").toLowerCase();
            const sevKey = sev.startsWith("crit") ? "crit" : sev === "high" ? "high" : sev.startsWith("med") ? "med" : sev === "low" ? "low" : "";
            const st = String(f.state || "");
            const pill = st === "needs_human" ? "review" : st === "confirmed" ? "confirmed" : "candidate";
            const stLabel = typeof window.stateLabel === "function" ? window.stateLabel(st, f) : st;
            return `<li><button type="button" class="atlas-finding" data-finding="${esc(f.id)}">
              ${sevKey ? `<span class="vf-sev vf-sev--${sevKey}">${esc(sev)}</span>` : ""}
              <span class="atlas-finding-title">${esc((f.body || {}).title || f.title || `Finding #${f.id}`)}</span>
              <span class="vf-pill vf-pill--${pill}">${esc(stLabel)}</span></button></li>`;
          })
          .join("")}</ul>`
      : `<p class="vf-empty">No findings filed here. That is not evidence of safety.</p>`;
    const picked = [...c.skills].filter((k) => cov.some((x) => x.skill === k));
    el.innerHTML = `
      <div class="atlas-insp-head">
        ${zone ? `<span class="atlas-zone-tag is-${zone.id}">${esc(zone.label)}</span>` : ""}
        <h2 class="atlas-insp-name">${esc(area.name)}</h2>
        ${area.role ? `<p class="atlas-insp-role">${esc(area.role)}</p>` : ""}
      </div>
      <dl class="atlas-facts">
        <dt>Paths</dt><dd>${hints}</dd>
        <dt>Entrypoints</dt><dd>${epHtml}</dd>
        <dt>Sinks</dt><dd>${sinkHtml}</dd>
        ${files != null ? `<dt>Files</dt><dd>${esc(files)}</dd>` : ""}
      </dl>
      <section>
        <h3 class="vf-section-label">Hunt coverage <span class="vf-faint atlas-open">${H.openCount(cov)} of ${cov.length} open</span></h3>
        <ul class="atlas-cov-grid">${grid}</ul>
        ${cov.length ? `<ul class="atlas-cov-key" aria-label="Coverage key">${H.stateCounts(cov)
          .map((k) => `<li title="${esc(H.STATE_TIP[k.state] || "")}"><span class="vf-cell vf-cell--${k.state}" aria-hidden="true"></span>${esc(k.label)} <b class="vf-mono">${k.count}</b></li>`)
          .join("")}${cov.some((x) => focus.has(x.skill)) ? `<li title="Recon marked this skill as a hunt focus for this area"><span class="atlas-focus" aria-hidden="true">◆</span>Recon focus</li>` : ""}</ul>` : ""}
      </section>
      <section>
        <h3 class="vf-section-label">Findings here</h3>
        ${fHtml}
      </section>
      <section class="atlas-composer vf-card">
        <h3 class="atlas-composer-title">Hunt this area</h3>
        <p class="vf-faint atlas-composer-hint">Preselected: skills that were too shallow or aborted, plus recon focus (otherwise the first skills not hunted). Click a coverage cell above to add or remove one.</p>
        <div class="atlas-picked" role="group" aria-label="Skills to hunt">${
          picked.length
            ? picked.map((k) => `<button type="button" class="vf-chip" aria-pressed="true" data-skill-toggle="${esc(k)}">${esc(k)} ×</button>`).join("")
            : `<span class="vf-faint">No skills picked.</span>`
        }</div>
        <label class="atlas-field">Notes for the hunter
          <textarea id="atlas-composer-notes" rows="2" placeholder="What should the hunter look at?">${esc(c.notes)}</textarea>
        </label>
        <button type="button" class="vf-btn vf-btn--primary vf-btn--lg" id="atlas-enqueue" ${picked.length ? "" : "disabled"}>Enqueue ${picked.length} hunt${picked.length === 1 ? "" : "s"}</button>
        <p class="vf-faint atlas-composer-hint">Enqueues only. Ralph runs them; nothing is confirmed without review.</p>
      </section>`;
  }

  async function enqueueArea() {
    const m = model(state.snap);
    const area = m.areas.find((a) => a.name === state.selected);
    if (!area) return;
    const c = composerFor(area.name);
    const notesEl = $("#atlas-composer-notes", state.root);
    if (notesEl) c.notes = notesEl.value;
    const skills = [...c.skills].filter((k) => (m.cov[area.name] || []).some((x) => x.skill === k));
    if (!skills.length) return;
    const btn = $("#atlas-enqueue", state.root);
    if (btn) btn.disabled = true;
    try {
      const r = await api(`${base()}/coverage/requeue-bulk`, {
        method: "POST",
        body: JSON.stringify({
          cells: skills.map((k) => ({ area: area.name, class: k, path_hints: area.path_hints })),
          force_depth: true,
          reason: "operator_atlas_area",
          operator_notes: (c.notes || "").trim(),
        }),
      });
      const n = r.enqueued != null ? (Array.isArray(r.enqueued) ? r.enqueued.length : r.enqueued) : skills.length;
      toast(`Enqueued ${n} hunt(s) on ${area.name}`);
      c.notes = "";
      await refresh();
    } catch (e) {
      toast(e.message, true);
      if (btn) btn.disabled = false;
    }
  }

  /* ---------- folds: recon, history, codemap, raw ---------- */

  async function runRecon(withHunts) {
    const notes = ($("#atlas-recon-notes", state.root)?.value || "").trim();
    try {
      const r = await api(`${base()}/recon/rerun`, {
        method: "POST",
        body: JSON.stringify({
          operator_notes: notes,
          include_prior_architecture: true,
          enqueue_hunts: withHunts,
          reason: withHunts ? "operator_recon_from_atlas" : "operator_recon_atlas_only",
        }),
      });
      const ids = Array.isArray(r.task_ids) && r.task_ids.length ? r.task_ids : r.task_id != null ? [r.task_id] : [];
      toast(`Queued recon ${ids.length ? ids.map((n) => `#${n}`).join(", ") : ""}`.trim());
      await refresh();
    } catch (e) {
      toast(e.message, true);
    }
  }

  async function loadHistory() {
    const el = $("#atlas-history", state.root);
    el.innerHTML = `<p class="vf-empty">Loading…</p>`;
    try {
      const r = await api(`${base()}/architecture/history?limit=50`);
      const revs = Array.isArray(r.revisions) ? r.revisions : [];
      if (!revs.length) {
        el.innerHTML = `<p class="vf-empty">No prior revisions yet. Each recon merge archives the previous map here.</p>`;
        return;
      }
      el.innerHTML = `<ul class="atlas-revs">${revs
        .map((rev) => `<li>
          <span class="vf-mono">#${esc(rev.id)}</span>
          <span class="vf-pill">${esc(rev.source || "—")}</span>
          <span class="vf-faint">${esc(rev.created_at || "")}${rev.recon_generation != null ? ` · gen ${esc(rev.recon_generation)}` : ""}</span>
          ${rev.note ? `<span class="atlas-rev-note">${esc(String(rev.note).slice(0, 120))}</span>` : ""}
          <span class="vf-spacer"></span>
          <button type="button" class="vf-btn" data-rev-view="${esc(rev.id)}">View</button>
          <button type="button" class="vf-btn" data-rev-restore="${esc(rev.id)}">Restore</button>
        </li>`)
        .join("")}</ul><div id="atlas-rev-detail"></div>`;
    } catch (e) {
      el.innerHTML = `<p class="atlas-empty-warn">${esc(e.message)}</p>`;
    }
  }

  async function viewRevision(id) {
    const el = $("#atlas-rev-detail", state.root);
    if (!el) return;
    el.innerHTML = `<p class="vf-empty">Loading revision #${esc(id)}…</p>`;
    try {
      const rev = await api(`${base()}/architecture/history/${encodeURIComponent(id)}`);
      const snap = rev.snapshot && typeof rev.snapshot === "object" ? rev.snapshot : {};
      const comps = (snap.components || []).map((c) => (typeof c === "string" ? c : c && (c.name || c.id))).filter(Boolean);
      el.innerHTML = `<div class="atlas-rev-detail vf-card">
        <p><b>Revision #${esc(rev.id ?? id)}</b> <span class="vf-faint">${esc(rev.source || "")} · ${esc(rev.created_at || "")}</span></p>
        ${snap.summary ? `<p>${esc(String(snap.summary).slice(0, 800))}</p>` : ""}
        <p class="vf-faint">${comps.length} components: ${esc(comps.slice(0, 30).join(", "))}${comps.length > 30 ? "…" : ""}</p>
        <p class="vf-faint">${(snap.input_surfaces || []).length} input surfaces · ${(snap.trust_boundaries || []).length} trust boundaries · ${(snap.hunt_focus || []).length} hunt focus items</p>
      </div>`;
    } catch (e) {
      el.innerHTML = `<p class="atlas-empty-warn">${esc(e.message)}</p>`;
    }
  }

  async function restoreRevision(id) {
    if (!confirm(`Restore architecture revision #${id}? The current map is archived first.`)) return;
    try {
      await api(`${base()}/architecture/restore/${encodeURIComponent(id)}`, {
        method: "POST",
        body: JSON.stringify({ note: `restored from #${id} (Atlas)` }),
      });
      toast(`Restored architecture #${id}`);
      await refresh();
      loadHistory();
    } catch (e) {
      toast(e.message, true);
    }
  }

  function paintCodemap() {
    const el = state.root && $("#atlas-codemap", state.root);
    if (!el) return;
    const s = state.snap || {};
    const sum = s.codemap_summary || {};
    const map = s.codemap || null;
    const has = !!(sum.has_codemap || s.has_codemap || (map && (map.modules || []).length));
    if (!has) {
      el.innerHTML = `<p class="vf-empty">No codemap yet. It is built mechanically at recon (structure only, not the architecture).</p>
        <button type="button" class="vf-btn" id="atlas-codemap-rebuild">Rebuild codemap</button>`;
      return;
    }
    const langs = Object.entries(sum.languages || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const mods = (map && map.modules) || [];
    el.innerHTML = `
      <ul class="atlas-stats">
        <li><b>${esc(sum.file_count ?? "—")}</b> files</li>
        <li><b>${esc(sum.module_count ?? mods.length)}</b> modules</li>
        ${sum.symbol_count ? `<li><b>${esc(sum.symbol_count)}</b> symbols</li>` : ""}
        ${sum.entrypoint_count ? `<li><b>${esc(sum.entrypoint_count)}</b> entrypoints</li>` : ""}
        ${langs.map(([k, v]) => `<li class="vf-mono">${esc(k)} ${esc(v)}</li>`).join("")}
        <li class="vf-spacer"></li>
        <li><button type="button" class="vf-btn" id="atlas-codemap-rebuild">Rebuild</button></li>
      </ul>
      <ul class="atlas-modules">${mods
        .slice(0, 60)
        .map((md) => `<li><button type="button" class="atlas-path" data-reveal="${esc(md.path)}">${esc(md.path || md.label)}</button><span class="vf-faint">${esc(md.kind || "")} · ${esc(md.file_count ?? 0)} files</span></li>`)
        .join("")}</ul>
      ${mods.length > 60 ? `<p class="vf-faint">${mods.length - 60} more modules not shown.</p>` : ""}`;
  }

  async function rebuildCodemap() {
    try {
      await api(`${base()}/codemap/rebuild`, { method: "POST" });
      toast("Codemap rebuilt");
      await refresh();
    } catch (e) {
      toast(e.message, true);
    }
  }

  function paintRaw() {
    const el = state.root && $("#atlas-raw", state.root);
    if (!el) return;
    const arch = (state.snap && state.snap.architecture) || null;
    if (state.editRaw) {
      if (el.querySelector("#atlas-raw-json")) return; // keep the operator's draft
      el.innerHTML = `
        <label class="atlas-field">Architecture JSON (fields you send overwrite the stored map; inventory is kept)
          <textarea id="atlas-raw-json" rows="16" spellcheck="false">${esc(JSON.stringify(arch || {}, null, 2))}</textarea>
        </label>
        <label class="atlas-field">Note (optional)<input type="text" id="atlas-raw-note" placeholder="Why this manual edit"></label>
        <div class="atlas-row">
          <button type="button" class="vf-btn vf-btn--primary" id="atlas-raw-save">Save</button>
          <button type="button" class="vf-btn" id="atlas-raw-edit">Cancel</button>
        </div>`;
      return;
    }
    el.innerHTML = `
      <div class="atlas-row"><button type="button" class="vf-btn" id="atlas-raw-edit" ${arch ? "" : "disabled"}>Edit JSON</button></div>
      <pre class="atlas-raw-pre">${esc(arch ? JSON.stringify(arch, null, 2) : "No architecture stored.")}</pre>`;
  }

  async function saveRaw() {
    let arch;
    try {
      arch = JSON.parse(($("#atlas-raw-json", state.root)?.value || "{}").trim() || "{}");
    } catch (e) {
      toast("Invalid JSON: " + e.message, true);
      return;
    }
    if (!arch || typeof arch !== "object" || Array.isArray(arch)) {
      toast("Architecture must be a JSON object", true);
      return;
    }
    try {
      await api(`${base()}/architecture`, {
        method: "PUT",
        body: JSON.stringify({ architecture: arch, note: ($("#atlas-raw-note", state.root)?.value || "").trim() }),
      });
      toast("Architecture saved");
      state.editRaw = false;
      await refresh();
    } catch (e) {
      toast(e.message, true);
    }
  }

  /* ---------- lifecycle ---------- */

  function render(snap) {
    if (snap) state.snap = snap;
    if (!state.root || !state.snap) return;
    if (!state.built) build();
    // Keep the operator's typing: don't repaint the inspector while its notes field is focused.
    const typing = document.activeElement && document.activeElement.id === "atlas-composer-notes";
    paintMap();
    paintTree();
    if (!typing) paintInspector();
    paintCodemap();
    paintRaw();
  }

  function isActive() {
    return window.VulnForgeModes?.activeMode?.() === "explorer";
  }

  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (isActive() && state.view === "map") paintMap();
    }, 120);
  });

  window.VFPages = window.VFPages || {};
  window.VFPages.atlas = {
    mount(el) {
      state.root = el;
    },
    render,
    isActive,
    onShow(snap) {
      render(snap);
      if (state.view === "code") setTimeout(() => window.VulnForgeExplorer?.layout?.(), 0);
    },
    onHide() {},
    /** Open a path in the Code view. */
    reveal(path, line) {
      openCode(path, line);
    },
    /** Switch to the Code view (explorer.reveal calls this for goExplorer deep links). */
    showCode() {
      if (state.built && state.view !== "code") setView("code");
    },
  };

  function boot() {
    const el = document.getElementById("page-atlas");
    if (el) state.root = el;
    window.addEventListener("vf:snapshot", (ev) => render(ev.detail));
    if (window.__VF_last_snap) render(window.__VF_last_snap);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
}
