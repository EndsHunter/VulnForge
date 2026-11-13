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

  /* ---------- v2 schema (docs/harness/recon/FLOWS.md) ---------- */

  const V2_SCHEMA = "vulnforge/architecture@2";
  /** Zone kinds in band order, with band and short (badge) labels. */
  const ZONE_KINDS = [
    { kind: "internet", label: "Internet-facing", short: "Internet", tone: "exposed" },
    { kind: "authenticated", label: "Authenticated", short: "Authenticated", tone: "boundary" },
    { kind: "internal", label: "Internal", short: "Internal", tone: "internal" },
    { kind: "external", label: "External services", short: "External", tone: "external" },
    { kind: "build", label: "Build & supply chain", short: "Build", tone: "build" },
  ];
  const ZONE_KIND_BY_ID = Object.fromEntries(ZONE_KINDS.map((z, i) => [z.kind, Object.assign({ rank: i }, z)]));
  const GUESSED_TIP =
    "Guessed: this map has no zones, so Atlas placed areas by matching input surfaces and trust-boundary text. Re-run recon for labelled zones.";
  const V2_LIST_KEYS = ["zones", "components", "boundaries", "relations", "flows"];

  function isObj(x) {
    return !!x && typeof x === "object" && !Array.isArray(x);
  }

  /** True for a `vulnforge/architecture@2` map. */
  function isV2(a) {
    return isObj(a) && a.schema === V2_SCHEMA;
  }

  function hasComponents(a) {
    return isObj(a) && Array.isArray(a.components) && a.components.length > 0;
  }

  /**
   * Which map Atlas draws. kind:
   *   "v2"       recon wrote a v2 map (explicit zones, relations, flows)
   *   "v1"       recon wrote a v1 map (zones guessed from free text)
   *   "skeleton" only the mechanical skeleton (no LLM labels yet)
   *   "none"     nothing yet (coverage-only areas may still show)
   * The raw `architecture` is preferred over `architecture_summary` because the
   * summary is compacted (it drops zones, flows and component entrypoints).
   */
  function selectSource(snap) {
    const s = snap || {};
    const raw = isObj(s.architecture) ? s.architecture : null;
    const sum = isObj(s.architecture_summary) ? s.architecture_summary : null;
    const v2 = isV2(raw) && hasComponents(raw) ? raw : isV2(sum) && hasComponents(sum) ? sum : null;
    if (v2) {
      const other = v2 === raw ? (isV2(sum) ? sum : null) : isV2(raw) ? raw : null;
      const arch = Object.assign({}, v2);
      for (const k of V2_LIST_KEYS) {
        if (!(Array.isArray(arch[k]) && arch[k].length) && other && Array.isArray(other[k])) arch[k] = other[k];
      }
      return { kind: lc(v2.origin) === "mechanical" ? "skeleton" : "v2", arch };
    }
    if (hasComponents(sum) || hasComponents(raw)) return { kind: "v1", arch: raw || sum };
    const sk = s.architecture_skeleton;
    if (isV2(sk) && hasComponents(sk)) return { kind: "skeleton", arch: sk };
    return { kind: "none", arch: null };
  }

  /** Resolve a zone reference (zone id, or a bare kind) against v2 `zones`. */
  function resolveZone(ref, zones) {
    const r = lc(ref).trim();
    if (!r) return null;
    const list = Array.isArray(zones) ? zones.filter(isObj) : [];
    const z = list.find((x) => lc(x.id) === r) || list.find((x) => lc(x.kind) === r);
    if (z) {
      const kind = lc(z.kind) || (ZONE_KIND_BY_ID[lc(z.id)] ? lc(z.id) : "");
      const meta = ZONE_KIND_BY_ID[kind];
      return { id: String(z.id || kind), kind, label: String(z.label || (meta ? meta.label : z.id)), description: String(z.description || "") };
    }
    if (ZONE_KIND_BY_ID[r]) return { id: r, kind: r, label: ZONE_KIND_BY_ID[r].label, description: "" };
    return null;
  }

  /** Short badge label for a zone reference ("Internet", "Internal", …). */
  function zoneShort(ref, zones) {
    const z = resolveZone(ref, zones);
    if (!z) return String(ref || "");
    const meta = ZONE_KIND_BY_ID[z.kind];
    return meta ? meta.short : z.label;
  }

  /**
   * Find an area / component by reference: a string (id or name) or an object with
   * `component`. Case-insensitive on both id and name.
   */
  function resolveComponent(ref, comps) {
    const r = lc(isObj(ref) ? ref.component : ref).trim();
    if (!r) return null;
    const list = Array.isArray(comps) ? comps : [];
    return (
      list.find((c) => c && lc(c.id) === r) ||
      list.find((c) => c && lc(typeof c === "string" ? c : c.name) === r) ||
      null
    );
  }

  /** Component names a flow passes through: source → steps → sink, consecutive repeats collapsed. */
  function flowComponentPath(flow, areas) {
    const f = flow || {};
    const refs = [f.source, ...(Array.isArray(f.steps) ? f.steps : []), f.sink];
    const out = [];
    for (const ref of refs) {
      const a = resolveComponent(ref, areas);
      if (!a) continue;
      if (out.length && out[out.length - 1] === a.name) continue;
      out.push(a.name);
    }
    return out;
  }

  function locText(x) {
    if (!isObj(x) || !x.path) return "";
    return `${normPath(x.path)}${x.line ? ":" + x.line : ""}`;
  }

  /** Ordered step list for the inspector: source, steps, sink (each may carry path:line). */
  function flowSteps(flow, areas) {
    const f = flow || {};
    const comp = (ref) => {
      const a = resolveComponent(ref, areas);
      return a ? a.name : isObj(ref) && ref.component ? String(ref.component) : "";
    };
    const out = [];
    if (isObj(f.source)) {
      out.push({ role: "source", component: comp(f.source), text: String(f.source.label || "source"), path: normPath(f.source.path), line: f.source.line || null });
    }
    for (const st of Array.isArray(f.steps) ? f.steps : []) {
      if (!isObj(st)) continue;
      out.push({ role: "step", component: comp(st), text: String(st.note || ""), path: normPath(st.path), line: st.line || null });
    }
    if (isObj(f.sink)) {
      out.push({ role: "sink", component: comp(f.sink), text: String(f.sink.kind || "sink"), path: normPath(f.sink.path), line: f.sink.line || null });
    }
    return out;
  }

  /** Files a flow cites, in order, unique. */
  function flowFiles(flow) {
    const out = [];
    for (const st of flowSteps(flow, [])) if (st.path && !out.includes(st.path)) out.push(st.path);
    return out;
  }

  /** One-line description used to prefill hunt notes. */
  function flowNote(flow) {
    const f = flow || {};
    const src = isObj(f.source) ? `${f.source.label || "source"}${locText(f.source) ? " (" + locText(f.source) + ")" : ""}` : "source";
    const sink = isObj(f.sink) ? `${f.sink.kind || "sink"}${locText(f.sink) ? " at " + locText(f.sink) : ""}` : "sink";
    return `Recon flow "${f.title || f.id || "flow"}": ${src} → ${sink}. Confirm or rule out; the flow is a hint, not proof.`;
  }

  /**
   * Zone crossing for the badge: {from, to} short labels, or null when the flow
   * stays in one zone. Uses `crosses` when given, else the source/sink component zones.
   */
  function flowCrossing(flow, areas, zones) {
    const f = flow || {};
    let ids = Array.isArray(f.crosses) ? f.crosses.map((x) => String(x || "")).filter(Boolean) : [];
    if (ids.length < 2) {
      const a = resolveComponent(f.source, areas);
      const b = resolveComponent(f.sink, areas);
      ids = [a && a.zone, b && b.zone].filter(Boolean);
    }
    if (ids.length < 2) return null;
    const from = zoneShort(ids[0], zones);
    const to = zoneShort(ids[ids.length - 1], zones);
    if (!from || !to || lc(from) === lc(to)) return null;
    return { from, to };
  }

  /** Flows whose component path includes `areaName`. */
  function flowsForArea(flows, areas, areaName) {
    const n = lc(areaName);
    return (Array.isArray(flows) ? flows : []).filter((f) => flowComponentPath(f, areas).some((x) => lc(x) === n));
  }

  /** Area a flow hunt is filed under: the sink component, else the last one on its path. */
  function flowHuntArea(flow, areas) {
    const sink = resolveComponent(flow && flow.sink, areas);
    if (sink) return sink;
    const path = flowComponentPath(flow, areas);
    return path.length ? areas.find((a) => a.name === path[path.length - 1]) || null : null;
  }

  /** flow.classes ∩ skills (skills order kept, matched case-insensitively). */
  function flowSkills(flow, skills) {
    const want = new Set(((flow && flow.classes) || []).map(lc));
    return (skills || []).filter((s) => want.has(lc(s)));
  }

  /**
   * Relations split into layers and deduplicated per unordered pair.
   * links: everything but imports; imports: kind "imports", or mechanical relations
   * of the skeleton. Each edge: {from, to, bidir, layer, kinds[], items[], inferred}.
   */
  function buildEdges(relations, areas, opts) {
    const skeleton = !!(opts && opts.skeleton);
    const layers = { links: new Map(), imports: new Map() };
    for (const r of Array.isArray(relations) ? relations : []) {
      if (!isObj(r)) continue;
      const a = resolveComponent(r.from, areas);
      const b = resolveComponent(r.to, areas);
      if (!a || !b || a === b) continue;
      const kind = lc(r.kind).trim() || "related";
      const conf = lc(r.confidence).trim();
      const layer = kind === "imports" || (skeleton && conf === "mechanical") ? "imports" : "links";
      const key = [a.name, b.name].sort().join("\0");
      const map = layers[layer];
      let e = map.get(key);
      if (!e) {
        e = { from: a.name, to: b.name, bidir: false, layer, kinds: [], items: [], inferred: true };
        map.set(key, e);
      } else if (e.from !== a.name) {
        e.bidir = true;
      }
      if (!e.kinds.includes(kind)) e.kinds.push(kind);
      const ev = isObj(r.evidence) ? r.evidence : null;
      e.items.push({
        from: a.name,
        to: b.name,
        kind,
        confidence: conf,
        path: ev ? normPath(ev.path) : "",
        line: ev && ev.line ? ev.line : null,
        note: String(r.note || ""),
      });
      if (conf !== "inferred") e.inferred = false;
    }
    return { links: [...layers.links.values()], imports: [...layers.imports.values()] };
  }

  /** Tooltip text for a deduplicated edge. */
  function edgeTitle(e) {
    return e.items
      .map((it) => {
        const loc = it.path ? ` · ${it.path}${it.line ? ":" + it.line : ""}` : " · no citation";
        const conf = it.confidence === "inferred" ? " (inferred)" : "";
        return `${it.from} → ${it.to}: ${it.kind}${conf}${loc}${it.note ? " — " + it.note : ""}`;
      })
      .join("\n");
  }

  /** Zones for the map: explicit (v2 / skeleton) or the heuristic fallback (v1). */
  function zoneModel(areas, snap) {
    const src = selectSource(snap);
    if (src.kind === "v2" || src.kind === "skeleton") {
      const zlist = Array.isArray(src.arch.zones) ? src.arch.zones : [];
      const zones = {};
      const used = new Map();
      let any = false;
      for (const a of areas) {
        if (a.source !== "recon") {
          zones[a.name] = "other";
          continue;
        }
        const z = resolveZone(a.zone, zlist);
        if (z) {
          any = true;
          zones[a.name] = z.id;
          if (!used.has(z.id)) used.set(z.id, z);
        } else {
          zones[a.name] = "unzoned";
        }
      }
      if (!any) {
        const extras = areas.some((a) => a.source !== "recon");
        if (!extras) return { zones: null, bands: [], guessed: false };
      }
      const order = (z) => {
        const k = ZONE_KIND_BY_ID[z.kind];
        const declared = zlist.findIndex((x) => isObj(x) && lc(x.id) === lc(z.id));
        return (k ? k.rank : ZONE_KINDS.length) * 1000 + (declared < 0 ? 999 : declared);
      };
      const bands = [...used.values()].sort((x, y) => order(x) - order(y)).map((z) => {
        const k = ZONE_KIND_BY_ID[z.kind];
        return { id: z.id, kind: z.kind, label: z.label, tone: k ? k.tone : "other", hint: z.description || (k ? k.label : z.label), guessed: false };
      });
      bands.push({ id: "unzoned", kind: "", label: "No zone", tone: "other", hint: "Recon did not place these components in a zone", guessed: false });
      bands.push({ id: "other", kind: "", label: ZONES[3].label, tone: "other", hint: ZONES[3].hint, guessed: false });
      return { zones, bands, guessed: false };
    }
    const zones = assignZones(areas, snap);
    const bands = ZONES.map((z) => Object.assign({}, z, { tone: z.id, guessed: z.id !== "other", hint: z.id !== "other" ? `${z.hint}. ${GUESSED_TIP}` : z.hint }));
    return { zones, bands, guessed: !!zones };
  }

  /* ---------- orthogonal routing ---------- */

  function clamp(v, lo, hi) {
    return Math.max(lo, Math.min(hi, v));
  }

  function simplifyPoints(pts) {
    const out = [];
    for (const p of pts) {
      const q = out[out.length - 1];
      if (q && Math.abs(q[0] - p[0]) < 0.01 && Math.abs(q[1] - p[1]) < 0.01) continue;
      out.push(p);
    }
    // Drop middle points of collinear runs.
    for (let i = out.length - 2; i >= 1; i--) {
      const [a, b, c] = [out[i - 1], out[i], out[i + 1]];
      const colX = Math.abs(a[0] - b[0]) < 0.01 && Math.abs(b[0] - c[0]) < 0.01;
      const colY = Math.abs(a[1] - b[1]) < 0.01 && Math.abs(b[1] - c[1]) < 0.01;
      if (colX || colY) out.splice(i, 1);
    }
    return out;
  }

  function pointsToD(pts) {
    return pts.map((p, i) => `${i ? "L" : "M"}${Math.round(p[0] * 10) / 10} ${Math.round(p[1] * 10) / 10}`).join(" ");
  }

  /**
   * Orthogonal route from node `a` to node `b` over a `layoutMap` result. Lines run
   * in the gutters between rows and between columns (every node sits on one column
   * grid), so they do not cross a third node. Start and end points sit on the node
   * borders. `opts.lane` shifts the line a few px so parallel routes stay apart.
   * Returns {points, d}.
   */
  function routeEdge(a, b, layout, opts) {
    const g = Object.assign({ gapX: 20, gapY: 20 }, (layout && layout.grid) || {});
    const lane = (opts && opts.lane) || 0;
    const offX = clamp(lane * 4, -(g.gapX / 2 - 3), g.gapX / 2 - 3);
    const offY = clamp(lane * 4, -(g.gapY / 2 - 3), g.gapY / 2 - 3);
    const nodes = ((layout && layout.nodes) || []).filter((n) => n !== a && n !== b && n.name !== a.name && n.name !== b.name);
    const cx = (n) => n.x + n.w / 2;
    const cy = (n) => n.y + n.h / 2;
    const inset = (n) => Math.min(Math.abs(offX), n.w / 2 - 4) * Math.sign(offX);
    let pts;
    if (Math.abs(a.y - b.y) < 1) {
      const [l, r] = a.x < b.x ? [a, b] : [b, a];
      const between = nodes.some((n) => Math.abs(n.y - a.y) < 1 && n.x > l.x && n.x < r.x);
      if (!between) {
        const y = cy(a) + clamp(offY, -(a.h / 2 - 4), a.h / 2 - 4);
        pts = a.x < b.x ? [[a.x + a.w, y], [b.x, y]] : [[a.x, y], [b.x + b.w, y]];
      } else {
        const yc = a.y + a.h + g.gapY / 2 + offY;
        const ax = cx(a) + inset(a);
        const bx = cx(b) + inset(b);
        pts = [[ax, a.y + a.h], [ax, yc], [bx, yc], [bx, b.y + b.h]];
      }
    } else {
      const down = b.y > a.y;
      const y1 = down ? a.y + a.h : a.y;
      const y2 = down ? b.y : b.y + b.h;
      const ya = down ? y1 + g.gapY / 2 + offY : y1 - g.gapY / 2 + offY;
      const yb = down ? y2 - g.gapY / 2 + offY : y2 + g.gapY / 2 + offY;
      const ax = cx(a) + inset(a);
      const bx = cx(b) + inset(b);
      const lo = Math.min(y1, y2);
      const hi = Math.max(y1, y2);
      const rowsBetween = nodes.some((n) => n.y >= lo - 0.5 && n.y + n.h <= hi + 0.5);
      if (!rowsBetween) {
        pts = Math.abs(ax - bx) < 0.5 ? [[ax, y1], [bx, y2]] : [[ax, y1], [ax, ya], [bx, ya], [bx, y2]];
      } else {
        const sameCol = Math.abs(a.x - b.x) < 1;
        const vx = (!sameCol && cx(a) < cx(b) ? b.x - g.gapX / 2 : b.x + b.w + g.gapX / 2) + offX;
        pts = [[ax, y1], [ax, ya], [vx, ya], [vx, yb], [bx, yb], [bx, y2]];
      }
    }
    const points = simplifyPoints(pts);
    return { points, d: pointsToD(points) };
  }

  /** Point halfway along a polyline (by length). */
  function polylineMid(points) {
    const pts = points || [];
    if (pts.length < 2) return pts[0] ? pts[0].slice() : [0, 0];
    let total = 0;
    for (let i = 1; i < pts.length; i++) total += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
    let left = total / 2;
    for (let i = 1; i < pts.length; i++) {
      const seg = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
      if (seg >= left && seg > 0) {
        const t = left / seg;
        return [pts[i - 1][0] + (pts[i][0] - pts[i - 1][0]) * t, pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * t];
      }
      left -= seg;
    }
    return pts[pts.length - 1].slice();
  }

  /** First point where an orthogonal polyline enters `band` (a rect), or null. */
  function bandEntryPoint(points, band) {
    const inside = (p) => p[0] >= band.x && p[0] <= band.x + band.w && p[1] >= band.y && p[1] <= band.y + band.h;
    const pts = points || [];
    if (!pts.length || inside(pts[0])) return null;
    for (let i = 1; i < pts.length; i++) {
      const [p, q] = [pts[i - 1], pts[i]];
      if (!inside(q) && !(Math.min(p[0], q[0]) <= band.x + band.w && Math.max(p[0], q[0]) >= band.x && Math.min(p[1], q[1]) <= band.y + band.h && Math.max(p[1], q[1]) >= band.y)) continue;
      // Walk the segment to the first edge crossing.
      const cands = [];
      if (Math.abs(p[0] - q[0]) < 0.01) {
        for (const yy of [band.y, band.y + band.h]) if ((yy - p[1]) * (yy - q[1]) <= 0) cands.push([p[0], yy]);
      } else {
        for (const xx of [band.x, band.x + band.w]) if ((xx - p[0]) * (xx - q[0]) <= 0) cands.push([xx, p[1]]);
      }
      const hits = cands.filter(inside).sort((m, n) => Math.hypot(m[0] - p[0], m[1] - p[1]) - Math.hypot(n[0] - p[0], n[1] - p[1]));
      if (hits.length) return hits[0];
    }
    return null;
  }

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
    const src = selectSource(s);
    const explicit = src.kind === "v2" || src.kind === "skeleton";
    const rawComps = explicit
      ? src.arch.components
      : Array.isArray(sum.components) && sum.components.length
        ? sum.components
        : Array.isArray(arch.components) ? arch.components : [];
    const out = [];
    const seen = new Set();
    const locs = (xs) => (Array.isArray(xs) ? xs.filter((x) => isObj(x)) : []);
    for (const c of rawComps) {
      const name = typeof c === "string" ? c.trim() : String((c && (c.name || c.id)) || "").trim();
      if (!name || seen.has(lc(name))) continue;
      seen.add(lc(name));
      const obj = isObj(c) ? c : {};
      const id = String(obj.id || "").trim();
      if (id) seen.add(lc(id));
      const hints = Array.isArray(obj.path_hints) ? obj.path_hints : [];
      out.push({
        name,
        id,
        role: String(obj.role || obj.description || ""),
        path_hints: hints.map(normPath).filter(Boolean),
        source: "recon",
        origin: explicit ? String(obj.origin || (src.kind === "skeleton" ? "mechanical" : "recon")) : "recon",
        kind: String(obj.kind || ""),
        zone: explicit ? String(obj.zone || "") : "",
        entrypoints: explicit ? locs(obj.entrypoints) : [],
        sinks: explicit ? locs(obj.sinks) : [],
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
      out.push({ name, id: "", role: "", path_hints: hints.slice(0, 12), source: "coverage", origin: "coverage", kind: "", zone: "", entrypoints: [], sinks: [] });
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
  function areaCoverage(area, snap, skills, live) {
    const s = snap || {};
    const cells = (s.coverage && s.coverage.cells) || [];
    const lw = live || liveWork(s.tasks);
    const areaName = isObj(area) ? area.name : area;
    // A v2 component may be hunted under its id or its name.
    const names = new Set((isObj(area) ? [area.name, area.id] : [area]).filter(Boolean).map(lc));
    const byClass = {};
    for (const c of cells) {
      if (c && names.has(lc(c.area)) && (!byClass[lc(c.class)] || lc(c.area) === lc(areaName))) byClass[lc(c.class)] = c;
    }
    return (skills || []).map((skill) => {
      const cell = byClass[lc(skill)];
      let state = cellState(cell && cell.last_depth);
      if ([...names].some((n) => lw.cells.has(n + "\0" + lc(skill)))) state = "running";
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
    const o = Object.assign({ width: 900, nodeW: 168, nodeH: 76, gapX: 36, gapY: 30, pad: 20, bandHead: 30 }, opts || {});
    const cols = Math.max(1, Math.floor((o.width - o.pad * 2 + o.gapX) / (o.nodeW + o.gapX)));
    const nodes = [];
    const bands = [];
    let y = o.pad;
    let row = 0;
    const zoneList = Array.isArray(o.bands) && o.bands.length ? o.bands : ZONES;
    const known = new Set(zoneList.map((z) => z.id));
    const fallbackZone = known.has("internal") ? "internal" : zoneList[zoneList.length - 1].id;
    const groups = zones
      ? zoneList.map((z) => ({
          zone: z,
          items: areas.filter((a) => (known.has(zones[a.name]) ? zones[a.name] : fallbackZone) === z.id),
        }))
      : [{ zone: null, items: areas.slice() }];
    for (const g of groups) {
      if (!g.items.length) continue;
      const rows = Math.ceil(g.items.length / cols);
      const head = g.zone ? o.bandHead : 0;
      const bandH = head + rows * o.nodeH + (rows - 1) * o.gapY + (g.zone ? o.pad : 0);
      if (g.zone) {
        bands.push({
          id: g.zone.id,
          label: g.zone.label,
          hint: g.zone.hint,
          tone: g.zone.tone || g.zone.id,
          guessed: !!g.zone.guessed,
          x: o.pad / 2,
          y,
          w: o.width - o.pad,
          h: bandH,
        });
      }
      g.items.forEach((a, i) => {
        const r = Math.floor(i / cols);
        const c = i % cols;
        nodes.push({
          name: a.name,
          zone: g.zone ? g.zone.id : null,
          row: row + r,
          col: c,
          x: o.pad + c * (o.nodeW + o.gapX),
          y: y + head + r * (o.nodeH + o.gapY),
          w: o.nodeW,
          h: o.nodeH,
        });
      });
      row += rows;
      y += bandH + (g.zone ? o.gapY : 0);
    }
    const height = Math.max(y + (zones ? 0 : o.pad), o.nodeH + o.pad * 2);
    return {
      width: o.width,
      height,
      nodes,
      bands,
      cols,
      grid: { pad: o.pad, nodeW: o.nodeW, nodeH: o.nodeH, gapX: o.gapX, gapY: o.gapY },
    };
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
    const own = ((area && area.sinks) || []).filter((k) => k && k.path);
    if (own.length) return own;
    const s = snap || {};
    const arch = s.architecture && typeof s.architecture === "object" ? s.architecture : {};
    const inv = arch.inventory && typeof arch.inventory === "object" ? arch.inventory : {};
    const raw = Array.isArray(arch.seed_sinks) ? arch.seed_sinks : Array.isArray(inv.seed_sinks) ? inv.seed_sinks : [];
    return raw.filter((k) => k && typeof k === "object" && area.path_hints.some((h) => pathUnder(k.path, h)));
  }

  function entrypointsForArea(area, snap) {
    const s = snap || {};
    const out = [];
    // v2 component entrypoints carry path:line; prefer them.
    for (const e of (area && area.entrypoints) || []) {
      if (e && (e.label || e.path)) out.push({ label: String(e.label || normPath(e.path)), path: normPath(e.path), line: e.line || null });
    }
    if (out.length) return out;
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
    ZONE_KINDS,
    V2_SCHEMA,
    GUESSED_TIP,
    isV2,
    selectSource,
    resolveZone,
    zoneShort,
    zoneModel,
    resolveComponent,
    flowComponentPath,
    flowSteps,
    flowFiles,
    flowNote,
    flowCrossing,
    flowsForArea,
    flowHuntArea,
    flowSkills,
    buildEdges,
    edgeTitle,
    routeEdge,
    polylineMid,
    bandEntryPoint,
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
    leftTab: "files", // files | flows
    layers: { flows: true, links: true, imports: false },
    flow: null, // selected flow id
    flowComposer: {}, // flow id -> {skills:Set, notes}
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
    const src = H.selectSource(s);
    const areas = H.buildAreas(s);
    const zm = H.zoneModel(areas, s);
    const zones = zm.zones;
    const skills = H.skillColumns(s);
    const live = H.liveWork(s.tasks);
    const byArea = H.findingsByArea(s.findings, areas);
    const cov = {};
    const gapAreas = new Set();
    for (const a of areas) {
      cov[a.name] = H.areaCoverage(a, s, skills, live);
      if (H.gapSkills(cov[a.name]).length) gapAreas.add(a.name);
    }
    const sum = s.architecture_summary || {};
    const hasArch = src.kind !== "none" || !!(sum.has_architecture || (s.architecture && Object.keys(s.architecture).length));
    const explicit = src.kind === "v2" || src.kind === "skeleton";
    const relations = explicit
      ? src.arch.relations || []
      : (sum.relations && sum.relations.length ? sum.relations : (s.architecture || {}).relations) || [];
    const edges = H.buildEdges(relations, areas, { skeleton: src.kind === "skeleton" });
    const flows = (explicit && Array.isArray(src.arch.flows) ? src.arch.flows : [])
      .filter((f) => f && typeof f === "object")
      .map((f, i) => (f.id ? f : Object.assign({}, f, { id: `flow-${i + 1}` })));
    const zoneList = explicit && Array.isArray(src.arch.zones) ? src.arch.zones : [];
    return { src, areas, zones, zm, zoneList, skills, live, byArea, cov, gapAreas, hasArch, sum, edges, flows };
  }

  function selectedFlow(m) {
    return state.flow ? m.flows.find((f) => String(f.id) === String(state.flow)) || null : null;
  }

  /* ---------- skeleton ---------- */

  function build() {
    const el = state.root;
    el.innerHTML = `
    <div class="atlas">
      <aside class="atlas-tree" aria-label="Target files and data flows">
        <div class="atlas-seg atlas-left-tabs" role="tablist" aria-label="Left panel">
          <button type="button" role="tab" data-left-tab="files" aria-pressed="true" aria-selected="true">Files</button>
          <button type="button" role="tab" data-left-tab="flows" aria-pressed="false" aria-selected="false">Flows <span class="atlas-tab-count" id="atlas-flow-count"></span></button>
        </div>
        <div class="atlas-left-pane" id="atlas-pane-files">
          <label class="atlas-tree-search">
            <span class="visually-hidden">Filter files</span>
            <input type="search" id="atlas-tree-filter" placeholder="Filter loaded files…" autocomplete="off">
          </label>
          <ul class="atlas-tree-list" id="atlas-tree-list" role="tree" aria-label="Target tree"></ul>
          <p class="atlas-tree-foot vf-faint">Read-only target. <span class="atlas-legend-chip is-gap">gap</span> = an area with skills not hunted, too shallow or aborted. <span class="atlas-legend-chip is-live">live</span> = a hunt is running here.</p>
        </div>
        <div class="atlas-left-pane" id="atlas-pane-flows" hidden>
          <ul class="atlas-flows" id="atlas-flows" aria-label="Data flows"></ul>
          <p class="atlas-tree-foot vf-faint">Flows are recon hints about how data moves, not proof of a bug. Swatches show the hunt state of each flow class on the sink area.</p>
        </div>
      </aside>

      <main class="atlas-main">
        <div class="atlas-head">
          <h1 class="atlas-title">Architecture</h1>
          <span class="atlas-meta" id="atlas-meta"></span>
          <span class="vf-spacer"></span>
          <div class="atlas-seg" role="group" aria-label="Arrow layers" id="atlas-layer-group">
            <button type="button" data-layer="flows" aria-pressed="true" title="Recon data flows: source → steps → sink">Flows</button>
            <button type="button" data-layer="links" aria-pressed="true" title="Recon relations between components (dashed = inferred, no citation)">Links</button>
            <button type="button" data-layer="imports" aria-pressed="false" title="Module imports (mechanical)">Imports</button>
          </div>
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
          <p class="atlas-honesty vf-faint">Arrows are recon's map of how data moves. Not proof of a bug; no arrow is not proof of safety.</p>
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
    const layer = t.closest("[data-layer]");
    if (layer) {
      const k = layer.dataset.layer;
      state.layers[k] = !state.layers[k];
      paintMap();
      return;
    }
    const tab = t.closest("[data-left-tab]");
    if (tab) {
      setLeftTab(tab.dataset.leftTab);
      return;
    }
    if (t.closest("[data-flow-clear]")) {
      selectFlow(null);
      return;
    }
    const fskill = t.closest("[data-flow-skill]");
    if (fskill) {
      const fc = flowComposerFor(state.flow);
      const k = fskill.dataset.flowSkill;
      if (fc.skills.has(k)) fc.skills.delete(k);
      else fc.skills.add(k);
      paintInspector();
      return;
    }
    if (t.closest("#atlas-flow-enqueue")) {
      enqueueFlow();
      return;
    }
    const flowEl = t.closest("[data-flow]");
    if (flowEl) {
      selectFlow(String(flowEl.dataset.flow) === String(state.flow) && flowEl.closest(".atlas-flows, .atlas-edges") ? null : flowEl.dataset.flow);
      return;
    }
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
    const fnotes = ev.target.closest("#atlas-flow-notes");
    if (fnotes && state.flow) flowComposerFor(state.flow).notes = fnotes.value;
  }

  function setLeftTab(tab) {
    state.leftTab = tab === "flows" ? "flows" : "files";
    const root = state.root;
    $("#atlas-pane-files", root).hidden = state.leftTab !== "files";
    $("#atlas-pane-flows", root).hidden = state.leftTab !== "flows";
    root.querySelectorAll("[data-left-tab]").forEach((b) => {
      const on = b.dataset.leftTab === state.leftTab;
      b.setAttribute("aria-pressed", String(on));
      b.setAttribute("aria-selected", String(on));
    });
    if (state.leftTab === "flows") paintFlows();
  }

  function selectFlow(id) {
    state.flow = id == null || id === "" ? null : String(id);
    if (state.flow && state.view !== "map") setView("map");
    paintMap();
    paintFlows();
    paintInspector();
  }

  function flowComposerFor(id) {
    const key = String(id);
    if (!state.flowComposer[key]) {
      const m = model(state.snap);
      const flow = m.flows.find((f) => String(f.id) === key);
      const cat = (state.snap && state.snap.hunt_classes) || {};
      const active = (cat.active && cat.active.length ? cat.active : m.skills) || [];
      state.flowComposer[key] = {
        skills: new Set(H.flowSkills(flow, active)),
        notes: flow ? H.flowNote(flow) : "",
      };
    }
    return state.flowComposer[key];
  }

  function setView(v) {
    state.view = v === "code" ? "code" : "map";
    const root = state.root;
    $("#atlas-map-view", root).hidden = state.view !== "map";
    $("#atlas-code-view", root).hidden = state.view !== "code";
    $("#atlas-shade-group", root).hidden = state.view !== "map";
    $("#atlas-layer-group", root).hidden = state.view !== "map";
    root.querySelectorAll("[data-view]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.view === state.view)));
    if (state.view === "map") paintMap(); // re-fit: the map may have been laid out while hidden
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
    state.flow = null;
    paintMap();
    paintFlows();
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
    const ncomp = m.areas.filter((a) => a.source === "recon").length;
    if (m.src.kind === "skeleton") {
      bits.push(`${ncomp} modules`, `<span class="vf-pill">mechanical</span>`);
    } else if (m.hasArch) {
      bits.push(`${ncomp} components`);
      if (agents.length) bits.push(`merged from ${agents.length} recon agent${agents.length === 1 ? "" : "s"}`);
      if (m.src.kind === "v2" && m.flows.length) bits.push(`${m.flows.length} flow${m.flows.length === 1 ? "" : "s"}`);
    } else {
      bits.push("no architecture yet");
    }
    const reconRunning = (s.tasks || []).some((t) => t.kind === "recon" && ["leased", "running", "queued"].includes(String(t.state)));
    if (reconRunning) bits.push(`<span class="atlas-meta-live">recon in progress</span>`);
    meta.innerHTML = bits.join(" · ");
    const summ = $("#atlas-summary", state.root);
    const text = String((m.src.kind !== "v1" && m.src.arch && m.src.arch.summary) || sum.summary || "").trim();
    if (m.src.kind === "skeleton") {
      summ.innerHTML = `<span class="atlas-skeleton-note">Mechanical skeleton — recon has not labelled this yet.</span> <span class="vf-faint">Modules, zones and imports come from static facts only. Run recon to name components and trace data flows.</span>`;
      summ.hidden = false;
      return;
    }
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

  const markers = (prefix) => `<defs>${["flow", "link", "import"]
    .map(
      (k) => `<marker id="${prefix}-${k}" class="atlas-ah atlas-ah--${k}" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="${k === "flow" ? 10 : 8}" markerHeight="${k === "flow" ? 10 : 8}" orient="auto-start-reverse"><path d="M0 0.5L10 5L0 9.5z"/></marker>`
    )
    .join("")}</defs>`;

  /** SVG for the three arrow layers. Pure string building over the layout. */
  function edgesSvg(m, lay, flow) {
    const nodeBy = {};
    for (const n of lay.nodes) nodeBy[n.name] = n;
    const parts = [];
    const dimOthers = !!flow;
    const linkG = (e, i, cls) => {
      const a = nodeBy[e.from];
      const b = nodeBy[e.to];
      if (!a || !b) return "";
      const r = H.routeEdge(a, b, lay, { lane: cls === "import" ? 2 : i % 2 ? 3 : -3 });
      const ev = e.items.find((it) => it.path);
      const dashed = e.inferred ? " is-inferred" : "";
      const ends = `marker-end="url(#atlas-ah-${cls})"${e.bidir ? ` marker-start="url(#atlas-ah-${cls})"` : ""}`;
      return `<g class="atlas-edge atlas-edge--${cls}${dashed}${dimOthers ? " is-dim" : ""}"${ev ? ` data-reveal="${esc(ev.path)}" data-line="${esc(ev.line || "")}"` : ""}>
        <title>${esc(H.edgeTitle(e))}${ev ? "\nClick to open the cited line." : ""}</title>
        <path class="atlas-edge-hit" d="${r.d}"/><path class="atlas-edge-line" d="${r.d}" ${ends}/></g>`;
    };
    if (state.layers.imports) m.edges.imports.forEach((e, i) => parts.push(linkG(e, i, "import")));
    if (state.layers.links) m.edges.links.forEach((e, i) => parts.push(linkG(e, i, "link")));
    const overlay = [];
    const drawFlows = m.flows.filter((f) => state.layers.flows || f === flow);
    // Selected flow last so it sits on top.
    drawFlows.sort((x, y) => (x === flow ? 1 : 0) - (y === flow ? 1 : 0));
    const zoneOf = (name) => (m.zones ? m.zones[name] : null);
    drawFlows.forEach((f) => {
      const fi = m.flows.indexOf(f);
      const path = H.flowComponentPath(f, m.areas).filter((n) => nodeBy[n]);
      const on = flow && f === flow;
      const dim = flow && !on;
      const cls = `atlas-edge atlas-edge--flow${f.confidence === "inferred" ? " is-inferred" : ""}${on ? " is-on" : ""}${dim ? " is-dim" : ""}`;
      const title = `${f.title || f.id}${f.confidence ? ` (${f.confidence})` : ""}`;
      for (let i = 0; i + 1 < path.length; i++) {
        const a = nodeBy[path[i]];
        const b = nodeBy[path[i + 1]];
        const r = H.routeEdge(a, b, lay, { lane: on ? 0 : (fi % 3) - 1 });
        parts.push(`<g class="${cls}" data-flow="${esc(f.id)}"><title>${esc(`Flow: ${title}\nHop ${i + 1}: ${a.name} → ${b.name}\nClick to select this flow.`)}</title>
          <path class="atlas-edge-hit" d="${r.d}"/><path class="atlas-edge-line" d="${r.d}" marker-end="url(#atlas-ah-flow)"/></g>`);
        if (dim) continue;
        const mid = H.polylineMid(r.points);
        overlay.push(`<g class="atlas-step-dot${on ? " is-on" : ""}" aria-hidden="true"><circle cx="${mid[0]}" cy="${mid[1]}" r="${on ? 8 : 7}"/><text x="${mid[0]}" y="${mid[1]}">${i + 1}</text></g>`);
        const za = zoneOf(a.name);
        const zb = zoneOf(b.name);
        if (za && zb && za !== zb) {
          const band = lay.bands.find((bd) => bd.id === zb);
          const p = band && H.bandEntryPoint(r.points, band);
          if (p) {
            overlay.push(`<g class="atlas-cross${on ? " is-on" : ""}"><title>${esc(`Crosses into ${band.label}`)}</title><rect x="${p[0] - 4.5}" y="${p[1] - 4.5}" width="9" height="9" transform="rotate(45 ${p[0]} ${p[1]})"/></g>`);
          }
        }
      }
    });
    if (!parts.length && !overlay.length) return "";
    return `<svg class="atlas-edges" width="${lay.width}" height="${lay.height}" viewBox="0 0 ${lay.width} ${lay.height}">${markers("atlas-ah")}${parts.join("")}${overlay.join("")}</svg>`;
  }

  function arrowSwatch(cls, extra) {
    return `<svg class="atlas-arrow-key atlas-edge atlas-edge--${cls}${extra || ""}" width="28" height="10" aria-hidden="true"><path class="atlas-edge-line" d="M1 5H21" marker-end="url(#atlas-lg-${cls})"/></svg>`;
  }

  function paintMap() {
    const scroll = state.root && $("#atlas-map-scroll", state.root);
    if (!scroll) return;
    const m = model(state.snap);
    paintMeta(m);
    state.root.querySelectorAll("[data-shade]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.shade === state.shade)));
    state.root.querySelectorAll("[data-layer]").forEach((b) => b.setAttribute("aria-pressed", String(!!state.layers[b.dataset.layer])));

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
      $(".atlas-honesty", state.root).hidden = true;
      return;
    }
    $(".atlas-honesty", state.root).hidden = false;

    const flow = selectedFlow(m);
    if (state.flow && !flow) state.flow = null;
    const onPath = new Set(flow ? H.flowComponentPath(flow, m.areas) : []);
    const width = Math.max(560, Math.min(1400, scroll.clientWidth - 2 || 900));
    const lay = H.layoutMap(m.areas, m.zones, { width, bands: m.zm.bands });
    if (!state.selected || !m.areas.some((a) => a.name === state.selected)) {
      const ranked = m.areas.slice().sort((a, b) => H.openCount(m.cov[b.name]) - H.openCount(m.cov[a.name]));
      state.selected = ranked[0].name;
    }

    const bandsHtml = lay.bands
      .map(
        (b) => `<div class="atlas-zone is-${esc(b.tone)}" style="left:${b.x}px;top:${b.y}px;width:${b.w}px;height:${b.h}px" title="${esc(b.hint)}"><span class="atlas-zone-label">${esc(b.label)}${b.guessed ? ` <span class="atlas-guessed" title="${esc(H.GUESSED_TIP)}">guessed</span>` : ""}</span></div>`
      )
      .join("");
    const edgesHtml = edgesSvg(m, lay, flow);
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
        const roleKind = area.role ? area.role.split(/[.;\n]/)[0].slice(0, 42) : "";
        const kind = roleKind || (area.kind ? area.kind.replace(/_/g, " ") : area.source === "recon" ? "component" : "hunted area");
        const flowCls = flow ? (onPath.has(n.name) ? " is-onflow" : " is-dim") : "";
        const selected = !flow && state.selected === n.name;
        return `<button type="button" class="atlas-node is-${tone}${selected ? " is-selected" : ""}${flowCls}" data-area="${esc(n.name)}"
            style="left:${n.x}px;top:${n.y}px;width:${n.w}px;height:${n.h}px"
            aria-pressed="${selected}"
            aria-label="${esc(`${n.name}: ${open} of ${cov.length} skill cells open, ${fcount} finding${fcount === 1 ? "" : "s"}`)}">
          <span class="atlas-node-top"><span class="atlas-node-name">${esc(n.name)}</span>${isLive ? '<span class="atlas-node-live" title="Hunt running">●</span>' : ""}${fcount ? `<span class="atlas-pin" title="${fcount} finding(s) filed">${fcount}</span>` : ""}</span>
          <span class="atlas-node-kind">${esc(kind)}</span>
          <span class="atlas-skillbar" aria-hidden="true">${bar}</span>
        </button>`;
      })
      .join("");
    scroll.innerHTML = `<div class="atlas-map${flow ? " has-flow" : ""}" style="width:${lay.width}px;height:${lay.height}px">${bandsHtml}${edgesHtml}${nodesHtml}</div>`;

    const hasLinks = m.edges.links.length > 0;
    const hasInferred = m.edges.links.some((e) => e.inferred) || m.flows.some((f) => f.confidence === "inferred");
    const arrows = [
      m.flows.length ? `<li title="A recon data flow, source to sink. Numbers are hops; ◆ marks a zone crossing.">${arrowSwatch("flow")}Flow</li>` : "",
      hasLinks ? `<li title="A recon relation between components, with a cited line">${arrowSwatch("link")}Link</li>` : "",
      hasInferred ? `<li title="Inferred: recon gave no citation for this arrow">${arrowSwatch("link", " is-inferred")}Inferred (dashed)</li>` : "",
      m.edges.imports.length ? `<li title="Module import (mechanical)">${arrowSwatch("import")}Import</li>` : "",
    ].join("");
    $("#atlas-legend", state.root).innerHTML =
      (arrows ? `<li class="atlas-legend-svg"><svg width="0" height="0" aria-hidden="true">${markers("atlas-lg")}</svg></li>${arrows}<li class="atlas-legend-sep" aria-hidden="true"></li>` : "") +
      H.STATE_ORDER.map((k) => `<li title="${esc(H.STATE_TIP[k] || "")}"><span class="vf-cell vf-cell--${k}" aria-hidden="true"></span>${esc(H.STATE_LABEL[k])}</li>`).join("") +
      `<li class="vf-faint">${state.shade === "risk" ? "Shading = share of open cells (not hunted, too shallow, aborted or nothing found). Calm is not proof of safety." : "Shading = areas with filed findings. No pin is not proof of safety."}</li>`;
  }

  /* ---------- flows panel ---------- */

  function flowStateSwatches(flow, m) {
    const area = H.flowHuntArea(flow, m.areas);
    const classes = (flow.classes || []).map(String).filter(Boolean);
    if (!classes.length) return `<span class="vf-faint">no classes</span>`;
    const cov = area ? H.areaCoverage(area, state.snap, classes, m.live) : classes.map((skill) => ({ skill, state: "empty", label: H.STATE_LABEL.empty }));
    return cov
      .map((c) => `<span class="atlas-flow-sw" title="${esc(`${c.skill} on ${area ? area.name : "sink"}: ${c.label}. ${H.STATE_TIP[c.state] || ""}`)}"><span class="vf-cell vf-cell--${c.state}" aria-hidden="true"></span>${esc(c.skill)}</span>`)
      .join("");
  }

  function crossingBadge(flow, m) {
    const x = H.flowCrossing(flow, m.areas, m.zoneList);
    return x ? `<span class="atlas-crossing" title="Crosses trust zones">${esc(x.from)} → ${esc(x.to)}</span>` : "";
  }

  function confPill(conf) {
    const c = String(conf || "").toLowerCase();
    if (!c) return "";
    return `<span class="atlas-conf is-${c === "cited" ? "cited" : "inferred"}" title="${c === "cited" ? "Each step cites a file and line" : "Some steps have no citation"}">${esc(c)}</span>`;
  }

  function paintFlows() {
    const el = state.root && $("#atlas-flows", state.root);
    if (!el) return;
    const m = model(state.snap);
    const count = $("#atlas-flow-count", state.root);
    if (count) count.textContent = m.flows.length ? String(m.flows.length) : "";
    if (!m.flows.length) {
      el.innerHTML = `<li class="vf-empty atlas-flows-empty">No data flows traced yet. Recon's flow tracer adds them; until then, Links and Imports show structure only.</li>`;
      return;
    }
    el.innerHTML = m.flows
      .map((f) => {
        const on = String(f.id) === String(state.flow);
        const src = (f.source && (f.source.label || f.source.component)) || "source";
        const sink = (f.sink && (f.sink.kind || f.sink.component)) || "sink";
        return `<li><button type="button" class="atlas-flow${on ? " is-on" : ""}" data-flow="${esc(f.id)}" aria-pressed="${on}">
          <span class="atlas-flow-title">${esc(f.title || f.id)}</span>
          <span class="atlas-flow-ends vf-mono">${esc(src)} → ${esc(sink)}</span>
          <span class="atlas-flow-meta">${crossingBadge(f, m)}${confPill(f.confidence)}</span>
          <span class="atlas-flow-states">${flowStateSwatches(f, m)}</span>
        </button></li>`;
      })
      .join("");
  }

  /* ---------- inspector ---------- */

  function paintInspector() {
    const el = state.root && $("#atlas-inspector", state.root);
    if (!el) return;
    const m = model(state.snap);
    const flow = selectedFlow(m);
    if (flow) {
      paintFlowInspector(el, flow, m);
      return;
    }
    const area = m.areas.find((a) => a.name === state.selected);
    if (!area) {
      el.innerHTML = `<p class="vf-empty">Select an area on the map to see its coverage, findings and hunts.</p>`;
      return;
    }
    const zone = m.zones ? m.zm.bands.find((z) => z.id === m.zones[area.name]) || null : null;
    const through = H.flowsForArea(m.flows, m.areas, area.name);
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
      ? eps.slice(0, 6).map((e) => e.path ? `<button type="button" class="atlas-path" data-reveal="${esc(e.path)}" data-line="${esc(e.line || "")}" title="${esc(e.path + (e.line ? ":" + e.line : ""))}">${esc(e.label)}${e.line && e.label !== e.path ? ` <span class="vf-faint">${esc(H.normPath(e.path))}:${esc(e.line)}</span>` : ""}</button>` : `<span>${esc(e.label)}</span>`).join("")
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
        ${zone ? `<span class="atlas-zone-tag is-${esc(zone.tone || zone.id)}"${zone.guessed ? ` title="${esc(H.GUESSED_TIP)}"` : ""}>${esc(zone.label)}${zone.guessed ? " · guessed" : ""}</span>` : ""}
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
      ${m.flows.length ? `<section>
        <h3 class="vf-section-label">Flows through this area</h3>
        ${through.length
          ? `<ul class="atlas-through">${through
              .map((f) => `<li><button type="button" class="atlas-through-item" data-flow="${esc(f.id)}"><span>${esc(f.title || f.id)}</span>${confPill(f.confidence)}</button></li>`)
              .join("")}</ul>`
          : `<p class="vf-empty">No traced flow passes through here. That is not evidence of safety.</p>`}
      </section>` : ""}
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

  function paintFlowInspector(el, flow, m) {
    const steps = H.flowSteps(flow, m.areas);
    const huntArea = H.flowHuntArea(flow, m.areas);
    const files = H.flowFiles(flow);
    const c = flowComposerFor(flow.id);
    const options = m.skills.length ? m.skills : (flow.classes || []).map(String);
    const picked = [...c.skills].filter((k) => options.includes(k));
    const roleLabel = { source: "Source", step: "Step", sink: "Sink" };
    let n = 0;
    const stepHtml = steps
      .map((st) => {
        const num = st.role === "step" ? String(++n) : st.role === "source" ? "S" : "▼";
        const loc = st.path
          ? `<button type="button" class="atlas-path" data-reveal="${esc(st.path)}" data-line="${esc(st.line || "")}">${esc(st.path)}${st.line ? ":" + esc(st.line) : ""}</button>`
          : `<span class="vf-faint">no citation</span>`;
        return `<li class="atlas-step is-${st.role}">
          <span class="atlas-step-num" aria-hidden="true">${esc(num)}</span>
          <div class="atlas-step-body">
            <div class="atlas-step-head"><span class="atlas-step-role">${roleLabel[st.role]}</span>${st.component ? `<span class="vf-mono atlas-step-comp">${esc(st.component)}</span>` : ""}</div>
            ${st.text ? `<div class="atlas-step-text">${esc(st.text)}</div>` : ""}
            ${loc}
          </div></li>`;
      })
      .join("");
    el.innerHTML = `
      <div class="atlas-insp-head">
        <div class="atlas-row"><button type="button" class="vf-btn vf-btn--ghost atlas-back" data-flow-clear="1" title="Back to the area (Esc)">← Back</button><span class="vf-kbd">Esc</span></div>
        <span class="atlas-zone-tag">Data flow</span>
        <h2 class="atlas-insp-name atlas-flow-name">${esc(flow.title || flow.id)}</h2>
        <div class="atlas-flow-meta">${crossingBadge(flow, m)}${confPill(flow.confidence)}</div>
        <p class="vf-faint atlas-composer-hint">A recon hint about how data moves. Not proof of a bug.</p>
      </div>
      <section>
        <h3 class="vf-section-label">Steps</h3>
        <ol class="atlas-steps">${stepHtml || `<li class="vf-empty">No steps recorded.</li>`}</ol>
      </section>
      <section>
        <h3 class="vf-section-label">Hunt state on ${esc(huntArea ? huntArea.name : "sink")}</h3>
        <div class="atlas-flow-states">${flowStateSwatches(flow, m)}</div>
      </section>
      <section class="atlas-composer vf-card">
        <h3 class="atlas-composer-title">Hunt this flow</h3>
        <p class="vf-faint atlas-composer-hint">Files on area <b class="vf-mono">${esc(huntArea ? huntArea.name : "—")}</b>: ${files.length ? files.map((f) => `<span class="vf-mono">${esc(f)}</span>`).join(", ") : "none cited"}. Preselected: the flow's classes.</p>
        <div class="atlas-picked" role="group" aria-label="Skills to hunt">${options
          .map((k) => `<button type="button" class="vf-chip" aria-pressed="${c.skills.has(k)}" data-flow-skill="${esc(k)}">${esc(k)}</button>`)
          .join("") || `<span class="vf-faint">No hunt skills are active yet.</span>`}</div>
        <label class="atlas-field">Notes for the hunter
          <textarea id="atlas-flow-notes" rows="3">${esc(c.notes)}</textarea>
        </label>
        <button type="button" class="vf-btn vf-btn--primary vf-btn--lg" id="atlas-flow-enqueue" ${picked.length && huntArea ? "" : "disabled"}>Enqueue ${picked.length} hunt${picked.length === 1 ? "" : "s"}</button>
        <p class="vf-faint atlas-composer-hint">Enqueues only. Ralph runs them; nothing is confirmed without review.</p>
      </section>`;
  }

  async function enqueueFlow() {
    const m = model(state.snap);
    const flow = selectedFlow(m);
    if (!flow) return;
    const area = H.flowHuntArea(flow, m.areas);
    if (!area) return;
    const c = flowComposerFor(flow.id);
    const notesEl = $("#atlas-flow-notes", state.root);
    if (notesEl) c.notes = notesEl.value;
    const options = m.skills.length ? m.skills : (flow.classes || []).map(String);
    const skills = [...c.skills].filter((k) => options.includes(k));
    if (!skills.length) return;
    const files = H.flowFiles(flow);
    const hints = files.length ? files : area.path_hints;
    const btn = $("#atlas-flow-enqueue", state.root);
    if (btn) btn.disabled = true;
    try {
      const r = await api(`${base()}/coverage/requeue-bulk`, {
        method: "POST",
        body: JSON.stringify({
          cells: skills.map((k) => ({ area: area.name, class: k, path_hints: hints })),
          force_depth: true,
          reason: "operator_atlas_flow",
          operator_notes: (c.notes || "").trim(),
        }),
      });
      const n = r.enqueued != null ? (Array.isArray(r.enqueued) ? r.enqueued.length : r.enqueued) : skills.length;
      toast(`Enqueued ${n} hunt(s) for flow "${flow.title || flow.id}"`);
      delete state.flowComposer[String(flow.id)];
      await refresh();
    } catch (e) {
      toast(e.message, true);
      if (btn) btn.disabled = false;
    }
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
    const typing = document.activeElement && (document.activeElement.id === "atlas-composer-notes" || document.activeElement.id === "atlas-flow-notes");
    paintMap();
    paintTree();
    paintFlows();
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

  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || !state.flow || !isActive()) return;
    const a = document.activeElement;
    if (a && (a.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName))) return;
    if (document.querySelector("dialog[open], .modal-backdrop.open")) return;
    selectFlow(null);
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
