"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const H = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "pages", "atlas.js"));

function snapFixture() {
  return {
    architecture_summary: {
      has_architecture: true,
      components: [
        { name: "api", role: "REST handlers", path_hints: ["app/api"] },
        { name: "auth", role: "login and sessions", path_hints: ["app/auth/"] },
        { name: "worker", role: "background jobs", path_hints: ["./app/jobs"] },
      ],
      input_surfaces: [{ name: "HTTP routes", path_hints: ["app/api/routes.py"] }],
      trust_boundaries: ["session cookie → auth"],
      relations: [
        { from: "api", to: "worker", kind: "enqueues" },
        { from: "api", to: "ghost", kind: "calls" },
      ],
    },
    architecture: {
      seed_sinks: [
        { path: "app/api/db.py", line: 12, kind: "sql" },
        { path: "app/jobs/run.py", line: 4, kind: "exec" },
      ],
    },
    hunt_classes: { active: ["injection", "authz"] },
    coverage: {
      areas: ["api", "auth", "worker", "legacy"],
      classes: ["injection", "authz", "ssrf"],
      cells: [
        { area: "api", class: "injection", last_depth: "candidate", visit_count: 2 },
        { area: "api", class: "authz", last_depth: "shallow", visit_count: 1 },
        { area: "auth", class: "injection", last_depth: "none", visit_count: 1 },
        { area: "legacy", class: "ssrf", last_depth: "aborted", visit_count: 1 },
      ],
    },
    tasks: [
      { id: 5, kind: "hunt", state: "leased", payload: { area: "worker", class: "ssrf", path_hints: ["app/jobs"] } },
      { id: 6, kind: "hunt", state: "done", payload: { area: "legacy", class: "ssrf", path_hints: ["old/"] } },
    ],
    findings: [
      { id: 1, state: "needs_human", body: { citations: [{ path: "app/api/db.py", start_line: 12 }] } },
      { id: 2, state: "rejected_mech", body: { citations: [{ path: "app/api/db.py" }] } },
      { id: 3, state: "candidate", body: { area: "auth", citations: [{ path: "elsewhere.py" }] } },
    ],
    codemap: {
      modules: [{ path: "app/api", file_count: 7 }, { path: "app/auth", file_count: 3 }],
      entrypoints: [{ path: "app/api/main.py" }],
    },
  };
}

describe("paths", () => {
  it("normalizes and matches path hints", () => {
    assert.equal(H.normPath("./app/api/"), "app/api");
    assert.equal(H.normPath("."), "");
    assert.equal(H.pathUnder("app/api/db.py", "app/api"), true);
    assert.equal(H.pathUnder("app/apiary.py", "app/api"), false);
    assert.equal(H.pathUnder("x.py", ""), false);
    assert.equal(H.pathsOverlap("app", "app/api"), true);
  });

  it("matches whole words only", () => {
    assert.equal(H.textMentions("session cookie → auth", "auth"), true);
    assert.equal(H.textMentions("oauth flow", "auth"), false);
  });
});

describe("buildAreas / assignZones", () => {
  it("lists recon components then extra hunted areas", () => {
    const areas = H.buildAreas(snapFixture());
    assert.deepEqual(areas.map((a) => [a.name, a.source]), [
      ["api", "recon"],
      ["auth", "recon"],
      ["worker", "recon"],
      ["legacy", "coverage"],
    ]);
    assert.deepEqual(areas[2].path_hints, ["app/jobs"]);
    assert.deepEqual(areas[3].path_hints, ["old"]);
  });

  it("zones by surface path, boundary text, else internal; extras go to other", () => {
    const snap = snapFixture();
    const zones = H.assignZones(H.buildAreas(snap), snap);
    assert.deepEqual(zones, { api: "exposed", auth: "boundary", worker: "internal", legacy: "other" });
  });

  it("returns null (plain grid) without surfaces, boundaries or extras", () => {
    const snap = { architecture_summary: { components: [{ name: "a" }, { name: "b" }] } };
    assert.equal(H.assignZones(H.buildAreas(snap), snap), null);
  });
});

describe("coverage", () => {
  it("maps depths to cell states and marks running hunts", () => {
    const snap = snapFixture();
    const skills = H.skillColumns(snap);
    assert.deepEqual(skills, ["injection", "authz", "ssrf"]);
    const api = H.areaCoverage("api", snap, skills);
    assert.deepEqual(api.map((c) => c.state), ["finding", "shallow", "empty"]);
    const worker = H.areaCoverage("worker", snap, skills);
    assert.equal(worker[2].state, "running");
    assert.equal(H.openCount(api), 2);
    assert.deepEqual(H.gapSkills(api), ["authz", "ssrf"]);
  });

  it("treats none as residual but not as a gap to preselect", () => {
    const cov = [{ skill: "x", state: "none" }, { skill: "y", state: "planned" }];
    assert.equal(H.openCount(cov), 2);
    assert.deepEqual(H.gapSkills(cov), []);
  });
});

describe("findings", () => {
  it("assigns by explicit area, else longest hint; skips rejected", () => {
    const snap = snapFixture();
    const by = H.findingsByArea(snap.findings, H.buildAreas(snap));
    assert.deepEqual(by.api.map((f) => f.id), [1]);
    assert.deepEqual(by.auth.map((f) => f.id), [3]);
    assert.equal(by.worker.length, 0);
  });

  it("counts findings under a tree path", () => {
    const f = snapFixture().findings;
    assert.equal(H.findingCountForPath("app", f), 1);
    assert.equal(H.findingCountForPath("app/api/db.py", f), 1);
    assert.equal(H.findingCountForPath("app/auth", f), 0);
  });

  it("badges live paths over gap paths", () => {
    const snap = snapFixture();
    const areas = H.buildAreas(snap);
    const ctx = {
      findings: snap.findings,
      livePaths: H.liveWork(snap.tasks).paths,
      areas,
      gapAreas: new Set(["api"]),
    };
    assert.deepEqual(H.treeBadge("app/jobs", ctx), { findings: 0, tag: "live" });
    assert.deepEqual(H.treeBadge("app/api", ctx), { findings: 1, tag: "gap" });
    assert.deepEqual(H.treeBadge("app/auth", ctx), { findings: 0, tag: "" });
  });
});

describe("layout", () => {
  it("bands zones in order and wraps columns", () => {
    const snap = snapFixture();
    const areas = H.buildAreas(snap);
    const lay = H.layoutMap(areas, H.assignZones(areas, snap), { width: 420 });
    assert.equal(lay.cols, 2);
    assert.deepEqual(lay.bands.map((b) => b.id), ["exposed", "boundary", "internal", "other"]);
    const ys = lay.nodes.map((n) => n.y);
    assert.ok(ys[0] < ys[1] && ys[1] < ys[2] && ys[2] < ys[3]);
    for (const n of lay.nodes) assert.ok(n.x + n.w <= lay.width);
    assert.ok(lay.height >= ys[3] + 76);
  });

  it("uses a plain grid without zones", () => {
    const areas = ["a", "b", "c"].map((name) => ({ name, path_hints: [], source: "recon" }));
    const lay = H.layoutMap(areas, null, { width: 420 });
    assert.equal(lay.bands.length, 0);
    assert.equal(lay.nodes[0].y, lay.nodes[1].y);
    assert.ok(lay.nodes[2].y > lay.nodes[0].y);
  });

  it("draws edges only between nodes on the map", () => {
    const snap = snapFixture();
    const areas = H.buildAreas(snap);
    const lay = H.layoutMap(areas, H.assignZones(areas, snap), { width: 900 });
    const edges = H.edgePaths(snap.architecture_summary.relations, lay.nodes);
    assert.equal(edges.length, 1);
    assert.equal(edges[0].from, "api");
    assert.match(edges[0].d, /^M[\d.]+ [\d.]+ C/);
  });

  it("tones nodes by residual share or findings", () => {
    const cov = [{ state: "empty" }, { state: "empty" }, { state: "shallow" }, { state: "finding" }];
    assert.equal(H.nodeTone("risk", cov, 0), "hot");
    assert.equal(H.nodeTone("risk", [{ state: "finding" }, { state: "empty" }], 0), "warm");
    assert.equal(H.nodeTone("findings", cov, 0), "calm");
    assert.equal(H.nodeTone("findings", cov, 2), "hot");
    assert.equal(H.nodeTone("risk", [], 0), "calm");
  });
});

describe("inspector facts", () => {
  it("collects sinks, entrypoints and file counts under the area hints", () => {
    const snap = snapFixture();
    const api = H.buildAreas(snap)[0];
    assert.deepEqual(H.sinksForArea(api, snap).map((s) => s.kind), ["sql"]);
    const eps = H.entrypointsForArea(api, snap).map((e) => e.path);
    assert.deepEqual(eps, ["app/api/routes.py", "app/api/main.py"]);
    assert.equal(H.fileCountForArea(api, snap), 7);
    assert.equal(H.fileCountForArea(H.buildAreas(snap)[2], snap), null);
  });
});

describe("suggestSkills", () => {
  it("prefers shallow/aborted and recon focus over unhunted", () => {
    const cov = [
      { skill: "injection", state: "empty" },
      { skill: "authz", state: "shallow" },
      { skill: "ssrf", state: "aborted" },
      { skill: "xss", state: "empty" },
      { skill: "crypto", state: "finding" },
    ];
    assert.deepEqual(H.suggestSkills(cov, ["xss", "crypto"]), ["authz", "ssrf", "xss"]);
  });

  it("falls back to the first unhunted skills, skipping planned/running", () => {
    const cov = ["a", "b", "c", "d"].map((skill) => ({ skill, state: "empty" }));
    cov.unshift({ skill: "p", state: "planned" }, { skill: "r", state: "running" });
    assert.deepEqual(H.suggestSkills(cov, []), ["a", "b", "c"]);
    assert.deepEqual(H.suggestSkills(cov, [], 1), ["a"]);
  });
});

describe("coverage key", () => {
  it("counts states in legend order and drops zero counts", () => {
    const cov = [
      { skill: "a", state: "empty" },
      { skill: "b", state: "shallow" },
      { skill: "c", state: "empty" },
      { skill: "d", state: "finding" },
    ];
    assert.deepEqual(
      H.stateCounts(cov).map((k) => [k.state, k.count]),
      [["finding", 1], ["shallow", 1], ["empty", 2]]
    );
    assert.equal(H.STATE_LABEL.empty, "Not hunted");
    assert.equal(H.STATE_LABEL.none, "Nothing found");
    assert.deepEqual(H.stateCounts([]), []);
  });
});

/* ------------------------------------------------------------------ */
/* v2 maps: source selection, zones, flows, edges, routing             */
/* ------------------------------------------------------------------ */

const fs = require("node:fs");
const V2 = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "arch_v2_toy_sqli.json"), "utf8"));

function v2Snap(extra) {
  return Object.assign(
    {
      architecture: JSON.parse(JSON.stringify(V2)),
      // The summary is compacted server-side: no zones / flows / entrypoints.
      architecture_summary: { has_architecture: true, components: V2.components.map((c) => ({ name: c.name, path_hints: c.path_hints, role: c.role })) },
      hunt_classes: { active: ["injection", "authz", "authn", "ssrf", "path_traversal"] },
      coverage: {
        cells: [
          { area: "api/invoices", class: "injection", last_depth: "candidate" },
          { area: "db", class: "injection", last_depth: "none" },
          { area: "api-pdf", class: "path_traversal", last_depth: "shallow" },
        ],
      },
      tasks: [],
      findings: [],
    },
    extra || {}
  );
}

/** Strict interior intersection of an axis-aligned segment with a rect. */
function segHitsRect(p, q, r) {
  const x0 = Math.min(p[0], q[0]);
  const x1 = Math.max(p[0], q[0]);
  const y0 = Math.min(p[1], q[1]);
  const y1 = Math.max(p[1], q[1]);
  return x1 > r.x + 0.5 && x0 < r.x + r.w - 0.5 && y1 > r.y + 0.5 && y0 < r.y + r.h - 0.5;
}

function onBorder(pt, n) {
  const inX = pt[0] >= n.x - 0.01 && pt[0] <= n.x + n.w + 0.01;
  const inY = pt[1] >= n.y - 0.01 && pt[1] <= n.y + n.h + 0.01;
  const onH = Math.abs(pt[1] - n.y) < 0.01 || Math.abs(pt[1] - (n.y + n.h)) < 0.01;
  const onV = Math.abs(pt[0] - n.x) < 0.01 || Math.abs(pt[0] - (n.x + n.w)) < 0.01;
  return inX && inY && (onH || onV);
}

describe("selectSource", () => {
  it("prefers the raw v2 map over the compacted summary", () => {
    const src = H.selectSource(v2Snap());
    assert.equal(src.kind, "v2");
    assert.equal(src.arch.flows.length, 4);
    assert.ok(H.isV2(src.arch));
  });

  it("falls back to v1, then the mechanical skeleton, then none", () => {
    const v1 = H.selectSource(snapFixture());
    assert.equal(v1.kind, "v1");
    const sk = Object.assign({}, V2, { origin: "mechanical", flows: [] });
    assert.equal(H.selectSource({ architecture_skeleton: sk }).kind, "skeleton");
    assert.equal(H.selectSource({ architecture: {}, architecture_skeleton: sk }).kind, "skeleton");
    // A v1 recon map wins over the skeleton.
    assert.equal(H.selectSource(Object.assign(snapFixture(), { architecture_skeleton: sk })).kind, "v1");
    assert.equal(H.selectSource({ architecture_skeleton: null }).kind, "none");
    assert.equal(H.selectSource({}).kind, "none");
  });

  it("treats a v2 map stored with origin mechanical as the skeleton", () => {
    const sk = Object.assign({}, V2, { origin: "mechanical" });
    assert.equal(H.selectSource({ architecture: sk }).kind, "skeleton");
  });

  it("builds areas from v2 components with id, zone, entrypoints and sinks", () => {
    const areas = H.buildAreas(v2Snap());
    const inv = areas.find((a) => a.name === "api/invoices");
    assert.equal(inv.id, "api-invoices");
    assert.equal(inv.zone, "internet");
    assert.deepEqual(inv.entrypoints[0], { label: "GET /invoices/search?q", path: "app.py", line: 9 });
    assert.deepEqual(H.entrypointsForArea(inv, v2Snap()), [{ label: "GET /invoices/search?q", path: "app.py", line: 9 }]);
    assert.deepEqual(H.sinksForArea(inv, v2Snap()).map((k) => k.kind), ["sql"]);
    assert.equal(areas.filter((a) => a.source === "recon").length, 10);
  });

  it("reads coverage cells filed under a component id or name", () => {
    const snap = v2Snap();
    const pdf = H.buildAreas(snap).find((a) => a.name === "api/pdf");
    const cov = H.areaCoverage(pdf, snap, ["path_traversal", "injection"]);
    assert.deepEqual(cov.map((c) => c.state), ["shallow", "empty"]);
  });
});

describe("zones", () => {
  it("orders explicit zones internet → authenticated → internal → external", () => {
    const snap = v2Snap();
    // Shuffle the declaration order; band order must follow kind rank.
    snap.architecture.zones = snap.architecture.zones.slice().reverse();
    const areas = H.buildAreas(snap);
    const zm = H.zoneModel(areas, snap);
    assert.equal(zm.guessed, false);
    const lay = H.layoutMap(areas, zm.zones, { width: 900, bands: zm.bands });
    assert.deepEqual(lay.bands.map((b) => b.id), ["internet", "authed", "internal", "external"]);
    assert.deepEqual(lay.bands.map((b) => b.label), ["Internet-facing", "Authenticated", "Internal", "External services"]);
    assert.equal(zm.zones["api/payments"], "authed");
    assert.ok(lay.bands.every((b) => !b.guessed));
  });

  it("resolves a zone given as a bare kind and labels unknown kinds", () => {
    const z = H.resolveZone("build", []);
    assert.equal(z.label, "Build & supply chain");
    assert.equal(H.resolveZone("authenticated", V2.zones).id, "authed");
    assert.equal(H.resolveZone("nowhere", V2.zones), null);
    assert.equal(H.zoneShort("authed", V2.zones), "Authenticated");
  });

  it("falls back to guessed heuristic bands for v1 maps", () => {
    const snap = snapFixture();
    const areas = H.buildAreas(snap);
    const zm = H.zoneModel(areas, snap);
    assert.equal(zm.guessed, true);
    const lay = H.layoutMap(areas, zm.zones, { width: 900, bands: zm.bands });
    assert.deepEqual(lay.bands.map((b) => [b.id, b.guessed]), [
      ["exposed", true],
      ["boundary", true],
      ["internal", true],
      ["other", false],
    ]);
  });

  it("puts components without a zone in a No zone band and coverage-only areas in other", () => {
    const snap = v2Snap();
    snap.architecture.components[7].zone = "";
    snap.coverage.cells.push({ area: "legacy", class: "ssrf", last_depth: "aborted" });
    const areas = H.buildAreas(snap);
    const zm = H.zoneModel(areas, snap);
    assert.equal(zm.zones.settings, "unzoned");
    assert.equal(zm.zones.legacy, "other");
    const lay = H.layoutMap(areas, zm.zones, { width: 900, bands: zm.bands });
    assert.deepEqual(lay.bands.slice(-2).map((b) => b.id), ["unzoned", "other"]);
  });
});

describe("components and flows", () => {
  const areas = H.buildAreas(v2Snap());

  it("resolves components by id or name, case-insensitively", () => {
    assert.equal(H.resolveComponent("API-INVOICES", areas).name, "api/invoices");
    assert.equal(H.resolveComponent("Api/Pdf", areas).name, "api/pdf");
    assert.equal(H.resolveComponent({ component: "db" }, areas).name, "db");
    assert.equal(H.resolveComponent("ghost", areas), null);
    assert.equal(H.resolveComponent("", areas), null);
  });

  it("walks a flow through its components, collapsing repeats", () => {
    const [f1, f2, f3, f4] = V2.flows;
    assert.deepEqual(H.flowComponentPath(f1, areas), ["api/invoices", "db"]);
    assert.deepEqual(H.flowComponentPath(f2, areas), ["api/pdf"]);
    assert.deepEqual(H.flowComponentPath(f3, areas), ["hooks/stripe", "db"]);
    assert.deepEqual(H.flowComponentPath(f4, areas), ["api/payments", "settings", "psp"]);
    // Non-consecutive repeats are kept (a real back-and-forth).
    const back = { source: { component: "db" }, steps: [{ component: "api-pdf" }], sink: { component: "db" } };
    assert.deepEqual(H.flowComponentPath(back, areas), ["db", "api/pdf", "db"]);
  });

  it("lists steps and cited files in order", () => {
    const steps = H.flowSteps(V2.flows[0], areas);
    assert.deepEqual(steps.map((s) => [s.role, s.component, `${s.path}:${s.line}`]), [
      ["source", "api/invoices", "app.py:9"],
      ["step", "api/invoices", "app.py:11"],
      ["step", "db", "billing/db.py:21"],
      ["sink", "db", "app.py:12"],
    ]);
    assert.deepEqual(H.flowFiles(V2.flows[0]), ["app.py", "billing/db.py"]);
    assert.match(H.flowNote(V2.flows[0]), /Invoice search q → SQL.*GET \/invoices\/search\?q \(app\.py:9\) → sql at app\.py:12/);
  });

  it("derives zone crossings from crosses or component zones", () => {
    const [f1, f2, f3, f4] = V2.flows;
    assert.deepEqual(H.flowCrossing(f1, areas, V2.zones), { from: "Internet", to: "Internal" });
    assert.equal(H.flowCrossing(f2, areas, V2.zones), null);
    // f3 has no `crosses`: hooks/stripe (internet) → db (internal).
    assert.deepEqual(H.flowCrossing(f3, areas, V2.zones), { from: "Internet", to: "Internal" });
    assert.deepEqual(H.flowCrossing(f4, areas, V2.zones), { from: "Authenticated", to: "External" });
  });

  it("finds flows through an area, the hunt area and the preselected skills", () => {
    assert.deepEqual(H.flowsForArea(V2.flows, areas, "db").map((f) => f.id), ["f1", "f3"]);
    assert.deepEqual(H.flowsForArea(V2.flows, areas, "settings").map((f) => f.id), ["f4"]);
    assert.equal(H.flowHuntArea(V2.flows[1], areas).name, "api/pdf");
    assert.equal(H.flowHuntArea(V2.flows[3], areas).name, "psp");
    assert.deepEqual(H.flowSkills(V2.flows[1], ["injection", "authz", "path_traversal"]), ["authz", "path_traversal"]);
    assert.deepEqual(H.flowSkills(V2.flows[2], ["xss"]), []);
  });
});

describe("edges", () => {
  const areas = H.buildAreas(v2Snap());

  it("splits links and imports, dedupes parallel edges and drops unknown ends", () => {
    const e = H.buildEdges(V2.relations, areas);
    const invDb = e.links.filter((x) => [x.from, x.to].sort().join() === ["api/invoices", "db"].sort().join());
    assert.equal(invDb.length, 1, "id and name references to the same pair collapse");
    assert.deepEqual(invDb[0].kinds, ["db", "calls"]);
    assert.equal(invDb[0].items.length, 2);
    assert.equal(invDb[0].inferred, false);
    assert.ok(!e.links.some((x) => x.to === "ghost"));
    assert.equal(e.imports.length, 3);
    assert.ok(e.imports.every((x) => x.kinds[0] === "imports"));
    const admin = e.links.find((x) => x.from === "admin/panel");
    assert.equal(admin.inferred, true);
    assert.match(H.edgeTitle(invDb[0]), /api\/invoices → db: db · app\.py:12/);
    assert.match(H.edgeTitle(admin), /\(inferred\) · no citation/);
  });

  it("marks reverse edges between the same pair as bidirectional", () => {
    const rels = [
      { from: "db", to: "settings", kind: "calls" },
      { from: "settings", to: "db", kind: "calls" },
    ];
    const e = H.buildEdges(rels, areas);
    assert.equal(e.links.length, 1);
    assert.equal(e.links[0].bidir, true);
  });

  it("sends mechanical skeleton relations to the imports layer", () => {
    const rels = [{ from: "db", to: "settings", kind: "calls", confidence: "mechanical" }];
    assert.equal(H.buildEdges(rels, areas, { skeleton: true }).imports.length, 1);
    assert.equal(H.buildEdges(rels, areas).links.length, 1);
  });
});

describe("routeEdge", () => {
  // 3 × 3 grid, one band: every pair must route around the other nodes.
  const areas = "abcdefghi".split("").map((name) => ({ name, path_hints: [], source: "recon" }));
  const lay = H.layoutMap(areas, null, { width: 3 * 168 + 2 * 36 + 40 });
  const by = Object.fromEntries(lay.nodes.map((n) => [n.name, n]));

  it("lays out a 3 × 3 grid", () => {
    assert.equal(lay.cols, 3);
    assert.equal(by.e.row, 1);
    assert.equal(by.e.col, 1);
  });

  it("starts and ends on node borders and never crosses a third node", () => {
    for (const a of lay.nodes) {
      for (const b of lay.nodes) {
        if (a === b) continue;
        for (const lane of [0, -1, 2]) {
          const r = H.routeEdge(a, b, lay, { lane });
          const pts = r.points;
          assert.ok(pts.length >= 2, `${a.name}->${b.name}`);
          assert.ok(onBorder(pts[0], a), `${a.name}->${b.name} start ${pts[0]}`);
          assert.ok(onBorder(pts[pts.length - 1], b), `${a.name}->${b.name} end ${pts[pts.length - 1]}`);
          for (let i = 1; i < pts.length; i++) {
            const [p, q] = [pts[i - 1], pts[i]];
            assert.ok(Math.abs(p[0] - q[0]) < 0.01 || Math.abs(p[1] - q[1]) < 0.01, "orthogonal segments");
            for (const n of lay.nodes) {
              if (n === a || n === b) continue;
              assert.ok(!segHitsRect(p, q, n), `${a.name}->${b.name} crosses ${n.name}`);
            }
            // The path never runs through its own endpoints' bodies either.
            if (i > 1) assert.ok(!segHitsRect(p, q, a), `${a.name}->${b.name} re-enters ${a.name}`);
            if (i < pts.length - 1) assert.ok(!segHitsRect(p, q, b), `${a.name}->${b.name} enters ${b.name} early`);
          }
          assert.match(r.d, /^M[\d.]+ [\d.]+( L[\d.]+ [\d.]+)+$/);
        }
      }
    }
  });

  it("draws neighbours as one straight segment", () => {
    assert.equal(H.routeEdge(by.a, by.b, lay).points.length, 2);
    assert.equal(H.routeEdge(by.a, by.d, lay).points.length, 2);
  });

  it("routes the v2 fixture without crossing nodes across bands", () => {
    const snap = v2Snap();
    const as = H.buildAreas(snap);
    const zm = H.zoneModel(as, snap);
    const l2 = H.layoutMap(as, zm.zones, { width: 760, bands: zm.bands });
    const nb = Object.fromEntries(l2.nodes.map((n) => [n.name, n]));
    const edges = H.buildEdges(V2.relations, as);
    for (const e of [...edges.links, ...edges.imports]) {
      const pts = H.routeEdge(nb[e.from], nb[e.to], l2).points;
      for (let i = 1; i < pts.length; i++) {
        for (const n of l2.nodes) {
          if (n.name === e.from || n.name === e.to) continue;
          assert.ok(!segHitsRect(pts[i - 1], pts[i], n), `${e.from}->${e.to} crosses ${n.name}`);
        }
      }
    }
  });

  it("finds the band entry point and the polyline midpoint", () => {
    const pts = [[0, 0], [0, 100], [50, 100]];
    assert.deepEqual(H.polylineMid(pts), [0, 75]);
    assert.deepEqual(H.bandEntryPoint(pts, { x: -10, y: 40, w: 100, h: 100 }), [0, 40]);
    assert.equal(H.bandEntryPoint(pts, { x: 200, y: 0, w: 10, h: 10 }), null);
    assert.equal(H.bandEntryPoint(pts, { x: -10, y: -10, w: 100, h: 100 }), null, "starts inside: no entry");
  });
});
