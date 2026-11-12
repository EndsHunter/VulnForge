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
