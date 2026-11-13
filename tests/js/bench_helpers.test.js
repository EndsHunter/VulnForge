"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const H = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "pages", "bench", "helpers.js"));

describe("formatting", () => {
  it("formats pct, tokens, durations and missing values", () => {
    assert.equal(H.fmtPct(0.625), "62.5%");
    assert.equal(H.fmtPct(null), "–");
    assert.equal(H.fmtTokens(950), "950");
    assert.equal(H.fmtTokens(12345), "12k");
    assert.equal(H.fmtTokens(1500), "1.5k");
    assert.equal(H.fmtTokens(2500000), "2.5M");
    assert.equal(H.fmtDuration(42), "42s");
    assert.equal(H.fmtDuration(252), "4m 12s");
    assert.equal(H.fmtDuration(7260), "2h 1m");
    assert.equal(H.fmtMetric("recall", 1), "100.0%");
    assert.equal(H.fmtMetric("tokens_per_hit", undefined), "–");
  });
});

describe("fmtDelta", () => {
  it("tones by metric direction", () => {
    assert.deepEqual(H.fmtDelta("recall", 0.125), { text: "+12.5 pt", tone: "good" });
    assert.deepEqual(H.fmtDelta("recall", -0.05), { text: "−5.0 pt", tone: "bad" });
    assert.equal(H.fmtDelta("tokens_per_hit", -2000).tone, "good");
    assert.equal(H.fmtDelta("tokens_per_hit", 2000).text, "+2.0k");
    assert.equal(H.fmtDelta("unmatched_per_target", 0.5).tone, "bad");
    assert.equal(H.fmtDelta("wall_s", -90).text, "−1m 30s");
    assert.deepEqual(H.fmtDelta("recall", 0), { text: "±0", tone: "flat" });
    assert.deepEqual(H.fmtDelta("recall", null), { text: "–", tone: "none" });
  });
});

describe("fmtSpread", () => {
  it("shows min–max only over several differing repeats", () => {
    const sp = { mean: 0.75, min: 0.5, max: 1 };
    assert.equal(H.fmtSpread("recall", sp, 2), "75.0% (50.0%–100.0%)");
    assert.equal(H.fmtSpread("recall", sp, 1), "75.0%");
    assert.equal(H.fmtSpread("recall", { mean: 0.5, min: 0.5, max: 0.5 }, 3), "50.0%");
    assert.equal(H.fmtSpread("recall", null, 3), "–");
  });
});

describe("fmtRange", () => {
  it("only when repeats disagree", () => {
    assert.equal(H.fmtRange("recall", { mean: 0.75, min: 0.5, max: 1 }, 2), "50.0%–100.0%");
    assert.equal(H.fmtRange("recall", { mean: 0.5, min: 0.5, max: 0.5 }, 2), "");
    assert.equal(H.fmtRange("recall", { mean: 0.5, min: 0.4, max: 0.6 }, 1), "");
  });
});

describe("statusView", () => {
  it("directed suites read finished, directed cases hit/miss, L0 keeps pass/fail", () => {
    assert.deepEqual(H.statusView("failed", { suite: true, tier: "directed" }), { text: "finished", cls: "vf-pill--candidate" });
    assert.deepEqual(H.statusView("passed", { tier: "directed" }), { text: "hit", cls: "vf-pill--confirmed" });
    assert.deepEqual(H.statusView("failed", { tier: "directed" }), { text: "miss", cls: "vf-pill--rejected" });
    assert.deepEqual(H.statusView("failed", { suite: true, tier: "l0" }), { text: "failed", cls: "bench-pill--fail" });
    assert.equal(H.statusView("error", { suite: true, tier: "directed" }).text, "error");
    assert.equal(H.statusView("running", { suite: true, tier: "directed" }).text, "running");
  });
});

describe("honest labels", () => {
  it("labels tiers and never calls a metric confirmed", () => {
    assert.equal(H.tierLabel("l0"), "L0 fixture check");
    assert.match(H.tierCaveat("l0"), /nothing about model quality/);
    assert.match(H.tierCaveat("directed"), /told where to look/);
    assert.match(H.metricSpec("unmatched_per_target").note, /Not proven false positives/);
    H.METRICS.forEach((m) => assert.doesNotMatch(m.label + m.sub, /confirm/i));
    assert.equal(H.statusPill("passed"), "vf-pill--confirmed");
    assert.equal(H.statusPill("error"), "bench-pill--fail");
    assert.equal(H.statusPill("running"), "vf-pill--review");
  });
});

describe("fingerprint rows", () => {
  it("fixed order, short sha, booleans as words", () => {
    const rows = H.fingerprintRows({ git_sha: "0123456789abcdef", git_dirty: true, validate_llm: false, model: "m" });
    assert.equal(rows[0].label, "Commit");
    assert.equal(rows[0].value, "01234567");
    assert.equal(rows.find((r) => r.key === "git_dirty").value, "yes");
    assert.equal(rows.find((r) => r.key === "validate_llm").value, "off");
    assert.equal(rows.find((r) => r.key === "prompts_hash").value, "–");
    const diff = H.fingerprintDiffRows([{ key: "model", a: "m1", b: "m2" }]);
    assert.deepEqual(diff, [{ key: "model", label: "Model", a: "m1", b: "m2" }]);
  });
});

describe("caseRows", () => {
  const m = (def_id, repeat, status, hit, oracles, extra) =>
    Object.assign({ def_id, repeat, status, hit_count: hit, oracle_count: oracles, unmatched: 0, tokens_total: 100, wall_s: 5, run_id: def_id + repeat }, extra || {});

  it("folds repeats per case and sorts errors, then misses first", () => {
    const rows = H.sortCaseRows(H.caseRows([
      m("a", 0, "passed", 1, 1),
      m("a", 1, "failed", 0, 1, { unmatched: 2 }),
      m("b", 0, "passed", 1, 1),
      m("c", 0, "error", 0, 0, { error: "boom", tokens_total: null, wall_s: null }),
      m("d", 0, "failed", 0, 1)
    ]));
    assert.deepEqual(rows.map((r) => r.def_id), ["c", "d", "a", "b"]);
    const a = rows.find((r) => r.def_id === "a");
    assert.equal(a.repeats, 2);
    assert.equal(a.hit_rate, 0.5);
    assert.equal(a.unmatched, 2);
    assert.equal(a.tokens, 200);
    assert.equal(a.status, "failed");
    assert.deepEqual(a.run_ids, ["a0", "a1"]);
    const c = rows[0];
    assert.equal(c.hit_rate, null);
    assert.equal(c.tokens, null);
    assert.deepEqual(c.errors, ["boom"]);
  });

  it("caseVerdict reads hit / partial / miss from folded hits", () => {
    const rows = H.caseRows([m("a", 0, "passed", 1, 1), m("a", 1, "failed", 0, 1), m("b", 0, "passed", 1, 1),
      m("c", 0, "failed", 0, 1), m("d", 0, "error", 0, 0), m("e", 0, "running", 0, 0)]);
    const v = Object.fromEntries(rows.map((r) => [r.def_id, H.caseVerdict(r).text]));
    assert.deepEqual(v, { a: "partial", b: "hit", c: "miss", d: "error", e: "running" });
  });

  it("worstStatus ranks error over running over passed", () => {
    assert.equal(H.worstStatus(["passed", "running"]), "running");
    assert.equal(H.worstStatus(["passed", "error", "failed"]), "error");
    assert.equal(H.worstStatus([]), "queued");
  });
});

describe("flipGroups", () => {
  it("splits regressions, gains, unchanged", () => {
    const g = H.flipGroups([
      { change: "regression" }, { change: "gain" }, { change: "hit" }, { change: "miss" }, { change: "gain" }
    ]);
    assert.equal(g.regression.length, 1);
    assert.equal(g.gain.length, 2);
    assert.equal(g.unchanged.length, 2);
    assert.deepEqual(H.flipGroups(null), { regression: [], gain: [], unchanged: [] });
  });
});

describe("trendGeometry", () => {
  it("maps recall 0..1 onto the box and skips missing points", () => {
    const g = H.trendGeometry(
      [{ id: "a", recall: 0 }, { id: "x", recall: null }, { id: "b", recall: 1 }],
      { width: 100, height: 20, pad: 0 }
    );
    assert.equal(g.empty, false);
    assert.deepEqual(g.dots.map((d) => [d.x, d.y, d.id]), [[0, 20, "a"], [100, 0, "b"]]);
    assert.equal(g.points, "0,20 100,0");
    const one = H.trendGeometry([{ id: "a", recall: 0.5 }], { width: 100, height: 20, pad: 0 });
    assert.deepEqual([one.dots[0].x, one.dots[0].y], [50, 10]);
    assert.equal(H.trendGeometry([], {}).empty, true);
  });
});

describe("progressText / groupBySuite / shortAge", () => {
  it("covers suites, single runs, grouping and ages", () => {
    assert.equal(H.progressText({ metrics: { suite: true, live: { done: 3, total: 10 } } }), "3 / 10 case runs");
    assert.equal(H.progressText({ status: "running", metrics: { live: { phase: "ralph" } } }), "phase: ralph");
    const groups = H.groupBySuite([
      { id: "z", suite: "fixtures" }, { id: "b", suite: "realworld" }, { id: "a", suite: "realworld" }, { id: "s", suite: "synthetic" }
    ]);
    assert.deepEqual(groups.map((g) => g.suite), ["realworld", "synthetic", "fixtures"]);
    assert.deepEqual(groups[0].defs.map((d) => d.id), ["a", "b"]);
    const now = Date.parse("2026-11-12T12:00:00Z");
    assert.equal(H.shortAge("2026-11-12T11:58:00Z", now), "2m ago");
    assert.equal(H.shortAge("2026-11-10T12:00:00Z", now), "2d ago");
    assert.equal(H.shortAge("", now), "");
  });
});
