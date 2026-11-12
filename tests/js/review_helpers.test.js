"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const H = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "pages", "review.js"));

const f = (id, state, sev, body = {}) => ({ id, state, body: { severity_claim: sev, ...body } });

describe("queue order and filters", () => {
  it("sorts by severity desc, then needs review before candidate, then newest", () => {
    const list = [
      f(1, "candidate", "HIGH"),
      f(2, "needs_human", "LOW"),
      f(3, "needs_human", "HIGH"),
      f(4, "confirmed", "CRITICAL"),
      f(5, "needs_human", "HIGH"),
    ];
    assert.deepEqual(list.slice().sort(H.compareQueue).map((x) => x.id), [4, 5, 3, 1, 2]);
  });

  it("never counts a candidate as needs review", () => {
    const list = [f(1, "candidate", "high", { needs_human: true }), f(2, "needs_human", "high")];
    const c = H.queueCounts(list);
    assert.equal(c.needs_human, 1);
    assert.equal(c.candidate, 1);
    assert.equal(H.matchesQueueFilter(list[0], "needs_human"), false);
    assert.equal(H.matchesQueueFilter(list[0], "candidate"), true);
  });

  it("groups rejected states and honours the near-dup predicate", () => {
    assert.equal(H.matchesQueueFilter(f(1, "rejected_llm"), "rejected"), true);
    assert.equal(H.matchesQueueFilter(f(2, "superseded"), "rejected"), true);
    assert.equal(H.matchesQueueFilter(f(3, "needs_human"), "near_dup", (x) => x.id === 3), true);
    assert.equal(H.matchesQueueFilter(f(4, "needs_human"), "near_dup", () => false), false);
    assert.equal(H.queueCounts([f(1, "rejected_mech"), f(2, "confirmed")]).all, 2);
  });

  it("labels state pills honestly", () => {
    assert.deepEqual(H.statePill(f(1, "candidate")), { tone: "candidate", label: "Candidate" });
    assert.equal(H.statePill(f(1, "needs_human")).label, "Needs review");
    assert.equal(H.statePill(f(1, "rejected_llm")).tone, "rejected");
    assert.equal(H.sevKey(f(1, "x", "CRITICAL")), "crit");
    assert.equal(H.sevKey(f(1, "x", "weird")), "");
  });
});

describe("selection", () => {
  const q = [f(1, "needs_human"), f(2, "confirmed"), f(3, "candidate"), f(4, "needs_human")];

  it("moves to the next undecided after the current one", () => {
    assert.equal(H.nextUndecided(q, 1), 3);
    assert.equal(H.nextUndecided(q, 3), 4);
  });

  it("falls back to an earlier undecided, then null", () => {
    assert.equal(H.nextUndecided(q, 4), 3);
    assert.equal(H.nextUndecided([f(9, "needs_human")], 9), null);
    assert.equal(H.nextUndecided([], 1), null);
  });

  it("steps J/K with clamping", () => {
    assert.equal(H.stepSelection(q, 1, 1), 2);
    assert.equal(H.stepSelection(q, 4, 1), 4);
    assert.equal(H.stepSelection(q, 1, -1), 1);
    assert.equal(H.stepSelection(q, 99, 1), 1);
    assert.equal(H.stepSelection([], 1, 1), null);
  });

  it("maps keys only without modifiers", () => {
    assert.equal(H.keyAction({ key: "j" }), "next");
    assert.equal(H.keyAction({ key: "A" }), "accept");
    assert.equal(H.keyAction({ key: "a", ctrlKey: true }), null);
    assert.equal(H.keyAction({ key: "x" }), null);
  });
});

describe("buildTrace", () => {
  it("prefers an explicit trace", () => {
    const t = H.buildTrace({
      trace: [
        { kind: "source", path: "a.py", line: 3, symbol: "request.args" },
        { role: "sink", path: "b.py", start_line: 9, expr: "db.execute" },
      ],
    });
    assert.deepEqual(t.map((s) => [s.kind, s.what, s.where, s.derived]), [
      ["source", "request.args", "a.py:3", false],
      ["sink", "db.execute", "b.py:9", false],
    ]);
  });

  it("derives source → flow → sink from citations", () => {
    const t = H.buildTrace({
      citations: [
        { path: "api.py", start_line: 10, symbol: "handler" },
        { path: "filters.py", start_line: 22 },
        { path: "api.py", start_line: 88, end_line: 90, symbol: "run" },
      ],
    });
    assert.deepEqual(t.map((s) => s.kind), ["source", "flow", "sink"]);
    assert.equal(t[2].where, "api.py:88-90");
    assert.equal(t[0].derived, true);
  });

  it("uses the recorded sink and handles one or no citation", () => {
    const t = H.buildTrace({
      sink_path: "db.py",
      citations: [{ path: "db.py", start_line: 5 }, { path: "web.py", start_line: 1 }],
    });
    assert.deepEqual(t.map((s) => s.kind), ["sink", "flow"]);
    assert.equal(H.buildTrace({ citations: [{ path: "x.py" }] })[0].kind, "cited");
    assert.equal(H.buildTrace({ sink_path: "y.py" })[0].kind, "sink");
    assert.deepEqual(H.buildTrace({}), []);
    assert.deepEqual(H.buildTrace(null), []);
  });
});

describe("mechGates / disproveJudges / pocStatus", () => {
  it("is pending before mech runs", () => {
    const g = H.mechGates(f(1, "candidate"));
    assert.equal(g.status, "pending");
    assert.ok(g.gates.every((x) => x.status === "pending"));
  });

  it("passes every gate after mech passes", () => {
    const g = H.mechGates(f(1, "needs_human", "high", { validation_mech: { status: "passed" } }));
    assert.equal(g.status, "passed");
    assert.equal(g.passed, g.total);
  });

  it("fails the gates that own the reasons and keeps unmapped ones", () => {
    const g = H.mechGates(
      f(1, "rejected_mech", "high", { validation_reasons: ["line_oob:app.py", "vacuous_impact", "mystery_code"] })
    );
    assert.equal(g.status, "failed");
    assert.equal(g.gates.find((x) => x.id === "citations").status, "failed");
    assert.equal(g.gates.find((x) => x.id === "nonvacuous").status, "failed");
    assert.equal(g.gates.find((x) => x.id === "schema").status, "passed");
    assert.deepEqual(g.other, ["mystery_code"]);
  });

  it("reads disprove judges as demote-only signals", () => {
    const j = H.disproveJudges(
      f(1, "needs_human", "high", {
        validation_llm: { verifiers: [{ id: "A", verdict: "stand", reasoning: "no sanitizer" }, { verdict: "reject" }] },
      })
    );
    assert.deepEqual(j.map((x) => [x.name, x.label, x.tone]), [
      ["A", "could not disprove", "stand"],
      ["Judge B", "rejected", "reject"],
    ]);
    assert.deepEqual(H.disproveJudges(f(1, "candidate")), []);
  });

  it("summarises PoC status without claiming proof", () => {
    assert.match(H.pocStatus(f(1, "x", "h", { poc_validation_latest: { verdict: "signal", exit_code: 0 } })).text, /does not confirm/);
    assert.equal(H.pocStatus(f(1, "x", "h", { poc_relpath: "poc.py" })).tone, "draft");
    assert.equal(H.pocStatus(f(1, "x")).text, "No PoC yet.");
  });

  it("formats ages", () => {
    const now = Date.parse("2026-11-12T12:00:00Z");
    assert.equal(H.ageLabel("2026-11-12T11:54:00Z", now), "6 min ago");
    assert.equal(H.ageLabel("2026-11-12T09:00:00Z", now), "3 h ago");
    assert.equal(H.ageLabel("nope", now), "");
  });
});
