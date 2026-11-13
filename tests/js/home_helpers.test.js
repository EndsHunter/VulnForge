"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const H = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "pages", "home.js"));

const run = (over) => ({ target_id: "t", run_id: "r", runner: { state: "idle" }, tasks: {}, findings: {}, ...over });

describe("runStatus", () => {
  it("maps runner states and stalled queued work", () => {
    assert.equal(H.runStatus(run({ runner: { state: "running" } })), "running");
    assert.equal(H.runStatus(run({ runner: { state: "paused" } })), "paused");
    assert.equal(H.runStatus(run({ runner: { state: "idle", stop: true } })), "paused");
    assert.equal(H.runStatus(run({ has_work: true, tasks: { queued: 3 } })), "stalled");
    assert.equal(H.runStatus(run({ has_work: true, tasks: {} })), "idle");
    assert.equal(H.runStatus(run({ runner: { state: "failed" } })), "error");
    assert.equal(H.runStatus(run({ last_event: { event: "failed_infra" } })), "error");
    assert.equal(H.runStatus({ key: "x", error: "boom" }), "error");
    assert.equal(H.runStatus(null), "idle");
  });
});

describe("runPipeline", () => {
  it("never counts candidate as review", () => {
    const p = H.runPipeline(run({ findings: { candidate: 4, needs_human: 1, confirmed: 2 }, total_tasks: 5, done_tasks: 3 }));
    assert.deepEqual(p, { tasks: "3/5", review: 1, confirmed: 2 });
    assert.deepEqual(H.runPipeline(run({ findings: { candidate: 2 } })), { tasks: "0", review: 0, confirmed: 0 });
  });
});

describe("sortRuns", () => {
  it("puts running first, then status rank, then most recent", () => {
    const out = H.sortRuns([
      run({ run_id: "old-idle", updated_at: "2026-01-01T00:00:00Z" }),
      run({ run_id: "new-idle", updated_at: "2026-02-01T00:00:00Z" }),
      run({ run_id: "paused", runner: { state: "paused" } }),
      run({ run_id: "live", runner: { state: "running" } }),
    ]).map((r) => r.run_id);
    assert.deepEqual(out, ["live", "paused", "new-idle", "old-idle"]);
  });
  it("does not mutate input", () => {
    const input = [run({ run_id: "a" }), run({ run_id: "b", runner: { state: "running" } })];
    H.sortRuns(input);
    assert.equal(input[0].run_id, "a");
  });
});

describe("attentionItems", () => {
  it("lists review, error, stalled and paused runs; review first", () => {
    const items = H.attentionItems([
      run({ run_id: "calm", findings: { candidate: 3 } }),
      run({ run_id: "stuck", has_work: true, tasks: { queued: 2 } }),
      run({ run_id: "rev", findings: { needs_human: 2 } }),
      run({ run_id: "bad", runner: { state: "failed" } }),
      { key: "broken/run", error: "db locked" },
    ]);
    assert.deepEqual(items.map((i) => i.kind), ["review", "error", "error", "stalled"]);
    assert.equal(items[0].href, "/runs/t/rev#report/report");
    assert.equal(items[0].count, 2);
    assert.equal(items.find((i) => i.label === "broken/run").href, null);
    assert.ok(!items.some((i) => i.label === "t / calm"));
  });
  it("gives one row per run, keeping the most urgent kind", () => {
    const items = H.attentionItems([
      run({ run_id: "both", has_work: true, tasks: { queued: 4 }, findings: { needs_human: 1 } }),
    ]);
    assert.equal(items.length, 1);
    assert.equal(items[0].kind, "review");
    assert.equal(items[0].text, "1 finding needs review · 4 tasks queued, Ralph not running");
  });
  it("is empty for quiet runs and renders nothing", () => {
    assert.deepEqual(H.attentionItems([run({})]), []);
    assert.equal(H.renderAttentionHtml([], String), "");
  });
  it("escapes labels in markup", () => {
    const html = H.renderAttentionHtml(
      [{ kind: "review", label: "<x>", text: "1 finding need review", href: "/runs/a/b#report/report" }],
      (s) => String(s).replace(/</g, "&lt;").replace(/>/g, "&gt;")
    );
    assert.ok(html.includes("&lt;x&gt;"));
    assert.ok(html.includes('href="/runs/a/b#report/report"'));
  });
});
