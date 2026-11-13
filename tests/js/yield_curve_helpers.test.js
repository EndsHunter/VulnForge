"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { buildYieldView, yieldSentence, formatYieldRate } = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "mission_overview_helpers.js")
);

function pt(end, { hunts = 20, tokens = 1_000_000, gated = 0, available = true } = {}) {
  return {
    start_task_id: Math.max(1, end - hunts + 1),
    end_task_id: end,
    hunts,
    tokens,
    gated,
    available,
    rate_per_mtok: available ? (gated * 1e6) / tokens : null,
  };
}

function payload(series, extra = {}) {
  const latest = series[series.length - 1] || null;
  return {
    schema: "vulnforge.yield@1",
    advisory: true,
    window: { basis: "hunts", size: 20 },
    available: !!(latest && latest.available),
    latest,
    series,
    ...extra,
  };
}

describe("yieldSentence", () => {
  it("matches the issue wording", () => {
    assert.equal(
      yieldSentence({ hunts: 20, tokens: 1_400_000, gated: 0, available: true }),
      "0 new gated findings in the last 1.4M tokens (20 hunts)"
    );
  });
  it("singular forms", () => {
    assert.equal(
      yieldSentence({ hunts: 1, tokens: 900, gated: 1, available: true }),
      "1 new gated finding in the last 900 tokens (1 hunt)"
    );
  });
  it("says unavailable instead of zero when usage is missing", () => {
    const s = yieldSentence({ hunts: 5, tokens: 0, gated: 0, available: false });
    assert.match(s, /^Yield unavailable/);
    assert.doesNotMatch(s, /\b0 new\b/);
  });
  it("empty run", () => {
    assert.equal(yieldSentence(null), "No finished hunts yet.");
  });
});

describe("formatYieldRate", () => {
  it("formats per million tokens", () => {
    assert.equal(formatYieldRate(0), "0 per 1M tokens");
    assert.equal(formatYieldRate(1.5), "1.5 per 1M tokens");
    assert.equal(formatYieldRate(0.25), "0.25 per 1M tokens");
    assert.equal(formatYieldRate(12.4), "12 per 1M tokens");
  });
  it("blank for null", () => {
    assert.equal(formatYieldRate(null), "");
  });
});

describe("buildYieldView", () => {
  it("empty run: no line, open cells still shown", () => {
    const v = buildYieldView({ available: false, reason: "no_hunts", latest: null, series: [] }, 12);
    assert.equal(v.state, "empty");
    assert.equal(v.path, "");
    assert.equal(v.openText, "12 open cells");
  });

  it("missing payload (older server) degrades to empty", () => {
    const v = buildYieldView(undefined, null);
    assert.equal(v.state, "empty");
    assert.equal(v.openText, "");
  });

  it("no usage data: unavailable, draws nothing", () => {
    const series = [pt(1, { hunts: 1, available: false }), pt(2, { hunts: 2, available: false })];
    const v = buildYieldView(payload(series, { reason: "no_usage" }), 3);
    assert.equal(v.state, "unavailable");
    assert.equal(v.path, "");
    assert.equal(v.last, null);
    assert.match(v.sentence, /^Yield unavailable/);
    assert.equal(v.openText, "3 open cells");
  });

  it("draws a line with a gap where usage is missing, never a zero", () => {
    const series = [pt(20, { gated: 2 }), pt(21, { available: false }), pt(22, { gated: 1 }), pt(23)];
    const v = buildYieldView(payload(series), 1);
    assert.equal(v.state, "ok");
    // Two separate subpaths (M … M …): the missing window is a gap.
    assert.equal((v.path.match(/M/g) || []).length, 2);
    assert.equal(v.gapCount, 1);
    assert.equal(v.hits[1].y, null);
    assert.equal(v.openText, "1 open cell");
    assert.equal(v.sentence, "0 new gated findings in the last 1.0M tokens (20 hunts)");
    assert.equal(v.rateText, "0 per 1M tokens");
    // Latest point is at the right edge and on the baseline (a real zero).
    assert.ok(v.last.x > 100);
    assert.equal(v.last.y, 24);
  });

  it("flat zero curve still draws (available) and keeps open cells beside it", () => {
    const series = [pt(20), pt(21), pt(22)];
    const v = buildYieldView(payload(series), 40);
    assert.equal(v.state, "ok");
    assert.ok(v.path.startsWith("M"));
    assert.equal(v.openText, "40 open cells");
    assert.match(v.openTitle, /flat curve does not mean nothing is left/);
  });

  it("single window gets a visible tick", () => {
    const v = buildYieldView(payload([pt(1, { hunts: 1, gated: 1, tokens: 500_000 })]), 0);
    assert.equal(v.state, "ok");
    assert.match(v.path, /^M[\d.]+ [\d.]+L/);
    assert.equal(v.rateText, "2 per 1M tokens");
  });

  it("empty matrix never reads as 0 open cells", () => {
    const v = buildYieldView(payload([pt(20)]), { open: 0, total: 0 });
    assert.equal(v.openText, "No coverage matrix yet");
    assert.match(v.openTitle, /does not mean nothing is left/);
    const w = buildYieldView(payload([pt(20)]), { open: 5, total: 16 });
    assert.equal(w.openText, "5 open cells");
  });

  it("title says advisory", () => {
    const v = buildYieldView(payload([pt(20)]), 0);
    assert.match(v.title, /never pauses or stops Ralph/);
  });
});
