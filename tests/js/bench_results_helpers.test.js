"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const helpers = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "bench_results_helpers.js")
);

const {
  formatScore,
  formatDelta,
  deltaTone,
  seriesToPolyline,
  gridYs,
} = helpers;

describe("formatScore / formatDelta", () => {
  it("formats finite numbers and blanks the rest", () => {
    assert.equal(formatScore(0.5), "0.500");
    assert.equal(formatScore(1, 1), "1.0");
    assert.equal(formatScore("nope"), "—");
    assert.equal(formatDelta(0.25), "+0.250");
    assert.equal(formatDelta(-0.5), "-0.500");
    assert.equal(formatDelta(0), "0.000");
  });
});

describe("deltaTone", () => {
  it("classifies pos / neg / zero", () => {
    assert.equal(deltaTone(0.1), "pos");
    assert.equal(deltaTone(-0.1), "neg");
    assert.equal(deltaTone(0), "zero");
    assert.equal(deltaTone("x"), "zero");
  });
});

describe("seriesToPolyline", () => {
  it("returns empty layout for no points", () => {
    const layout = seriesToPolyline([]);
    assert.equal(layout.empty, true);
    assert.equal(layout.points, "");
    assert.deepEqual(layout.dots, []);
  });

  it("maps two unit scores onto a descending-y polyline", () => {
    const layout = seriesToPolyline(
      [
        { score: 0, started_at: "2026-01-01T00:00:00Z", run_id: "br-a", version: 1 },
        { score: 1, started_at: "2026-01-02T00:00:00Z", run_id: "br-b", version: 2 },
      ],
      { width: 640, height: 180, pad: 28 }
    );
    assert.equal(layout.empty, false);
    assert.equal(layout.dots.length, 2);
    assert.equal(layout.dots[0].x, 28);
    assert.equal(layout.dots[1].x, 612);
    assert.ok(layout.dots[0].y > layout.dots[1].y);
    assert.equal(layout.dots[0].score, 0);
    assert.equal(layout.dots[1].score, 1);
    assert.match(layout.points, /28,/);
  });

  it("centers a single point", () => {
    const layout = seriesToPolyline([{ score: 0.5 }], { width: 100, height: 100, pad: 10 });
    assert.equal(layout.dots.length, 1);
    assert.equal(layout.dots[0].x, 50);
  });
});

describe("gridYs", () => {
  it("emits top / mid / bottom ticks", () => {
    const rows = gridYs(180, 28, 2);
    assert.equal(rows.length, 3);
    assert.equal(rows[0].label, "1.0");
    assert.equal(rows[2].label, "0.0");
  });
});
