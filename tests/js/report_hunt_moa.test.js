"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  huntMoaMeta,
  huntMoaBadgeHtml,
  huntMoaDetailHtml,
  normalizeRequeueNote,
  cellRequeueNoteHtml,
  TIP,
} = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "report_hunt_moa.js")
);

describe("ReportHuntMoa", () => {
  it("is graceful when hunt_moa is absent", () => {
    assert.equal(huntMoaMeta({ state: "candidate", body: { title: "x" } }), null);
    assert.equal(huntMoaBadgeHtml({ body: {} }), "");
    assert.equal(huntMoaDetailHtml({ body: {} }), "");
    assert.equal(huntMoaMeta(null), null);
    assert.equal(huntMoaMeta({ body: { hunt_moa: {} } }), null);
  });

  it("renders muted agree label without confirm wording", () => {
    const f = {
      state: "candidate",
      body: {
        hunt_moa: {
          perspectives: [
            { id: "sink_driven", outcome: "candidate", title: "SQLi in q", reason: "concat" },
            { id: "dataflow", outcome: "candidate" },
            { id: "authz", outcome: "none", reason: "no authz path" },
          ],
          agree_count: 2,
          label: "2/3 hunt agree",
          cell_outcome: "candidate",
          requeue_note: "partial_none",
          none_perspectives: ["authz"],
        },
      },
    };
    const m = huntMoaMeta(f);
    assert.equal(m.label, "2/3 hunt agree");
    assert.equal(m.requeue_note, "partial_none");
    const badge = huntMoaBadgeHtml(f);
    assert.match(badge, /2\/3 hunt agree/);
    assert.match(badge, /hunt-moa-agree/);
    assert.match(badge, /not confirmed/i);
    // Visible label text must not say "confirmed" (tips may say "not confirmed").
    const labelText = badge.replace(/<[^>]+>/g, " ");
    assert.match(labelText, /2\/3 hunt agree/);
    assert.equal(/\bconfirmed\b/i.test(labelText.replace(/not confirmed/gi, "")), false);
    const detail = huntMoaDetailHtml(f);
    assert.match(detail, /sink_driven/);
    assert.match(detail, /authz/);
    assert.match(detail, /partial_none/);
    assert.match(detail, /SQLi in q/);
    assert.equal(/\bauto-confirm\b/i.test(detail), false);
    assert.match(detail, /never auto-confirms/i);
  });

  it("builds label from agree_count when label missing", () => {
    const m = huntMoaMeta({
      body: {
        hunt_moa: {
          perspectives: [{ id: "a", outcome: "candidate" }, { id: "b", outcome: "none" }],
          agree_count: 1,
        },
      },
    });
    assert.equal(m.label, "1/2 hunt agree");
  });

  it("normalizes spike long requeue_note strings", () => {
    assert.equal(normalizeRequeueNote("all_perspectives_none"), "all_perspectives_none");
    assert.equal(
      normalizeRequeueNote("all_perspectives_none: keep cell as none; ..."),
      "all_perspectives_none"
    );
    assert.equal(
      normalizeRequeueNote("partial_none: keep best-ranked candidate"),
      "partial_none"
    );
    assert.equal(normalizeRequeueNote(null), "");
  });

  it("emits residual cell MoA note from findings", () => {
    const html = cellRequeueNoteHtml([
      {
        body: {
          hunt_moa: { requeue_note: "all_perspectives_none", label: "0/3 hunt agree" },
        },
      },
    ]);
    assert.match(html, /all_perspectives_none/);
    assert.match(html, /Not proof of safety/);
    assert.equal(cellRequeueNoteHtml([]), "");
  });
});
