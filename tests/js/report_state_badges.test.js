"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  TIPS,
  findingStateTrail,
  findingStateTrailHtml,
  llmSignal,
} = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "report_state_badges.js")
);

function labels(finding) {
  return findingStateTrail(finding).map((s) => s.label);
}

function tones(finding) {
  return findingStateTrail(finding).map((s) => s.tone);
}

function current(finding) {
  return findingStateTrail(finding).filter((s) => s.current).map((s) => s.id);
}

function badgeTexts(html) {
  return [...html.matchAll(/class="([^"]+)"[^>]*>([^<]*)</g)].map((m) => ({
    cls: m[1].split(/\s+/),
    text: m[2].trim(),
  }));
}

function assertNoFalseConfirm(finding) {
  const state = String((finding && finding.state) || "").toLowerCase();
  const html = findingStateTrailHtml(finding);
  const badges = badgeTexts(html);
  for (const b of badges) {
    if (state !== "confirmed") {
      assert.ok(!b.cls.includes("confirmed"), html);
      assert.equal(/\bconfirmed\b/i.test(b.text), false, b.text);
    }
    if (b.cls.includes("step-stood") || b.cls.includes("llm-verify")) {
      assert.ok(!b.cls.includes("confirmed"));
      assert.equal(/\baccepted\b/i.test(b.text), false, b.text);
    }
  }
  const trail = findingStateTrail(finding);
  const confirmedSteps = trail.filter((s) => s.tone === "confirmed");
  if (state === "confirmed") {
    assert.equal(confirmedSteps.length, 1);
    assert.equal(confirmedSteps[0].id, "human");
    assert.equal(confirmedSteps[0].label, "Human accepted");
    assert.match(confirmedSteps[0].title, /human-only/i);
    assert.match(confirmedSteps[0].title, /never auto/i);
  } else {
    assert.equal(confirmedSteps.length, 0);
  }
}

describe("findingStateTrail", () => {
  it("shows the full path while a finding is still proposed", () => {
    const f = { state: "candidate", body: { title: "sketch" } };
    assert.deepEqual(labels(f), ["Proposed", "Mech", "Disprove", "Human"]);
    assert.deepEqual(current(f), ["proposed"]);
    assert.equal(tones(f)[0], "candidate");
    assert.ok(tones(f).slice(1).every((t) => t === "step-wait"));
    assertNoFalseConfirm(f);
  });

  it("stops at mech rejected", () => {
    const f = {
      state: "rejected_mech",
      body: { validation_reasons: ["citation_missing_line"] },
    };
    assert.deepEqual(labels(f), ["Proposed", "Mech rejected"]);
    assert.deepEqual(current(f), ["mech"]);
    assert.equal(tones(f)[1], "rejected_mech");
    assertNoFalseConfirm(f);
  });

  it("shows disprove pending without a confirmed tone", () => {
    const f = {
      state: "needs_human",
      body: { validation_mech: { status: "passed", pending_llm: true } },
    };
    assert.deepEqual(labels(f), ["Proposed", "Mech pass", "Disprove pending", "Human"]);
    assert.deepEqual(current(f), ["disprove"]);
    assert.equal(tones(f)[1], "step-pass");
    assert.ok(!tones(f).includes("confirmed"));
    assert.match(findingStateTrail(f)[2].title, /never auto-confirms/i);
    assertNoFalseConfirm(f);
  });

  it("does not treat an LLM self-grade as confirmed", () => {
    const f = {
      state: "needs_human",
      body: {
        confirmed: true,
        validation_mech: { status: "passed", pending_llm: false },
        validation_llm: {
          status: "needs_human",
          stood: 2,
          total: 2,
          label: "2/2",
          aggregate: "needs_human",
          verdict: "stand",
          self_grade: "confirmed",
          grade: "confirmed",
          confirmed: true,
          verifiers: [
            { id: "a", verdict: "stand" },
            { id: "b", verdict: "stand" },
          ],
        },
      },
    };
    assert.deepEqual(labels(f), [
      "Proposed",
      "Mech pass",
      "Disprove stood 2/2",
      "Needs human",
    ]);
    assert.deepEqual(current(f), ["human"]);
    assert.equal(tones(f)[2], "step-stood");
    assert.match(findingStateTrail(f)[2].title, /not confirmed/i);
    assert.match(findingStateTrail(f)[2].title, /human-only/i);
    const html = findingStateTrailHtml(f);
    assert.match(html, /data-step="disprove"/);
    assert.match(html, /title="[^"]*human-only/);
    assert.equal(html.includes('class="badge report-state-step confirmed'), false);
    assertNoFalseConfirm(f);
    const signal = llmSignal(f.body.validation_llm);
    assert.equal(signal.word, "disprove stood");
    assert.equal(signal.tone, "llm-verify-all");
    assert.equal(signal.tone.includes("confirmed"), false);
    assert.match(signal.title, /not confirmed/i);
  });

  it("treats a stored verdict of confirmed as a stand, not a confirm", () => {
    const f = {
      state: "needs_human",
      body: {
        validation_mech: { status: "passed" },
        validation_llm: { verdict: "confirmed", status: "completed", label: "pass" },
      },
    };
    assert.equal(labels(f).includes("Disprove stood"), true);
    assert.deepEqual(current(f), ["human"]);
    assertNoFalseConfirm(f);
  });

  it("shows disprove off when mech passed and no LLM ran", () => {
    const f = {
      state: "needs_human",
      body: { needs_human: true, validation_mech: { status: "passed" } },
    };
    assert.deepEqual(labels(f), ["Proposed", "Mech pass", "Disprove off", "Needs human"]);
    assert.deepEqual(current(f), ["human"]);
    assertNoFalseConfirm(f);
  });

  it("stops at disprove rejected and does not say survived", () => {
    const f = {
      state: "rejected_llm",
      body: {
        validation_mech: { status: "passed", pending_llm: false },
        validation_llm: {
          status: "completed",
          stood: 0,
          total: 2,
          label: "0/2",
          aggregate: "rejected_llm",
          verdict: "reject",
          verifiers: [
            { verdict: "reject" },
            { verdict: "reject" },
          ],
        },
      },
    };
    assert.deepEqual(labels(f), ["Proposed", "Mech pass", "Disprove rejected 0/2"]);
    assert.deepEqual(current(f), ["disprove"]);
    assert.equal(tones(f).includes("confirmed"), false);
    const signal = llmSignal(f.body.validation_llm);
    assert.equal(signal.word, "disprove rejected");
    assert.equal(signal.tone, "llm-verify-none");
    assertNoFalseConfirm(f);
  });

  it("does not call a zero-stand mixed result rejected", () => {
    const f = {
      state: "needs_human",
      body: {
        validation_mech: { status: "passed" },
        validation_llm: {
          stood: 0,
          total: 2,
          status: "needs_human",
          aggregate: "needs_human",
          verdict: "needs_human",
          verifiers: [
            { verdict: "needs_human" },
            { verdict: "needs_human" },
          ],
        },
      },
    };
    assert.equal(labels(f)[2], "Disprove stood 0/2");
    assert.equal(tones(f)[2], "step-stood");
    assert.equal(llmSignal(f.body.validation_llm).word, "disprove stood");
    assertNoFalseConfirm(f);
  });

  it("marks human accepted only for state confirmed", () => {
    const f = {
      state: "confirmed",
      body: {
        validation_mech: { status: "passed", pending_llm: false },
        validation_llm: {
          stood: 2,
          total: 2,
          aggregate: "needs_human",
          verdict: "stand",
          self_grade: "confirmed",
        },
        human_review_latest: { action: "confirm", to_state: "confirmed" },
      },
    };
    assert.deepEqual(labels(f), [
      "Proposed",
      "Mech pass",
      "Disprove stood 2/2",
      "Human accepted",
    ]);
    assert.deepEqual(current(f), ["human"]);
    assert.equal(tones(f)[2], "step-stood");
    assert.equal(tones(f)[3], "confirmed");
    const html = findingStateTrailHtml(f);
    assert.match(html, /Human accepted/);
    assert.match(html, /title="[^"]*never auto-confirms/);
    assert.equal((html.match(/report-state-step confirmed/g) || []).length, 1);
    assertNoFalseConfirm(f);
  });

  it("keeps a prior disprove reject visible when a human later accepts", () => {
    const f = {
      state: "confirmed",
      body: {
        validation_mech: { status: "passed" },
        validation_llm: { aggregate: "rejected_llm", stood: 0, total: 2, verdict: "reject" },
      },
    };
    assert.deepEqual(labels(f), [
      "Proposed",
      "Mech pass",
      "Disprove rejected 0/2",
      "Human accepted",
    ]);
    assert.equal(tones(f)[2], "rejected_llm");
    assert.equal(tones(f)[3], "confirmed");
    assert.deepEqual(current(f), ["human"]);
  });

  it("shows human rejected", () => {
    const f = {
      state: "rejected_human",
      body: { validation_mech: { status: "passed" } },
    };
    assert.equal(labels(f).at(-1), "Human rejected");
    assert.equal(tones(f).at(-1), "rejected_human");
    assert.deepEqual(current(f), ["human"]);
    assertNoFalseConfirm(f);
  });

  it("shows superseded as not confirmed", () => {
    const f = { state: "superseded", body: { superseded_by: 7 } };
    assert.deepEqual(labels(f), ["Superseded"]);
    assert.match(findingStateTrail(f)[0].title, /Not confirmed/);
    assertNoFalseConfirm(f);
  });

  it("does not invent mech pass when a human confirms a bare candidate", () => {
    const f = { state: "confirmed", body: {} };
    assert.deepEqual(labels(f), ["Proposed", "Mech n/a", "Disprove n/a", "Human accepted"]);
    assert.equal(tones(f).filter((t) => t === "confirmed").length, 1);
  });

  it("labels an unfinished disprove as incomplete, not stood and not confirmed", () => {
    const f = {
      state: "needs_human",
      body: {
        validation_mech: { status: "passed", pending_llm: false },
        validation_llm: { status: "partial", stood: 1, total: 2, verdict: "pending" },
      },
    };
    assert.equal(labels(f)[2], "Disprove incomplete");
    assert.equal(llmSignal(f.body.validation_llm).word, "disprove incomplete");
    assertNoFalseConfirm(f);
  });

  it("escapes titles and never puts raw state into a confirmed class", () => {
    const f = { state: 'confirmed"><img', body: {} };
    const html = findingStateTrailHtml(f);
    assert.equal(html.includes("<img"), false);
    const badges = badgeTexts(html);
    assert.equal(badges.some((b) => b.cls.includes("confirmed")), false);
    assert.equal(badges.some((b) => /confirmed/i.test(b.text)), false);
    assert.equal(html.includes('class="badge report-state-step confirmed'), false);
  });
});

describe("tips", () => {
  it("states the human-only confirm bar on the accept step", () => {
    assert.match(TIPS.humanAccepted, /human-only/);
    assert.match(TIPS.humanAccepted, /never auto-confirms/);
    assert.match(TIPS.disproveStood, /not confirmed/i);
    assert.match(TIPS.disprovePending, /never auto-confirms/);
  });
});
