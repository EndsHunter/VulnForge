"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const P = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "report_policy_promote.js")
);

describe("report_policy_promote", () => {
  it("offers promote only for an explicit human reject", () => {
    assert.equal(P.canPromote({ state: "rejected_human" }), true);
    for (const st of ["needs_human", "confirmed", "rejected_mech", "rejected_llm", "candidate", ""]) {
      assert.equal(P.canPromote({ state: st }), false, st);
    }
    assert.equal(P.canPromote(null), false);
  });

  it("only demote-only lists are targets", () => {
    assert.deepEqual(P.TARGETS, ["exclusions", "out_of_scope"]);
  });

  it("builds a body without provenance and parses paths", () => {
    const b = P.buildPromoteBody(
      {
        target_list: "exclusions",
        id: " ex-hr-3 ",
        paths: "app.py\n admin/** ,app.py\n",
        weakness_class: "injection",
        reason: " admin only ",
        all_classes: false,
        base_revision: 4,
      },
      true
    );
    assert.deepEqual(b.rule, {
      id: "ex-hr-3",
      paths: ["app.py", "admin/**"],
      reason: "admin only",
      weakness_class: "injection",
    });
    assert.equal(b.dry_run, true);
    assert.equal(b.base_revision, 4);
    assert.equal(b.all_classes, false);
    assert.ok(!("provenance" in b.rule));
    assert.ok(!("provenance" in b));
  });

  it("all-classes is explicit and only for exclusions", () => {
    const ex = P.buildPromoteBody({ target_list: "exclusions", paths: "a", all_classes: true }, false);
    assert.equal(ex.all_classes, true);
    assert.ok(!("weakness_class" in ex.rule));
    const oos = P.buildPromoteBody(
      { target_list: "out_of_scope", paths: "a", weakness_class: "x", all_classes: true },
      false
    );
    assert.equal(oos.all_classes, false);
    assert.ok(!("weakness_class" in oos.rule));
    const bogus = P.buildPromoteBody({ target_list: "attacker_controlled", paths: "a" }, false);
    assert.equal(bogus.target_list, "exclusions");
    assert.equal(P.buildPromoteBody({ paths: "" }, false).base_revision, null);
  });

  it("extracts error lines from API failures", () => {
    assert.deepEqual(P.errorLines({ detail: { error: "invalid_rule", errors: ["a", "b"] } }), ["a", "b"]);
    assert.deepEqual(P.errorLines({ detail: { error: "policy_changed", detail: "moved" } }), ["moved"]);
    assert.deepEqual(P.errorLines({ detail: "nope" }), ["nope"]);
    assert.deepEqual(P.errorLines(null), ["request failed"]);
  });

  it("would-match list says nothing is changed and escapes", () => {
    const html = P.wouldMatchHtml({
      needs_human: [{ finding_id: 7, title: "<x>", matched_paths: ["app.py"] }],
      matches_source: true,
    });
    assert.match(html, /not<\/strong> changed/);
    assert.match(html, /&lt;x&gt;/);
    assert.match(html, /data-fid="7"/);
    assert.match(P.wouldMatchHtml({ needs_human: [], matches_source: false }), /would not match/);
    assert.match(P.wouldMatchHtml(null), /No findings awaiting review/);
  });

  it("history shows provenance rows", () => {
    assert.equal(P.historyProvenanceHtml([]), "");
    const html = P.historyProvenanceHtml([
      {
        list: "exclusions",
        rule_id: "ex-hr-3",
        finding_id: 3,
        hitl_report_id: "finding-3",
        hitl_block_id: "finding-3-review",
        hitl_response_at: "2026-01-01T00:00:00Z",
        operator: "op",
      },
    ]);
    assert.match(html, /ex-hr-3/);
    assert.match(html, /#3/);
    assert.match(html, /finding-3\/finding-3-review/);
  });
});
