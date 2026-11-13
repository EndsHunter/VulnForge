"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const H = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "pages", "dev", "helpers.js"));

describe("parseDevHash / devHash", () => {
  it("routes sections and ids", () => {
    assert.deepEqual(H.parseDevHash("#skills/injection"), { section: "skills", id: "injection" });
    assert.deepEqual(H.parseDevHash("#recon"), { section: "recon", id: "" });
    assert.deepEqual(H.parseDevHash("#lab/ast_query"), { section: "lab", id: "ast_query" });
    assert.deepEqual(H.parseDevHash(""), { section: "skills", id: "" });
    assert.deepEqual(H.parseDevHash("#nonsense"), { section: "skills", id: "" });
  });
  it("keeps legacy deep links working", () => {
    // Campaign matrix → /dev#hunt/<cls>
    assert.deepEqual(H.parseDevHash("#hunt/path-traversal"), { section: "skills", id: "path-traversal" });
    // /tool-gaps "Create tool…" → /dev#tools/<draftId>
    assert.deepEqual(H.parseDevHash("#tools/ast_query"), { section: "lab", id: "ast_query" });
    assert.deepEqual(H.parseDevHash("#tools"), { section: "tools", id: "" });
    assert.deepEqual(H.parseDevHash("#skillgen"), { section: "skills", id: "" });
  });
  it("round-trips encoded ids", () => {
    const h = H.devHash("skills", "a b/c");
    assert.equal(h, "#skills/a%20b%2Fc");
    assert.deepEqual(H.parseDevHash(h), { section: "skills", id: "a b/c" });
    assert.equal(H.devHash("bogus", ""), "#skills");
  });
});

describe("skill filters", () => {
  const P = [
    { id: "injection", title: "Injection", source: "seed", seed_status: "seed", active: true },
    { id: "authz", source: "seed", seed_status: "modified_seed", active: false },
    { id: "jwt", title: "JWT confusion", source: "generated", seed_status: "generated", active: false },
    { id: "mine", source: "custom", seed_status: "custom", active: true },
  ];
  it("filters by provenance and active", () => {
    const ids = (f) => H.filterSkills(P, f, "").map((p) => p.id);
    assert.deepEqual(ids("all"), ["injection", "authz", "jwt", "mine"]);
    assert.deepEqual(ids("active"), ["injection", "mine"]);
    assert.deepEqual(ids("seed"), ["injection"]);
    assert.deepEqual(ids("modified"), ["authz"]);
    assert.deepEqual(ids("custom"), ["jwt", "mine"]);
  });
  it("searches id and title", () => {
    assert.deepEqual(H.filterSkills(P, "all", "jwt").map((p) => p.id), ["jwt"]);
    assert.deepEqual(H.filterSkills(P, "all", "INJECT").map((p) => p.id), ["injection"]);
  });
  it("counts each filter", () => {
    assert.deepEqual(H.skillFilterCounts(P), { all: 4, active: 2, seed: 1, modified: 1, custom: 2 });
  });
  it("labels provenance", () => {
    assert.deepEqual(H.provenance(P[1]), { label: "modified seed", tone: "review" });
    assert.equal(H.provenance({}).label, "custom");
  });
  it("sorts recon agents by order then id", () => {
    const out = H.sortAgents([{ id: "b", order: 20 }, { id: "z" }, { id: "a", order: 20 }, { id: "c", order: 10 }]);
    assert.deepEqual(out.map((a) => a.id), ["c", "a", "b", "z"]);
  });
});

describe("lineDiff", () => {
  it("marks removed seed lines and added current lines", () => {
    const d = H.lineDiff("a\nb\nc", "a\nB\nc\nd");
    assert.deepEqual(d, [
      { op: " ", text: "a" },
      { op: "-", text: "b" },
      { op: "+", text: "B" },
      { op: " ", text: "c" },
      { op: "+", text: "d" },
    ]);
    assert.deepEqual(H.diffStats(d), { added: 2, removed: 1, same: false });
  });
  it("reports identical bodies", () => {
    assert.equal(H.diffStats(H.lineDiff("x\ny", "x\ny")).same, true);
  });
  it("degrades to replace when too large", () => {
    const d = H.lineDiff("a\nb", "c\nd", 2);
    assert.deepEqual(d.map((l) => l.op), ["-", "-", "+", "+"]);
  });
});

describe("parseUnifiedDiff", () => {
  it("classifies lines", () => {
    const kinds = H.parseUnifiedDiff("--- /dev/null\n+++ b/x.py\n@@ -0,0 +1 @@\n+hi\n-bye\n ctx\n").map((l) => l.kind);
    assert.deepEqual(kinds, ["file", "file", "hunk", "add", "del", "ctx"]);
    assert.deepEqual(H.parseUnifiedDiff(""), []);
  });
});

describe("tool allowlists", () => {
  const catalog = [
    { name: "grep", stages: ["hunt", "recon"] },
    { name: "read_file", stages: ["hunt"] },
    { name: "submit_candidate", stages: ["hunt"] },
    { name: "submit_architecture", stages: ["recon"] },
  ];
  it("offers non-submit tools for a stage", () => {
    assert.deepEqual(H.toolChoices(catalog, "hunt"), ["grep", "read_file"]);
    assert.deepEqual(H.toolChoices(catalog, "recon"), ["grep"]);
    assert.deepEqual(H.toolChoices(catalog, "hunt", ["note", "grep", "submit_none", "note"]), ["note", "grep"]);
  });
  it("maps null/empty to the full set", () => {
    assert.deepEqual(H.allowlistState(null), { all: true, selected: [] });
    assert.deepEqual(H.allowlistState([]), { all: true, selected: [] });
    assert.deepEqual(H.allowlistState(["grep"]), { all: false, selected: ["grep"] });
  });
  it("builds hunt and stage-default payloads", () => {
    assert.deepEqual(H.huntToolsPayload(true, ["grep"]), { clear_tools: true, tools: null });
    assert.deepEqual(H.huntToolsPayload(false, ["grep"]), { clear_tools: false, tools: ["grep"] });
    assert.deepEqual(H.stageDefaultsPayload({ hunt: ["grep"] }), { recon: null, hunt: ["grep"], develop_poc: null });
  });
  it("builds recon payloads, omitting blank numbers", () => {
    const p = H.reconPayload({ title: " T ", active: 1, body_md: "# b", order: "10", temperature: "", max_tool_rounds: "x", allTools: false, tools: ["grep"] });
    assert.deepEqual(p, { title: "T", description: "", active: true, body_md: "# b", tools: ["grep"], order: 10 });
    assert.deepEqual(H.reconPayload({ allTools: true, tools: ["grep"], temperature: "0.2" }).tools, []);
    assert.equal(H.reconPayload({ temperature: "0.2" }).temperature, 0.2);
  });
});

describe("tool lab", () => {
  it("tracks step progress", () => {
    const p = H.labProgress({
      id: "x",
      meta: { id: "x", status: "validated" },
      spec_md: "# s",
      impl_py: "def x(): pass",
      schema: { tools: [{ name: "x" }] },
      validation_report: { ok: true },
    });
    assert.deepEqual(p, { brief: true, spec: true, impl: true, validate: true, integrate: false });
    assert.equal(H.labProgress({ impl_py: "x", schema: { tools: [] } }).impl, false);
  });
  it("gates apply on a fresh dry-run and overwrite consent", () => {
    assert.equal(H.applyGate({}).enabled, false);
    assert.match(H.applyGate({}).reason, /dry-run/);
    const dry = { plan_hash: "h", overwrites: [] };
    assert.equal(H.applyGate({ dry }).enabled, true);
    assert.equal(H.applyGate({ dry, stale: true }).enabled, false);
    const ow = { plan_hash: "h", overwrites: ["vulnforge/tools/agent/grep.py"] };
    assert.equal(H.applyGate({ dry: ow }).enabled, false);
    assert.match(H.applyGate({ dry: ow }).reason, /overwrite of 1 existing file\./);
    assert.equal(H.applyGate({ dry: ow, overwriteAck: true }).enabled, true);
    assert.equal(H.applyGate({ dry, status: "integrated" }).enabled, false);
    assert.equal(H.applyGate({ dry, status: "rejected" }).enabled, false);
  });
  it("labels planned ops", () => {
    assert.equal(H.opBadge({ op: "write", exists: false }).label, "new file");
    assert.equal(H.opBadge({ op: "write", exists: true, overwrite: true }).tone, "danger");
    assert.equal(H.opBadge({ op: "write", exists: true, overwrite: false }).label, "updates");
    assert.equal(H.opBadge({ op: "skip", exists: true }).label, "skipped (exists)");
  });
});

describe("summarizeSetupImport", () => {
  it("lists imported sections", () => {
    const s = H.summarizeSetupImport({ sections: { hunt_profiles: { count: 3 }, ui_settings: { ok: true } } });
    assert.equal(s, "3 hunt skills · settings");
    assert.equal(H.summarizeSetupImport({}), "nothing imported");
  });
});
