"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const H = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "pages", "settings_helpers.js"));

const A = { host_id: "lab", model_id: "qwen" };
const B = { host_id: "lab", model_id: "llama" };
const C = { host_id: "cloud|x", model_id: "m/1" };

describe("refKey / parseRefKey", () => {
  it("round-trips host and model ids, including separators", () => {
    assert.deepEqual(H.parseRefKey(H.refKey(A)), A);
    assert.deepEqual(H.parseRefKey(H.refKey(C)), C);
  });
  it("rejects blanks and junk", () => {
    assert.equal(H.refKey({ host_id: "lab" }), "");
    assert.equal(H.refKey(null), "");
    assert.equal(H.parseRefKey(""), null);
    assert.equal(H.parseRefKey("nopipe"), null);
    assert.equal(H.parseRefKey("|m"), null);
    assert.equal(H.parseRefKey("%E0%A4%A|m"), null);
  });
});

describe("pairState / catalogSummary", () => {
  const verified = new Set([H.refKey(A)]);
  it("verified, unchecked, and failing", () => {
    assert.equal(H.pairState(A, verified, {}), "verified");
    assert.equal(H.pairState(B, verified, {}), "unchecked");
    assert.equal(H.pairState(B, verified, { [H.refKey(B)]: "timeout" }), "failing");
  });
  it("a failure this session wins over an older verification", () => {
    assert.equal(H.pairState(A, verified, { [H.refKey(A)]: "401" }), "failing");
  });
  it("accepts an array of verified keys", () => {
    assert.equal(H.pairState(A, [H.refKey(A)], null), "verified");
  });
  it("counts per state", () => {
    const sum = H.catalogSummary([A, B, C], verified, { [H.refKey(C)]: "x" });
    assert.deepEqual(sum, { total: 3, verified: 1, failing: 1, unchecked: 1 });
  });
});

describe("budgetRowsFromAvailable / pairBudget", () => {
  it("normalizes rows to the table shape with nulls for blanks", () => {
    const rows = H.budgetRowsFromAvailable([
      { ...A, verified_at: "t", context_tokens: "8192", max_tokens: null },
      { host_id: "", model_id: "x" },
      "junk",
    ]);
    assert.deepEqual(rows, [
      { ...A, verified_at: "t", context_tokens: 8192, max_tokens: null, max_concurrent_agents: null },
    ]);
  });
  it("pair override wins; blank falls back to the global seed", () => {
    const eff = H.pairBudget({ context_tokens: 8192, max_tokens: "" }, { context_tokens: 32768, max_tokens: 4096, max_concurrent_agents: 2 });
    assert.deepEqual(eff.context_tokens, { value: 8192, source: "pair" });
    assert.deepEqual(eff.max_tokens, { value: 4096, source: "seed" });
    assert.deepEqual(eff.max_concurrent_agents, { value: 2, source: "seed" });
    assert.equal("max_context_fraction" in eff, false);
  });
});

describe("dirtySections / rebaseline", () => {
  const base = { hosts: [{ id: "lab", base_url: "u" }], model: A, context_tokens: 32768, available: [], poc_iterate_max_cycles: 5 };
  it("is clean for equal bodies regardless of key order", () => {
    const same = { poc_iterate_max_cycles: 5, available: [], context_tokens: 32768, model: { model_id: "qwen", host_id: "lab" }, hosts: [{ base_url: "u", id: "lab" }] };
    assert.deepEqual(H.dirtySections(base, same), []);
  });
  it("names each section that changed", () => {
    const cur = { ...base, model: B, context_tokens: 8192 };
    assert.deepEqual(H.dirtySections(base, cur), ["roles", "budgets"]);
    assert.deepEqual(H.dirtySections(base, { ...base, hosts: [] }), ["connections"]);
    assert.deepEqual(H.dirtySections(base, { ...base, poc_iterate_max_cycles: 6 }), ["sandbox"]);
  });
  it("a typed API key makes Connections dirty", () => {
    const cur = { ...base, hosts: [{ id: "lab", base_url: "u", api_key: "sk-typed" }] };
    assert.deepEqual(H.dirtySections(base, cur), ["connections"]);
  });
  it("rebaseline follows the server for untouched keys and keeps edits dirty", () => {
    const before = { ...base, context_tokens: 8192 }; // operator edited the seed
    const after = { ...before, available: [A], model: null }; // verify added A, server cleared model
    const next = H.rebaseline(base, before, after);
    assert.deepEqual(next.available, [A]);
    assert.equal(next.model, null);
    assert.equal(next.context_tokens, 32768);
    assert.deepEqual(H.dirtySections(next, after), ["budgets"]);
  });
});

describe("validateWarning", () => {
  const a = H.refKey(A);
  const b = H.refKey(B);
  it("same model as hunt is a weak signal", () => {
    assert.equal(H.validateWarning({ checked: [a], hunt: a }), H.SAME_MODEL_WARN);
    assert.equal(H.validateWarning({ dedicated: "", hunt: "", defaultRole: a }), H.SAME_MODEL_WARN);
    assert.equal(H.validateWarning({}), H.SAME_MODEL_WARN);
  });
  it("checked list beats the dedicated role", () => {
    // Dedicated = hunt would be same-model; the checked list replaces it.
    assert.equal(H.validateWarning({ checked: [b], dedicated: a, hunt: a }), H.ONE_MODEL_WARN);
  });
  it("one distinct validation model is weaker than two", () => {
    assert.equal(H.validateWarning({ dedicated: b, hunt: a }), H.ONE_MODEL_WARN);
    assert.equal(H.validateWarning({ checked: [b, b], hunt: a }), H.ONE_MODEL_WARN);
  });
  it("two distinct models off the hunt model: no warning", () => {
    assert.equal(H.validateWarning({ checked: [a, b], hunt: a }), "");
  });
  it("copy never claims confirmation", () => {
    assert.match(H.SAME_MODEL_WARN, /same-model dual disprove is a weak signal/);
    assert.match(H.ONE_MODEL_WARN, /One validation model is a weaker signal than two/);
    assert.match(H.SAME_MODEL_WARN, /Never auto-confirms/);
  });
});

describe("perspectiveWarning / defaultHuntPrompt", () => {
  it("warns only when every slot pins the same model", () => {
    assert.equal(H.perspectiveWarning([{ model: A }, { model: { ...A } }]), H.SAME_PERSPECTIVE_WARN);
    assert.equal(H.perspectiveWarning([{ model: A }, { model: "" }]), "");
    assert.equal(H.perspectiveWarning([{ model: A }, { model: B }]), "");
    assert.equal(H.perspectiveWarning([{ model: A }]), "");
  });
  it("derives the prompt file from the id", () => {
    const known = [{ id: "sink_driven", prompt: "hunt_sink.md" }];
    assert.equal(H.defaultHuntPrompt("sink_driven", known), "hunt_sink.md");
    assert.equal(H.defaultHuntPrompt("my perspective!", known), "hunt_my_perspective.md");
    assert.equal(H.defaultHuntPrompt("", known), "hunt_perspective.md");
  });
});

describe("hostEditImpact", () => {
  const saved = [
    { id: "lab", base_url: "http://lab/v1", api_mode: "chat_completions", api_key_set: true },
    { id: "cloud", base_url: "http://cloud/v1", api_mode: "responses" },
  ];
  const avail = [A, B, { host_id: "cloud", model_id: "d" }];
  const same = () => saved.map(({ api_key_set, ...h }) => ({ ...h }));
  it("no edits, no impact (blank key field keeps the stored key)", () => {
    assert.deepEqual(H.hostEditImpact(saved, same(), avail), []);
  });
  it("a typed or cleared key unverifies that host's pairs", () => {
    const form = same();
    form[0].api_key = "sk-new";
    assert.deepEqual(H.hostEditImpact(saved, form, avail), [
      { host_id: "lab", base_url: "http://lab/v1", reason: "key", pairs: 2 },
    ]);
    form[0].api_key = "";
    assert.equal(H.hostEditImpact(saved, form, avail)[0].reason, "key");
  });
  it("URL change, mode change, and removal", () => {
    const form = same();
    form[0].base_url = "http://lab2/v1";
    form[1].api_mode = "messages";
    assert.deepEqual(
      H.hostEditImpact(saved, form, avail).map((i) => [i.host_id, i.reason, i.pairs]),
      [["lab", "url", 2], ["cloud", "mode", 1]]
    );
    assert.deepEqual(H.hostEditImpact(saved, [form[1]], avail).map((i) => i.reason), ["removed", "mode"]);
  });
  it("a key change on a host with nothing verified is not worth a warning", () => {
    const form = same();
    form[1].api_key = "x";
    assert.deepEqual(H.hostEditImpact(saved, form, [A]), []);
  });
});
