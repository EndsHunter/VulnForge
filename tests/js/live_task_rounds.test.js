"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_JS = path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "app.js");

function renderLivePaneBody(source) {
  const start = source.indexOf("function renderLivePane");
  const end = source.indexOf("async function sendLiveNote");
  if (start < 0 || end < start) {
    throw new Error("renderLivePane span missing");
  }
  return source.slice(start, end);
}

function element() {
  return {
    innerHTML: "",
    textContent: "",
    disabled: false,
    title: "",
    scrollTop: 0,
    scrollHeight: 0,
  };
}

function loadRenderLivePane() {
  const nodes = new Map();
  const sandbox = {
    Number,
    String,
    Array,
    Date,
    globalThis: {},
    esc(s) {
      return String(s ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    },
    $(sel) {
      if (!nodes.has(sel)) nodes.set(sel, element());
      return nodes.get(sel);
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(
    `${renderLivePaneBody(fs.readFileSync(APP_JS, "utf8"))}\nthis.renderLivePane = renderLivePane;`,
    sandbox
  );
  return {
    renderLivePane: sandbox.renderLivePane,
    nodes,
  };
}

function roundBadges(html) {
  return html.match(/round\s+\d+\s*\/\s*\d+/gi) || [];
}

const sample = {
  task_id: 4,
  kind: "hunt",
  state: "leased",
  round: 9,
  max_rounds: 50,
  tool: "submit_none",
  args_summary: "reason=done",
  steps: [
    {
      round: 9,
      max_rounds: 50,
      call: 1,
      tool: "grep",
      args_summary: "pattern=SELECT path=app.py",
      ok: true,
    },
    {
      round: 9,
      max_rounds: 50,
      call: 2,
      tool: "read_file",
      args_summary: "path=app.py",
      ok: true,
    },
    {
      round: 9,
      max_rounds: 50,
      call: 3,
      tool: "submit_none",
      args_summary: "reason=done",
      ok: false,
    },
  ],
  steer: {},
};

describe("renderLivePane round vs tool lines", () => {
  it("shows one model round and one line per tool call", () => {
    const { renderLivePane, nodes } = loadRenderLivePane();
    renderLivePane(sample);
    const header = nodes.get("#live-task-now").innerHTML;
    const steps = nodes.get("#live-task-steps").innerHTML;
    assert.deepEqual(roundBadges(header), ["Round 9/50"]);
    assert.deepEqual(roundBadges(steps), []);
    assert.equal((header.match(/Round /g) || []).length, 1);
    assert.doesNotMatch(steps, /round\s+9\/50/i);
    assert.match(steps, /round 9 · call 1/);
    assert.match(steps, /round 9 · call 2/);
    assert.match(steps, /round 9 · call 3/);
    for (const name of ["grep", "read_file", "submit_none"]) {
      assert.match(steps, new RegExp(name));
    }
    assert.match(steps, /call 1/);
    assert.match(steps, /call 2/);
    assert.match(steps, /call 3/);
    assert.match(steps, /submit_none · failed/);
    assert.equal((steps.match(/<li>/g) || []).length, 3);
    assert.equal(nodes.get("#live-task-now").className, "live-task-now");
    assert.doesNotMatch(header, /Thinking/);
  });

  it("numbers legacy steps that still carry a round field", () => {
    const { renderLivePane, nodes } = loadRenderLivePane();
    const legacy = {
      ...sample,
      steps: sample.steps.map(({ call, ...step }) => step),
    };
    renderLivePane(legacy);
    const steps = nodes.get("#live-task-steps").innerHTML;
    assert.deepEqual(roundBadges(steps), []);
    assert.match(steps, /round 9 · call 1/);
    assert.match(steps, /round 9 · call 2/);
    assert.match(steps, /round 9 · call 3/);
    assert.match(steps, /grep/);
  });

  it("shows thinking chrome while a leased round has no tool", () => {
    const { renderLivePane, nodes } = loadRenderLivePane();
    const started = new Date(Date.now() - 47000).toISOString();
    renderLivePane({
      task_id: 4,
      kind: "hunt",
      state: "leased",
      phase: "thinking",
      round: 9,
      max_rounds: 50,
      tool: null,
      args_summary: "",
      wait_started_at: started,
      updated_at: started,
      steps: [],
      steer: {},
    });
    const now = nodes.get("#live-task-now");
    const header = now.innerHTML;
    const steps = nodes.get("#live-task-steps").innerHTML;
    assert.equal(now.className, "live-task-now is-thinking");
    assert.match(header, /Round 9\/50/);
    assert.match(header, /Thinking…/);
    assert.match(header, /Waiting for model · \d+s/);
    assert.doesNotMatch(header, /Waiting for the next tool round/);
    assert.match(steps, /No tool calls yet/);
    assert.equal((steps.match(/<li>/g) || []).length, 1);
    assert.equal((header.match(/Round /g) || []).length, 1);
  });

  it("keeps prior tool rows and does not invent a thinking step", () => {
    const { renderLivePane, nodes } = loadRenderLivePane();
    renderLivePane({
      task_id: 4,
      kind: "hunt",
      state: "leased",
      phase: "thinking",
      round: 2,
      max_rounds: 8,
      tool: null,
      wait_started_at: new Date(Date.now() - 5000).toISOString(),
      steps: [
        {
          round: 1,
          call: 1,
          tool: "grep",
          args_summary: "pattern=SELECT path=app.py",
          ok: true,
        },
      ],
      steer: {},
    });
    const header = nodes.get("#live-task-now").innerHTML;
    const steps = nodes.get("#live-task-steps").innerHTML;
    assert.match(header, /Thinking…/);
    assert.match(header, /Waiting for model/);
    assert.match(steps, /grep/);
    assert.doesNotMatch(steps, /Thinking/);
    assert.equal((steps.match(/<li>/g) || []).length, 1);
  });
});
