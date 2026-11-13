"use strict";

// Pure display helpers in static/chat.js (VulnForgeChat.helpers).
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const CHAT = fs.readFileSync(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "chat.js"),
  "utf8"
);

function load() {
  const sandbox = {
    document: {
      readyState: "complete",
      body: { getAttribute: () => null },
      getElementById: () => null,
      querySelector: () => null,
      addEventListener() {},
    },
    setTimeout,
    clearTimeout,
    console,
  };
  sandbox.window = sandbox;
  vm.runInNewContext(CHAT, sandbox, { filename: "chat.js" });
  return sandbox.VulnForgeChat.helpers;
}

const H = load();

describe("renderMarkdown", () => {
  it("escapes raw HTML everywhere", () => {
    const out = H.renderMarkdown('<script>alert(1)</script>\n- <img src=x onerror="y">\n```\n<b>x</b>\n```\n`<i>`');
    assert.doesNotMatch(out, /<script|<img|<b>|<i>/);
    assert.match(out, /&lt;script&gt;/);
    assert.match(out, /&lt;img src=x onerror=&quot;y&quot;&gt;/);
    assert.match(out, /<code>&lt;i&gt;<\/code>/);
  });

  it("renders paragraphs, line breaks, bold, em and inline code", () => {
    const out = H.renderMarkdown("**Bold** and *em* and `a**b**`\nnext line\n\nsecond para");
    assert.equal(
      out,
      "<p><strong>Bold</strong> and <em>em</em> and <code>a**b**</code><br/>next line</p><p>second para</p>"
    );
  });

  it("does not treat snake_case or lone asterisks as emphasis", () => {
    assert.equal(H.renderMarkdown("needs_human * 2 * 3"), "<p>needs_human * 2 * 3</p>");
  });

  it("renders bullet and ordered lists with continuations", () => {
    assert.equal(
      H.renderMarkdown("Runs:\n- toy/run-001\n- big/run-002\n  still item two\n\n3. third\n4. fourth"),
      '<p>Runs:</p><ul><li>toy/run-001</li><li>big/run-002 still item two</li></ul><ol start="3"><li>third</li><li>fourth</li></ol>'
    );
  });

  it("renders fenced code with a language tag and keeps whitespace", () => {
    const out = H.renderMarkdown("```json\n{\n  \"a\": 1\n}\n```");
    assert.equal(out, '<pre class="oc-code" data-lang="json"><code>{\n  &quot;a&quot;: 1\n}</code></pre>');
  });

  it("closes an unterminated fence at end of text", () => {
    assert.match(H.renderMarkdown("```\nx"), /^<pre class="oc-code"><code>x<\/code><\/pre>$/);
  });

  it("renders headings as a bold line", () => {
    assert.equal(H.renderMarkdown("## Summary"), '<p class="oc-h">Summary</p>');
  });

  it("handles empty input", () => {
    assert.equal(H.renderMarkdown(""), "");
    assert.equal(H.renderMarkdown(null), "");
  });
});

describe("tool display helpers", () => {
  it("reads tool calls in OpenAI and flat shapes", () => {
    const calls = H.toolCallsOf({
      tool_calls: [
        { function: { name: "list_runs", arguments: '{"limit":5}' } },
        { name: "status", arguments: { run_id: "r1" } },
        { function: { name: "bad", arguments: "{oops" } },
      ],
    });
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [
      { name: "list_runs", args: { limit: 5 } },
      { name: "status", args: { run_id: "r1" } },
      { name: "bad", args: { raw: "{oops" } },
    ]);
    assert.equal(H.toolCallsOf({}).length, 0);
  });

  it("previews args on one clipped line", () => {
    assert.equal(H.argsPreview({ target_id: "toy", cells: [1, 2], opts: { a: 1 } }), "target_id=toy cells=[2] opts={…}");
    assert.equal(H.argsPreview({}), "");
    assert.equal(H.argsPreview({ k: "x".repeat(200) }, 20).length, 20);
  });

  it("summarizes tool results by status", () => {
    assert.deepEqual({ ...H.summarizeToolResult({ ok: true, count: 1 }) }, { status: "ok", text: "1 result" });
    assert.deepEqual({ ...H.summarizeToolResult({ ok: true, runs: [1, 2, 3] }) }, { status: "ok", text: "3 runs" });
    assert.deepEqual({ ...H.summarizeToolResult({ ok: false, error: "no such run" }) }, { status: "error", text: "no such run" });
    assert.equal(H.summarizeToolResult({ ok: false, pending_confirm: true }).status, "pending");
    assert.deepEqual({ ...H.summarizeToolResult('{"ok":true}') }, { status: "ok", text: "ok" });
    assert.equal(H.summarizeToolResult("plain text result").text, "plain text result");
  });

  it("pretty-prints JSON and truncates long payloads", () => {
    assert.equal(H.prettyJson({ a: 1 }), '{\n  "a": 1\n}');
    assert.equal(H.prettyJson('{"a":1}'), '{\n  "a": 1\n}');
    assert.match(H.prettyJson("x".repeat(50), 10), /^x{10}\n… truncated$/);
  });
});

describe("describePending", () => {
  it("names the action, the run and the expiry", () => {
    const d = H.describePending({
      tool_name: "enqueue_hunt",
      arguments: { target_id: "toy", run_id: "run-001", class: "sqli" },
      summary: "Enqueue hunt class=sqli",
      expires_in_s: 599.7,
    });
    assert.equal(d.title, "Enqueue a hunt");
    assert.equal(d.run, "toy/run-001");
    assert.equal(d.argCount, 3);
    assert.equal(d.expiresIn, 599);
    assert.equal(d.danger, false);
  });

  it("falls back to run_key, init target, or scope", () => {
    assert.equal(H.describePending({ tool_name: "requeue_hunt", run_key: "a/b" }).run, "a/b");
    assert.equal(H.describePending({ tool_name: "init_run", arguments: { target: "/src" } }).run, "new run · /src");
    assert.equal(H.describePending({ tool_name: "start_run", scope: "home" }).run, "Fleet (no single run)");
    assert.equal(H.describePending({ tool_name: "some_new_tool" }).title, "Some new tool");
    assert.equal(H.describePending({ tool_name: "hard_stop_run" }).danger, true);
    assert.equal(H.describePending({}).expiresIn, null);
  });

  it("formats the countdown", () => {
    assert.equal(H.formatCountdown(600), "10:00");
    assert.equal(H.formatCountdown(61), "1:01");
    assert.equal(H.formatCountdown(-5), "0:00");
  });
});
