"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  renderTurnHtml,
  prefersTurnsTab,
  normalizeToolCalls,
  formatToolOutput,
} = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "transcript_turns.js"));

function block(html, cls) {
  const re = new RegExp(`<div class="turn-block ${cls}[\\s\\S]*?</div>\\s*</div>`);
  const match = html.match(re);
  assert.ok(match, `missing ${cls} in ${html}`);
  return match[0];
}

describe("normalizeToolCalls", () => {
  it("parses OpenAI function arguments that are JSON strings", () => {
    const calls = normalizeToolCalls([
      {
        id: "call_grep_1",
        type: "function",
        function: {
          name: "grep",
          arguments: JSON.stringify({ pattern: "execute\\(", path: "app.py", context: 2 }),
        },
      },
    ]);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].name, "grep");
    assert.equal(calls[0].id, "call_grep_1");
    assert.deepEqual(calls[0].args, { pattern: "execute\\(", path: "app.py", context: 2 });
  });

  it("accepts the normalized name + arguments object shape", () => {
    const calls = normalizeToolCalls([
      { id: "call_read_2", name: "read_file", arguments: { path: "app.py", start_line: 1 } },
    ]);
    assert.equal(calls[0].name, "read_file");
    assert.equal(calls[0].args.start_line, 1);
  });

  it("keeps a non-JSON arguments string instead of throwing", () => {
    const calls = normalizeToolCalls([
      { id: "c", name: "note", arguments: "not json {" },
    ]);
    assert.equal(calls[0].args, "not json {");
  });
});

describe("renderTurnHtml", () => {
  it("splits assistant text, reasoning, and a tool call into distinct blocks", () => {
    const html = renderTurnHtml({
      role: "assistant",
      content: "I'll search app.py for execute( calls.",
      reasoning_content: "Grep first so the read stays on the sink.",
      tool_calls: [
        {
          id: "call_grep_1",
          type: "function",
          function: {
            name: "grep",
            arguments: JSON.stringify({ pattern: "execute\\(", path: "app.py" }),
          },
        },
      ],
    });
    assert.match(html, /class="transcript-turn role-assistant"/);
    assert.match(html, /class="turn-block turn-text"/);
    assert.match(html, /I'll search app\.py/);
    assert.match(html, /class="turn-block turn-reasoning"/);
    assert.match(html, /<details class="turn-block turn-reasoning">/);
    assert.equal(html.includes("[reasoning]"), false);
    assert.equal(html.includes('"type": "function"'), false);
    const call = block(html, "turn-tool-call");
    assert.match(call, /Tool call/);
    assert.match(call, /class="turn-tool-name">grep</);
    assert.match(call, /<dt>path<\/dt><dd>app\.py<\/dd>/);
    assert.match(call, /call_grep_1/);
  });

  it("lifts read_file output out of a JSON dump and marks ok", () => {
    const html = renderTurnHtml({
      role: "tool",
      name: "read_file",
      tool_call_id: "call_read_2",
      content: JSON.stringify({
        ok: true,
        path: "app.py",
        start_line: 1,
        end_line: 5,
        content: "def search_users(q):\n    cur.execute(q)\n",
      }),
    });
    assert.match(html, /class="transcript-turn role-tool"/);
    assert.match(html, /class="turn-block turn-tool-result"/);
    assert.match(html, /class="turn-tool-name">read_file</);
    assert.match(html, /class="turn-status ok">ok</);
    assert.match(html, /app\.py · lines 1–5/);
    assert.match(html, /def search_users\(q\)/);
    assert.equal(html.includes('"start_line"'), false);
  });

  it("shows a failed tool error without confirming anything", () => {
    const html = renderTurnHtml({
      role: "tool",
      name: "submit_candidate",
      content: JSON.stringify({ ok: false, error: "citation_missing_line" }),
    });
    assert.match(html, /class="turn-status bad">failed</);
    assert.match(html, /citation_missing_line/);
    assert.equal(/\bconfirmed\b/i.test(html), false);
  });

  it("summarizes a successful submit on the output head", () => {
    const formatted = formatToolOutput(
      JSON.stringify({ ok: true, finding_id: 1, state: "candidate" })
    );
    assert.equal(formatted.status, "ok");
    assert.match(formatted.meta, /finding #1/);
    assert.match(formatted.meta, /candidate/);
    const html = renderTurnHtml({
      role: "tool",
      name: "submit_candidate",
      content: JSON.stringify({ ok: true, finding_id: 1, state: "candidate" }),
    });
    assert.match(html, /finding #1/);
    assert.equal(html.includes('"finding_id"'), false);
  });

  it("escapes HTML in assistant text and tool names", () => {
    const html = renderTurnHtml({
      role: "assistant",
      content: `<script>alert("x")</script>`,
      tool_calls: [{ name: `<img>`, arguments: { path: `<b>` } }],
    });
    assert.equal(html.includes("<script>"), false);
    assert.match(html, /&lt;script&gt;/);
    assert.match(html, /&lt;img&gt;/);
    assert.match(html, /&lt;b&gt;/);
  });

  it("renders a user turn as text without a tool block", () => {
    const html = renderTurnHtml({ role: "user", content: "Hunt injection in app.py" });
    assert.match(html, /class="transcript-turn role-user"/);
    assert.match(html, /Hunt injection in app\.py/);
    assert.equal(html.includes("turn-tool-call"), false);
    assert.equal(html.includes("turn-tool-result"), false);
  });

  it("folds a long tool body", () => {
    const html = renderTurnHtml({
      role: "tool",
      name: "read_file",
      content: JSON.stringify({ ok: true, path: "big.py", content: "x".repeat(600) }),
    });
    assert.match(html, /<details class="turn-fold">/);
    assert.match(html, /Show output/);
    assert.match(html, /600 chars/);
  });
});

describe("prefersTurnsTab", () => {
  it("opens Turns when the transcript has tool use", () => {
    assert.equal(
      prefersTurnsTab({
        turns: [
          { role: "user", content: "go" },
          { role: "assistant", content: "", tool_calls: [{ name: "grep", arguments: {} }] },
        ],
      }),
      true
    );
  });

  it("stays on Input when there are no tool calls", () => {
    assert.equal(
      prefersTurnsTab({
        turns: [
          { role: "system", content: "sys" },
          { role: "assistant", content: "plain answer" },
        ],
      }),
      false
    );
  });
});
