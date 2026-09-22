/**
 * Organize one LLM transcript message into scannable blocks:
 * assistant text, reasoning, tool calls (name + args), and tool outputs.
 *
 * UMD: browser global TranscriptTurns and node require().
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.TranscriptTurns = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function parseJsonish(value) {
    if (typeof value !== "string") return undefined;
    const text = value.trim();
    if (!text || (text[0] !== "{" && text[0] !== "[")) return undefined;
    try {
      return JSON.parse(text);
    } catch {
      return undefined;
    }
  }

  function pretty(value) {
    if (value == null) return "";
    if (typeof value === "string") {
      const parsed = parseJsonish(value);
      if (parsed !== undefined) {
        try {
          return JSON.stringify(parsed, null, 2);
        } catch {
          return value;
        }
      }
      return value;
    }
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  function isScalar(value) {
    return value == null || ["string", "number", "boolean"].includes(typeof value);
  }

  function formatScalar(value) {
    if (value == null) return "null";
    if (typeof value === "boolean") return value ? "true" : "false";
    return String(value);
  }

  function messageText(content) {
    if (content == null) return "";
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
      const texts = content
        .map((block) => {
          if (typeof block === "string") return block;
          if (block && typeof block === "object" && typeof block.text === "string") return block.text;
          return "";
        })
        .filter(Boolean);
      if (texts.length) return texts.join("\n");
    }
    return pretty(content);
  }

  function normalizeToolCalls(raw, content) {
    const list = Array.isArray(raw) && raw.length ? raw : toolUsesFromContent(content);
    const out = [];
    for (const tc of list) {
      if (!tc || typeof tc !== "object") continue;
      const fn = tc.function && typeof tc.function === "object" ? tc.function : {};
      const name = String(fn.name || tc.name || "").trim();
      if (!name) continue;
      let args = Object.prototype.hasOwnProperty.call(fn, "arguments") ? fn.arguments : tc.arguments;
      if (typeof args === "string") {
        const parsed = parseJsonish(args);
        if (parsed !== undefined) args = parsed;
      }
      if (args == null) args = {};
      out.push({
        id: String(tc.id || tc.call_id || tc.toolUseId || ""),
        name,
        args,
      });
    }
    return out;
  }

  function toolUsesFromContent(content) {
    if (!Array.isArray(content)) return [];
    const calls = [];
    for (const block of content) {
      const tu = block && typeof block === "object" ? block.toolUse : null;
      if (!tu || typeof tu !== "object") continue;
      calls.push({
        id: tu.toolUseId || "",
        name: tu.name || "",
        arguments: tu.input || {},
      });
    }
    return calls;
  }

  function previewLine(text) {
    return String(text || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 72);
  }

  function isLong(text) {
    const value = String(text || "");
    return value.length > 480 || value.split("\n").length > 12;
  }

  function foldOrPre(text, summaryLabel) {
    const value = text == null ? "" : String(text);
    if (!value) return "";
    const pre = `<pre class="turn-pre">${esc(value)}</pre>`;
    if (!isLong(value)) return pre;
    return `<details class="turn-fold"><summary><span class="turn-kind">${esc(
      summaryLabel
    )}</span> <span class="turn-preview">${esc(previewLine(value))}</span> <span class="turn-fold-meta">${
      value.length
    } chars</span></summary>${pre}</details>`;
  }

  function textBlock(text, label) {
    const head = label
      ? `<div class="turn-block-head"><span class="turn-kind">${esc(label)}</span></div>`
      : "";
    return `<div class="turn-block turn-text">${head}${foldOrPre(text, "Show text")}</div>`;
  }

  function reasoningBlock(text) {
    const value = String(text || "");
    return `<details class="turn-block turn-reasoning"><summary class="turn-block-head"><span class="turn-kind">Reasoning</span> <span class="turn-preview">${esc(
      previewLine(value)
    )}</span></summary><pre class="turn-pre">${esc(value)}</pre></details>`;
  }

  function renderArgs(args) {
    if (args && typeof args === "object" && !Array.isArray(args)) {
      const keys = Object.keys(args);
      if (!keys.length) return `<p class="turn-empty">No arguments</p>`;
      const compact = keys.every((key) => isScalar(args[key]) && formatScalar(args[key]).length <= 180);
      if (compact) {
        return `<dl class="turn-args">${keys
          .map((key) => `<dt>${esc(key)}</dt><dd>${esc(formatScalar(args[key]))}</dd>`)
          .join("")}</dl>`;
      }
    }
    if (typeof args === "string" && !args.trim()) return `<p class="turn-empty">No arguments</p>`;
    return foldOrPre(pretty(args), "Show arguments");
  }

  function toolCallBlock(call) {
    const id = call.id
      ? `<span class="turn-id" title="tool call id">${esc(call.id)}</span>`
      : "";
    return `<div class="turn-block turn-tool-call">
      <div class="turn-block-head"><span class="turn-kind">Tool call</span><code class="turn-tool-name">${esc(
        call.name
      )}</code>${id}</div>
      ${renderArgs(call.args)}
    </div>`;
  }

  function formatToolOutput(content) {
    const parsed = typeof content === "string" ? parseJsonish(content) : content;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { status: null, meta: "", body: messageText(content) };
    }
    const status = parsed.ok === true ? "ok" : parsed.ok === false ? "failed" : null;
    const meta = [];
    if (parsed.path) meta.push(String(parsed.path));
    if (parsed.start_line != null && parsed.end_line != null) {
      meta.push(`lines ${parsed.start_line}–${parsed.end_line}`);
    } else if (parsed.start_line != null) {
      meta.push(`line ${parsed.start_line}`);
    }
    if (parsed.count != null && parsed.count !== "") {
      const n = Number(parsed.count);
      meta.push(`${parsed.count} match${n === 1 ? "" : "es"}`);
    }
    if (parsed.truncated) meta.push("truncated");
    if (parsed.finding_id != null && parsed.finding_id !== "") meta.push(`finding #${parsed.finding_id}`);
    if (parsed.state) meta.push(String(parsed.state));

    let body = "";
    if (typeof parsed.content === "string" && parsed.content) body = parsed.content;
    else if (typeof parsed.error === "string" && parsed.error) body = parsed.error;
    else if (Array.isArray(parsed.matches)) body = JSON.stringify(parsed.matches, null, 2);
    else if (Array.isArray(parsed.results)) body = JSON.stringify(parsed.results, null, 2);
    else {
      const rest = {};
      for (const key of Object.keys(parsed)) {
        if (key === "ok" || key === "path" || key === "start_line" || key === "end_line") continue;
        if (key === "count" || key === "truncated" || key === "finding_id" || key === "state") continue;
        if (key === "total_lines") continue;
        rest[key] = parsed[key];
      }
      if (Object.keys(rest).length) body = pretty(rest);
    }
    return { status, meta: meta.join(" · "), body };
  }

  function toolResultBlock(msg, formatted) {
    const name = String((msg && msg.name) || "").trim();
    const id = msg && (msg.tool_call_id || msg.id)
      ? `<span class="turn-id">${esc(msg.tool_call_id || msg.id)}</span>`
      : "";
    const nameHtml = name ? `<code class="turn-tool-name">${esc(name)}</code>` : "";
    const status = formatted.status
      ? `<span class="turn-status ${formatted.status === "ok" ? "ok" : "bad"}">${esc(formatted.status)}</span>`
      : "";
    const meta = formatted.meta ? `<div class="turn-meta">${esc(formatted.meta)}</div>` : "";
    const body = formatted.body ? foldOrPre(formatted.body, "Show output") : "";
    return `<div class="turn-block turn-tool-result">
      <div class="turn-block-head"><span class="turn-kind">Output</span>${nameHtml}${id}${status}</div>
      ${meta}${body}
    </div>`;
  }

  function renderTurnHtml(m) {
    const msg = m && typeof m === "object" ? m : {};
    const role = String(msg.role || "unknown");
    const parts = [];
    if (role === "tool") {
      parts.push(toolResultBlock(msg, formatToolOutput(msg.content)));
    } else {
      if (msg.reasoning_content) parts.push(reasoningBlock(msg.reasoning_content));
      const text = messageText(msg.content);
      if (text.trim()) parts.push(textBlock(text, role === "assistant" ? "Text" : ""));
      for (const call of normalizeToolCalls(msg.tool_calls, msg.content)) {
        parts.push(toolCallBlock(call));
      }
    }
    if (!parts.length) {
      parts.push(`<p class="turn-empty">Empty ${esc(role)} turn</p>`);
    }
    return `<div class="transcript-turn role-${esc(role)}"><div class="role">${esc(
      role
    )}</div>${parts.join("")}</div>`;
  }

  function prefersTurnsTab(data) {
    const turns = (data && (data.turns || data.messages)) || [];
    return turns.some((msg) => {
      if (!msg || typeof msg !== "object") return false;
      if (msg.role === "tool") return true;
      if (Array.isArray(msg.tool_calls) && msg.tool_calls.length) return true;
      return toolUsesFromContent(msg.content).length > 0;
    });
  }

  return {
    esc,
    renderTurnHtml,
    prefersTurnsTab,
    normalizeToolCalls,
    formatToolOutput,
  };
});
