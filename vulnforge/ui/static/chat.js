/* VulnForge operator AI chat — Home fleet + in-run campaign co-pilot */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ---------- Pure display helpers (unit-tested via VulnForgeChat.helpers) ---------- */

  // Inline markdown: `code`, **bold**, *em*. Escapes first; never emits raw HTML
  // from the input. Code spans are split out so emphasis never applies inside them.
  function inlineMd(s) {
    return String(s ?? "")
      .split(/(`[^`\n]+`)/)
      .map((part, idx) => {
        if (idx % 2 === 1) return `<code>${escapeHtml(part.slice(1, -1))}</code>`;
        let t = escapeHtml(part);
        t = t.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
        t = t.replace(/(^|[^*\w])\*([^*\s][^*\n]*?)\*(?![*\w])/g, "$1<em>$2</em>");
        return t;
      })
      .join("");
  }

  const LIST_RE = /^\s*([-*+]|\d{1,4}[.)])\s+/;

  // Block markdown: paragraphs, #-headings, -/1. lists and ``` fences.
  // Output is built only from escaped text plus a fixed tag set.
  function renderMarkdown(text) {
    const lines = String(text ?? "").replace(/\r\n?/g, "\n").split("\n");
    const out = [];
    let para = [];
    const flush = () => {
      if (para.length) out.push(`<p>${para.map(inlineMd).join("<br/>")}</p>`);
      para = [];
    };
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      const fence = line.match(/^\s*```\s*([\w+.#-]*)\s*$/);
      if (fence) {
        flush();
        const buf = [];
        i++;
        while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) buf.push(lines[i++]);
        i++;
        const lang = fence[1] ? ` data-lang="${escapeHtml(fence[1])}"` : "";
        out.push(`<pre class="oc-code"${lang}><code>${escapeHtml(buf.join("\n"))}</code></pre>`);
        continue;
      }
      const head = line.match(/^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$/);
      if (head) {
        flush();
        out.push(`<p class="oc-h">${inlineMd(head[1])}</p>`);
        i++;
        continue;
      }
      if (LIST_RE.test(line)) {
        flush();
        const ordered = /^\s*\d/.test(line);
        const itemRe = ordered ? /^\s*(\d{1,4})[.)]\s+(.*)$/ : /^\s*[-*+]\s+(.*)$/;
        const first = line.match(itemRe);
        const start = ordered && first && Number(first[1]) > 1 ? ` start="${Number(first[1])}"` : "";
        const items = [];
        while (i < lines.length) {
          const m = lines[i].match(itemRe);
          if (m) {
            items.push(ordered ? m[2] : m[1]);
            i++;
          } else if (items.length && /^\s{2,}\S/.test(lines[i]) && !LIST_RE.test(lines[i])) {
            items[items.length - 1] += " " + lines[i].trim();
            i++;
          } else break;
        }
        const tag = ordered ? "ol" : "ul";
        out.push(`<${tag}${start}>${items.map((t) => `<li>${inlineMd(t)}</li>`).join("")}</${tag}>`);
        continue;
      }
      if (!line.trim()) {
        flush();
        i++;
        continue;
      }
      para.push(line);
      i++;
    }
    flush();
    return out.join("");
  }

  function parseArgs(raw) {
    if (raw && typeof raw === "object") return raw;
    if (typeof raw !== "string" || !raw.trim()) return {};
    try {
      const v = JSON.parse(raw);
      return v && typeof v === "object" ? v : { value: v };
    } catch (_) {
      return { raw };
    }
  }

  // [{ name, args }] from an assistant message's tool_calls (OpenAI or flat shape).
  function toolCallsOf(m) {
    if (!m || !Array.isArray(m.tool_calls)) return [];
    return m.tool_calls.map((tc) => {
      const fn = (tc && tc.function) || {};
      return {
        name: String(fn.name || (tc && tc.name) || "tool"),
        args: parseArgs(fn.arguments !== undefined ? fn.arguments : tc && tc.arguments),
      };
    });
  }

  function clip(s, n) {
    const t = String(s ?? "");
    return t.length > n ? t.slice(0, n - 1) + "…" : t;
  }

  function scalarText(v) {
    if (v === null || v === undefined) return "null";
    if (typeof v === "object") return Array.isArray(v) ? `[${v.length}]` : "{…}";
    return String(v);
  }

  // One-line `k=v k=v` preview of tool arguments.
  function argsPreview(args, max) {
    const keys = args && typeof args === "object" ? Object.keys(args) : [];
    if (!keys.length) return "";
    return clip(keys.map((k) => `${k}=${scalarText(args[k])}`).join(" "), max || 72);
  }

  function prettyJson(v, max) {
    let t;
    if (typeof v === "string") {
      try {
        t = JSON.stringify(JSON.parse(v), null, 2);
      } catch (_) {
        t = v;
      }
    } else {
      try {
        t = JSON.stringify(v, null, 2);
      } catch (_) {
        t = String(v);
      }
    }
    const lim = max || 6000;
    t = String(t ?? "");
    return t.length > lim ? t.slice(0, lim) + "\n… truncated" : t;
  }

  // { status: ok|error|pending, text } for a tool result payload.
  function summarizeToolResult(content) {
    let c = content;
    if (typeof c === "string") {
      try {
        c = JSON.parse(c);
      } catch (_) {
        return { status: "ok", text: clip(c.replace(/\s+/g, " ").trim(), 64) };
      }
    }
    if (!c || typeof c !== "object") return { status: "ok", text: c == null ? "" : String(c) };
    if (c.pending_confirm) return { status: "pending", text: "confirm requested" };
    if (c.ok === false) return { status: "error", text: clip(c.error || c.detail || "failed", 64) };
    if (typeof c.count === "number") return { status: "ok", text: `${c.count} result${c.count === 1 ? "" : "s"}` };
    for (const k of Object.keys(c)) {
      if (Array.isArray(c[k])) return { status: "ok", text: `${c[k].length} ${k}` };
    }
    if (typeof c.message === "string") return { status: "ok", text: clip(c.message, 64) };
    if (typeof c.summary === "string") return { status: "ok", text: clip(c.summary, 64) };
    return { status: "ok", text: "ok" };
  }

  const ACTION_TITLES = {
    init_run: "Init a new audit run",
    start_run: "Start Ralph",
    pause_run: "Pause Ralph",
    resume_run: "Resume Ralph",
    hard_stop_run: "Hard-stop Ralph",
    enqueue_hunt: "Enqueue a hunt",
    requeue_hunt: "Re-queue a hunt",
    requeue_hunts_bulk: "Re-queue hunt cells",
    rerun_recon: "Re-run recon",
    review_finding: "Record a review decision",
    enqueue_develop_poc: "Queue PoC development",
    enqueue_validate_poc: "Queue a sandbox PoC run",
    enqueue_iterate_poc: "Queue a sandbox PoC iteration",
  };
  const DANGER_TOOLS = { hard_stop_run: true };

  // Display model for a pending mutation (server pending_confirm payload).
  function describePending(p) {
    const pending = p || {};
    const name = String(pending.tool_name || "action");
    const args = pending.arguments && typeof pending.arguments === "object" ? pending.arguments : {};
    let run = "";
    if (args.target_id && args.run_id) run = `${args.target_id}/${args.run_id}`;
    else if (pending.run_key) run = String(pending.run_key);
    else if (name === "init_run" && args.target) run = `new run · ${args.target}`;
    const fallback = name.replace(/_/g, " ");
    const expires = Number(pending.expires_in_s);
    return {
      tool: name,
      title: ACTION_TITLES[name] || fallback.charAt(0).toUpperCase() + fallback.slice(1),
      run: run || (pending.scope === "home" ? "Fleet (no single run)" : "This run"),
      summary: String(pending.summary || ""),
      args,
      argCount: Object.keys(args).length,
      danger: !!DANGER_TOOLS[name],
      expiresIn: Number.isFinite(expires) ? Math.max(0, Math.floor(expires)) : null,
    };
  }

  function formatCountdown(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  }

  function runKeyFromBody() {
    const key = document.body.getAttribute("data-run-key") || "";
    const parts = key.split("/");
    if (parts.length >= 2) return { target_id: parts[0], run_id: parts.slice(1).join("/") };
    return null;
  }

  function apiBase(scope) {
    if (scope === "home") return "/api/chat";
    const rk = runKeyFromBody();
    if (!rk) return "/api/chat";
    return `/api/runs/${encodeURIComponent(rk.target_id)}/${encodeURIComponent(rk.run_id)}/chat`;
  }

  let paneSeq = 1;

  const state = {
    scope: "home",
    sessionId: null,
    busy: false,
    root: null,
    pending: null,
    chips: [],
    mounted: false,
    sheetOpen: false,
    fab: null,
    sheet: null,
    scopeKey: "",
    panes: [],
    activeId: null,
    sessionList: [],
    listToken: 0,
  };

  const PANE_IDS = ["oc-messages", "oc-chips", "oc-confirm", "oc-input", "oc-send"];

  function currentScopeKey() {
    if (document.body.getAttribute("data-page") === "run") {
      return document.body.getAttribute("data-run-key") || "run";
    }
    return "fleet";
  }

  function activePane() {
    return state.panes.find((p) => p.id === state.activeId) || null;
  }

  function messagesEl(pane) {
    return pane && pane.el ? pane.el.querySelector(".oc-messages") : null;
  }

  function syncBadge() {
    const pending = state.panes.some((p) => p.pending && !p.pending._expired);
    state.pending = (activePane() && activePane().pending) || null;
    // Run pages open the sheet from the header ⌘K button (no FAB): flag it there too.
    const cmd = typeof document !== "undefined" && document.getElementById("btn-command");
    if (cmd && cmd.classList) cmd.classList.toggle("oc-has-pending", pending);
    const badge = state.fab && state.fab.querySelector(".ai-badge");
    if (badge) badge.hidden = !pending;
  }

  function resetSession() {
    state.sessionId = null;
    state.pending = null;
    state.busy = false;
    state.mounted = false;
    state.panes = [];
    state.activeId = null;
    state.sessionList = [];
    const root = document.getElementById("operator-chat-root");
    if (root) {
      delete root.dataset.ready;
      root.innerHTML = "";
    }
    syncBadge();
  }

  function sessionStorageKey() {
    return "vf-chat:" + currentScopeKey();
  }

  function readStoredSessionId() {
    try {
      return sessionStorage.getItem(sessionStorageKey()) || "";
    } catch (_) {
      return "";
    }
  }

  function writeStoredSessionId(id) {
    try {
      if (id) sessionStorage.setItem(sessionStorageKey(), id);
      else sessionStorage.removeItem(sessionStorageKey());
    } catch (_) {}
  }

  function adoptStoredSession() {
    if (state.sessionId) return;
    const id = readStoredSessionId();
    if (id) state.sessionId = id;
  }

  function bindChrome() {
    state.fab = document.getElementById("ai-fab");
    state.sheet = document.getElementById("ai-sheet");
    const key = currentScopeKey();
    if (state.scopeKey && state.scopeKey !== key) resetSession();
    state.scopeKey = key;
    const title = document.getElementById("ai-title");
    if (title) {
      title.textContent = key === "fleet" ? "Across runs" : key.replace("/", " / ");
    }
    if (state.fab && !state.fab.dataset.bound) {
      state.fab.dataset.bound = "1";
      state.fab.addEventListener("click", () => toggleSheet());
    }
    const entry = document.getElementById("ai-entry");
    if (entry && !entry.dataset.bound) {
      entry.dataset.bound = "1";
      entry.addEventListener("click", () => toggleSheet());
    }
    const closeBtn = document.getElementById("ai-close");
    if (closeBtn && !closeBtn.dataset.bound) {
      closeBtn.dataset.bound = "1";
      closeBtn.addEventListener("click", () => closeSheet());
    }
    const maxBtn = document.getElementById("ai-max");
    if (maxBtn && !maxBtn.dataset.bound) {
      maxBtn.dataset.bound = "1";
      maxBtn.addEventListener("click", () => toggleMaximize());
    }
    syncChrome();
  }

  function syncChrome() {
    syncBadge();
    const maxed = !!(state.sheet && state.sheet.classList.contains("is-max"));
    const maxBtn = document.getElementById("ai-max");
    if (maxBtn) {
      const label = maxed ? "Minimize" : "Expand";
      maxBtn.textContent = label;
      maxBtn.setAttribute("aria-pressed", maxed ? "true" : "false");
      maxBtn.setAttribute("aria-label", label);
    }
    if (state.fab) {
      state.fab.classList.toggle("open", state.sheetOpen);
      state.fab.setAttribute("aria-expanded", state.sheetOpen ? "true" : "false");
    }
    const entry = document.getElementById("ai-entry");
    if (entry) entry.setAttribute("aria-expanded", state.sheetOpen ? "true" : "false");
    document.querySelectorAll('[data-nav-id="ai"]').forEach((rail) => {
      rail.classList.toggle("on", state.sheetOpen);
      rail.setAttribute("aria-expanded", state.sheetOpen ? "true" : "false");
    });
  }

  function openSheet() {
    bindChrome();
    const key = currentScopeKey();
    if (state.scopeKey !== key) {
      resetSession();
      state.scopeKey = key;
    }
    ensureMounted();
    state.sheetOpen = true;
    if (state.sheet) state.sheet.hidden = false;
    syncChrome();
  }

  function closeSheet() {
    state.sheetOpen = false;
    if (state.sheet) state.sheet.hidden = true;
    syncChrome();
  }

  function toggleSheet() {
    if (state.sheetOpen) closeSheet();
    else openSheet();
  }

  function toggleMaximize() {
    bindChrome();
    if (!state.sheet) return;
    const next = !state.sheet.classList.contains("is-max");
    state.sheet.classList.toggle("is-max", next);
    syncChrome();
  }

  function isMaximized() {
    return !!(state.sheet && state.sheet.classList.contains("is-max"));
  }

  const CHAT_CSS = "/static/pages/chat.css";

  // The chat mounts on pages owned by other modules (run, home, dev, …). Its CSS
  // is page-owned, so load it here instead of adding a <link> to every template.
  function ensureStyles() {
    if (typeof document === "undefined" || !document.head || !document.createElement) return;
    if (document.querySelector('link[data-vf-chat-css], link[href="' + CHAT_CSS + '"]')) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = CHAT_CSS;
    link.setAttribute("data-vf-chat-css", "1");
    document.head.appendChild(link);
  }

  function shellHtml() {
    const runKey = document.body.getAttribute("data-run-key") || "";
    const scopePill =
      state.scope === "run"
        ? `<span class="vf-pill oc-scope">Run</span><span class="oc-context vf-mono" title="${escapeHtml(runKey)}">${escapeHtml(runKey)}</span>`
        : `<span class="vf-pill oc-scope">Fleet</span><span class="oc-context">All runs</span>`;
    return `
      <div class="oc-shell">
        <div class="oc-layout">
          <aside class="oc-sidebar" id="oc-sidebar" aria-label="Previous chats">
            <button type="button" class="vf-btn oc-new" id="oc-new">New chat</button>
            <h2 class="vf-section-label oc-sessions-label">History</h2>
            <ul class="oc-sessions" id="oc-sessions"></ul>
          </aside>
          <div class="oc-stage">
            <div class="oc-toolbar">
              <button type="button" class="vf-icon-btn oc-history-toggle" aria-controls="oc-sidebar" aria-expanded="false">History</button>
              ${scopePill}
              <span class="vf-spacer"></span>
              <button type="button" class="vf-icon-btn oc-new-inline" aria-label="New chat">+ New</button>
            </div>
            <div class="oc-tabs" id="oc-tabs" role="tablist" aria-label="Open chats"></div>
            <div class="oc-panes" id="oc-panes"></div>
          </div>
        </div>
        <div class="oc-toasts" id="oc-toasts" aria-live="polite"></div>
      </div>`;
  }

  function paneHtml(pane) {
    const placeholder =
      state.scope === "run" ? "Ask about this run, or queue a hunt…" : "Ask across runs, hunts, findings…";
    return `
      <section class="oc-pane pane-${pane.id}" data-pane-id="${pane.id}">
        <div class="oc-messages" role="log" aria-live="polite"></div>
        <div class="oc-confirm" hidden></div>
        <div class="oc-chips" aria-label="Suggestions"></div>
        <div class="oc-composer">
          <textarea class="oc-input" rows="1" placeholder="${escapeHtml(placeholder)}" aria-label="Chat message"></textarea>
          <button type="button" class="vf-btn vf-btn--primary oc-send">Send</button>
        </div>
        <p class="oc-hint"><span class="vf-kbd">Enter</span> send · <span class="vf-kbd">Shift</span>+<span class="vf-kbd">Enter</span> newline · Actions that change state wait for your Confirm. needs_human ≠ exploit proof.</p>
      </section>`;
  }

  function setHistoryOpen(open) {
    const shell = state.root && state.root.querySelector(".oc-shell");
    if (!shell) return;
    shell.classList.toggle("is-history-open", !!open);
    const btn = shell.querySelector(".oc-history-toggle");
    if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
  }

  function claimPaneIds(active) {
    for (const pane of state.panes) {
      const on = pane === active;
      pane.el.classList.toggle("is-active", on);
      for (const id of PANE_IDS) {
        const el = pane.el.querySelector("." + id);
        if (!el) continue;
        if (on) {
          el.id = id;
          if (el.attrs) el.attrs.id = id;
        } else if (el.id === id) {
          el.id = "";
          if (el.attrs) delete el.attrs.id;
          if (typeof el.removeAttribute === "function") el.removeAttribute("id");
        }
      }
    }
  }

  function noteSession(pane, id) {
    if (!id) return;
    pane.sessionId = id;
    if (pane.id === state.activeId) {
      state.sessionId = id;
      writeStoredSessionId(id);
    }
  }

  function createPane(opts) {
    const pane = {
      id: "p" + paneSeq++,
      sessionId: opts?.sessionId || null,
      busy: false,
      pending: null,
      preview: opts?.preview || "",
      restoreToken: 0,
      restorePromise: null,
      el: null,
    };
    const wrap = state.root.querySelector("#oc-panes");
    wrap.insertAdjacentHTML("beforeend", paneHtml(pane));
    const found = wrap.querySelectorAll(".oc-pane");
    pane.el = found[found.length - 1];
    state.panes.push(pane);
    bindPane(pane);
    renderMessages(pane, []);
    return pane;
  }

  function activate(pane) {
    if (!pane) return;
    state.activeId = pane.id;
    state.sessionId = pane.sessionId || null;
    writeStoredSessionId(pane.sessionId || "");
    claimPaneIds(pane);
    renderChromeLists();
    const input = pane.el.querySelector(".oc-input");
    if (input) setTimeout(() => input.focus(), 50);
  }

  function newChat() {
    const pane = createPane({});
    activate(pane);
  }

  function mount(root, opts) {
    if (!root) return;
    state.root = root;
    state.scope = opts?.scope || root.closest("[data-chat-scope]")?.getAttribute("data-chat-scope") || "home";
    if (document.body.getAttribute("data-page") === "run") state.scope = "run";
    if (document.body.getAttribute("data-page") === "chat") state.scope = "home";
    state.chips = opts?.chips || defaultChips(state.scope);
    state.panes = [];
    state.activeId = null;
    state.mounted = true;
    ensureStyles();
    root.innerHTML = shellHtml();
    const pane = createPane({ sessionId: state.sessionId });
    const neu = root.querySelector("#oc-new");
    if (neu)
      neu.addEventListener("click", () => {
        setHistoryOpen(false);
        newChat();
      });
    root.querySelector(".oc-new-inline")?.addEventListener("click", () => newChat());
    const hist = root.querySelector(".oc-history-toggle");
    if (hist) {
      hist.addEventListener("click", () => {
        const shell = root.querySelector(".oc-shell");
        setHistoryOpen(!(shell && shell.classList.contains("is-history-open")));
      });
    }
    activate(pane);
    restorePane(pane);
    refreshSessions();
  }

  function restorePane(pane) {
    const id = pane.sessionId;
    const token = ++pane.restoreToken;
    if (!id || !pane.el) {
      pane.restorePromise = null;
      return Promise.resolve();
    }
    const p = (async () => {
      try {
        const res = await fetch(apiBase(state.scope) + "/sessions/" + encodeURIComponent(id));
        if (token !== pane.restoreToken) return;
        if (!res.ok) {
          if (pane.sessionId === id) {
            pane.sessionId = null;
            if (pane.id === state.activeId) {
              state.sessionId = null;
              writeStoredSessionId("");
            }
          }
          return;
        }
        const data = await res.json();
        if (token !== pane.restoreToken || pane.sessionId !== id || !pane.el) return;
        const msgs = (Array.isArray(data.messages) ? data.messages : []).filter(
          (m) => m && m.role !== "system"
        );
        const firstUser = msgs.find((m) => m.role === "user" && m.content);
        if (firstUser && !pane.preview) pane.preview = String(firstUser.content).slice(0, 120);
        renderMessages(pane, msgs);
        renderChromeLists();
      } catch (_) {
        /* keep the shell; a later send still uses the stored id */
      }
    })();
    pane.restorePromise = p;
    return p;
  }

  function refreshSessions() {
    const token = ++state.listToken;
    const scope = state.scope;
    const p = (async () => {
      try {
        const res = await fetch(apiBase(scope) + "/sessions");
        if (token !== state.listToken || scope !== state.scope) return;
        const data = await res.json().catch(() => ({}));
        state.sessionList = Array.isArray(data.sessions) ? data.sessions : [];
        renderChromeLists();
      } catch (_) {}
    })();
    return p;
  }

  function ensureMounted() {
    const root = document.getElementById("operator-chat-root");
    if (!root) return;
    adoptStoredSession();
    if (state.mounted && root.dataset.ready === "1" && state.root === root && state.panes.length) {
      const input = root.querySelector("#oc-input");
      if (input) setTimeout(() => input.focus(), 50);
      return;
    }
    const page = document.body.getAttribute("data-page");
    const scope = page === "run" ? "run" : "home";
    mount(root, { scope, chips: defaultChips(scope) });
    root.dataset.ready = "1";
  }

  /**
   * Prefill the composer (does not send). Ensures the chat shell is mounted.
   * @param {string} text
   * @param {{ select?: boolean }} [opts]
   */
  function prefill(text, opts) {
    ensureMounted();
    const root = state.root || document.getElementById("operator-chat-root");
    if (!root) return false;
    const input = root.querySelector("#oc-input");
    if (!input) return false;
    input.value = String(text ?? "");
    setTimeout(() => {
      input.focus();
      if (opts?.select) {
        try {
          input.select();
        } catch (_) {}
      } else {
        try {
          const n = input.value.length;
          input.setSelectionRange(n, n);
        } catch (_) {}
      }
    }, 50);
    return true;
  }

  function defaultChips(scope) {
    if (scope === "run") {
      return [
        "Status summary for this run",
        "List hunts",
        "What findings need human review?",
        "Hunts residuals",
        "Queue an injection hunt",
      ];
    }
    return [
      "List all runs",
      "Findings needing review (all runs)",
      "Summarize results across runs",
      "What hunts are open?",
      "Explain VulnForge",
    ];
  }

  function bindPane(pane) {
    const root = pane.el;
    root.querySelector(".oc-send")?.addEventListener("click", () => send(pane));
    const input = root.querySelector(".oc-input");
    input?.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        send(pane);
      }
    });
    input?.addEventListener("input", () => autoGrow(input));
    const chips = root.querySelector(".oc-chips");
    if (chips) {
      chips.innerHTML = state.chips
        .map((c) => `<button type="button" class="vf-chip oc-chip">${escapeHtml(c)}</button>`)
        .join("");
      chips.querySelectorAll(".oc-chip").forEach((btn) => {
        btn.addEventListener("click", () => {
          const inputEl = root.querySelector(".oc-input");
          if (inputEl) {
            inputEl.value = btn.textContent || "";
            send(pane);
          }
        });
      });
    }
  }

  function paneLabel(pane) {
    if (pane.preview) return String(pane.preview).slice(0, 42);
    if (!pane.sessionId) return "New chat";
    const row = (state.sessionList || []).find((s) => s && s.id === pane.sessionId);
    return (row && row.preview) || "Chat";
  }

  function renderChromeLists() {
    renderSidebar();
    renderTabs();
    syncBadge();
    state.busy = state.panes.some((p) => p.busy);
  }

  function renderSidebar() {
    const ul = state.root && state.root.querySelector("#oc-sessions");
    if (!ul) return;
    const seen = new Set();
    const rows = [];
    for (const pane of state.panes) {
      if (pane.sessionId) seen.add(pane.sessionId);
      const busy = pane.busy ? " is-busy" : "";
      const active = pane.id === state.activeId ? " is-active" : "";
      const sid = escapeHtml(pane.sessionId || "");
      rows.push(
        `<li><button type="button" class="oc-session${busy}${active}" data-pane-id="${pane.id}" data-session-id="${sid}" aria-busy="${pane.busy ? "true" : "false"}"><span class="oc-busy-dot" aria-hidden="true"></span><span class="oc-session-label">${escapeHtml(paneLabel(pane))}</span></button></li>`
      );
    }
    for (const s of state.sessionList || []) {
      if (!s || !s.id || seen.has(s.id)) continue;
      const sid = escapeHtml(s.id);
      const label = s.preview || "Chat";
      rows.push(
        `<li><button type="button" class="oc-session" data-session-id="${sid}" aria-busy="false"><span class="oc-busy-dot" aria-hidden="true"></span><span class="oc-session-label">${escapeHtml(label)}</span></button></li>`
      );
    }
    ul.innerHTML = rows.join("");
    ul.querySelectorAll(".oc-session").forEach((btn) => {
      btn.addEventListener("click", () => openFromSidebar(btn));
    });
  }

  function renderTabs() {
    const host = state.root && state.root.querySelector("#oc-tabs");
    if (!host) return;
    host.innerHTML = state.panes
      .map((pane) => {
        const busy = pane.busy ? " is-busy" : "";
        const active = pane.id === state.activeId ? " is-active" : "";
        return `<button type="button" class="oc-tab${busy}${active}" data-pane-id="${pane.id}" role="tab" aria-selected="${pane.id === state.activeId ? "true" : "false"}" aria-busy="${pane.busy ? "true" : "false"}"><span class="oc-busy-dot" aria-hidden="true"></span><span class="oc-tab-label">${escapeHtml(paneLabel(pane))}</span></button>`;
      })
      .join("");
    host.querySelectorAll(".oc-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        const pane = state.panes.find((p) => p.id === btn.getAttribute("data-pane-id"));
        if (pane) activate(pane);
      });
    });
  }

  function autoGrow(input) {
    if (!input || !input.style || typeof input.scrollHeight !== "number") return;
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 180) + "px";
  }

  function openFromSidebar(btn) {
    setHistoryOpen(false);
    const paneId = btn.getAttribute("data-pane-id");
    if (paneId) {
      const pane = state.panes.find((p) => p.id === paneId);
      if (pane) {
        activate(pane);
        return;
      }
    }
    const sid = btn.getAttribute("data-session-id");
    if (!sid) return;
    const existing = state.panes.find((p) => p.sessionId === sid);
    if (existing) {
      activate(existing);
      return;
    }
    const label = (btn.querySelector(".oc-session-label") || {}).textContent || "";
    const pane = createPane({ sessionId: sid, preview: String(label || "").slice(0, 120) });
    activate(pane);
    restorePane(pane);
  }

  function emptyHtml() {
    const run = state.scope === "run";
    return `<div class="oc-empty">
        <p class="oc-empty-title">${run ? "Ask about this run" : "Ask across all runs"}</p>
        <p>${
          run
            ? "Status, coverage, findings and tasks for this campaign. I can queue or re-queue hunts; Ralph runs them."
            : "Query findings across runs, list or start hunts on a named run, init audits, start or pause Ralph."
        }</p>
        <p class="oc-empty-note">Anything that changes state waits for your Confirm. Try a suggestion below.</p>
      </div>`;
  }

  function markHasMessages(pane) {
    const box = messagesEl(pane);
    if (pane && pane.el) pane.el.classList.toggle("has-messages", !!(box && !box.querySelector(".oc-empty")));
  }

  function renderMessages(pane, msgs) {
    const box = messagesEl(pane);
    if (!box) return;
    if (!msgs.length) {
      box.innerHTML = emptyHtml();
      markHasMessages(pane);
      return;
    }
    box.innerHTML = msgs.map(renderOne).join("");
    markHasMessages(pane);
    box.scrollTop = box.scrollHeight;
  }

  function appendMessages(pane, msgs) {
    const box = messagesEl(pane);
    if (!box) return;
    if (box.querySelector(".oc-empty")) box.innerHTML = "";
    box.insertAdjacentHTML("beforeend", msgs.map(renderOne).join(""));
    markHasMessages(pane);
    box.scrollTop = box.scrollHeight;
  }

  function clearThinking(pane) {
    const box = messagesEl(pane);
    if (!box) return;
    for (const el of box.querySelectorAll(".oc-thinking")) el.remove();
  }

  function renderCalls(calls) {
    const rows = calls
      .map((c) => {
        const preview = argsPreview(c.args);
        const head = `<span class="oc-call-verb">Calling</span><code class="oc-call-name">${escapeHtml(c.name)}</code>${
          preview ? `<span class="oc-call-args vf-mono">${escapeHtml(preview)}</span>` : ""
        }`;
        if (!Object.keys(c.args || {}).length) return `<div class="oc-call">${head}</div>`;
        return `<details class="oc-call"><summary>${head}</summary><pre class="oc-pre vf-mono">${escapeHtml(
          prettyJson(c.args, 3000)
        )}</pre></details>`;
      })
      .join("");
    return `<div class="oc-msg oc-calls"><div class="oc-call-list">${rows}</div></div>`;
  }

  function renderReceipt(m) {
    const kind = m.receipt === "confirmed" ? "is-confirmed" : m.receipt === "failed" ? "is-failed" : "is-cancelled";
    const mark = m.receipt === "confirmed" ? "✓" : m.receipt === "failed" ? "!" : "×";
    return `<div class="oc-msg oc-receipt ${kind}"><span class="oc-receipt-mark" aria-hidden="true">${mark}</span><span>${escapeHtml(
      m.content
    )}</span></div>`;
  }

  function renderOne(m) {
    const role = m.role || "assistant";
    if (m.thinking) {
      return `<div class="oc-msg oc-assistant oc-thinking" aria-label="Thinking"><div class="oc-bubble"><span class="oc-dots" aria-hidden="true"><i></i><i></i><i></i></span>thinking</div></div>`;
    }
    if (m.receipt) return renderReceipt(m);
    if (role === "user") {
      return `<div class="oc-msg oc-user"><div class="oc-bubble oc-md">${renderMarkdown(m.content)}</div></div>`;
    }
    if (role === "tool") {
      const name = escapeHtml(m.name || "tool");
      const sum = summarizeToolResult(m.content);
      const label = { ok: "ok", error: "error", pending: "needs confirm" }[sum.status];
      return `<div class="oc-msg oc-tool">
        <details class="oc-tool-card is-${sum.status}">
          <summary><span class="oc-tool-dot" aria-hidden="true"></span><span class="oc-tool-name vf-mono">${name}</span><span class="oc-tool-state">${label}</span>${
            sum.text && sum.text !== "ok" ? `<span class="oc-tool-sum">${escapeHtml(sum.text)}</span>` : ""
          }</summary>
          <pre class="oc-pre vf-mono">${escapeHtml(prettyJson(m.content))}</pre>
        </details>
      </div>`;
    }
    const calls = role === "assistant" ? toolCallsOf(m) : [];
    const text = typeof m.content === "string" ? m.content : m.content == null ? "" : prettyJson(m.content);
    const bubble = text.trim()
      ? `<div class="oc-msg oc-assistant${m.error ? " is-error" : ""}"><div class="oc-bubble oc-md">${renderMarkdown(text)}</div></div>`
      : "";
    return bubble + (calls.length ? renderCalls(calls) : "");
  }

  function stopConfirmTimer(pane) {
    if (pane && pane.confirmTimer) {
      clearTimeout(pane.confirmTimer);
      pane.confirmTimer = null;
    }
  }

  function confirmCardHtml(d, view) {
    const expired = view.expired;
    const running = view.running;
    const kicker = expired ? "Confirm expired" : running ? "Running…" : "Needs your confirmation";
    const timer =
      d.expiresIn == null || running
        ? ""
        : `<span class="oc-confirm-timer vf-mono">${expired ? "expired" : "expires in " + formatCountdown(view.left)}</span>`;
    const note = expired
      ? "This request expired and can no longer run. Ask again to get a fresh Confirm."
      : "Nothing runs until you press Confirm.";
    const args = d.argCount
      ? `<details class="oc-confirm-args"><summary>Arguments (${d.argCount})</summary><pre class="oc-pre vf-mono">${escapeHtml(
          prettyJson(d.args, 3000)
        )}</pre></details>`
      : "";
    const yesCls = d.danger ? "vf-btn--danger" : "vf-btn--primary";
    return `
      <div class="oc-confirm-card${expired ? " is-expired" : running ? " is-running" : " is-pending"}${d.danger ? " is-danger" : ""}" role="group" aria-label="Pending action: ${escapeHtml(d.title)}">
        <div class="oc-confirm-head"><span class="oc-confirm-kicker">${kicker}</span>${timer}</div>
        <p class="oc-confirm-title">${escapeHtml(d.title)}</p>
        <dl class="oc-confirm-meta">
          <dt>Run</dt><dd class="vf-mono">${escapeHtml(d.run)}</dd>
          <dt>Tool</dt><dd class="vf-mono">${escapeHtml(d.tool)}</dd>
        </dl>
        ${d.summary ? `<p class="oc-confirm-summary">${escapeHtml(d.summary)}</p>` : ""}
        ${args}
        <p class="oc-confirm-note">${note}</p>
        <div class="oc-confirm-actions">
          <button type="button" class="vf-btn ${yesCls} oc-confirm-yes"${expired || running ? " disabled" : ""}>Confirm</button>
          <button type="button" class="vf-btn vf-btn--ghost oc-confirm-no"${running ? " disabled" : ""}>${expired ? "Dismiss" : "Cancel"}</button>
        </div>
      </div>`;
  }

  function paintConfirm(pane) {
    const el = pane && pane.el && pane.el.querySelector(".oc-confirm");
    const p = pane && pane.pending;
    if (!el || !p) return;
    const d = describePending(p);
    const left = p._deadline ? Math.max(0, Math.ceil((p._deadline - Date.now()) / 1000)) : null;
    if (left === 0) p._expired = true;
    el.hidden = false;
    el.innerHTML = confirmCardHtml(d, { expired: !!p._expired, running: !!p._running, left });
    el.querySelector(".oc-confirm-yes")?.addEventListener("click", () => doConfirm(pane));
    el.querySelector(".oc-confirm-no")?.addEventListener("click", () => cancelConfirm(pane));
    pane.el.classList.toggle("has-pending", true);
  }

  function tickConfirm(pane) {
    stopConfirmTimer(pane);
    const p = pane && pane.pending;
    if (!p || !p._deadline || p._expired || p._running) return;
    pane.confirmTimer = setTimeout(() => {
      if (pane.pending !== p || p._running) return;
      const left = Math.max(0, Math.ceil((p._deadline - Date.now()) / 1000));
      if (left > 0) {
        // Only the timer text changes: re-rendering the card would swap the
        // Confirm button out from under a click in progress.
        const timer = pane.el.querySelector(".oc-confirm-timer");
        if (timer) timer.textContent = "expires in " + formatCountdown(left);
      } else {
        paintConfirm(pane);
        syncBadge();
      }
      tickConfirm(pane);
    }, 1000);
    // Node (tests) only: a countdown must not keep the process alive.
    if (pane.confirmTimer && typeof pane.confirmTimer.unref === "function") pane.confirmTimer.unref();
  }

  function showConfirm(pane, pending) {
    if (!pane || !pane.el || !pending) return;
    stopConfirmTimer(pane);
    const p = Object.assign({}, pending);
    const secs = Number(pending.expires_in_s);
    if (Number.isFinite(secs)) p._deadline = Date.now() + Math.max(0, secs) * 1000;
    pane.pending = p;
    paintConfirm(pane);
    tickConfirm(pane);
    syncBadge();
  }

  function cancelConfirm(pane) {
    const p = pane && pane.pending;
    if (!p || p._running) return;
    const d = describePending(p);
    const expired = !!p._expired;
    hideConfirm(pane);
    appendMessages(pane, [
      {
        receipt: "cancelled",
        content: expired
          ? `Expired · ${d.title} · ${d.run}. No action was taken.`
          : `Cancelled. No action was taken. (${d.title} · ${d.run})`,
      },
    ]);
  }

  function hideConfirm(pane) {
    stopConfirmTimer(pane);
    if (pane) pane.pending = null;
    const el = pane && pane.el && pane.el.querySelector(".oc-confirm");
    if (el) {
      el.hidden = true;
      el.innerHTML = "";
    }
    if (pane && pane.el) pane.el.classList.toggle("has-pending", false);
    syncBadge();
  }

  function showToast(text, opts) {
    const host = state.root && state.root.querySelector("#oc-toasts");
    if (!host) return;
    const failed = !!(opts && opts.ok === false);
    const cls = failed ? "oc-toast oc-toast-err" : "oc-toast";
    const role = failed ? "alert" : "status";
    host.insertAdjacentHTML(
      "beforeend",
      `<div class="${cls}" role="${role}">${escapeHtml(text)}</div>`
    );
    const added = host.querySelectorAll(".oc-toast");
    const fresh = added[added.length - 1];
    const t = setTimeout(() => fresh && fresh.remove && fresh.remove(), failed ? 8000 : 4000);
    if (t && typeof t.unref === "function") t.unref();
    const nodes = Array.prototype.slice.call(host.querySelectorAll(".oc-toast"));
    while (nodes.length > 3) {
      const old = nodes.shift();
      if (old && old.remove) old.remove();
    }
  }

  function finishPane(pane, ok) {
    const succeeded = ok !== false;
    pane.busy = false;
    setSendEnabled(pane, true);
    renderChromeLists();
    const label = paneLabel(pane);
    showToast((succeeded ? "Done · " : "Failed · ") + label, { ok: succeeded });
    refreshSessions();
  }

  function applyStreamEvent(pane, ev) {
    if (!ev || typeof ev !== "object") return;
    if (ev.event === "session") {
      noteSession(pane, ev.session_id);
      renderChromeLists();
      return;
    }
    if (ev.event === "message" && ev.message) {
      clearThinking(pane);
      if (ev.message.role === "user") return;
      appendMessages(pane, [ev.message]);
      return;
    }
    if (ev.event === "error") {
      clearThinking(pane);
      const text = String(ev.error || "Error");
      const box = messagesEl(pane);
      if (!box || !String(box.textContent || "").includes(text)) {
        appendMessages(pane, [{ role: "assistant", content: text }]);
      }
      return;
    }
    if (ev.event === "done") {
      clearThinking(pane);
      noteSession(pane, ev.session_id);
      if (ev.pending_confirm) showConfirm(pane, ev.pending_confirm);
      applyHints(ev.ui_hints);
      finishPane(pane, ev.ok !== false);
    }
  }

  function isNdjson(res) {
    let ctype = "";
    if (res && res.headers && typeof res.headers.get === "function") {
      ctype = res.headers.get("content-type") || "";
    }
    return (
      String(ctype).toLowerCase().includes("application/x-ndjson") &&
      res.body &&
      typeof res.body.getReader === "function"
    );
  }

  async function readNdjson(pane, res) {
    const reader = res.body.getReader();
    const decoder = typeof TextDecoder === "function" ? new TextDecoder() : null;
    let buf = "";
    let sawDone = false;
    const orig = applyStreamEvent;
    const wrapped = (p, ev) => {
      if (ev && ev.event === "done") sawDone = true;
      orig(p, ev);
    };
    while (true) {
      const step = await reader.read();
      if (step.done) break;
      if (typeof step.value === "string") buf += step.value;
      else if (decoder) buf += decoder.decode(step.value, { stream: true });
      else buf += String(step.value || "");
      let nl = buf.indexOf("\n");
      while (nl >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        nl = buf.indexOf("\n");
        if (!line) continue;
        try {
          wrapped(pane, JSON.parse(line));
        } catch (_) {
          appendMessages(pane, [{ role: "assistant", content: "Unreadable stream event." }]);
        }
      }
    }
    if (!sawDone) {
      clearThinking(pane);
      appendMessages(pane, [{ role: "assistant", content: "Stream ended before done." }]);
      finishPane(pane, false);
    }
  }

  async function applyJson(pane, res) {
    const data = await res.json().catch(() => ({}));
    clearThinking(pane);
    if (!res.ok) {
      appendMessages(pane, [
        { role: "assistant", content: data.detail || data.error || `Error ${res.status}` },
      ]);
      finishPane(pane, false);
      return;
    }
    noteSession(pane, data.session_id);
    const msgs = (data.messages || []).filter((m) => m.role !== "user");
    appendMessages(pane, msgs);
    if (data.pending_confirm) showConfirm(pane, data.pending_confirm);
    applyHints(data.ui_hints);
    finishPane(pane, data.ok !== false);
  }

  async function send(pane) {
    pane = pane || activePane();
    if (!pane || !pane.el) return;
    if (pane.restorePromise) {
      try {
        await pane.restorePromise;
      } catch (_) {}
    }
    if (pane.busy) return;
    const input = pane.el.querySelector(".oc-input");
    const text = (input?.value || "").trim();
    if (!text) return;
    input.value = "";
    pane.preview = text.slice(0, 120);
    pane.busy = true;
    setSendEnabled(pane, false);
    renderChromeLists();
    appendMessages(pane, [{ role: "user", content: text }]);
    appendMessages(pane, [{ role: "assistant", thinking: true }]);
    try {
      // The JSON handler returns one object after the tool loop. Asking for
      // NDJSON makes the server emit session/message/done while that loop runs.
      const res = await fetch(apiBase(state.scope), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/x-ndjson",
        },
        body: JSON.stringify({ message: text, session_id: pane.sessionId }),
      });
      if (isNdjson(res)) await readNdjson(pane, res);
      else await applyJson(pane, res);
    } catch (e) {
      clearThinking(pane);
      appendMessages(pane, [{ role: "assistant", content: `Request failed: ${e}` }]);
      finishPane(pane, false);
    }
  }

  async function doConfirm(pane) {
    if (!pane || !pane.pending || pane.busy) return;
    const p = pane.pending;
    if (p._expired || p._running) return;
    const d = describePending(p);
    pane.busy = true;
    p._running = true;
    stopConfirmTimer(pane);
    paintConfirm(pane);
    setSendEnabled(pane, false);
    renderChromeLists();
    const token = p.token;
    const sessionId = pane.sessionId;
    const where = `${d.title} · ${d.run}`;
    try {
      const res = await fetch(apiBase(state.scope) + "/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, session_id: sessionId }),
      });
      const data = await res.json().catch(() => ({}));
      // The token is one-shot server-side, so the card goes away either way.
      hideConfirm(pane);
      if (!res.ok) {
        appendMessages(pane, [
          { receipt: "failed", content: `Confirm failed · ${where}` },
          { role: "assistant", content: data.detail || data.error || "Confirm failed" },
        ]);
        return;
      }
      appendMessages(pane, [
        { receipt: data.ok === false ? "failed" : "confirmed", content: `${data.ok === false ? "Ran with errors" : "Confirmed"} · ${where}` },
      ].concat(data.messages || []));
      applyHints(data.ui_hints);
    } catch (e) {
      hideConfirm(pane);
      appendMessages(pane, [
        { receipt: "failed", content: `Confirm failed · ${where}` },
        { role: "assistant", content: `Confirm failed: ${e}` },
      ]);
    } finally {
      pane.busy = false;
      setSendEnabled(pane, true);
      renderChromeLists();
    }
  }

  function applyHints(hints) {
    if (!hints) return;
    if (hints.navigate && typeof hints.navigate === "string") {
      if (hints.navigate.startsWith("/")) {
        // Offer only. Auto-nav surprises the operator.
      }
    }
    if (hints.refresh_run && typeof window.refreshSnapshot === "function") {
      try {
        window.refreshSnapshot();
      } catch (_) {}
    }
  }

  function setSendEnabled(pane, on) {
    const btn = pane && pane.el && pane.el.querySelector(".oc-send");
    if (btn) btn.disabled = !on;
    const input = pane && pane.el && pane.el.querySelector(".oc-input");
    if (input) input.disabled = !on;
  }

  function bootChrome() {
    if (
      !document.getElementById("ai-fab") &&
      !document.getElementById("ai-sheet") &&
      !document.getElementById("ai-entry")
    ) {
      return;
    }
    ensureStyles();
    bindChrome();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootChrome);
  } else {
    bootChrome();
  }

  window.VulnForgeChat = {
    mount,
    ensureMounted,
    prefill,
    bindChrome,
    openSheet,
    closeSheet,
    toggleSheet,
    toggleMaximize,
    isMaximized,
    isSheetOpen: () => state.sheetOpen,
    syncChrome,
    helpers: {
      escapeHtml,
      inlineMd,
      renderMarkdown,
      toolCallsOf,
      argsPreview,
      prettyJson,
      summarizeToolResult,
      describePending,
      formatCountdown,
    },
  };
})();
