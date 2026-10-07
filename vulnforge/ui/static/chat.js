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

  function simpleMarkdown(text) {
    let t = escapeHtml(text || "");
    t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
    t = t.replace(/\n/g, "<br/>");
    return t;
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
    const badge = state.fab && state.fab.querySelector(".ai-badge");
    if (!badge) return;
    const pending = state.panes.some((p) => p.pending);
    badge.hidden = !pending;
    state.pending = (activePane() && activePane().pending) || null;
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

  function shellHtml() {
    const ctx =
      state.scope === "run"
        ? `Run ${escapeHtml(document.body.getAttribute("data-run-key") || "")}`
        : "Home — all runs";
    return `
      <div class="oc-shell">
        <div class="oc-layout">
          <aside class="oc-sidebar" aria-label="Previous chats">
            <button type="button" class="btn btn-ghost" id="oc-new">New chat</button>
            <ul class="oc-sessions" id="oc-sessions"></ul>
          </aside>
          <div class="oc-stage">
            <div class="oc-toolbar">
              <span class="oc-context mono">${ctx}</span>
            </div>
            <div class="oc-tabs" id="oc-tabs" role="tablist" aria-label="Open chats"></div>
            <div class="oc-panes" id="oc-panes"></div>
          </div>
        </div>
        <div class="oc-toasts" id="oc-toasts" aria-live="polite"></div>
      </div>`;
  }

  function paneHtml(pane) {
    return `
      <section class="oc-pane pane-${pane.id}" data-pane-id="${pane.id}">
        <div class="oc-messages" role="log" aria-live="polite"></div>
        <div class="oc-chips"></div>
        <div class="oc-confirm" hidden></div>
        <div class="oc-composer">
          <textarea class="oc-input" rows="2" placeholder="Ask about runs, hunts, findings…" aria-label="Chat message"></textarea>
          <button type="button" class="btn btn-primary oc-send">Send</button>
        </div>
        <p class="controls-hint oc-hint">Mutating tools (start, enqueue, stop) require Confirm. needs_human ≠ exploit proof.</p>
      </section>`;
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
    root.innerHTML = shellHtml();
    const pane = createPane({ sessionId: state.sessionId });
    const neu = root.querySelector("#oc-new");
    if (neu) neu.addEventListener("click", () => newChat());
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
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        send(pane);
      }
    });
    const chips = root.querySelector(".oc-chips");
    if (chips) {
      chips.innerHTML = state.chips
        .map((c) => `<button type="button" class="chip oc-chip">${escapeHtml(c)}</button>`)
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

  function openFromSidebar(btn) {
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

  function renderMessages(pane, msgs) {
    const box = messagesEl(pane);
    if (!box) return;
    if (!msgs.length) {
      box.innerHTML = `<div class="oc-empty">Ask anything about ${
        state.scope === "run" ? "this campaign" : "your fleet"
      }. Use chips below to start.</div>`;
      return;
    }
    box.innerHTML = msgs.map(renderOne).join("");
    box.scrollTop = box.scrollHeight;
  }

  function appendMessages(pane, msgs) {
    const box = messagesEl(pane);
    if (!box) return;
    if (box.querySelector(".oc-empty")) box.innerHTML = "";
    box.insertAdjacentHTML("beforeend", msgs.map(renderOne).join(""));
    box.scrollTop = box.scrollHeight;
  }

  function clearThinking(pane) {
    const box = messagesEl(pane);
    if (!box) return;
    for (const el of box.querySelectorAll(".oc-thinking")) el.remove();
  }

  function renderOne(m) {
    const role = m.role || "assistant";
    if (m.thinking) {
      return `<div class="oc-msg oc-assistant oc-thinking"><div class="oc-bubble">…thinking</div></div>`;
    }
    if (role === "user") {
      return `<div class="oc-msg oc-user"><div class="oc-bubble">${simpleMarkdown(m.content)}</div></div>`;
    }
    if (role === "tool") {
      const name = escapeHtml(m.name || "tool");
      const ok = m.content && m.content.ok !== false;
      const body =
        typeof m.content === "object"
          ? escapeHtml(JSON.stringify(m.content, null, 0).slice(0, 1200))
          : escapeHtml(String(m.content || "").slice(0, 1200));
      return `<div class="oc-msg oc-tool">
        <details class="oc-tool-card ${ok ? "ok" : "bad"}">
          <summary>tool: ${name} ${ok ? "✓" : "·"}</summary>
          <pre class="oc-tool-pre">${body}</pre>
        </details>
      </div>`;
    }
    if (role === "assistant" && Array.isArray(m.tool_calls) && !(m.content || "").trim()) {
      const names = m.tool_calls
        .map((tc) => (tc && tc.function && tc.function.name) || (tc && tc.name) || "tool")
        .join(", ");
      return `<div class="oc-msg oc-assistant oc-live"><div class="oc-bubble">Calling ${escapeHtml(names)}…</div></div>`;
    }
    if (!(m.content || "").trim() && m.tool_calls) {
      return "";
    }
    return `<div class="oc-msg oc-assistant"><div class="oc-bubble">${simpleMarkdown(m.content)}</div></div>`;
  }

  function showConfirm(pane, pending) {
    const el = pane && pane.el && pane.el.querySelector(".oc-confirm");
    if (!el || !pending) return;
    pane.pending = pending;
    el.hidden = false;
    el.innerHTML = `
      <div class="oc-confirm-card">
        <strong>Confirm action</strong>
        <p>${escapeHtml(pending.summary || pending.tool_name)}</p>
        <div class="oc-confirm-actions">
          <button type="button" class="btn btn-good" id="oc-confirm-yes">Confirm</button>
          <button type="button" class="btn btn-ghost" id="oc-confirm-no">Cancel</button>
        </div>
      </div>`;
    el.querySelector("#oc-confirm-yes")?.addEventListener("click", () => doConfirm(pane));
    el.querySelector("#oc-confirm-no")?.addEventListener("click", () => {
      hideConfirm(pane);
      appendMessages(pane, [
        {
          role: "assistant",
          content: "Cancelled. No action was taken.",
        },
      ]);
    });
    syncBadge();
  }

  function hideConfirm(pane) {
    if (pane) pane.pending = null;
    const el = pane && pane.el && pane.el.querySelector(".oc-confirm");
    if (el) {
      el.hidden = true;
      el.innerHTML = "";
    }
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
    pane.busy = true;
    setSendEnabled(pane, false);
    renderChromeLists();
    const token = pane.pending.token;
    const sessionId = pane.sessionId;
    hideConfirm(pane);
    try {
      const res = await fetch(apiBase(state.scope) + "/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, session_id: sessionId }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        appendMessages(pane, [
          { role: "assistant", content: data.detail || data.error || "Confirm failed" },
        ]);
        return;
      }
      appendMessages(pane, data.messages || []);
      applyHints(data.ui_hints);
    } catch (e) {
      appendMessages(pane, [{ role: "assistant", content: `Confirm failed: ${e}` }]);
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
  };
})();
