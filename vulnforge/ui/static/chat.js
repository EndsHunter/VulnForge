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
  };

  function currentScopeKey() {
    if (document.body.getAttribute("data-page") === "run") {
      return document.body.getAttribute("data-run-key") || "run";
    }
    return "fleet";
  }

  function syncBadge() {
    const badge = state.fab && state.fab.querySelector(".ai-badge");
    if (!badge) return;
    badge.hidden = !state.pending;
  }

  function resetSession() {
    state.sessionId = null;
    state.pending = null;
    state.mounted = false;
    const root = document.getElementById("operator-chat-root");
    if (root) {
      delete root.dataset.ready;
      root.innerHTML = "";
    }
    syncBadge();
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
    const closeBtn = document.getElementById("ai-close");
    if (closeBtn && !closeBtn.dataset.bound) {
      closeBtn.dataset.bound = "1";
      closeBtn.addEventListener("click", () => closeSheet());
    }
    syncBadge();
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
    if (state.fab) {
      state.fab.classList.add("open");
      state.fab.setAttribute("aria-expanded", "true");
    }
  }

  function closeSheet() {
    state.sheetOpen = false;
    if (state.sheet) state.sheet.hidden = true;
    if (state.fab) {
      state.fab.classList.remove("open");
      state.fab.setAttribute("aria-expanded", "false");
    }
  }

  function toggleSheet() {
    if (state.sheetOpen) closeSheet();
    else openSheet();
  }

  function mount(root, opts) {
    if (!root) return;
    state.root = root;
    state.scope = opts?.scope || root.closest("[data-chat-scope]")?.getAttribute("data-chat-scope") || "home";
    if (document.body.getAttribute("data-page") === "run") state.scope = "run";
    if (document.body.getAttribute("data-page") === "chat") state.scope = "home";
    state.chips = opts?.chips || defaultChips(state.scope);
    state.mounted = true;
    root.innerHTML = shellHtml();
    bind(root);
    renderMessages([]);
  }

  function ensureMounted() {
    const root = document.getElementById("operator-chat-root");
    if (!root) return;
    if (state.mounted && root.dataset.ready === "1") {
      const input = root.querySelector("#oc-input");
      if (input) setTimeout(() => input.focus(), 50);
      return;
    }
    const page = document.body.getAttribute("data-page");
    const scope = page === "run" ? "run" : "home";
    mount(root, { scope, chips: defaultChips(scope) });
    root.dataset.ready = "1";
    const input = root.querySelector("#oc-input");
    if (input) setTimeout(() => input.focus(), 50);
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

  function shellHtml() {
    const ctx =
      state.scope === "run"
        ? `Run ${escapeHtml(document.body.getAttribute("data-run-key") || "")}`
        : "Home — all runs";
    return `
      <div class="oc-shell">
        <div class="oc-toolbar">
          <span class="oc-context mono">${ctx}</span>
          <button type="button" class="btn btn-ghost" id="oc-new">New chat</button>
        </div>
        <div class="oc-messages" id="oc-messages" role="log" aria-live="polite"></div>
        <div class="oc-chips" id="oc-chips"></div>
        <div class="oc-confirm" id="oc-confirm" hidden></div>
        <div class="oc-composer">
          <textarea id="oc-input" rows="2" placeholder="Ask about runs, hunts, findings…" aria-label="Chat message"></textarea>
          <button type="button" class="btn btn-primary" id="oc-send">Send</button>
        </div>
        <p class="controls-hint oc-hint">Mutating tools (start, enqueue, stop) require Confirm. needs_human ≠ exploit proof.</p>
      </div>`;
  }

  function bind(root) {
    $("#oc-send", root)?.addEventListener("click", () => send());
    $("#oc-new", root)?.addEventListener("click", () => {
      state.sessionId = null;
      state.pending = null;
      renderMessages([]);
      hideConfirm();
    });
    const input = $("#oc-input", root);
    input?.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        send();
      }
    });
    const chips = $("#oc-chips", root);
    if (chips) {
      chips.innerHTML = state.chips
        .map((c) => `<button type="button" class="chip oc-chip">${escapeHtml(c)}</button>`)
        .join("");
      chips.querySelectorAll(".oc-chip").forEach((btn) => {
        btn.addEventListener("click", () => {
          const inputEl = $("#oc-input", root);
          if (inputEl) {
            inputEl.value = btn.textContent || "";
            send();
          }
        });
      });
    }
  }

  function renderMessages(msgs) {
    const box = state.root && $("#oc-messages", state.root);
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

  function appendMessages(msgs) {
    const box = state.root && $("#oc-messages", state.root);
    if (!box) return;
    if (box.querySelector(".oc-empty")) box.innerHTML = "";
    box.insertAdjacentHTML("beforeend", msgs.map(renderOne).join(""));
    box.scrollTop = box.scrollHeight;
  }

  function renderOne(m) {
    const role = m.role || "assistant";
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
    if (!(m.content || "").trim() && m.tool_calls) {
      return "";
    }
    return `<div class="oc-msg oc-assistant"><div class="oc-bubble">${simpleMarkdown(m.content)}</div></div>`;
  }

  function showConfirm(pending) {
    const el = state.root && $("#oc-confirm", state.root);
    if (!el || !pending) return;
    state.pending = pending;
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
    $("#oc-confirm-yes", el)?.addEventListener("click", () => doConfirm());
    $("#oc-confirm-no", el)?.addEventListener("click", () => {
      hideConfirm();
      appendMessages([
        {
          role: "assistant",
          content: "Cancelled. No action was taken.",
        },
      ]);
    });
    syncBadge();
  }

  function hideConfirm() {
    state.pending = null;
    const el = state.root && $("#oc-confirm", state.root);
    if (el) {
      el.hidden = true;
      el.innerHTML = "";
    }
    syncBadge();
  }

  async function send() {
    if (state.busy || !state.root) return;
    const input = $("#oc-input", state.root);
    const text = (input?.value || "").trim();
    if (!text) return;
    input.value = "";
    state.busy = true;
    setSendEnabled(false);
    appendMessages([{ role: "user", content: text }]);
    appendMessages([{ role: "assistant", content: "…thinking" }]);
    try {
      const res = await fetch(apiBase(state.scope), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, session_id: state.sessionId }),
      });
      const data = await res.json().catch(() => ({}));
      // remove thinking
      const box = $("#oc-messages", state.root);
      const last = box?.querySelector(".oc-msg.oc-assistant:last-child");
      if (last && last.textContent?.includes("…thinking")) last.remove();

      if (!res.ok) {
        appendMessages([
          { role: "assistant", content: data.detail || data.error || `Error ${res.status}` },
        ]);
        return;
      }
      if (data.session_id) state.sessionId = data.session_id;
      const msgs = (data.messages || []).filter((m) => m.role !== "user");
      appendMessages(msgs);
      if (data.pending_confirm) showConfirm(data.pending_confirm);
      applyHints(data.ui_hints);
    } catch (e) {
      const box = $("#oc-messages", state.root);
      const last = box?.querySelector(".oc-msg.oc-assistant:last-child");
      if (last && last.textContent?.includes("…thinking")) last.remove();
      appendMessages([{ role: "assistant", content: `Request failed: ${e}` }]);
    } finally {
      state.busy = false;
      setSendEnabled(true);
    }
  }

  async function doConfirm() {
    if (!state.pending || state.busy) return;
    state.busy = true;
    setSendEnabled(false);
    const token = state.pending.token;
    const sessionId = state.sessionId;
    hideConfirm();
    try {
      const res = await fetch(apiBase(state.scope) + "/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, session_id: sessionId }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        appendMessages([
          { role: "assistant", content: data.detail || data.error || "Confirm failed" },
        ]);
        return;
      }
      appendMessages(data.messages || []);
      applyHints(data.ui_hints);
    } catch (e) {
      appendMessages([{ role: "assistant", content: `Confirm failed: ${e}` }]);
    } finally {
      state.busy = false;
      setSendEnabled(true);
    }
  }

  function applyHints(hints) {
    if (!hints) return;
    if (hints.navigate && typeof hints.navigate === "string") {
      // same-origin relative
      if (hints.navigate.startsWith("/")) {
        // soft: offer is enough; auto-nav can surprise — only if home scope open_run
        // keep as no auto for now
      }
    }
    if (hints.refresh_run && typeof window.refreshSnapshot === "function") {
      try {
        window.refreshSnapshot();
      } catch (_) {}
    }
  }

  function setSendEnabled(on) {
    const btn = state.root && $("#oc-send", state.root);
    if (btn) btn.disabled = !on;
    const input = state.root && $("#oc-input", state.root);
    if (input) input.disabled = !on;
  }

  function bootChrome() {
    if (!document.getElementById("ai-fab")) return;
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
  };
})();
