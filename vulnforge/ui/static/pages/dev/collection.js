/*
 * Dev workbench shared UI (issue #203): API/toast wrappers, list rows, the
 * tool chip picker, modals and the tool catalog cache. Section modules
 * (skills, recon, tools, lab) build on window.DevUI.
 */
(function () {
  "use strict";
  if (document.body?.dataset?.page !== "dev") return;

  const H = window.DevHelpers;

  async function api(path, opts) {
    if (typeof window.api === "function") return window.api(path, opts);
    const r = await fetch(path, {
      headers: { "Content-Type": "application/json", ...((opts && opts.headers) || {}) },
      ...opts,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || data.error || r.statusText);
    return data;
  }

  function toast(msg, bad) {
    if (typeof window.toast === "function") return window.toast(msg, bad);
    console.log(bad ? "ERR" : "OK", msg);
  }

  function fail(e) {
    toast((e && e.message) || String(e), true);
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function pill(label, tone) {
    const t = tone ? ` vf-pill--${esc(tone)}` : "";
    return `<span class="vf-pill${t}">${esc(label)}</span>`;
  }

  function setHash(section, id) {
    const next = H.devHash(section, id);
    if (location.hash !== next) history.replaceState(null, "", next);
  }

  /** Busy-state a button around an async action. */
  async function busy(btn, label, fn) {
    const prev = btn ? btn.textContent : "";
    if (btn) {
      btn.disabled = true;
      if (label) btn.textContent = label;
    }
    try {
      return await fn();
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = prev;
      }
    }
  }

  /**
   * Render a selectable list.
   * opts: { items, selectedId, empty, row(item) → inner HTML,
   *         onSelect(id), onToggle(id, checked) (optional active checkbox) }
   */
  function renderList(ul, opts) {
    const items = opts.items || [];
    if (!items.length) {
      ul.innerHTML = `<li class="vf-empty dev-list-empty">${esc(opts.empty || "Nothing here")}</li>`;
      return;
    }
    ul.innerHTML = items
      .map((it) => {
        const sel = it.id === opts.selectedId;
        const toggle = opts.onToggle
          ? `<input type="checkbox" class="dev-row-toggle" data-toggle="${esc(it.id)}" ${it.active ? "checked" : ""} title="Active" aria-label="Active: ${esc(it.id)}" />`
          : "";
        return `<li class="dev-row${sel ? " is-selected" : ""}" data-id="${esc(it.id)}" role="option" aria-selected="${sel}" tabindex="0">${toggle}${opts.row(it)}</li>`;
      })
      .join("");
    ul.querySelectorAll(".dev-row").forEach((li) => {
      const id = li.getAttribute("data-id");
      li.addEventListener("click", (ev) => {
        if (ev.target.closest("a, input")) return;
        opts.onSelect(id);
      });
      li.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          opts.onSelect(id);
        }
      });
    });
    if (opts.onToggle) {
      ul.querySelectorAll("[data-toggle]").forEach((cb) => {
        cb.addEventListener("change", () => opts.onToggle(cb.getAttribute("data-toggle"), cb.checked, cb));
      });
    }
  }

  /**
   * Tool allowlist as chips. state = { all: bool, selected: [] }.
   * Returns { get() → state } for editable pickers.
   */
  function chipPicker(el, { choices, state, editable, allLabel }) {
    const st = { all: !!state.all, selected: (state.selected || []).slice() };
    // Keep names the profile already lists even if the catalog lacks them.
    const names = choices.slice();
    st.selected.forEach((n) => {
      if (!names.includes(n)) names.push(n);
    });
    function draw() {
      if (!editable) {
        el.innerHTML = st.all
          ? `<span class="vf-faint">${esc(allLabel)}</span>`
          : st.selected.map((n) => `<span class="vf-chip dev-chip-static vf-mono" aria-pressed="true">${esc(n)}</span>`).join("");
        return;
      }
      el.innerHTML =
        `<button type="button" class="vf-chip" data-all aria-pressed="${st.all}">${esc(allLabel)}</button>` +
        `<span class="dev-chip-sep" aria-hidden="true"></span>` +
        names
          .map(
            (n) =>
              `<button type="button" class="vf-chip vf-mono" data-name="${esc(n)}" aria-pressed="${!st.all && st.selected.includes(n)}" ${st.all ? "disabled" : ""}>${esc(n)}</button>`
          )
          .join("");
      el.querySelector("[data-all]").addEventListener("click", () => {
        st.all = !st.all;
        if (!st.all && !st.selected.length) st.selected = names.slice();
        draw();
        el.dispatchEvent(new Event("input", { bubbles: true }));
      });
      el.querySelectorAll("[data-name]").forEach((b) => {
        b.addEventListener("click", () => {
          const n = b.getAttribute("data-name");
          st.selected = st.selected.includes(n) ? st.selected.filter((x) => x !== n) : st.selected.concat(n);
          draw();
          el.dispatchEvent(new Event("input", { bubbles: true }));
        });
      });
    }
    draw();
    return { get: () => ({ all: st.all, selected: st.selected.slice() }) };
  }

  function openModal(id) {
    document.getElementById(id)?.classList.add("open");
  }
  function closeModal(id) {
    document.getElementById(id)?.classList.remove("open");
  }

  function downloadJson(name, data) {
    const blob = new Blob([JSON.stringify(data, null, 2) + "\n"], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /* Tool catalog + per-stage built-ins, cached across sections. */
  let catalogP = null;
  function catalog(force) {
    if (force || !catalogP) {
      catalogP = Promise.all([api("/api/tools"), api("/api/tools/defaults")])
        .then(([t, d]) => ({ tools: t.tools || [], defaults: d.defaults || {}, builtin: d.builtin || {} }))
        .catch((e) => {
          catalogP = null;
          throw e;
        });
    }
    return catalogP;
  }

  /* Unsaved-edit registry: warn before leaving the page. */
  const dirty = new Set();
  function setDirty(key, on) {
    if (on) dirty.add(key);
    else dirty.delete(key);
  }
  window.addEventListener("beforeunload", (ev) => {
    if (dirty.size) {
      ev.preventDefault();
      ev.returnValue = "";
    }
  });

  /** Diff lines → HTML rows. kind: "add" | "del" | "ctx" | "file" | "hunk". */
  function diffHtml(rows) {
    if (!rows.length) return `<div class="vf-empty">No changes.</div>`;
    return `<pre class="dev-diff vf-mono">${rows
      .map((r) => `<span class="dev-diff-line is-${r.kind}">${esc(r.text) || " "}</span>`)
      .join("")}</pre>`;
  }

  window.DevUI = {
    api,
    toast,
    fail,
    esc,
    pill,
    setHash,
    busy,
    renderList,
    chipPicker,
    openModal,
    closeModal,
    downloadJson,
    catalog,
    setDirty,
    diffHtml,
  };
  window.VFPages = window.VFPages || {};
})();
