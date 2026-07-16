/* VulnForge Target Explorer  -  polished research surface */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  const state = {
    browsePath: ".",
    openFile: null,
    selRange: null,
    filter: "",
    mounted: false,
    treeLoaded: false,
    entries: [],
    lastTaskId: null,
  };

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function runApiBase() {
    if (typeof window.runApiBase === "function") return window.runApiBase();
    const key = document.body?.dataset?.runKey || "";
    const [t, r] = key.split("/");
    return `/api/runs/${encodeURIComponent(t)}/${encodeURIComponent(r)}`;
  }

  async function api(path, opts) {
    if (typeof window.api === "function") return window.api(path, opts);
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts?.headers || {}) },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || data.error || res.statusText);
    return data;
  }

  function toast(msg, err) {
    if (typeof window.toast === "function") window.toast(msg, err);
  }

  function huntClassOptionsHtml(selected) {
    if (typeof window.huntClassOptionsHtml === "function") {
      return window.huntClassOptionsHtml(selected);
    }
    const defaults = [
      "wildcard",
      "injection",
      "access-control",
      "business-logic",
      "cryptography",
    ];
    return defaults
      .map(
        (c) =>
          `<option value="${esc(c)}"${c === selected ? " selected" : ""}>${esc(c)}</option>`
      )
      .join("");
  }

  function formatPwd(path) {
    const p = (path || ".").replace(/\\/g, "/");
    if (!p || p === ".") return "target root";
    return p.replace(/^\//, "");
  }

  function breadcrumbHtml(path) {
    const p = (path || ".").replace(/\\/g, "/");
    const parts = !p || p === "." ? [] : p.split("/").filter(Boolean);
    let acc = [];
    let html = `<button type="button" class="bc-seg" data-path="." title="Target root">target</button>`;
    for (const seg of parts) {
      acc.push(seg);
      const full = acc.join("/");
      html += `<span class="bc-sep" aria-hidden="true">/</span>`;
      html += `<button type="button" class="bc-seg" data-path="${esc(full)}">${esc(seg)}</button>`;
    }
    return html;
  }

  function mount() {
    const el = $("#explorer-panel");
    if (!el) return;
    const prevClass = $("#explorer-hunt-class")?.value || "wildcard";
    const prevNotes = $("#explorer-op-notes")?.value || "";

    el.innerHTML = `
    <div class="card explorer-card">
      <div class="explorer-header">
        <div>
          <h2 class="explorer-title">Target explorer</h2>
          <p class="controls-hint">Browse the audit target (read-only). Select lines or hunt the whole file with operator notes.</p>
        </div>
      </div>
      <div class="explorer-layout">
        <div class="explorer-tree-pane">
          <div class="explorer-breadcrumbs" id="explorer-breadcrumbs" aria-label="Path">${breadcrumbHtml(state.browsePath)}</div>
          <div class="explorer-tree-toolbar">
            <input type="search" id="explorer-filter" class="explorer-filter" placeholder="Filter..." value="${esc(state.filter)}" autocomplete="off" aria-label="Filter directory entries" />
            <button type="button" class="btn btn-ghost" id="explorer-up" title="Parent directory">Up</button>
            <button type="button" class="btn btn-ghost" id="explorer-root" title="Target root">Root</button>
          </div>
          <div id="explorer-tree-list" class="explorer-tree-list">Loading...</div>
        </div>
        <div class="explorer-viewer">
          <div class="explorer-steer">
            <div class="explorer-file-meta">
              <code class="mono" id="explorer-file-label">${esc(state.openFile || "No file open")}</code>
              <span class="controls-hint" id="explorer-sel-meta">Open a file, then hunt whole file or select lines.</span>
            </div>
            <div class="explorer-steer-row">
              <label class="sr-only" for="explorer-hunt-class">Hunt skill</label>
              <select id="explorer-hunt-class" title="Hunt skill">${huntClassOptionsHtml(prevClass)}</select>
              <input id="explorer-op-notes" type="text" placeholder="Operator notes for this hunt..." value="${esc(prevNotes)}" aria-label="Operator notes for this hunt" />
              <button type="button" class="btn btn-primary" id="explorer-hunt-sel" disabled>Enqueue hunt</button>
            </div>
            <div class="controls-hint" id="explorer-last-task"></div>
          </div>
          <pre class="code-view" id="explorer-code" tabindex="0">Open a file from the tree...</pre>
        </div>
      </div>
    </div>`;

    $("#explorer-up")?.addEventListener("click", () => {
      if (state.browsePath === "." || !state.browsePath) return;
      const parts = state.browsePath.replace(/\\/g, "/").split("/").filter(Boolean);
      parts.pop();
      state.browsePath = parts.length ? parts.join("/") : ".";
      loadTree();
    });
    $("#explorer-root")?.addEventListener("click", () => {
      state.browsePath = ".";
      loadTree();
    });
    $("#explorer-filter")?.addEventListener("input", (e) => {
      state.filter = e.target.value || "";
      renderTreeList();
    });
    $("#explorer-breadcrumbs")?.addEventListener("click", (e) => {
      const btn = e.target.closest(".bc-seg");
      if (!btn) return;
      state.browsePath = btn.getAttribute("data-path") || ".";
      loadTree();
    });
    $("#explorer-hunt-sel")?.addEventListener("click", enqueueHunt);
    const code = $("#explorer-code");
    code?.addEventListener("mouseup", updateSelection);
    code?.addEventListener("keyup", updateSelection);

    state.mounted = true;
    state.treeLoaded = false;
    // Export flags for legacy app.js
    window.explorerMounted = true;
    window.explorerTreeLoaded = false;
    loadTree();
    if (state.openFile) loadFile(state.openFile);
    updateHuntButton();
  }

  function ensureMounted() {
    if (!state.mounted || !$("#explorer-tree-list")) mount();
    else if (!state.treeLoaded) loadTree();
  }

  async function loadTree() {
    const list = $("#explorer-tree-list");
    if (!list) return;
    list.textContent = "Loading...";
    const bc = $("#explorer-breadcrumbs");
    if (bc) bc.innerHTML = breadcrumbHtml(state.browsePath);
    const up = $("#explorer-up");
    if (up) up.disabled = !state.browsePath || state.browsePath === ".";
    try {
      const data = await api(
        `${runApiBase()}/target/list?path=${encodeURIComponent(state.browsePath || ".")}`
      );
      state.entries = [...(data.entries || [])];
      state.entries.sort((a, b) => {
        if (!!a.is_dir !== !!b.is_dir) return a.is_dir ? -1 : 1;
        return String(a.name).localeCompare(String(b.name), undefined, {
          sensitivity: "base",
        });
      });
      state.treeLoaded = true;
      window.explorerTreeLoaded = true;
      renderTreeList();
    } catch (e) {
      list.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message)}</div>`;
    }
  }

  function renderTreeList() {
    const list = $("#explorer-tree-list");
    if (!list) return;
    const q = (state.filter || "").toLowerCase().trim();
    let entries = state.entries;
    if (q) {
      entries = entries.filter((e) => String(e.name).toLowerCase().includes(q));
    }
    if (!entries.length) {
      list.innerHTML = `<div class="empty" style="padding:0.5rem">${q ? "No matches" : "Empty folder"}</div>`;
      return;
    }
    const dirs = entries.filter((e) => e.is_dir);
    const files = entries.filter((e) => !e.is_dir);
    const row = (e) => {
      const full =
        !state.browsePath || state.browsePath === "."
          ? e.name
          : `${state.browsePath.replace(/\\/g, "/").replace(/\/$/, "")}/${e.name}`;
      const active =
        !e.is_dir && state.openFile && normalize(full) === normalize(state.openFile)
          ? " active"
          : "";
      if (e.is_dir) {
        return `<button type="button" class="tree-item dir" data-path="${esc(full)}" data-dir="1">
          <span class="tree-ico tree-ico-folder" aria-hidden="true"></span>
          <span class="tree-name">${esc(e.name)}</span>
          <span class="tree-chevron" aria-hidden="true"></span>
        </button>`;
      }
      return `<button type="button" class="tree-item file${active}" data-path="${esc(full)}" data-dir="0">
          <span class="tree-ico tree-ico-file" aria-hidden="true"></span>
          <span class="tree-name">${esc(e.name)}</span>
        </button>`;
    };
    let html = "";
    if (dirs.length) {
      html += `<div class="tree-section-label">Folders (${dirs.length})</div>`;
      html += dirs.map(row).join("");
    }
    if (files.length) {
      html += `<div class="tree-section-label">Files (${files.length})</div>`;
      html += files.map(row).join("");
    }
    list.innerHTML = html;
    list.querySelectorAll(".tree-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = btn.getAttribute("data-path");
        const isDir = btn.getAttribute("data-dir") === "1";
        if (isDir) {
          state.browsePath = p;
          loadTree();
        } else {
          loadFile(p);
        }
      });
    });
  }

  function normalize(p) {
    return String(p || "").replace(/\\/g, "/");
  }

  async function loadFile(path, focusLine) {
    state.openFile = path;
    state.selRange = null;
    window.explorerOpenFile = path;
    const label = $("#explorer-file-label");
    const code = $("#explorer-code");
    if (label) label.textContent = path;
    if (code) code.textContent = "Loading...";
    updateHuntButton();
    try {
      const data = await api(
        `${runApiBase()}/target/read?path=${encodeURIComponent(path)}`
      );
      const lines = (data.content || "").split("\n");
      const base = data.start_line || 1;
      if (code) {
        code.innerHTML = lines
          .map((ln, i) => {
            const n = base + i;
            return `<div class="code-line" data-line="${n}"><span class="ln">${n}</span><span class="tx">${esc(ln)}</span></div>`;
          })
          .join("");
      }
      const meta = $("#explorer-sel-meta");
      if (meta) {
        meta.textContent = "Whole file ready to hunt  -  or select lines for a tighter scope.";
      }
      renderTreeList();
      if (focusLine != null && code) {
        const el = code.querySelector(`.code-line[data-line="${focusLine}"]`);
        if (el) {
          el.classList.add("sel-hl");
          el.scrollIntoView({ block: "center" });
        }
      }
      updateHuntButton();
    } catch (e) {
      if (code) code.textContent = e.message;
    }
  }

  function updateSelection() {
    const code = $("#explorer-code");
    const meta = $("#explorer-sel-meta");
    if (!code || !state.openFile) return;
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed || !code.contains(sel.anchorNode)) {
      state.selRange = null;
      clearLineHighlight();
      if (meta)
        meta.textContent = "Whole file ready to hunt  -  or select lines for a tighter scope.";
      updateHuntButton();
      return;
    }
    const getLine = (node) => {
      let el = node.nodeType === 3 ? node.parentElement : node;
      while (el && el !== code) {
        if (el.dataset && el.dataset.line) return parseInt(el.dataset.line, 10);
        el = el.parentElement;
      }
      return null;
    };
    let a = getLine(sel.anchorNode);
    let b = getLine(sel.focusNode);
    if (a == null || b == null) {
      state.selRange = null;
      updateHuntButton();
      return;
    }
    const start = Math.min(a, b);
    const end = Math.max(a, b);
    state.selRange = { start_line: start, end_line: end };
    highlightLines(start, end);
    if (meta)
      meta.textContent = `Selection: lines ${start}-${end} in ${state.openFile}`;
    updateHuntButton();
  }

  function clearLineHighlight() {
    $$("#explorer-code .code-line.sel-hl").forEach((el) =>
      el.classList.remove("sel-hl")
    );
  }

  function highlightLines(start, end) {
    clearLineHighlight();
    for (let n = start; n <= end; n++) {
      $(`#explorer-code .code-line[data-line="${n}"]`)?.classList.add("sel-hl");
    }
  }

  function updateHuntButton() {
    const btn = $("#explorer-hunt-sel");
    if (btn) btn.disabled = !state.openFile;
  }

  async function enqueueHunt() {
    if (!state.openFile) {
      toast("Open a file first", true);
      return;
    }
    const cls = $("#explorer-hunt-class")?.value || "wildcard";
    const notes = ($("#explorer-op-notes")?.value || "").trim();
    const body = {
      path: state.openFile,
      attack_class: cls,
      note: notes || "operator selection from target explorer",
      operator_notes: notes || "operator selection from target explorer",
    };
    if (state.selRange) {
      body.start_line = state.selRange.start_line;
      body.end_line = state.selRange.end_line;
    }
    try {
      const r = await api(`${runApiBase()}/hunts/from-selection`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      state.lastTaskId = r.task_id;
      const scope = state.selRange
        ? `lines ${state.selRange.start_line}-${state.selRange.end_line}`
        : "whole file";
      toast(`Enqueued hunt #${r.task_id} (${scope}) on ${state.openFile}`);
      const last = $("#explorer-last-task");
      if (last)
        last.innerHTML = `Last enqueue: <strong>task #${esc(r.task_id)}</strong> | ${esc(cls)} | ${esc(scope)}`;
      if (typeof window.loadRunFull === "function") await window.loadRunFull();
    } catch (e) {
      toast(e.message, true);
    }
  }

  function reveal(path, line) {
    ensureMounted();
    const norm = normalize(path);
    const parts = norm.split("/").filter(Boolean);
    if (parts.length > 1) {
      state.browsePath = parts.slice(0, -1).join("/");
    } else {
      state.browsePath = ".";
    }
    loadTree().then(() => loadFile(norm, line != null ? Number(line) : undefined));
  }

  // Public API
  window.VulnForgeExplorer = {
    mount,
    ensureMounted,
    reveal,
    loadFile,
    loadTree,
    get state() {
      return state;
    },
  };

  // Override legacy symbols used by app.js
  window.mountExplorer = mount;
  window.renderExplorer = mount;
  window.loadExplorerTree = loadTree;
  window.loadExplorerFile = loadFile;
  window.loadArchTree = loadTree;
  window.loadArchFile = loadFile;

  // Auto-mount if panel visible on load
  function boot() {
    if (document.body?.dataset?.page !== "run") return;
    // Delay so app.js can set globals first
    setTimeout(() => {
      // Mode panel is data-mode-panel="explorer" with #explorer-panel (not legacy #panel-explorer)
      const explorerMode = document.querySelector('.mode-panel[data-mode-panel="explorer"]');
      if (explorerMode?.classList.contains("active") || $("#explorer-panel")) {
        // Only auto-mount when explorer mode is active
        if (explorerMode?.classList.contains("active")) ensureMounted();
      }
    }, 0);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
