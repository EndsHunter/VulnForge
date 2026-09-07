/* VulnForge Target Explorer — Monaco code viewer (Ticket 5) */

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
    editor: null,
    model: null,
    decoIds: [],
    focusLine: null,
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

  function languageFromPath(path) {
    if (window.VulnForgeMonaco?.languageFromPath) {
      return window.VulnForgeMonaco.languageFromPath(path);
    }
    return "plaintext";
  }

  function disposeEditor() {
    if (state.model) {
      try {
        state.model.dispose();
      } catch (_) {}
      state.model = null;
    }
    if (state.editor) {
      try {
        state.editor.dispose();
      } catch (_) {}
      state.editor = null;
    }
    state.decoIds = [];
  }

  async function ensureEditor() {
    const host = $("#explorer-monaco");
    if (!host) return null;
    if (state.editor && state.editor.getDomNode()?.isConnected) {
      return state.editor;
    }
    disposeEditor();
    const monacoApi = window.VulnForgeMonaco;
    if (!monacoApi?.loadMonaco) {
      host.innerHTML = `<pre class="code-view-fallback">Monaco loader unavailable. Open a file after scripts load.</pre>`;
      return null;
    }
    host.innerHTML = "";
    let monaco;
    try {
      monaco = await monacoApi.loadMonaco();
    } catch (e) {
      host.innerHTML = `<pre class="code-view-fallback">Monaco failed to load (${esc(
        e.message || e
      )}). Check network/CDN.</pre>`;
      return null;
    }
    monacoApi.defineCockpitTheme?.(monaco);
    monaco.editor.setTheme("vulnforge-cockpit");
    state.editor = monaco.editor.create(host, {
      value: "",
      language: "plaintext",
      readOnly: true,
      automaticLayout: true,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      fontFamily: 'var(--mono), "Cascadia Code", Consolas, monospace',
      fontSize: 12,
      lineNumbers: "on",
      renderLineHighlight: "line",
      wordWrap: "off",
      contextmenu: false,
      folding: true,
      padding: { top: 8, bottom: 8 },
      overviewRulerLanes: 0,
      scrollbar: { verticalScrollbarSize: 10, horizontalScrollbarSize: 10 },
    });
    state.editor.onDidChangeCursorSelection(() => updateSelectionFromEditor());
    return state.editor;
  }

  function setEditorContent(path, content, focusLine) {
    const monaco = window.monaco;
    if (!state.editor || !monaco) return;
    const lang = languageFromPath(path);
    const uri = monaco.Uri.parse("inmemory://vf-target/" + String(path || "file").replace(/\\/g, "/"));
    if (state.model) {
      try {
        state.model.dispose();
      } catch (_) {}
      state.model = null;
    }
    // Reuse URI if a stale model lingers
    const existing = monaco.editor.getModel(uri);
    if (existing) existing.dispose();
    state.model = monaco.editor.createModel(content || "", lang, uri);
    state.editor.setModel(state.model);
    state.decoIds = [];
    if (focusLine != null && Number(focusLine) > 0) {
      highlightFocusLine(Number(focusLine));
    }
  }

  function highlightFocusLine(line) {
    if (!state.editor || !window.monaco) return;
    const n = Math.max(1, Number(line) || 1);
    state.focusLine = n;
    state.decoIds = state.editor.deltaDecorations(state.decoIds || [], [
      {
        range: new window.monaco.Range(n, 1, n, 1),
        options: {
          isWholeLine: true,
          className: "vf-monaco-focus-line",
          linesDecorationsClassName: "vf-monaco-focus-glyph",
        },
      },
    ]);
    state.editor.revealLineInCenter(n);
    state.editor.setPosition({ lineNumber: n, column: 1 });
  }

  function updateSelectionFromEditor() {
    const meta = $("#explorer-sel-meta");
    if (!state.editor || !state.openFile) return;
    const sel = state.editor.getSelection();
    if (!sel || sel.isEmpty()) {
      state.selRange = null;
      if (meta)
        meta.textContent =
          "Whole file ready to hunt  -  or select lines for a tighter scope.";
      updateHuntButton();
      return;
    }
    const start = Math.min(sel.startLineNumber, sel.endLineNumber);
    const end = Math.max(sel.startLineNumber, sel.endLineNumber);
    state.selRange = { start_line: start, end_line: end };
    if (meta)
      meta.textContent = `Selection: lines ${start}-${end} in ${state.openFile}`;
    updateHuntButton();
  }

  function mount() {
    const el = $("#explorer-panel");
    if (!el) return;
    const prevClass = $("#explorer-hunt-class")?.value || "wildcard";
    const prevNotes = $("#explorer-op-notes")?.value || "";
    disposeEditor();

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
          <div class="code-view monaco-host" id="explorer-monaco" tabindex="0" role="region" aria-label="Target file viewer">Open a file from the tree...</div>
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

    state.mounted = true;
    state.treeLoaded = false;
    window.explorerMounted = true;
    window.explorerTreeLoaded = false;
    ensureEditor().then(() => {
      if (state.openFile) loadFile(state.openFile, state.focusLine);
    });
    loadTree();
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
      if (data.single_file && state.entries.length === 1 && !state.entries[0].is_dir) {
        const only = state.entries[0].name;
        if (!state.openFile || normalize(state.openFile) !== normalize(only)) {
          state.openFile = only;
          loadFile(only);
        }
      }
      renderTreeList();
      if (data.hint) state._targetHint = data.hint || "";
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
    const hintHtml = state._targetHint
      ? `<div class="controls-hint" style="padding:0.4rem 0.5rem;margin-bottom:0.25rem">${esc(state._targetHint)}</div>`
      : "";
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
    let html = hintHtml || "";
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
    state.focusLine = focusLine != null ? Number(focusLine) : null;
    window.explorerOpenFile = path;
    const label = $("#explorer-file-label");
    if (label) label.textContent = path;
    const host = $("#explorer-monaco");
    if (host && !state.editor) host.textContent = "Loading...";
    updateHuntButton();
    try {
      const data = await api(
        `${runApiBase()}/target/read?path=${encodeURIComponent(path)}`
      );
      const content = data.content || "";
      await ensureEditor();
      if (state.editor) {
        setEditorContent(path, content, state.focusLine);
      } else if (host) {
        // Fallback: plain pre if Monaco unavailable
        const lines = content.split("\n");
        const base = data.start_line || 1;
        host.innerHTML = `<pre class="code-view-fallback">${lines
          .map((ln, i) => {
            const n = base + i;
            return `<div class="code-line" data-line="${n}"><span class="ln">${n}</span><span class="tx">${esc(ln)}</span></div>`;
          })
          .join("")}</pre>`;
        if (state.focusLine != null) {
          const el = host.querySelector(`.code-line[data-line="${state.focusLine}"]`);
          el?.classList.add("sel-hl");
          el?.scrollIntoView({ block: "center" });
        }
      }
      const meta = $("#explorer-sel-meta");
      if (meta) {
        meta.textContent =
          "Whole file ready to hunt  -  or select lines for a tighter scope.";
      }
      renderTreeList();
      updateHuntButton();
    } catch (e) {
      if (host) host.textContent = e.message;
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
    updateSelectionFromEditor();
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

  window.mountExplorer = mount;
  window.renderExplorer = mount;
  window.loadExplorerTree = loadTree;
  window.loadExplorerFile = loadFile;
  window.loadArchTree = loadTree;
  window.loadArchFile = loadFile;

  function boot() {
    if (document.body?.dataset?.page !== "run") return;
    setTimeout(() => {
      const explorerMode = document.querySelector('.mode-panel[data-mode-panel="explorer"]');
      if (explorerMode?.classList.contains("active") || $("#explorer-panel")) {
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
