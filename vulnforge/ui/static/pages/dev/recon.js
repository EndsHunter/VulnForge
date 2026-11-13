/*
 * Dev → Recon agents (VFPages.devRecon). Collection in config/recon_agents/.
 * Active agents run in `order` on every recon. Read-only view; Edit to change.
 */
(function () {
  "use strict";
  if (document.body?.dataset?.page !== "dev") return;

  const H = window.DevHelpers;
  const U = window.DevUI;
  const { esc, api, fail, toast, pill } = U;

  const NEW_BODY =
    "# Recon agent: my-agent\n\n**Mission:** (describe the recon goal)\n\n## Method\n\n1. \n\n## Anti-patterns\n\n- \n\n## Submit checklist\n\n- `submit_architecture` with a non-empty summary\n";

  let root = null;
  let agents = [];
  let selectedId = null;
  let current = null;
  /** "empty" | "view" | "edit" | "new" */
  let mode = "empty";
  let picker = null;
  let toolChoices = [];
  let loaded = false;
  let dirty = false;

  const $ = (sel) => root.querySelector(sel);
  const numStr = (v) => (v === undefined || v === null ? "" : String(v));

  function mount(el) {
    root = el;
    root.innerHTML = `
      <div class="dev-section-head">
        <div>
          <h2 class="dev-h2">Recon agents</h2>
          <p class="dev-lede">Specialists that map the target after the mechanical inventory. <b>Active</b> agents run in list order on every recon.</p>
        </div>
        <div class="dev-actions">
          <button type="button" class="vf-btn" data-act="new">New agent</button>
          <details class="danger-menu dev-more">
            <summary class="vf-btn vf-btn--ghost" aria-label="More recon agent actions">⋯</summary>
            <nav class="danger-menu-body">
              <button type="button" class="vf-menu-link dev-menu-btn" data-act="reseed">Reseed collection from package…</button>
            </nav>
          </details>
        </div>
      </div>
      <div class="vf-split dev-split">
        <aside class="vf-split-side vf-card dev-list-card">
          <div class="vf-section-label">Run order</div>
          <ul class="dev-list" role="listbox" aria-label="Recon agents"></ul>
        </aside>
        <section class="vf-split-main vf-card dev-editor" aria-live="polite"></section>
      </div>`;
    root.querySelector('[data-act="new"]').addEventListener("click", () => guard() && openNew());
    root.querySelector('[data-act="reseed"]').addEventListener("click", () => reseed().catch(fail));
  }

  function guard() {
    if ((mode !== "edit" && mode !== "new") || !dirty) return true;
    return confirm("Discard unsaved changes to this agent?");
  }

  function renderList() {
    U.renderList($(".dev-list"), {
      items: agents,
      selectedId: mode === "new" ? null : selectedId,
      empty: "No recon agents.",
      row: (a) =>
        `<span class="dev-row-order vf-mono">${esc(numStr(a.order))}</span><div class="dev-row-main"><span class="vf-mono dev-row-id">${esc(a.id)}</span><span class="dev-row-title">${esc(a.title || "")}</span></div>${pill(a.source || "custom", a.source === "seed" ? "" : "candidate")}`,
      onSelect: (id) => guard() && select(id),
      onToggle: (id, on, cb) => toggleActive(id, on, cb),
    });
  }

  async function toggleActive(id, on, cb) {
    try {
      await api(`/api/recon-agents/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify({ active: !!on }) });
      const a = agents.find((x) => x.id === id);
      if (a) a.active = !!on;
      if (current && current.id === id) current.active = !!on;
      toast(on ? `Active: ${id}` : `Inactive: ${id}`);
      if (mode === "view" && current && current.id === id) renderEditor();
    } catch (e) {
      cb.checked = !on;
      fail(e);
    }
  }

  async function load(keepId) {
    const [data, cat] = await Promise.all([api("/api/recon-agents?include_body=0"), U.catalog().catch(() => null)]);
    agents = H.sortAgents(data.agents || []);
    if (cat) toolChoices = H.toolChoices(cat.tools, "recon", cat.builtin.recon);
    loaded = true;
    if (keepId !== undefined) selectedId = keepId;
    if (selectedId && !agents.some((a) => a.id === selectedId)) selectedId = null;
    renderList();
  }

  async function select(id) {
    selectedId = id;
    U.setHash("recon", id);
    try {
      const d = await api(`/api/recon-agents/${encodeURIComponent(id)}`);
      current = d.agent || null;
      mode = current ? "view" : "empty";
    } catch (e) {
      current = null;
      mode = "empty";
      fail(e);
    }
    renderList();
    renderEditor();
  }

  function openNew() {
    selectedId = null;
    const maxOrder = agents.reduce((m, a) => Math.max(m, Number(a.order) || 0), 0);
    current = { id: "", title: "", description: "", active: false, order: maxOrder + 10, tools: null, body_md: NEW_BODY };
    mode = "new";
    U.setHash("recon", "");
    renderList();
    renderEditor();
    root.querySelector("#ra-id")?.focus();
  }

  function renderEditor() {
    const box = $(".dev-editor");
    dirty = false;
    U.setDirty("recon", false);
    picker = null;
    if (mode === "empty" || !current) {
      box.innerHTML = `<div class="vf-empty dev-editor-empty">Select an agent, or create one with <b>New agent</b>.</div>`;
      return;
    }
    const a = current;
    const tools = H.allowlistState(a.tools);
    if (mode === "view") {
      box.innerHTML = `
        <header class="dev-ed-head">
          <div class="dev-ed-title">
            <h3 class="vf-mono">${esc(a.id)}</h3>
            <p>${esc(a.title || "")}</p>
            <div class="dev-ed-meta">${pill(a.source || "custom", a.source === "seed" ? "" : "candidate")} ${a.active ? pill("active", "confirmed") : pill("inactive", "rejected")}</div>
          </div>
          <div class="dev-actions">
            <button type="button" class="vf-btn vf-btn--primary" data-act="edit">Edit</button>
            <button type="button" class="vf-btn vf-btn--danger" data-act="delete">Delete</button>
          </div>
        </header>
        <dl class="dev-dl">
          <dt>Description</dt><dd>${a.description ? esc(a.description) : '<span class="vf-faint">None</span>'}</dd>
          <dt>Order</dt><dd class="vf-mono">${esc(numStr(a.order))}</dd>
          <dt>Temperature</dt><dd class="vf-mono">${a.temperature != null ? esc(a.temperature) : '<span class="vf-faint">config default</span>'}</dd>
          <dt>Max tool rounds</dt><dd class="vf-mono">${a.max_tool_rounds != null ? esc(a.max_tool_rounds) : '<span class="vf-faint">config default</span>'}</dd>
          <dt>Tools</dt><dd class="dev-chips"></dd>
        </dl>
        <div class="vf-section-label">Markdown body</div>
        <pre class="dev-md vf-mono">${esc(a.body_md || "")}</pre>`;
      U.chipPicker(box.querySelector(".dev-chips"), { choices: toolChoices, state: tools, editable: false, allLabel: "All recon tools (default set)" });
      box.querySelector('[data-act="edit"]').addEventListener("click", () => {
        mode = "edit";
        renderEditor();
      });
      box.querySelector('[data-act="delete"]').addEventListener("click", () => remove().catch(fail));
      return;
    }
    const isNew = mode === "new";
    box.innerHTML = `
      <form class="dev-form" novalidate>
        <header class="dev-ed-head">
          <div class="dev-ed-title"><h3>${isNew ? "New agent" : `Editing <span class="vf-mono">${esc(a.id)}</span>`}</h3>
          <p class="vf-faint">Changes apply to the next recon.</p></div>
          <div class="dev-actions">
            <button type="submit" class="vf-btn vf-btn--primary">Save</button>
            <button type="button" class="vf-btn" data-act="cancel">Cancel</button>
          </div>
        </header>
        <div class="dev-grid2">
          <label class="dev-field"><span class="vf-section-label">Agent id</span>
            <input id="ra-id" class="vf-mono" value="${esc(a.id)}" ${isNew ? "" : "readonly"} autocomplete="off" spellcheck="false" placeholder="my-agent" /></label>
          <label class="dev-field"><span class="vf-section-label">Title</span>
            <input id="ra-title" value="${esc(a.title || "")}" autocomplete="off" /></label>
        </div>
        <label class="dev-field"><span class="vf-section-label">Description</span>
          <input id="ra-desc" value="${esc(a.description || "")}" autocomplete="off" placeholder="Short operator blurb" /></label>
        <div class="dev-grid3">
          <label class="dev-field"><span class="vf-section-label">Order</span>
            <input id="ra-order" type="number" step="1" value="${esc(numStr(a.order))}" /></label>
          <label class="dev-field"><span class="vf-section-label">Temperature</span>
            <input id="ra-temp" type="number" step="0.05" min="0" max="2" value="${esc(numStr(a.temperature))}" placeholder="config default" /></label>
          <label class="dev-field"><span class="vf-section-label">Max tool rounds</span>
            <input id="ra-rounds" type="number" step="1" min="1" value="${esc(numStr(a.max_tool_rounds))}" placeholder="config default" /></label>
        </div>
        <label class="dev-check"><input type="checkbox" id="ra-active" ${a.active ? "checked" : ""} /> Active (runs on recon)</label>
        <div class="dev-field"><span class="vf-section-label">Tools</span>
          <p class="dev-hint">The default recon set, or only the chosen tools. <code>submit_architecture</code> is always kept.</p>
          <div class="dev-chips" id="ra-tools"></div></div>
        <label class="dev-field"><span class="vf-section-label">Markdown body</span>
          <textarea id="ra-body" class="dev-textarea vf-mono" rows="20" spellcheck="false">${esc(a.body_md || "")}</textarea></label>
      </form>`;
    picker = U.chipPicker(box.querySelector("#ra-tools"), { choices: toolChoices, state: tools, editable: true, allLabel: "All recon tools" });
    const form = box.querySelector("form");
    form.addEventListener("input", () => {
      dirty = true;
      U.setDirty("recon", true);
    });
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      save().catch(fail);
    });
    box.querySelector('[data-act="cancel"]').addEventListener("click", () => {
      if (!guard()) return;
      if (isNew) {
        current = null;
        mode = "empty";
      } else {
        mode = "view";
      }
      renderEditor();
    });
  }

  async function save() {
    const isNew = mode === "new";
    const v = (sel) => root.querySelector(sel).value;
    const id = v("#ra-id").trim().toLowerCase();
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(id)) {
      toast("Agent id must be a lowercase slug (a-z, 0-9, -)", true);
      return;
    }
    if (!v("#ra-body").trim()) {
      toast("Markdown body is required", true);
      return;
    }
    const t = picker.get();
    const payload = H.reconPayload({
      title: v("#ra-title"),
      description: v("#ra-desc"),
      active: root.querySelector("#ra-active").checked,
      body_md: v("#ra-body"),
      order: v("#ra-order"),
      temperature: v("#ra-temp"),
      max_tool_rounds: v("#ra-rounds"),
      allTools: t.all,
      tools: t.selected,
    });
    if (isNew) {
      await api("/api/recon-agents", { method: "POST", body: JSON.stringify({ id, mode: "sequential", ...payload }) });
      toast(`Created ${id}`);
    } else {
      await api(`/api/recon-agents/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(payload) });
      toast(`Saved ${id}`);
    }
    dirty = false;
    U.setDirty("recon", false);
    await load(id);
    await select(id);
  }

  async function remove() {
    const id = current && current.id;
    if (!id || !confirm(`Delete recon agent "${id}"? This cannot be undone.`)) return;
    await api(`/api/recon-agents/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast(`Deleted ${id}`);
    current = null;
    mode = "empty";
    U.setHash("recon", "");
    await load(null);
    renderEditor();
  }

  async function reseed() {
    root.querySelector(".dev-more")?.removeAttribute("open");
    if (!confirm("Replace the entire recon agent collection with the package seed library?\n\nExport setup first if you have custom agents.")) return;
    const r = await api("/api/recon-agents/reseed", { method: "POST", body: "{}" });
    toast(`Reseeded ${r.count || 0} agents`);
    current = null;
    mode = "empty";
    await load(null);
    renderEditor();
  }

  async function onShow(id) {
    try {
      if (!loaded) await load();
      if (id && id !== selectedId) {
        if (guard()) await select(id);
      } else if (!current && mode !== "new") {
        if (agents[0]) await select(agents[0].id);
        else renderEditor();
      } else if (selectedId) {
        U.setHash("recon", selectedId);
      }
    } catch (e) {
      fail(e);
    }
  }

  window.VFPages.devRecon = {
    mount,
    render() {},
    onShow,
    onHide() {},
    async reload() {
      await load(selectedId);
      if (selectedId && mode === "view") await select(selectedId);
    },
  };
})();
