/*
 * Dev → Tools (VFPages.devTools). Read and configure only: the integrated
 * tool catalog plus per-stage default tool sets (config/default_tools.json).
 * Nothing here writes package source; that is the Tool lab.
 */
(function () {
  "use strict";
  if (document.body?.dataset?.page !== "dev") return;

  const H = window.DevHelpers;
  const U = window.DevUI;
  const { esc, api, fail, toast, pill } = U;

  const STAGE_LABEL = { recon: "Recon", hunt: "Hunt", develop_poc: "Develop PoC" };

  let root = null;
  let cat = null;
  /** Editable copy: stage → null (built-in) | string[] */
  let draft = {};
  let pickers = {};
  let openTool = null;
  let loaded = false;

  function mount(el) {
    root = el;
    root.innerHTML = `
      <div class="dev-section-head">
        <div>
          <h2 class="dev-h2">Tools</h2>
          <p class="dev-lede">What each stage's agent may call. Skill and agent allowlists narrow these further. Critical <code>submit_*</code> tools are always kept, and <code>code_static</code> never gets a shell.</p>
        </div>
      </div>
      <section class="vf-card dev-defaults">
        <header class="dev-card-head">
          <div><div class="vf-section-label">Stage defaults</div>
          <p class="dev-hint dev-defaults-meta"></p></div>
          <div class="dev-actions">
            <button type="button" class="vf-btn vf-btn--primary" data-act="save">Save defaults</button>
            <button type="button" class="vf-btn" data-act="reset">Reset all to built-in</button>
          </div>
        </header>
        <div class="dev-stage-grid"></div>
      </section>
      <section class="vf-card dev-catalog">
        <div class="vf-section-label">Integrated tools</div>
        <div class="table-wrap"><table class="dev-table">
          <thead><tr><th>Name</th><th>Stages</th><th>Source</th></tr></thead>
          <tbody></tbody>
        </table></div>
      </section>`;
    root.querySelector('[data-act="save"]').addEventListener("click", () => save().catch(fail));
    root.querySelector('[data-act="reset"]').addEventListener("click", () => reset().catch(fail));
  }

  function renderDefaults() {
    const grid = root.querySelector(".dev-stage-grid");
    pickers = {};
    grid.innerHTML = H.STAGES.map(
      (s) => `<div class="dev-stage"><h3 class="dev-h3">${esc(STAGE_LABEL[s])}</h3><div class="dev-chips" data-stage="${s}"></div></div>`
    ).join("");
    for (const s of H.STAGES) {
      const choices = H.toolChoices(cat.tools, s, cat.builtin[s]);
      const st = draft[s] == null ? { all: true, selected: [] } : { all: false, selected: draft[s] };
      const el = grid.querySelector(`[data-stage="${s}"]`);
      pickers[s] = U.chipPicker(el, { choices, state: st, editable: true, allLabel: "Built-in set" });
      el.addEventListener("input", () => {
        const v = pickers[s].get();
        draft[s] = v.all ? null : v.selected;
        U.setDirty("tools", true);
        renderMeta();
      });
    }
    renderMeta();
  }

  function renderMeta() {
    root.querySelector(".dev-defaults-meta").textContent = H.STAGES.map(
      (s) => `${STAGE_LABEL[s]}: ${draft[s] == null ? "built-in" : `${draft[s].length} tools`}`
    ).join(" · ");
  }

  function renderCatalog() {
    const tb = root.querySelector(".dev-catalog tbody");
    const tools = cat.tools || [];
    if (!tools.length) {
      tb.innerHTML = `<tr><td colspan="3" class="vf-empty">No tools.</td></tr>`;
      return;
    }
    tb.innerHTML = tools
      .map((t) => {
        const open = t.name === openTool;
        const row = `<tr class="dev-trow${open ? " is-open" : ""}" data-tool="${esc(t.name)}" tabindex="0" aria-expanded="${open}">
          <td class="vf-mono">${esc(t.name)}</td><td>${(t.stages || []).map((s) => `<span class="vf-chip dev-chip-static">${esc(s)}</span>`).join(" ")}</td>
          <td>${pill(t.source || "builtin", t.source && t.source !== "builtin" ? "review" : "")}</td></tr>`;
        if (!open) return row;
        const props = (t.parameters && t.parameters.properties) || {};
        const req = new Set((t.parameters && t.parameters.required) || []);
        const keys = Object.keys(props);
        const params = keys.length
          ? `<table class="dev-table dev-params"><thead><tr><th>Parameter</th><th>Type</th><th></th><th>Description</th></tr></thead><tbody>${keys
              .map((k) => {
                const p = props[k] || {};
                return `<tr><td class="vf-mono">${esc(k)}</td><td class="vf-mono vf-faint">${esc(p.type || "")}</td><td>${req.has(k) ? pill("required", "review") : ""}</td><td>${esc(p.description || "")}</td></tr>`;
              })
              .join("")}</tbody></table>`
          : `<div class="vf-empty">No parameters.</div>`;
        return `${row}<tr class="dev-tdetail"><td colspan="3"><p>${esc(t.description || "")}</p>${params}</td></tr>`;
      })
      .join("");
    tb.querySelectorAll("[data-tool]").forEach((tr) => {
      const toggle = () => {
        const n = tr.getAttribute("data-tool");
        openTool = openTool === n ? null : n;
        renderCatalog();
      };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggle();
        }
      });
    });
  }

  function apply(defaults) {
    draft = H.stageDefaultsPayload(defaults || {});
    U.setDirty("tools", false);
    renderDefaults();
  }

  async function load(force) {
    cat = await U.catalog(force);
    loaded = true;
    apply(cat.defaults);
    renderCatalog();
  }

  async function save() {
    const r = await api("/api/tools/defaults", { method: "PUT", body: JSON.stringify(H.stageDefaultsPayload(draft)) });
    toast("Default tools saved");
    U.catalog(true).catch(() => {});
    apply(r.defaults);
  }

  async function reset() {
    if (!confirm("Reset recon, hunt and develop_poc default tools to the built-in sets?")) return;
    const r = await api("/api/tools/defaults", {
      method: "PUT",
      body: JSON.stringify({ recon: null, hunt: null, develop_poc: null }),
    });
    toast("Defaults reset to built-in");
    U.catalog(true).catch(() => {});
    apply(r.defaults);
  }

  window.VFPages.devTools = {
    mount,
    render() {},
    onShow() {
      if (!loaded) load().catch(fail);
    },
    onHide() {},
    async reload() {
      await load(true);
    },
  };
})();
