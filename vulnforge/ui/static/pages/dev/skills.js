/*
 * Dev → Hunt skills (VFPages.devSkills). Operator collection in
 * config/hunt_profiles/. Read-only view by default; Edit to change.
 * Generate-from-brief modal owns the author prompt (config/prompts/generate_skill.md).
 */
(function () {
  "use strict";
  if (document.body?.dataset?.page !== "dev") return;

  const H = window.DevHelpers;
  const U = window.DevUI;
  const { esc, api, fail, toast, pill } = U;

  const NEW_BODY =
    "# Hunt class: my-class\n\n**Mission:** (describe the attacker goal)\n\n## Focus\n\n- \n\n## Method\n\n1. \n\n## Submit\n\n- `submit_candidate` with weakness_class matching this id\n- or honest `submit_none`\n";

  let root = null;
  let profiles = [];
  let filter = "all";
  let query = "";
  let selectedId = null;
  /** Full profile shown in the editor. */
  let current = null;
  /** "empty" | "view" | "edit" | "new" */
  let mode = "empty";
  let picker = null;
  let toolChoices = [];
  let diffOpen = false;
  let loaded = false;
  /** Unsaved edits in the open form. */
  let dirty = false;

  const $ = (sel) => root.querySelector(sel);

  function mount(el) {
    root = el;
    root.innerHTML = `
      <div class="dev-section-head">
        <div>
          <h2 class="dev-h2">Hunt skills</h2>
          <p class="dev-lede">Weakness classes that recon, Atlas, Campaign and file-by-file enqueue. <b>Active</b> skills are bulk-enqueued.</p>
        </div>
        <div class="dev-actions">
          <button type="button" class="vf-btn" data-act="new">New skill</button>
          <button type="button" class="vf-btn vf-btn--primary" data-act="generate">Generate from brief…</button>
          <details class="danger-menu dev-more">
            <summary class="vf-btn vf-btn--ghost" aria-label="More hunt skill actions">⋯</summary>
            <nav class="danger-menu-body">
              <button type="button" class="vf-menu-link dev-menu-btn" data-act="reseed">Reseed collection from package…</button>
            </nav>
          </details>
        </div>
      </div>
      <div class="vf-split dev-split">
        <aside class="vf-split-side vf-card dev-list-card">
          <div class="dev-filters" role="group" aria-label="Filter skills"></div>
          <input type="search" class="dev-search" placeholder="Search id or title" aria-label="Search skills" />
          <ul class="dev-list" role="listbox" aria-label="Hunt skills"></ul>
        </aside>
        <section class="vf-split-main vf-card dev-editor" aria-live="polite"></section>
      </div>`;
    root.querySelector('[data-act="new"]').addEventListener("click", () => guard() && openNew());
    root.querySelector('[data-act="generate"]').addEventListener("click", openGenerate);
    root.querySelector('[data-act="reseed"]').addEventListener("click", () => reseed().catch(fail));
    $(".dev-search").addEventListener("input", (e) => {
      query = e.target.value;
      renderList();
    });
    wireGenerateModal();
  }

  /* ---------- list ---------- */

  function renderFilters() {
    const counts = H.skillFilterCounts(profiles);
    const box = $(".dev-filters");
    box.innerHTML = H.SKILL_FILTERS.map(
      (f) =>
        `<button type="button" class="vf-chip" data-filter="${f.id}" aria-pressed="${filter === f.id}">${esc(f.label)} <span class="vf-faint">${counts[f.id]}</span></button>`
    ).join("");
    box.querySelectorAll("[data-filter]").forEach((b) =>
      b.addEventListener("click", () => {
        filter = b.getAttribute("data-filter");
        renderFilters();
        renderList();
      })
    );
  }

  function renderList() {
    const items = H.filterSkills(profiles, filter, query);
    U.renderList($(".dev-list"), {
      items,
      selectedId: mode === "new" ? null : selectedId,
      empty: profiles.length ? "No skills match this filter." : "No skills yet.",
      row: (p) => {
        const pv = H.provenance(p);
        return `<div class="dev-row-main"><span class="vf-mono dev-row-id">${esc(p.id)}</span><span class="dev-row-title">${esc(p.title || "")}</span></div>${pill(pv.label, pv.tone)}`;
      },
      onSelect: (id) => guard() && select(id),
      onToggle: (id, on, cb) => toggleActive(id, on, cb),
    });
  }

  async function toggleActive(id, on, cb) {
    try {
      await api(`/api/hunt-profiles/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify({ active: !!on }),
      });
      const p = profiles.find((x) => x.id === id);
      if (p) p.active = !!on;
      if (current && current.id === id) current.active = !!on;
      toast(on ? `Active: ${id}` : `Inactive: ${id}`);
      renderFilters();
      if (mode === "view" && current && current.id === id) renderEditor();
    } catch (e) {
      cb.checked = !on;
      fail(e);
    }
  }

  async function load(keepId) {
    const [data, cat] = await Promise.all([
      api("/api/hunt-profiles?include_body=0"),
      U.catalog().catch(() => null),
    ]);
    profiles = data.profiles || [];
    if (cat) toolChoices = H.toolChoices(cat.tools, "hunt", cat.builtin.hunt);
    loaded = true;
    renderFilters();
    if (keepId !== undefined) selectedId = keepId;
    if (selectedId && !profiles.some((p) => p.id === selectedId)) selectedId = null;
    renderList();
  }

  /* ---------- editor ---------- */

  async function select(id) {
    selectedId = id;
    diffOpen = false;
    U.setHash("skills", id);
    try {
      const data = await api(`/api/hunt-profiles/${encodeURIComponent(id)}`);
      current = data.profile || null;
      mode = current ? "view" : "empty";
    } catch (e) {
      current = null;
      mode = "empty";
      fail(e);
    }
    renderList();
    renderEditor();
  }

  function openNew(prefill) {
    selectedId = null;
    current = { id: "", title: "", description: "", active: false, tools: null, body_md: NEW_BODY, ...(prefill || {}) };
    mode = "new";
    diffOpen = false;
    U.setHash("skills", "");
    renderList();
    renderEditor();
    root.querySelector("#sk-id")?.focus();
  }

  function originHtml(p) {
    const tid = String(p.origin_target_id || "").trim();
    const rid = String(p.origin_run_id || "").trim();
    if (!tid || !rid) return "";
    const href = `/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}`;
    return ` · origin <a class="vf-mono" href="${esc(href)}">${esc(tid)} / ${esc(rid)}</a>`;
  }

  function renderEditor() {
    const box = $(".dev-editor");
    U.setDirty("skills", false);
    dirty = false;
    picker = null;
    if (mode === "empty" || !current) {
      box.innerHTML = `<div class="vf-empty dev-editor-empty">Select a skill, or create one with <b>New skill</b> / <b>Generate from brief</b>.</div>`;
      return;
    }
    const p = current;
    const tools = H.allowlistState(p.tools);
    if (mode === "view") {
      const pv = H.provenance(p);
      const hasSeed = !!p.has_seed || ["seed", "modified_seed"].includes(String(p.seed_status || ""));
      box.innerHTML = `
        <header class="dev-ed-head">
          <div class="dev-ed-title">
            <h3 class="vf-mono">${esc(p.id)}</h3>
            <p>${esc(p.title || "")}</p>
            <div class="dev-ed-meta">${pill(pv.label, pv.tone)} ${p.active ? pill("active", "confirmed") : pill("inactive", "rejected")}<span class="vf-faint">${originHtml(p)}</span></div>
          </div>
          <div class="dev-actions">
            <button type="button" class="vf-btn vf-btn--primary" data-act="edit">Edit</button>
            ${hasSeed ? `<button type="button" class="vf-btn" data-act="diff" aria-expanded="${diffOpen}">Diff vs seed</button>` : ""}
            ${hasSeed ? `<button type="button" class="vf-btn" data-act="restore">Restore seed body</button>` : ""}
            <button type="button" class="vf-btn vf-btn--danger" data-act="delete">Delete</button>
          </div>
        </header>
        <div class="dev-diff-wrap" ${diffOpen ? "" : "hidden"}></div>
        <dl class="dev-dl">
          <dt>Description</dt><dd>${p.description ? esc(p.description) : '<span class="vf-faint">None</span>'}</dd>
          <dt>Approved tools</dt><dd class="dev-chips"></dd>
        </dl>
        <div class="vf-section-label">Markdown body</div>
        <pre class="dev-md vf-mono">${esc(p.body_md || "")}</pre>`;
      U.chipPicker(box.querySelector(".dev-chips"), {
        choices: toolChoices,
        state: tools,
        editable: false,
        allLabel: "All hunt tools (default set)",
      });
      box.querySelector('[data-act="edit"]').addEventListener("click", () => {
        mode = "edit";
        renderEditor();
      });
      box.querySelector('[data-act="delete"]').addEventListener("click", () => remove().catch(fail));
      box.querySelector('[data-act="diff"]')?.addEventListener("click", () => toggleDiff().catch(fail));
      box.querySelector('[data-act="restore"]')?.addEventListener("click", () => restoreSeed().catch(fail));
      if (diffOpen) toggleDiff(true).catch(fail);
      return;
    }
    // edit / new
    const isNew = mode === "new";
    box.innerHTML = `
      <form class="dev-form" novalidate>
        <header class="dev-ed-head">
          <div class="dev-ed-title"><h3>${isNew ? "New skill" : `Editing <span class="vf-mono">${esc(p.id)}</span>`}</h3>
          <p class="vf-faint">Changes apply to new hunt tasks.</p></div>
          <div class="dev-actions">
            <button type="submit" class="vf-btn vf-btn--primary">Save</button>
            <button type="button" class="vf-btn" data-act="cancel">Cancel</button>
          </div>
        </header>
        <div class="dev-grid2">
          <label class="dev-field"><span class="vf-section-label">Skill id</span>
            <input id="sk-id" class="vf-mono" value="${esc(p.id)}" ${isNew ? "" : "readonly"} pattern="[a-z][a-z0-9-]{0,63}" autocomplete="off" spellcheck="false" placeholder="my-class" /></label>
          <label class="dev-field"><span class="vf-section-label">Title</span>
            <input id="sk-title" value="${esc(p.title || "")}" autocomplete="off" /></label>
        </div>
        <label class="dev-field"><span class="vf-section-label">Description</span>
          <input id="sk-desc" value="${esc(p.description || "")}" autocomplete="off" placeholder="Short operator blurb" /></label>
        <label class="dev-check"><input type="checkbox" id="sk-active" ${p.active ? "checked" : ""} /> Active (bulk enqueue)</label>
        <div class="dev-field"><span class="vf-section-label">Approved tools</span>
          <p class="dev-hint">The default set, or only the chosen tools. <code>submit_candidate</code> and <code>submit_none</code> are always kept.</p>
          <div class="dev-chips" id="sk-tools"></div></div>
        <label class="dev-field"><span class="vf-section-label">Markdown body</span>
          <textarea id="sk-body" class="dev-textarea vf-mono" rows="20" spellcheck="false">${esc(p.body_md || "")}</textarea></label>
      </form>`;
    picker = U.chipPicker(box.querySelector("#sk-tools"), {
      choices: toolChoices,
      state: tools,
      editable: true,
      allLabel: "All hunt tools",
    });
    const form = box.querySelector("form");
    // chipPicker dispatches bubbling "input" too
    form.addEventListener("input", () => {
      dirty = true;
      U.setDirty("skills", true);
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
        if (selectedId) select(selectedId);
        else renderEditor();
      } else {
        mode = "view";
        renderEditor();
      }
    });
  }

  /** Confirm discarding unsaved edits. */
  function guard() {
    if ((mode !== "edit" && mode !== "new") || !dirty) return true;
    return confirm("Discard unsaved changes to this skill?");
  }

  async function save() {
    const isNew = mode === "new";
    const id = (root.querySelector("#sk-id").value || "").trim().toLowerCase();
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(id)) {
      toast("Skill id must be a lowercase slug (a-z, 0-9, -)", true);
      return;
    }
    const body = root.querySelector("#sk-body").value || "";
    if (!body.trim()) {
      toast("Markdown body is required", true);
      return;
    }
    const t = picker.get();
    const payload = {
      title: root.querySelector("#sk-title").value.trim(),
      description: root.querySelector("#sk-desc").value.trim(),
      active: root.querySelector("#sk-active").checked,
      body_md: body,
      ...H.huntToolsPayload(t.all, t.selected),
    };
    if (isNew) {
      await api("/api/hunt-profiles", { method: "POST", body: JSON.stringify({ id, ...payload }) });
      toast(`Created ${id}`);
    } else {
      await api(`/api/hunt-profiles/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(payload) });
      toast(`Saved ${id}`);
    }
    U.setDirty("skills", false);
    dirty = false;
    await load(id);
    await select(id);
  }

  async function remove() {
    const id = current && current.id;
    if (!id || !confirm(`Delete hunt skill "${id}"? This cannot be undone.`)) return;
    await api(`/api/hunt-profiles/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast(`Deleted ${id}`);
    current = null;
    mode = "empty";
    selectedId = null;
    U.setHash("skills", "");
    await load(null);
    renderEditor();
  }

  async function toggleDiff(keepOpen) {
    const wrap = root.querySelector(".dev-diff-wrap");
    const btn = root.querySelector('[data-act="diff"]');
    if (!keepOpen) diffOpen = !diffOpen;
    if (btn) btn.setAttribute("aria-expanded", String(diffOpen));
    if (!wrap) return;
    wrap.hidden = !diffOpen;
    if (!diffOpen) return;
    wrap.innerHTML = `<div class="vf-empty">Loading seed…</div>`;
    const d = await api(`/api/hunt-profiles/${encodeURIComponent(current.id)}/seed-diff`);
    if (!d.has_seed) {
      wrap.innerHTML = `<div class="vf-empty">No package seed for this skill.</div>`;
      return;
    }
    const lines = H.lineDiff(d.seed_body || "", d.current_body || "");
    const st = H.diffStats(lines);
    const rows = lines.map((l) => ({ kind: l.op === "+" ? "add" : l.op === "-" ? "del" : "ctx", text: `${l.op} ${l.text}` }));
    wrap.innerHTML = `<div class="dev-diff-head"><span class="vf-section-label">Package seed → current</span>
      <span class="vf-faint">${st.same ? "Identical to the package seed." : `+${st.added} −${st.removed} lines`}</span></div>
      ${st.same ? "" : U.diffHtml(rows)}`;
  }

  async function restoreSeed() {
    const id = current && current.id;
    if (!id || !confirm(`Restore the body of "${id}" from the package seed library?`)) return;
    const r = await api(`/api/hunt-profiles/${encodeURIComponent(id)}/restore-seed`, { method: "POST", body: "{}" });
    toast(`Restored seed body: ${id}`);
    await load(id);
    if (r && r.profile) {
      current = r.profile;
      mode = "view";
      renderEditor();
    } else {
      await select(id);
    }
  }

  async function reseed() {
    root.querySelector(".dev-more")?.removeAttribute("open");
    if (
      !confirm(
        "Replace the entire hunt collection with the package seed library?\n\nCustom and generated skills are removed. Export setup first if you need them."
      )
    )
      return;
    const r = await api("/api/hunt-profiles/reseed", { method: "POST", body: "{}" });
    toast(`Reseeded ${r.count || 0} skills`);
    current = null;
    mode = "empty";
    selectedId = null;
    await load(null);
    renderEditor();
  }

  /* ---------- generate + author prompt ---------- */

  function wireGenerateModal() {
    const m = document.getElementById("dev-generate-modal");
    if (!m) return;
    m.querySelector("#gen-cancel").addEventListener("click", () => U.closeModal("dev-generate-modal"));
    m.querySelector("#gen-submit").addEventListener("click", () => submitGenerate().catch(fail));
    const det = m.querySelector("#gen-author");
    det.addEventListener("toggle", () => {
      if (det.open) loadAuthorPrompt().catch(fail);
    });
    m.querySelector("#gen-author-save").addEventListener("click", () => saveAuthorPrompt().catch(fail));
    m.querySelector("#gen-author-reset").addEventListener("click", () => resetAuthorPrompt().catch(fail));
  }

  function openGenerate() {
    const m = document.getElementById("dev-generate-modal");
    m.querySelector("#gen-brief").value = "";
    m.querySelector("#gen-id").value = "";
    m.querySelector("#gen-active").checked = false;
    m.querySelector("#gen-save").checked = true;
    U.openModal("dev-generate-modal");
    m.querySelector("#gen-brief").focus();
  }

  async function submitGenerate() {
    const m = document.getElementById("dev-generate-modal");
    const brief = m.querySelector("#gen-brief").value.trim();
    if (!brief) {
      toast("Describe the hunt skill first", true);
      return;
    }
    const activate = m.querySelector("#gen-active").checked;
    const save = m.querySelector("#gen-save").checked;
    const r = await U.busy(m.querySelector("#gen-submit"), "Generating…", () =>
      api("/api/hunt-profiles/generate", {
        method: "POST",
        body: JSON.stringify({ brief, suggested_id: m.querySelector("#gen-id").value.trim() || null, activate, save }),
      })
    );
    U.closeModal("dev-generate-modal");
    const skill = r.skill || {};
    const pid = skill.id || (r.profile && r.profile.id);
    if (r.saved && pid) {
      toast(`Generated and saved ${pid}`);
      filter = "all";
      await load(pid);
      await select(pid);
    } else {
      toast(`Generated ${pid || "skill"}. Review, then Save.`);
      openNew({
        id: skill.id || "",
        title: skill.title || "",
        description: skill.description || "",
        active: activate,
        body_md: skill.body_md || "",
        source: "generated",
      });
    }
  }

  async function loadAuthorPrompt() {
    const d = await api("/api/skill-generator");
    const m = document.getElementById("dev-generate-modal");
    m.querySelector("#gen-author-body").value = d.body_md || "";
    const src = d.source || "package";
    const p = d.has_override ? d.path : d.package_path || d.path;
    m.querySelector("#gen-author-meta").textContent =
      (src === "override" ? "Operator override" : src === "fallback" ? "Built-in fallback" : "Package seed") + (p ? ` · ${p}` : "");
  }

  async function saveAuthorPrompt() {
    const m = document.getElementById("dev-generate-modal");
    const body = m.querySelector("#gen-author-body").value;
    if (!body.trim()) {
      toast("Author prompt is empty", true);
      return;
    }
    await api("/api/skill-generator", { method: "PUT", body: JSON.stringify({ body_md: body }) });
    toast("Author prompt saved");
    await loadAuthorPrompt();
  }

  async function resetAuthorPrompt() {
    if (!confirm("Reset the author prompt to the package seed? Your override is removed.")) return;
    await api("/api/skill-generator/reseed", { method: "POST", body: "{}" });
    toast("Author prompt reset to package");
    await loadAuthorPrompt();
  }

  /* ---------- page contract ---------- */

  async function onShow(id) {
    try {
      if (!loaded) await load();
      if (id && id !== selectedId) {
        if (guard()) await select(id);
      } else if (!current && mode !== "new") {
        const first = H.filterSkills(profiles, filter, query)[0];
        if (first) await select(first.id);
        else renderEditor();
      } else if (selectedId) {
        U.setHash("skills", selectedId);
      }
    } catch (e) {
      fail(e);
    }
  }

  window.VFPages.devSkills = {
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
