/* Dev dashboard: hunt profiles + recon agents editors */
(function () {
  if (document.body?.dataset?.page !== "dev") return;

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  let profiles = [];
  let selectedId = null;
  let isNew = false;

  let agents = [];
  let raSelectedId = null;
  let raIsNew = false;
  let raLoaded = false;

  let catalogTools = [];
  let toolDrafts = [];
  let toolsLoaded = false;
  let selectedToolName = null;
  let selectedDraftId = null;
  let wizardDraftId = null;
  let wizardStep = 1;

  let sgLoaded = false;

  async function api(path, opts) {
    if (typeof window.api === "function") return window.api(path, opts);
    const r = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(opts?.headers || {}) },
      ...opts,
    });
    if (!r.ok) {
      let msg = r.statusText;
      try {
        const j = await r.json();
        msg = j.detail || j.error || msg;
      } catch (_) {}
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    if (r.status === 204) return null;
    return r.json();
  }

  function toast(msg, bad) {
    if (typeof window.toast === "function") return window.toast(msg, bad);
    console.log(bad ? "ERR" : "OK", msg);
  }

  function esc(s) {
    if (typeof window.esc === "function") return window.esc(s);
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ---------- Tabs ---------- */

  function switchTab(name) {
    $$("[data-dev-tab]").forEach((btn) => {
      const on = btn.getAttribute("data-dev-tab") === name;
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-selected", on ? "true" : "false");
    });
    $$("[data-dev-panel]").forEach((panel) => {
      const on = panel.getAttribute("data-dev-panel") === name;
      panel.classList.toggle("active", on);
      if (on) panel.hidden = false;
      else panel.hidden = true;
    });
    if (name === "recon" && !raLoaded) {
      loadAgents().catch((e) => toast(e.message || String(e), true));
    }
    if (name === "skillgen" && !sgLoaded) {
      loadSkillGenerator().catch((e) => toast(e.message || String(e), true));
    }
    if (name === "tools" && !toolsLoaded) {
      loadToolsPanel().catch((e) => toast(e.message || String(e), true));
    }
  }

  $$("[data-dev-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const name = btn.getAttribute("data-dev-tab");
      if (name) switchTab(name);
    });
  });

  /* ---------- Hunt profiles ---------- */

  function renderList() {
    const body = $("#dev-profiles-body");
    const meta = $("#dev-meta");
    if (!body) return;
    if (!profiles.length) {
      body.innerHTML = `<tr><td colspan="4" class="empty">No profiles</td></tr>`;
      if (meta) meta.textContent = "";
      return;
    }
    const nActive = profiles.filter((p) => p.active).length;
    if (meta) meta.textContent = `${profiles.length} profiles · ${nActive} active`;
    body.innerHTML = profiles
      .map((p) => {
        const sel = p.id === selectedId ? " is-selected" : "";
        return `<tr class="dev-row${sel}" data-id="${esc(p.id)}" style="cursor:pointer">
          <td><input type="checkbox" data-active-toggle value="${esc(p.id)}" ${p.active ? "checked" : ""} title="Active for bulk enqueue" /></td>
          <td class="mono">${esc(p.id)}</td>
          <td>${esc(p.title || p.id)}</td>
          <td><span class="badge info">${esc(p.source || "custom")}</span></td>
        </tr>`;
      })
      .join("");

    body.querySelectorAll(".dev-row").forEach((row) => {
      row.addEventListener("click", (ev) => {
        if (ev.target?.matches?.("[data-active-toggle]")) return;
        const id = row.getAttribute("data-id");
        if (id) selectProfile(id);
      });
    });
    body.querySelectorAll("[data-active-toggle]").forEach((inp) => {
      inp.addEventListener("change", async (ev) => {
        ev.stopPropagation();
        const id = inp.value;
        try {
          await api(`/api/hunt-profiles/${encodeURIComponent(id)}`, {
            method: "PUT",
            body: JSON.stringify({ active: !!inp.checked }),
          });
          toast(inp.checked ? `Active: ${id}` : `Inactive: ${id}`);
          await loadProfiles(selectedId);
        } catch (e) {
          toast(e.message || String(e), true);
          inp.checked = !inp.checked;
        }
      });
    });
  }

  function ensureHuntToolChecks() {
    const box = $("#dev-tools-checks");
    if (!box || box.dataset.ready === "1") return;
    const names = (catalogTools.length
      ? catalogTools.map((t) => t.name)
      : [
          "list_dir",
          "file_inventory",
          "read_file",
          "grep",
          "write_evidence",
          "note",
          "submit_candidate",
          "submit_none",
        ]
    ).filter((n) => !String(n).startsWith("submit_") || n === "submit_candidate" || n === "submit_none");
    // Offer non-submit tools primarily; submit always kept at runtime
    const pick = names.filter((n) => !String(n).startsWith("submit_"));
    box.innerHTML = pick
      .map(
        (n) =>
          `<label class="init-check"><input type="checkbox" class="dev-tool-cb" value="${esc(n)}" /> <span class="mono">${esc(n)}</span></label>`
      )
      .join("");
    box.dataset.ready = "1";
  }

  function setHuntToolsUI(tools) {
    ensureHuntToolChecks();
    const unrestricted = $("#dev-tools-unrestricted");
    const hasList = Array.isArray(tools) && tools.length > 0;
    if (unrestricted) unrestricted.checked = !hasList;
    $$(".dev-tool-cb").forEach((cb) => {
      cb.checked = hasList ? tools.includes(cb.value) : false;
      cb.disabled = !hasList;
    });
  }

  function getHuntToolsPayload() {
    const unrestricted = $("#dev-tools-unrestricted");
    if (unrestricted?.checked) {
      return { clear_tools: true, tools: null };
    }
    const selected = $$(".dev-tool-cb")
      .filter((cb) => cb.checked)
      .map((cb) => cb.value);
    return { clear_tools: false, tools: selected };
  }

  function showEditor(profile, { create } = {}) {
    isNew = !!create;
    const form = $("#dev-editor-form");
    const hint = $("#dev-editor-hint");
    const title = $("#dev-editor-title");
    if (!form) return;
    form.hidden = false;
    if (hint) hint.hidden = true;
    if (title) title.textContent = create ? "New profile" : `Edit: ${profile.id}`;
    const idEl = $("#dev-id");
    idEl.value = profile.id || "";
    idEl.readOnly = !create;
    $("#dev-title").value = profile.title || "";
    $("#dev-description").value = profile.description || "";
    $("#dev-active").checked = !!profile.active;
    $("#dev-body").value = profile.body_md || "";
    $("#dev-delete").hidden = !!create;
    setHuntToolsUI(profile.tools);
  }

  async function selectProfile(id) {
    selectedId = id;
    isNew = false;
    renderList();
    try {
      const data = await api(`/api/hunt-profiles/${encodeURIComponent(id)}`);
      showEditor(data.profile || {}, { create: false });
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function loadProfiles(keepId) {
    const data = await api("/api/hunt-profiles?include_body=0");
    profiles = data.profiles || [];
    if (keepId && profiles.some((p) => p.id === keepId)) {
      selectedId = keepId;
    } else if (selectedId && !profiles.some((p) => p.id === selectedId)) {
      selectedId = profiles[0]?.id || null;
    } else if (!selectedId && profiles[0]) {
      selectedId = profiles[0].id;
    }
    renderList();
    if (selectedId && !isNew) {
      await selectProfile(selectedId);
    }
  }

  function openNew() {
    selectedId = null;
    isNew = true;
    renderList();
    showEditor(
      {
        id: "",
        title: "",
        description: "",
        active: false,
        body_md:
          "# Hunt class: my-class\n\n**Mission:** (describe the attacker goal)\n\n## Focus\n\n- \n\n## Method\n\n1. \n\n## Submit\n\n- `submit_candidate` with weakness_class matching this id\n- or honest `submit_none`\n",
      },
      { create: true }
    );
    $("#dev-id")?.focus();
  }

  async function saveForm(ev) {
    ev.preventDefault();
    const id = ($("#dev-id").value || "").trim().toLowerCase();
    const toolsPart = getHuntToolsPayload();
    const payload = {
      title: ($("#dev-title").value || "").trim(),
      description: ($("#dev-description").value || "").trim(),
      active: !!$("#dev-active").checked,
      body_md: $("#dev-body").value || "",
      clear_tools: !!toolsPart.clear_tools,
      tools: toolsPart.tools,
    };
    try {
      if (isNew) {
        payload.id = id;
        await api("/api/hunt-profiles", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast(`Created ${id}`);
      } else {
        await api(`/api/hunt-profiles/${encodeURIComponent(id)}`, {
          method: "PUT",
          body: JSON.stringify(payload),
        });
        toast(`Saved ${id}`);
      }
      isNew = false;
      selectedId = id;
      await loadProfiles(id);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function deleteCurrent() {
    const id = ($("#dev-id").value || "").trim();
    if (!id || isNew) return;
    if (!confirm(`Delete hunt profile "${id}"? This cannot be undone.`)) return;
    try {
      await api(`/api/hunt-profiles/${encodeURIComponent(id)}`, { method: "DELETE" });
      toast(`Deleted ${id}`);
      selectedId = null;
      isNew = false;
      $("#dev-editor-form").hidden = true;
      $("#dev-editor-hint").hidden = false;
      await loadProfiles();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function exportDevSetup() {
    try {
      const data = await api("/api/dev-setup/export");
      const blob = new Blob([JSON.stringify(data, null, 2) + "\n"], {
        type: "application/json",
      });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "vulnforge_dev_setup.json";
      a.click();
      URL.revokeObjectURL(a.href);
      const s = data.summary || {};
      toast(
        `Exported setup: ${s.hunt_profiles ?? "?"} hunts · ${s.recon_agents ?? "?"} recon · ${s.tool_drafts ?? "?"} drafts`
      );
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function openImport() {
    $("#dev-import-modal")?.classList.add("open");
    const ta = $("#dev-import-json");
    if (ta) ta.value = "";
    const file = $("#dev-import-file");
    if (file) file.value = "";
  }

  function closeImport() {
    $("#dev-import-modal")?.classList.remove("open");
  }

  function summarizeSetupImport(r) {
    const secs = r?.sections || {};
    const bits = [];
    if (secs.hunt_profiles) {
      bits.push(`${secs.hunt_profiles.count ?? "?"} hunts`);
    }
    if (secs.recon_agents) {
      bits.push(`${secs.recon_agents.count ?? "?"} recon`);
    }
    if (secs.tool_drafts) {
      bits.push(`${secs.tool_drafts.count ?? "?"} drafts`);
    }
    if (secs.skill_generator) {
      bits.push(`skill-gen ${secs.skill_generator.action || "ok"}`);
    }
    if (secs.ui_settings) {
      bits.push("settings");
    }
    if (!bits.length && r?.count != null) {
      return `${r.count} items`;
    }
    return bits.join(" · ") || "ok";
  }

  async function submitImport() {
    let text = ($("#dev-import-json").value || "").trim();
    const file = $("#dev-import-file")?.files?.[0];
    if (file && !text) {
      text = await file.text();
    }
    if (!text) {
      toast("Paste JSON or choose a file", true);
      return;
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      toast("Invalid JSON", true);
      return;
    }
    const mode =
      $$('input[name="dev-import-mode"]:checked')[0]?.value || "merge";
    try {
      const r = await api("/api/dev-setup/import", {
        method: "POST",
        body: JSON.stringify({ data, mode }),
      });
      toast(`Imported setup (${mode}): ${summarizeSetupImport(r)}`);
      closeImport();
      selectedId = null;
      raSelectedId = null;
      await loadProfiles();
      if (raLoaded) {
        await loadAgents();
      }
      if (sgLoaded) {
        await loadSkillGenerator();
      }
      if (toolsLoaded) {
        await loadToolsPanel();
      }
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function reseed() {
    if (
      !confirm(
        "Replace the entire hunt collection with the package seed library?\n\nUse Export setup first if you have custom profiles you care about."
      )
    ) {
      return;
    }
    try {
      const r = await api("/api/hunt-profiles/reseed", { method: "POST", body: "{}" });
      toast(`Reseeded ${r.count || 0} profiles`);
      selectedId = null;
      await loadProfiles();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function openGenerate() {
    $("#dev-generate-modal")?.classList.add("open");
    const brief = $("#dev-generate-brief");
    if (brief) brief.value = "";
    const sid = $("#dev-generate-id");
    if (sid) sid.value = "";
    const act = $("#dev-generate-active");
    if (act) act.checked = false;
    const save = $("#dev-generate-save");
    if (save) save.checked = true;
    brief?.focus();
  }

  function closeGenerate() {
    $("#dev-generate-modal")?.classList.remove("open");
  }

  async function submitGenerate() {
    const brief = ($("#dev-generate-brief")?.value || "").trim();
    if (!brief) {
      toast("Describe the hunt skill first", true);
      return;
    }
    const suggested = ($("#dev-generate-id")?.value || "").trim();
    const activate = !!$("#dev-generate-active")?.checked;
    const save = $("#dev-generate-save") ? !!$("#dev-generate-save").checked : true;
    const btn = $("#dev-generate-submit");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Generating…";
    }
    try {
      const r = await api("/api/hunt-profiles/generate", {
        method: "POST",
        body: JSON.stringify({
          brief,
          suggested_id: suggested || null,
          activate,
          save,
        }),
      });
      const skill = r.skill || {};
      const pid = skill.id || r.profile?.id;
      toast(
        r.saved
          ? `Generated and saved ${pid}`
          : `Generated ${pid} (not saved — review in editor)`
      );
      closeGenerate();
      if (r.saved && pid) {
        isNew = false;
        selectedId = pid;
        await loadProfiles(pid);
      } else {
        selectedId = null;
        isNew = true;
        renderList();
        showEditor(
          {
            id: skill.id || "",
            title: skill.title || "",
            description: skill.description || "",
            active: activate,
            body_md: skill.body_md || "",
          },
          { create: true }
        );
      }
    } catch (e) {
      toast(e.message || String(e), true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Generate";
      }
    }
  }

  $("#btn-dev-new")?.addEventListener("click", openNew);
  $("#btn-dev-generate")?.addEventListener("click", openGenerate);
  $("#btn-dev-setup-export")?.addEventListener("click", exportDevSetup);
  $("#btn-dev-setup-import")?.addEventListener("click", openImport);
  $("#btn-dev-reseed")?.addEventListener("click", reseed);
  $("#btn-dev-refresh")?.addEventListener("click", () =>
    loadProfiles(selectedId).catch((e) => toast(e.message, true))
  );
  $("#dev-editor-form")?.addEventListener("submit", saveForm);
  $("#dev-delete")?.addEventListener("click", deleteCurrent);
  $("#dev-import-cancel")?.addEventListener("click", closeImport);
  $("#dev-import-submit")?.addEventListener("click", submitImport);
  $("#dev-generate-cancel")?.addEventListener("click", closeGenerate);
  $("#dev-generate-submit")?.addEventListener("click", submitGenerate);
  $("#dev-import-file")?.addEventListener("change", async () => {
    const file = $("#dev-import-file")?.files?.[0];
    if (!file) return;
    try {
      $("#dev-import-json").value = await file.text();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });

  /* ---------- Skill generator prompt ---------- */

  async function loadSkillGenerator() {
    const data = await api("/api/skill-generator");
    const body = $("#sg-body");
    const meta = $("#sg-meta");
    const pathHint = $("#sg-path-hint");
    if (body) body.value = data.body_md || "";
    const src = data.source || "package";
    if (meta) {
      meta.textContent =
        src === "override"
          ? "Source: operator override"
          : src === "fallback"
            ? "Source: built-in fallback"
            : "Source: package seed";
    }
    if (pathHint) {
      const p = data.has_override ? data.path : data.package_path || data.path;
      pathHint.textContent = p
        ? `Editing ${src === "override" ? "override" : "seed view"}: ${p}`
        : "";
    }
    sgLoaded = true;
  }

  async function saveSkillGenerator() {
    const body = ($("#sg-body")?.value || "").trim();
    if (!body) {
      toast("Prompt body is required", true);
      return;
    }
    try {
      await api("/api/skill-generator", {
        method: "PUT",
        body: JSON.stringify({ body_md: $("#sg-body").value || "" }),
      });
      toast("Skill generator prompt saved");
      await loadSkillGenerator();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function reseedSkillGenerator() {
    if (
      !confirm(
        "Reset skill generator to package seed? Your operator override will be removed."
      )
    ) {
      return;
    }
    try {
      await api("/api/skill-generator/reseed", { method: "POST", body: "{}" });
      toast("Skill generator reset to package");
      await loadSkillGenerator();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  $("#btn-sg-save")?.addEventListener("click", () => {
    saveSkillGenerator().catch((e) => toast(e.message || String(e), true));
  });
  $("#btn-sg-reseed")?.addEventListener("click", () => {
    reseedSkillGenerator().catch((e) => toast(e.message || String(e), true));
  });
  $("#btn-sg-refresh")?.addEventListener("click", () => {
    loadSkillGenerator().catch((e) => toast(e.message || String(e), true));
  });

  /* ---------- Recon agents ---------- */

  function renderAgents() {
    const body = $("#ra-agents-body");
    const meta = $("#ra-meta");
    if (!body) return;
    if (!agents.length) {
      body.innerHTML = `<tr><td colspan="5" class="empty">No agents</td></tr>`;
      if (meta) meta.textContent = "";
      return;
    }
    const nActive = agents.filter((a) => a.active).length;
    if (meta) meta.textContent = `${agents.length} agents · ${nActive} active`;
    body.innerHTML = agents
      .map((a) => {
        const sel = a.id === raSelectedId ? " is-selected" : "";
        return `<tr class="dev-row${sel}" data-id="${esc(a.id)}" style="cursor:pointer">
          <td><input type="checkbox" data-ra-active-toggle value="${esc(a.id)}" ${a.active ? "checked" : ""} title="Active for recon" /></td>
          <td class="mono">${esc(a.order ?? "")}</td>
          <td class="mono">${esc(a.id)}</td>
          <td>${esc(a.title || a.id)}</td>
          <td><span class="badge info">${esc(a.source || "custom")}</span></td>
        </tr>`;
      })
      .join("");

    body.querySelectorAll(".dev-row").forEach((row) => {
      row.addEventListener("click", (ev) => {
        if (ev.target?.matches?.("[data-ra-active-toggle]")) return;
        const id = row.getAttribute("data-id");
        if (id) selectAgent(id);
      });
    });
    body.querySelectorAll("[data-ra-active-toggle]").forEach((inp) => {
      inp.addEventListener("change", async (ev) => {
        ev.stopPropagation();
        const id = inp.value;
        try {
          await api(`/api/recon-agents/${encodeURIComponent(id)}`, {
            method: "PUT",
            body: JSON.stringify({ active: !!inp.checked }),
          });
          toast(inp.checked ? `Active: ${id}` : `Inactive: ${id}`);
          await loadAgents(raSelectedId);
        } catch (e) {
          toast(e.message || String(e), true);
          inp.checked = !inp.checked;
        }
      });
    });
  }

  function showAgentEditor(agent, { create } = {}) {
    raIsNew = !!create;
    const form = $("#ra-editor-form");
    const hint = $("#ra-editor-hint");
    const title = $("#ra-editor-title");
    if (!form) return;
    form.hidden = false;
    if (hint) hint.hidden = true;
    if (title) title.textContent = create ? "New agent" : `Edit: ${agent.id}`;
    const idEl = $("#ra-id");
    idEl.value = agent.id || "";
    idEl.readOnly = !create;
    $("#ra-title").value = agent.title || "";
    $("#ra-description").value = agent.description || "";
    $("#ra-active").checked = !!agent.active;
    $("#ra-order").value =
      agent.order !== undefined && agent.order !== null ? String(agent.order) : "";
    $("#ra-mode").value = agent.mode || "sequential";
    $("#ra-temperature").value =
      agent.temperature !== undefined && agent.temperature !== null
        ? String(agent.temperature)
        : "";
    $("#ra-max-rounds").value =
      agent.max_tool_rounds !== undefined && agent.max_tool_rounds !== null
        ? String(agent.max_tool_rounds)
        : "";
    const tools = agent.tools;
    $("#ra-tools").value = Array.isArray(tools) ? tools.join(", ") : "";
    $("#ra-body").value = agent.body_md || "";
    $("#ra-delete").hidden = !!create;
  }

  async function selectAgent(id) {
    raSelectedId = id;
    raIsNew = false;
    renderAgents();
    try {
      const data = await api(`/api/recon-agents/${encodeURIComponent(id)}`);
      showAgentEditor(data.agent || {}, { create: false });
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function loadAgents(keepId) {
    const data = await api("/api/recon-agents?include_body=0");
    agents = data.agents || [];
    raLoaded = true;
    if (keepId && agents.some((a) => a.id === keepId)) {
      raSelectedId = keepId;
    } else if (raSelectedId && !agents.some((a) => a.id === raSelectedId)) {
      raSelectedId = agents[0]?.id || null;
    } else if (!raSelectedId && agents[0]) {
      raSelectedId = agents[0].id;
    }
    renderAgents();
    if (raSelectedId && !raIsNew) {
      await selectAgent(raSelectedId);
    }
  }

  function openNewAgent() {
    raSelectedId = null;
    raIsNew = true;
    renderAgents();
    showAgentEditor(
      {
        id: "",
        title: "",
        description: "",
        active: false,
        order: 100,
        mode: "sequential",
        body_md:
          "# Recon agent: my-agent\n\n**Mission:** (describe the recon goal)\n\n## Method\n\n1. \n\n## Anti-patterns\n\n- \n\n## Submit checklist\n\n- `submit_architecture` with a non-empty summary\n",
      },
      { create: true }
    );
    $("#ra-id")?.focus();
  }

  function parseToolsInput(raw) {
    const s = (raw || "").trim();
    if (!s) return []; // empty list clears allowlist on save
    return s
      .split(/[,;\s]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  }

  async function saveAgentForm(ev) {
    ev.preventDefault();
    const id = ($("#ra-id").value || "").trim().toLowerCase();
    const orderRaw = ($("#ra-order").value || "").trim();
    const tempRaw = ($("#ra-temperature").value || "").trim();
    const roundsRaw = ($("#ra-max-rounds").value || "").trim();
    const payload = {
      title: ($("#ra-title").value || "").trim(),
      description: ($("#ra-description").value || "").trim(),
      active: !!$("#ra-active").checked,
      mode: ($("#ra-mode").value || "sequential").trim() || "sequential",
      body_md: $("#ra-body").value || "",
      tools: parseToolsInput($("#ra-tools").value),
    };
    if (orderRaw !== "") payload.order = parseInt(orderRaw, 10);
    if (tempRaw !== "") payload.temperature = parseFloat(tempRaw);
    if (roundsRaw !== "") payload.max_tool_rounds = parseInt(roundsRaw, 10);
    try {
      if (raIsNew) {
        payload.id = id;
        await api("/api/recon-agents", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast(`Created ${id}`);
      } else {
        await api(`/api/recon-agents/${encodeURIComponent(id)}`, {
          method: "PUT",
          body: JSON.stringify(payload),
        });
        toast(`Saved ${id}`);
      }
      raIsNew = false;
      raSelectedId = id;
      await loadAgents(id);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function deleteCurrentAgent() {
    const id = ($("#ra-id").value || "").trim();
    if (!id || raIsNew) return;
    if (!confirm(`Delete recon agent "${id}"? This cannot be undone.`)) return;
    try {
      await api(`/api/recon-agents/${encodeURIComponent(id)}`, { method: "DELETE" });
      toast(`Deleted ${id}`);
      raSelectedId = null;
      raIsNew = false;
      $("#ra-editor-form").hidden = true;
      $("#ra-editor-hint").hidden = false;
      await loadAgents();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function reseedAgents() {
    if (
      !confirm(
        "Replace the entire recon agent collection with the package seed library?\n\nUse Export setup first if you have custom agents you care about."
      )
    ) {
      return;
    }
    try {
      const r = await api("/api/recon-agents/reseed", { method: "POST", body: "{}" });
      toast(`Reseeded ${r.count || 0} agents`);
      raSelectedId = null;
      await loadAgents();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  $("#btn-ra-new")?.addEventListener("click", openNewAgent);
  $("#btn-ra-reseed")?.addEventListener("click", reseedAgents);
  $("#btn-ra-refresh")?.addEventListener("click", () =>
    loadAgents(raSelectedId).catch((e) => toast(e.message, true))
  );
  $("#ra-editor-form")?.addEventListener("submit", saveAgentForm);
  $("#ra-delete")?.addEventListener("click", deleteCurrentAgent);

  /* ---------- Tools catalog + drafts + wizard ---------- */

  function renderToolsList() {
    const body = $("#tg-tools-body");
    const meta = $("#tg-meta");
    if (!body) return;
    if (!catalogTools.length) {
      body.innerHTML = `<tr><td colspan="3" class="empty">No tools</td></tr>`;
    } else {
      body.innerHTML = catalogTools
        .map((t) => {
          const sel = t.name === selectedToolName ? " is-selected" : "";
          return `<tr class="dev-row${sel}" data-tool="${esc(t.name)}" style="cursor:pointer">
            <td class="mono">${esc(t.name)}</td>
            <td>${esc((t.stages || []).join(", "))}</td>
            <td><span class="badge info">${esc(t.source || "builtin")}</span></td>
          </tr>`;
        })
        .join("");
      body.querySelectorAll("[data-tool]").forEach((row) => {
        row.addEventListener("click", () => {
          const n = row.getAttribute("data-tool");
          if (n) showToolDetail(n);
        });
      });
    }
    if (meta) {
      meta.textContent = `${catalogTools.length} tools · ${toolDrafts.length} drafts`;
    }
  }

  function renderDraftsList() {
    const body = $("#tg-drafts-body");
    if (!body) return;
    if (!toolDrafts.length) {
      body.innerHTML = `<tr><td colspan="3" class="empty">No drafts</td></tr>`;
      return;
    }
    body.innerHTML = toolDrafts
      .map((d) => {
        const sel = d.id === selectedDraftId ? " is-selected" : "";
        return `<tr class="dev-row${sel}" data-draft="${esc(d.id)}" style="cursor:pointer">
          <td class="mono">${esc(d.id)}</td>
          <td><span class="badge info">${esc(d.status || "draft")}</span></td>
          <td>${esc(d.source || "")}</td>
        </tr>`;
      })
      .join("");
    body.querySelectorAll("[data-draft]").forEach((row) => {
      row.addEventListener("click", () => {
        const id = row.getAttribute("data-draft");
        if (id) showDraftDetail(id);
      });
    });
  }

  function showToolDetail(name) {
    selectedToolName = name;
    selectedDraftId = null;
    renderToolsList();
    renderDraftsList();
    const tool = catalogTools.find((t) => t.name === name);
    $("#tg-tool-detail").hidden = false;
    $("#tg-draft-detail").hidden = true;
    $("#tg-detail-hint").hidden = true;
    $("#tg-detail-title").textContent = name;
    $("#tg-tool-desc").textContent = tool?.description || "";
    $("#tg-tool-stages").textContent = `Stages: ${(tool?.stages || []).join(", ") || "—"} · source=${tool?.source || "?"}`;
    const params = tool?.parameters?.properties || {};
    const req = new Set(tool?.parameters?.required || []);
    const tbody = $("#tg-params-body");
    const keys = Object.keys(params);
    if (!keys.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty">No parameters</td></tr>`;
    } else {
      tbody.innerHTML = keys
        .map((k) => {
          const p = params[k] || {};
          return `<tr>
            <td class="mono">${esc(k)}</td>
            <td class="mono">${esc(p.type || "")}</td>
            <td>${req.has(k) ? "yes" : ""}</td>
            <td>${esc(p.description || "")}</td>
          </tr>`;
        })
        .join("");
    }
  }

  async function showDraftDetail(id) {
    selectedDraftId = id;
    selectedToolName = null;
    renderToolsList();
    renderDraftsList();
    try {
      const data = await api(`/api/tool-drafts/${encodeURIComponent(id)}`);
      const d = data.draft || {};
      const meta = d.meta || {};
      $("#tg-tool-detail").hidden = true;
      $("#tg-draft-detail").hidden = false;
      $("#tg-detail-hint").hidden = true;
      $("#tg-detail-title").textContent = `Draft: ${id}`;
      $("#tg-draft-status").textContent = `status=${meta.status || "?"} · risk=${meta.risk_class || "?"} · stages=${(meta.stages || []).join(",")}`;
      $("#tg-draft-spec").value = d.spec_md || "";
      $("#tg-draft-impl").value = d.impl_py || "";
      $("#tg-draft-schema").value = d.schema ? JSON.stringify(d.schema, null, 2) : "";
      const rep = d.validation_report;
      $("#tg-validation-out").textContent = rep
        ? (rep.ok ? "PASS\n" : "FAIL\n") + JSON.stringify(rep.hard_fail || rep, null, 2)
        : "";
      wizardDraftId = id;
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function loadToolsPanel() {
    const [t, d] = await Promise.all([
      api("/api/tools"),
      api("/api/tool-drafts"),
    ]);
    catalogTools = t.tools || [];
    toolDrafts = d.drafts || [];
    toolsLoaded = true;
    // refresh hunt tool checkboxes if not locked
    const box = $("#dev-tools-checks");
    if (box) {
      box.dataset.ready = "0";
      box.innerHTML = "";
      ensureHuntToolChecks();
    }
    renderToolsList();
    renderDraftsList();
  }

  function setWizardStep(n) {
    wizardStep = n;
    for (let i = 1; i <= 6; i++) {
      const el = $(`#toolgen-step-${i}`);
      if (el) el.hidden = i !== n;
    }
    const label = $("#toolgen-step-label");
    if (label) label.textContent = `Step ${n} of 6`;
    const back = $("#tgw-back");
    const next = $("#tgw-next");
    if (back) back.hidden = n <= 1;
    if (next) {
      next.hidden = n >= 6;
      next.textContent = n === 1 ? "Create draft & continue" : "Next";
    }
  }

  function openToolgenWizard(prefill) {
    wizardDraftId = prefill?.draftId || null;
    wizardStep = 1;
    if (prefill?.brief) $("#tgw-brief").value = prefill.brief;
    else if (!wizardDraftId) $("#tgw-brief").value = "";
    if (prefill?.id) $("#tgw-id").value = prefill.id;
    else if (!wizardDraftId) $("#tgw-id").value = "";
    setWizardStep(1);
    $("#toolgen-wizard-modal")?.classList.add("open");
  }

  function closeToolgenWizard() {
    $("#toolgen-wizard-modal")?.classList.remove("open");
  }

  async function wizardNext() {
    if (wizardStep === 1) {
      if (!wizardDraftId) {
        const brief = ($("#tgw-brief").value || "").trim();
        if (!brief) {
          toast("Brief is required", true);
          return;
        }
        const stages = $$(".tgw-stage")
          .filter((c) => c.checked)
          .map((c) => c.value);
        try {
          const r = await api("/api/tool-drafts", {
            method: "POST",
            body: JSON.stringify({
              brief,
              suggested_id: ($("#tgw-id").value || "").trim() || null,
              source: "blank",
              stages: stages.length ? stages : ["hunt"],
              risk_class: $("#tgw-risk").value || "read_only",
              prefer_extend: ($("#tgw-extend").value || "").trim() || null,
              slots: {
                problem_statement: brief,
              },
            }),
          });
          wizardDraftId = r.draft?.id || r.draft?.meta?.id;
          toast(`Draft ${wizardDraftId}`);
          $("#tgw-problem").value = brief;
        } catch (e) {
          toast(e.message || String(e), true);
          return;
        }
      }
      setWizardStep(2);
      return;
    }
    if (wizardStep === 2) {
      // save slots
      try {
        await api(`/api/tool-drafts/${encodeURIComponent(wizardDraftId)}`, {
          method: "PUT",
          body: JSON.stringify({
            slots: {
              problem_statement: $("#tgw-problem").value || "",
              non_goals: $("#tgw-nongoals").value || "",
              io_contract: $("#tgw-io").value || "",
              safety_constraints: $("#tgw-safety").value || "",
            },
          }),
        });
      } catch (e) {
        toast(e.message || String(e), true);
        return;
      }
      setWizardStep(3);
      // load existing spec
      try {
        const d = await api(`/api/tool-drafts/${encodeURIComponent(wizardDraftId)}`);
        $("#tgw-spec").value = d.draft?.spec_md || "";
      } catch (_) {}
      return;
    }
    if (wizardStep === 3) {
      // save edited spec
      try {
        await api(`/api/tool-drafts/${encodeURIComponent(wizardDraftId)}`, {
          method: "PUT",
          body: JSON.stringify({ spec_md: $("#tgw-spec").value || "" }),
        });
      } catch (e) {
        toast(e.message || String(e), true);
        return;
      }
      setWizardStep(4);
      try {
        const d = await api(`/api/tool-drafts/${encodeURIComponent(wizardDraftId)}`);
        $("#tgw-impl").value = d.draft?.impl_py || "";
        $("#tgw-schema").value = d.draft?.schema
          ? JSON.stringify(d.draft.schema, null, 2)
          : "";
      } catch (_) {}
      return;
    }
    if (wizardStep === 4) {
      try {
        let schema = null;
        const raw = ($("#tgw-schema").value || "").trim();
        if (raw) schema = JSON.parse(raw);
        await api(`/api/tool-drafts/${encodeURIComponent(wizardDraftId)}`, {
          method: "PUT",
          body: JSON.stringify({
            impl_py: $("#tgw-impl").value || "",
            schema,
          }),
        });
      } catch (e) {
        toast(e.message || String(e), true);
        return;
      }
      setWizardStep(5);
      return;
    }
    if (wizardStep === 5) {
      setWizardStep(6);
    }
  }

  async function wizardBack() {
    if (wizardStep > 1) setWizardStep(wizardStep - 1);
  }

  $("#btn-tg-new")?.addEventListener("click", () => openToolgenWizard());
  $("#btn-tg-refresh")?.addEventListener("click", () =>
    loadToolsPanel().catch((e) => toast(e.message, true))
  );
  $("#btn-tg-open-wizard")?.addEventListener("click", () => {
    if (selectedDraftId) openToolgenWizard({ draftId: selectedDraftId });
    else openToolgenWizard();
  });
  $("#btn-tg-validate")?.addEventListener("click", async () => {
    if (!selectedDraftId) return;
    try {
      const r = await api(`/api/tool-drafts/${encodeURIComponent(selectedDraftId)}/validate`, {
        method: "POST",
        body: "{}",
      });
      const rep = r.validation || {};
      $("#tg-validation-out").textContent =
        (rep.ok ? "PASS\n" : "FAIL\n") + JSON.stringify(rep, null, 2);
      toast(rep.ok ? "Validation passed" : "Validation failed", !rep.ok);
      await loadToolsPanel();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });
  $("#btn-tg-export")?.addEventListener("click", async () => {
    if (!selectedDraftId) return;
    try {
      const data = await api(`/api/tool-drafts/${encodeURIComponent(selectedDraftId)}/export`);
      const blob = new Blob([JSON.stringify(data, null, 2) + "\n"], {
        type: "application/json",
      });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `tool_draft_${selectedDraftId}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });
  $("#btn-tg-delete-draft")?.addEventListener("click", async () => {
    if (!selectedDraftId) return;
    if (!confirm(`Delete draft ${selectedDraftId}?`)) return;
    try {
      await api(`/api/tool-drafts/${encodeURIComponent(selectedDraftId)}`, {
        method: "DELETE",
      });
      selectedDraftId = null;
      $("#tg-draft-detail").hidden = true;
      await loadToolsPanel();
      toast("Draft deleted");
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });
  $("#btn-tg-save-draft")?.addEventListener("click", async () => {
    if (!selectedDraftId) return;
    try {
      let schema = null;
      const raw = ($("#tg-draft-schema").value || "").trim();
      if (raw) schema = JSON.parse(raw);
      await api(`/api/tool-drafts/${encodeURIComponent(selectedDraftId)}`, {
        method: "PUT",
        body: JSON.stringify({
          spec_md: $("#tg-draft-spec").value || "",
          impl_py: $("#tg-draft-impl").value || "",
          schema,
        }),
      });
      toast("Draft saved");
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });

  $("#tgw-cancel")?.addEventListener("click", closeToolgenWizard);
  $("#tgw-next")?.addEventListener("click", () => wizardNext().catch((e) => toast(e.message, true)));
  $("#tgw-back")?.addEventListener("click", () => wizardBack());
  $("#tgw-preview-prompts")?.addEventListener("click", async () => {
    if (!wizardDraftId) {
      toast("Create draft first (Next from step 1)", true);
      return;
    }
    try {
      await api(`/api/tool-drafts/${encodeURIComponent(wizardDraftId)}`, {
        method: "PUT",
        body: JSON.stringify({
          slots: {
            problem_statement: $("#tgw-problem").value || "",
            non_goals: $("#tgw-nongoals").value || "",
            io_contract: $("#tgw-io").value || "",
            safety_constraints: $("#tgw-safety").value || "",
          },
        }),
      });
      const r = await api(
        `/api/tool-drafts/${encodeURIComponent(wizardDraftId)}/prompts/preview`,
        { method: "POST", body: JSON.stringify({ stage: "spec" }) }
      );
      $("#tgw-prompt-preview").textContent =
        "=== SYSTEM ===\n" +
        (r.system || "") +
        "\n\n=== USER ===\n" +
        (r.user || "");
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });
  $("#tgw-gen-spec")?.addEventListener("click", async () => {
    if (!wizardDraftId) return;
    const btn = $("#tgw-gen-spec");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Generating…";
    }
    try {
      const r = await api(
        `/api/tool-drafts/${encodeURIComponent(wizardDraftId)}/generate/spec`,
        { method: "POST", body: "{}" }
      );
      $("#tgw-spec").value = r.draft?.spec_md || "";
      toast("Spec generated");
    } catch (e) {
      toast(e.message || String(e), true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Generate spec with AI";
      }
    }
  });
  $("#tgw-gen-impl")?.addEventListener("click", async () => {
    if (!wizardDraftId) return;
    const btn = $("#tgw-gen-impl");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Generating…";
    }
    try {
      // save spec first
      await api(`/api/tool-drafts/${encodeURIComponent(wizardDraftId)}`, {
        method: "PUT",
        body: JSON.stringify({ spec_md: $("#tgw-spec").value || "" }),
      });
      const r = await api(
        `/api/tool-drafts/${encodeURIComponent(wizardDraftId)}/generate/impl`,
        { method: "POST", body: "{}" }
      );
      $("#tgw-impl").value = r.draft?.impl_py || "";
      $("#tgw-schema").value = r.draft?.schema
        ? JSON.stringify(r.draft.schema, null, 2)
        : "";
      toast("Implementation generated");
    } catch (e) {
      toast(e.message || String(e), true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Generate implementation";
      }
    }
  });
  $("#tgw-validate")?.addEventListener("click", async () => {
    if (!wizardDraftId) return;
    try {
      const r = await api(
        `/api/tool-drafts/${encodeURIComponent(wizardDraftId)}/validate`,
        { method: "POST", body: "{}" }
      );
      const rep = r.validation || {};
      $("#tgw-validation").textContent = JSON.stringify(rep, null, 2);
      toast(rep.ok ? "Validation passed" : "Validation failed", !rep.ok);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });
  $("#tgw-ai-fix")?.addEventListener("click", async () => {
    if (!wizardDraftId) return;
    try {
      const r = await api(
        `/api/tool-drafts/${encodeURIComponent(wizardDraftId)}/generate/fix`,
        { method: "POST", body: "{}" }
      );
      $("#tgw-validation").textContent = JSON.stringify(r.validation || r, null, 2);
      if (r.draft?.impl_py) $("#tgw-impl").value = r.draft.impl_py;
      toast("AI fix applied");
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });
  $("#tgw-dry-run")?.addEventListener("click", async () => {
    if (!wizardDraftId) return;
    try {
      const r = await api(
        `/api/tool-drafts/${encodeURIComponent(wizardDraftId)}/integrate`,
        { method: "POST", body: JSON.stringify({ dry_run: true, apply: false }) }
      );
      $("#tgw-integrate").textContent = JSON.stringify(r, null, 2);
      toast("Dry-run complete");
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });
  $("#tgw-apply")?.addEventListener("click", async () => {
    if (!wizardDraftId) return;
    if (!confirm("Apply integrate? This writes into package source (extra_registry + tools module)."))
      return;
    try {
      const r = await api(
        `/api/tool-drafts/${encodeURIComponent(wizardDraftId)}/integrate`,
        { method: "POST", body: JSON.stringify({ dry_run: false, apply: true }) }
      );
      $("#tgw-integrate").textContent = JSON.stringify(r, null, 2);
      toast(`Integrated ${r.tool_name || wizardDraftId}`);
      await loadToolsPanel();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  });

  $("#dev-tools-unrestricted")?.addEventListener("change", () => {
    const on = !!$("#dev-tools-unrestricted")?.checked;
    $$(".dev-tool-cb").forEach((cb) => {
      cb.disabled = on;
      if (on) cb.checked = false;
    });
  });

  // Hash deep-link: #tools or #tools/<draftId>
  async function handleHash() {
    const h = (location.hash || "").replace(/^#/, "");
    if (h.startsWith("tools")) {
      switchTab("tools");
      await loadToolsPanel().catch(() => {});
      const parts = h.split("/");
      if (parts[1]) {
        await showDraftDetail(parts[1]);
        openToolgenWizard({ draftId: parts[1] });
      }
    }
  }
  window.addEventListener("hashchange", () => {
    handleHash().catch(() => {});
  });

  // Prefetch catalog for hunt allowlist UI
  api("/api/tools")
    .then((t) => {
      catalogTools = t.tools || [];
      const box = $("#dev-tools-checks");
      if (box) {
        box.dataset.ready = "0";
        box.innerHTML = "";
      }
    })
    .catch(() => {});

  loadProfiles().catch((e) => toast(e.message || String(e), true));
  handleHash().catch(() => {});
})();
