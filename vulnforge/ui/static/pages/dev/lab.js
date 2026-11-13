/*
 * Dev → Tool lab (VFPages.devLab). Tool drafts in config/tool_drafts/ with one
 * workspace per draft: Brief → Spec → Impl → Validate → Integrate.
 *
 * Integrate writes package source. The UI requires a fresh dry-run (shows
 * every file and its diff) before Apply, and a separate consent for any
 * overwrite. The server enforces the same gate (plan_hash / allow_overwrite).
 */
(function () {
  "use strict";
  if (document.body?.dataset?.page !== "dev") return;

  const H = window.DevHelpers;
  const U = window.DevUI;
  const { esc, api, fail, toast, pill } = U;

  let root = null;
  let drafts = [];
  let selectedId = null;
  /** Full draft (GET /api/tool-drafts/{id}) */
  let draft = null;
  let step = "brief";
  let creating = false;
  let loaded = false;
  /** Unsaved workspace edits */
  let dirty = false;
  /** Integrate state */
  let dry = null;
  let stale = false;
  let overwriteAck = false;
  let applied = null;
  let validation = null;

  const $ = (sel) => root.querySelector(sel);
  const enc = encodeURIComponent;

  function mount(el) {
    root = el;
    root.innerHTML = `
      <div class="dev-section-head">
        <div>
          <h2 class="dev-h2">Tool lab</h2>
          <p class="dev-lede">Draft, generate and validate new agent tools. Rules: <code>toolgen.md</code>. Drafts never run until integrated. Ideas come from <a href="/tool-gaps">Tool gaps</a>.</p>
        </div>
        <div class="dev-actions">
          <button type="button" class="vf-btn vf-btn--primary" data-act="new">New draft</button>
        </div>
      </div>
      <div class="vf-card dev-lab-banner" role="note">
        <b>Integrate writes package source</b> under <code>vulnforge/</code> and <code>tests/</code>.
        Apply needs a fresh dry-run, shows every file it writes with its diff, and asks again before replacing an existing file.
        Review with <code>git diff</code> afterwards; commit or revert.
      </div>
      <div class="vf-split dev-split">
        <aside class="vf-split-side vf-card dev-list-card">
          <div class="vf-section-label">Drafts</div>
          <ul class="dev-list" role="listbox" aria-label="Tool drafts"></ul>
        </aside>
        <section class="vf-split-main vf-card dev-editor dev-lab" aria-live="polite"></section>
      </div>`;
    $('[data-act="new"]').addEventListener("click", () => guard() && openCreate());
  }

  function guard() {
    if (!dirty) return true;
    return confirm("Discard unsaved changes in this draft?");
  }

  function setDirty(on) {
    dirty = on;
    U.setDirty("lab", on);
  }

  /** Any saved change to the draft invalidates a previous dry-run. */
  function invalidatePlan() {
    if (dry) stale = true;
    overwriteAck = false;
  }

  /* ---------- list ---------- */

  function renderList() {
    U.renderList($(".dev-list"), {
      items: drafts,
      selectedId: creating ? null : selectedId,
      empty: "No drafts yet. Start one with New draft, or from Tool gaps.",
      row: (d) =>
        `<div class="dev-row-main"><span class="vf-mono dev-row-id">${esc(d.id)}</span><span class="dev-row-title">${esc(d.title || d.source || "")}</span></div>${pill(d.status || "draft", H.draftStatusTone(d.status))}`,
      onSelect: (id) => guard() && select(id),
    });
  }

  async function load(keepId) {
    const d = await api("/api/tool-drafts");
    drafts = d.drafts || [];
    loaded = true;
    if (keepId !== undefined) selectedId = keepId;
    renderList();
  }

  async function fetchDraft(id) {
    const d = await api(`/api/tool-drafts/${enc(id)}`);
    return d.draft || null;
  }

  async function select(id, opts) {
    const keepStep = opts && opts.keepStep;
    if (id !== selectedId) {
      dry = null;
      stale = false;
      overwriteAck = false;
      applied = null;
      validation = null;
    }
    selectedId = id;
    creating = false;
    U.setHash("lab", id);
    try {
      draft = await fetchDraft(id);
      validation = (draft && draft.validation_report) || validation;
    } catch (e) {
      draft = null;
      fail(e);
    }
    if (!keepStep) step = firstOpenStep();
    setDirty(false);
    renderList();
    renderWorkspace();
  }

  function firstOpenStep() {
    const p = H.labProgress(draft);
    for (const s of H.LAB_STEPS) if (!p[s.id]) return s.id;
    return "integrate";
  }

  /* ---------- create ---------- */

  function openCreate() {
    creating = true;
    selectedId = null;
    draft = null;
    setDirty(false);
    U.setHash("lab", "");
    renderList();
    const box = $(".dev-editor");
    box.innerHTML = `
      <form class="dev-form" novalidate>
        <header class="dev-ed-head"><div class="dev-ed-title"><h3>New tool draft</h3>
          <p class="vf-faint">Prefer a small tool, or extending an existing one when the model only needs a filter or argument.</p></div>
          <div class="dev-actions"><button type="submit" class="vf-btn vf-btn--primary">Create draft</button>
          <button type="button" class="vf-btn" data-act="cancel">Cancel</button></div></header>
        <label class="dev-field"><span class="vf-section-label">Brief / problem</span>
          <textarea id="lab-new-brief" class="dev-textarea dev-textarea--sm" rows="5" placeholder="What capability is missing, and why?"></textarea></label>
        <div class="dev-grid3">
          <label class="dev-field"><span class="vf-section-label">Tool id</span>
            <input id="lab-new-id" class="vf-mono" placeholder="ast_query" autocomplete="off" spellcheck="false" /></label>
          <label class="dev-field"><span class="vf-section-label">Risk class</span>
            <select id="lab-new-risk"><option value="read_only" selected>read_only</option><option value="evidence_write">evidence_write</option><option value="exec">exec (not for code_static)</option></select></label>
          <label class="dev-field"><span class="vf-section-label">Prefer extending</span>
            <input id="lab-new-extend" class="vf-mono" placeholder="grep" autocomplete="off" /></label>
        </div>
        <div class="dev-field"><span class="vf-section-label">Stages</span>
          <div class="dev-inline-checks">${H.STAGES.map((s) => `<label class="dev-check"><input type="checkbox" class="lab-new-stage" value="${s}" ${s === "hunt" ? "checked" : ""} /> ${s}</label>`).join("")}</div></div>
      </form>`;
    const form = box.querySelector("form");
    form.addEventListener("input", () => setDirty(true));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      create(form).catch(fail);
    });
    box.querySelector('[data-act="cancel"]').addEventListener("click", () => {
      if (!guard()) return;
      creating = false;
      setDirty(false);
      renderWorkspace();
    });
    box.querySelector("#lab-new-brief").focus();
  }

  async function create(form) {
    const brief = form.querySelector("#lab-new-brief").value.trim();
    if (!brief) {
      toast("Brief is required", true);
      return;
    }
    const stages = [...form.querySelectorAll(".lab-new-stage:checked")].map((c) => c.value);
    const r = await U.busy(form.querySelector('[type="submit"]'), "Creating…", () =>
      api("/api/tool-drafts", {
        method: "POST",
        body: JSON.stringify({
          brief,
          suggested_id: form.querySelector("#lab-new-id").value.trim() || null,
          source: "blank",
          stages: stages.length ? stages : ["hunt"],
          risk_class: form.querySelector("#lab-new-risk").value,
          prefer_extend: form.querySelector("#lab-new-extend").value.trim() || null,
          slots: { problem_statement: brief },
        }),
      })
    );
    const id = (r.draft && (r.draft.id || (r.draft.meta && r.draft.meta.id))) || "";
    toast(`Draft ${id} created`);
    setDirty(false);
    await load(id);
    await select(id);
    step = "brief";
    renderWorkspace();
  }

  /* ---------- workspace ---------- */

  function renderWorkspace() {
    const box = $(".dev-editor");
    if (creating) return;
    if (!draft) {
      box.innerHTML = `<div class="vf-empty dev-editor-empty">Select a draft, or start one with <b>New draft</b>.</div>`;
      return;
    }
    const meta = draft.meta || {};
    const prog = H.labProgress(draft);
    const status = meta.status || "draft";
    const integrated = status === "integrated";
    box.innerHTML = `
      <header class="dev-ed-head">
        <div class="dev-ed-title">
          <h3 class="vf-mono">${esc(draft.id)}</h3>
          <div class="dev-ed-meta">${pill(status, H.draftStatusTone(status))} ${pill(meta.risk_class || "?", meta.risk_class === "read_only" ? "" : "review")}
            <span class="vf-faint">stages: ${esc((meta.stages || []).join(", ") || "none")}${meta.source ? ` · source: ${esc(meta.source)}` : ""}</span></div>
        </div>
        <div class="dev-actions">
          <button type="button" class="vf-btn" data-act="export">Export</button>
          ${integrated || status === "rejected" ? "" : `<button type="button" class="vf-btn" data-act="reject">Reject</button>`}
          <button type="button" class="vf-btn vf-btn--danger" data-act="delete">Delete</button>
        </div>
      </header>
      <nav class="dev-stepper" role="tablist" aria-label="Draft steps">
        ${H.LAB_STEPS.map(
          (s, i) =>
            `<button type="button" class="dev-step${prog[s.id] ? " is-done" : ""}" role="tab" data-step="${s.id}" aria-selected="${step === s.id}"><span class="dev-step-n">${prog[s.id] ? "✓" : i + 1}</span>${esc(s.label)}</button>`
        ).join("")}
      </nav>
      <div class="dev-step-body"></div>`;
    box.querySelectorAll("[data-step]").forEach((b) =>
      b.addEventListener("click", () => {
        const s = b.getAttribute("data-step");
        if (s === step) return;
        if (!guard()) return;
        setDirty(false);
        step = s;
        renderWorkspace();
      })
    );
    box.querySelector('[data-act="export"]').addEventListener("click", () => exportDraft().catch(fail));
    box.querySelector('[data-act="reject"]')?.addEventListener("click", () => rejectDraft().catch(fail));
    box.querySelector('[data-act="delete"]').addEventListener("click", () => deleteDraft().catch(fail));
    const body = box.querySelector(".dev-step-body");
    ({ brief: stepBrief, spec: stepSpec, impl: stepImpl, validate: stepValidate, integrate: stepIntegrate })[step](body);
  }

  function trackDirty(form) {
    form.addEventListener("input", () => setDirty(true));
  }

  async function putDraft(payload) {
    const r = await api(`/api/tool-drafts/${enc(draft.id)}`, { method: "PUT", body: JSON.stringify(payload) });
    invalidatePlan();
    setDirty(false);
    return r;
  }

  async function refresh(keepStep) {
    await load(draft.id);
    await select(draft.id, { keepStep: keepStep !== false });
  }

  /* Step 1: brief + prompt slots */
  function stepBrief(body) {
    const b = draft.brief || {};
    const slots = b.slots || {};
    const meta = draft.meta || {};
    body.innerHTML = `
      <form class="dev-form" novalidate>
        <p class="dev-hint">These slots fill the AI authoring prompts. Preview them before generating.</p>
        <label class="dev-field"><span class="vf-section-label">Problem statement</span>
          <textarea id="lab-problem" class="dev-textarea dev-textarea--sm" rows="4">${esc(slots.problem_statement || b.brief || "")}</textarea></label>
        <div class="dev-grid2">
          <label class="dev-field"><span class="vf-section-label">Non-goals</span>
            <textarea id="lab-nongoals" class="dev-textarea dev-textarea--sm" rows="3">${esc(slots.non_goals || "")}</textarea></label>
          <label class="dev-field"><span class="vf-section-label">Safety constraints</span>
            <textarea id="lab-safety" class="dev-textarea dev-textarea--sm" rows="3">${esc(slots.safety_constraints || "")}</textarea></label>
        </div>
        <label class="dev-field"><span class="vf-section-label">I/O contract (example args → ok result)</span>
          <textarea id="lab-io" class="dev-textarea dev-textarea--sm vf-mono" rows="3" placeholder='{"path":"…"} → {"ok":true,…}'>${esc(slots.io_contract || "")}</textarea></label>
        <div class="dev-grid2">
          <label class="dev-field"><span class="vf-section-label">Risk class</span>
            <select id="lab-risk">${["read_only", "evidence_write", "exec"].map((r) => `<option value="${r}" ${meta.risk_class === r ? "selected" : ""}>${r}</option>`).join("")}</select></label>
          <div class="dev-field"><span class="vf-section-label">Stages</span>
            <div class="dev-inline-checks">${H.STAGES.map((s) => `<label class="dev-check"><input type="checkbox" class="lab-stage" value="${s}" ${(meta.stages || []).includes(s) ? "checked" : ""} /> ${s}</label>`).join("")}</div></div>
        </div>
        <div class="dev-actions">
          <button type="submit" class="vf-btn vf-btn--primary">Save brief</button>
          <button type="button" class="vf-btn" data-act="preview">Preview spec prompts</button>
        </div>
        <pre class="dev-pre vf-mono" id="lab-preview" hidden></pre>
      </form>`;
    const form = body.querySelector("form");
    trackDirty(form);
    const collect = () => ({
      slots: {
        problem_statement: form.querySelector("#lab-problem").value,
        non_goals: form.querySelector("#lab-nongoals").value,
        io_contract: form.querySelector("#lab-io").value,
        safety_constraints: form.querySelector("#lab-safety").value,
      },
      risk_class: form.querySelector("#lab-risk").value,
      stages: [...form.querySelectorAll(".lab-stage:checked")].map((c) => c.value),
    });
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      (async () => {
        const p = collect();
        if (!p.stages.length) {
          toast("Pick at least one stage", true);
          return;
        }
        await putDraft(p);
        toast("Brief saved");
        await refresh();
      })().catch(fail);
    });
    form.querySelector('[data-act="preview"]').addEventListener("click", (e) =>
      U.busy(e.currentTarget, "Loading…", async () => {
        if (dirty) await putDraft(collect());
        const r = await api(`/api/tool-drafts/${enc(draft.id)}/prompts/preview`, {
          method: "POST",
          body: JSON.stringify({ stage: "spec" }),
        });
        const pre = form.querySelector("#lab-preview");
        pre.hidden = false;
        pre.textContent = `=== SYSTEM ===\n${r.system || ""}\n\n=== USER ===\n${r.user || ""}`;
      }).catch(fail)
    );
  }

  /* Step 2: spec */
  function stepSpec(body) {
    body.innerHTML = `
      <form class="dev-form" novalidate>
        <p class="dev-hint">The tool's contract in markdown. Generate it, then edit.</p>
        <label class="dev-field"><span class="vf-section-label">spec.md</span>
          <textarea id="lab-spec" class="dev-textarea vf-mono" rows="18" spellcheck="false">${esc(draft.spec_md || "")}</textarea></label>
        <div class="dev-actions">
          <button type="submit" class="vf-btn vf-btn--primary">Save spec</button>
          <button type="button" class="vf-btn" data-act="gen">Generate spec with AI</button>
        </div>
      </form>`;
    const form = body.querySelector("form");
    trackDirty(form);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      putDraft({ spec_md: form.querySelector("#lab-spec").value })
        .then(() => toast("Spec saved"))
        .then(() => refresh())
        .catch(fail);
    });
    form.querySelector('[data-act="gen"]').addEventListener("click", (e) => {
      if (dirty && !confirm("Replace your unsaved spec with a generated one?")) return;
      U.busy(e.currentTarget, "Generating…", async () => {
        await api(`/api/tool-drafts/${enc(draft.id)}/generate/spec`, { method: "POST", body: "{}" });
        invalidatePlan();
        setDirty(false);
        toast("Spec generated");
        await refresh();
      }).catch(fail);
    });
  }

  /* Step 3: impl + schema */
  function stepImpl(body) {
    body.innerHTML = `
      <form class="dev-form" novalidate>
        <p class="dev-hint">Implementation, OpenAI schema and test stub. Not live until integrated.</p>
        <label class="dev-field"><span class="vf-section-label">impl.py</span>
          <textarea id="lab-impl" class="dev-textarea vf-mono" rows="18" spellcheck="false">${esc(draft.impl_py || "")}</textarea></label>
        <label class="dev-field"><span class="vf-section-label">schema.json</span>
          <textarea id="lab-schema" class="dev-textarea dev-textarea--sm vf-mono" rows="10" spellcheck="false">${esc(draft.schema ? JSON.stringify(draft.schema, null, 2) : "")}</textarea></label>
        <div class="dev-actions">
          <button type="submit" class="vf-btn vf-btn--primary">Save impl</button>
          <button type="button" class="vf-btn" data-act="gen">Generate implementation with AI</button>
        </div>
      </form>`;
    const form = body.querySelector("form");
    trackDirty(form);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      let schema = null;
      const raw = form.querySelector("#lab-schema").value.trim();
      try {
        if (raw) schema = JSON.parse(raw);
      } catch (err) {
        toast(`schema.json is not valid JSON: ${err.message}`, true);
        return;
      }
      putDraft({ impl_py: form.querySelector("#lab-impl").value, tool_schema: schema })
        .then(() => toast("Implementation saved"))
        .then(() => refresh())
        .catch(fail);
    });
    form.querySelector('[data-act="gen"]').addEventListener("click", (e) => {
      if (dirty && !confirm("Replace your unsaved implementation with a generated one?")) return;
      U.busy(e.currentTarget, "Generating…", async () => {
        await api(`/api/tool-drafts/${enc(draft.id)}/generate/impl`, { method: "POST", body: "{}" });
        invalidatePlan();
        setDirty(false);
        toast("Implementation generated");
        await refresh();
      }).catch(fail);
    });
  }

  /* Step 4: validate */
  function stepValidate(body) {
    const rep = validation;
    const checks = (rep && rep.checks) || [];
    body.innerHTML = `
      <p class="dev-hint">Deterministic checks from <code>toolgen.md</code>, run at integrate strictness. AI fix is one attempt per click; it never weakens safety checks.</p>
      <div class="dev-actions">
        <button type="button" class="vf-btn vf-btn--primary" data-act="run">Run validation</button>
        <button type="button" class="vf-btn" data-act="fix" ${rep && !rep.ok ? "" : "disabled"}>AI fix</button>
        ${rep ? `<span class="dev-verdict">${rep.ok ? pill("pass", "confirmed") : pill(`${(rep.hard_fail || []).length} hard fail`, "danger")} <span class="vf-faint">${esc(rep.generated_at || "")}</span></span>` : ""}
      </div>
      ${
        checks.length
          ? `<table class="dev-table dev-checks"><thead><tr><th>Check</th><th>Level</th><th>Result</th><th>Detail</th></tr></thead><tbody>${checks
              .map(
                (c) =>
                  `<tr class="${c.pass ? "" : c.level === "hard" ? "is-fail" : "is-warn"}"><td class="vf-mono">${esc(c.id)}</td><td>${esc(c.level)}</td><td>${c.pass ? pill("pass", "confirmed") : c.level === "hard" ? pill("fail", "danger") : pill("warn", "review")}</td><td>${esc(c.detail || "")}</td></tr>`
              )
              .join("")}</tbody></table>`
          : `<div class="vf-empty">Not validated yet.</div>`
      }`;
    body.querySelector('[data-act="run"]').addEventListener("click", (e) =>
      U.busy(e.currentTarget, "Validating…", async () => {
        const r = await api(`/api/tool-drafts/${enc(draft.id)}/validate?for_integrate=true`, { method: "POST", body: "{}" });
        validation = r.validation || null;
        toast(validation && validation.ok ? "Validation passed" : "Validation failed", !(validation && validation.ok));
        await refresh();
      }).catch(fail)
    );
    body.querySelector('[data-act="fix"]').addEventListener("click", (e) =>
      U.busy(e.currentTarget, "Fixing…", async () => {
        const r = await api(`/api/tool-drafts/${enc(draft.id)}/generate/fix`, { method: "POST", body: "{}" });
        invalidatePlan();
        validation = r.validation || validation;
        toast("AI fix applied. Review impl.py, then validate again.");
        await refresh();
      }).catch(fail)
    );
  }

  /* Step 5: integrate (dry-run → diff → apply) */
  function stepIntegrate(body) {
    const status = (draft.meta && draft.meta.status) || "draft";
    if (status === "integrated" || applied) {
      const written = (applied && applied.written) || (draft.meta && draft.meta.integrated_paths) || [];
      body.innerHTML = `
        <div class="dev-applied">
          <p>${pill("integrated", "confirmed")} <b>${esc((applied && applied.tool_name) || draft.id)}</b> was written into package source.</p>
          <ul class="dev-paths">${written.map((p) => `<li class="vf-mono">${esc(p)}</li>`).join("") || '<li class="vf-faint">No paths recorded.</li>'}</ul>
          <p class="dev-hint">Review with <code>git diff</code>, run the tests, then commit or revert. Optional: add the tool to a skill's approved tools in Hunt skills.</p>
        </div>`;
      return;
    }
    if (status === "rejected") {
      body.innerHTML = `<div class="vf-empty">This draft is rejected. It can't be integrated.</div>`;
      return;
    }
    const gate = H.applyGate({ status, dry, stale, overwriteAck });
    const ops = (dry && dry.ops) || [];
    const writes = ops.filter((o) => o.op === "write");
    body.innerHTML = `
      <p class="dev-hint">Dry-run validates at integrate strictness and shows every file Apply would write. Nothing is written until you Apply.</p>
      <div class="dev-actions">
        <button type="button" class="vf-btn vf-btn--primary" data-act="dry">${dry ? "Re-run dry-run" : "Dry-run"}</button>
        ${dry ? `<span class="vf-faint vf-mono" title="plan_hash">plan ${esc(String(dry.plan_hash).slice(0, 12))}</span>` : ""}
        ${stale ? pill("stale: draft changed", "review") : ""}
      </div>
      ${
        dry
          ? `<div class="dev-plan">
              <div class="vf-section-label">${writes.length} file${writes.length === 1 ? "" : "s"} to write · tool <span class="vf-mono">${esc(dry.tool_name || "")}</span></div>
              ${ops
                .map((o) => {
                  const b = H.opBadge(o);
                  return `<details class="dev-op${o.overwrite ? " is-danger" : ""}" ${o.op === "write" ? "open" : ""}>
                    <summary><span class="vf-mono">${esc(o.path)}</span> ${pill(b.label, b.tone)} <span class="vf-faint">${esc(o.description || "")}</span></summary>
                    ${o.op === "write" ? U.diffHtml(H.parseUnifiedDiff(o.diff)) : ""}
                  </details>`;
                })
                .join("")}
              ${
                (dry.overwrites || []).length
                  ? `<label class="dev-check dev-overwrite"><input type="checkbox" id="lab-ow" ${overwriteAck ? "checked" : ""} ${stale ? "disabled" : ""} />
                      I reviewed the diff. Replace the existing file${dry.overwrites.length > 1 ? "s" : ""}: <span class="vf-mono">${dry.overwrites.map(esc).join(", ")}</span></label>`
                  : ""
              }
            </div>`
          : ""
      }
      <div class="dev-apply">
        <button type="button" class="vf-btn vf-btn--danger" data-act="apply" ${gate.enabled ? "" : "disabled"}>Apply: write ${writes.length || ""} file${writes.length === 1 ? "" : "s"} to package source</button>
        <span class="vf-faint">${esc(gate.reason)}</span>
      </div>`;
    body.querySelector('[data-act="dry"]').addEventListener("click", (e) =>
      U.busy(e.currentTarget, "Planning…", async () => {
        dry = await api(`/api/tool-drafts/${enc(draft.id)}/integrate`, {
          method: "POST",
          body: JSON.stringify({ dry_run: true, apply: false }),
        });
        stale = false;
        overwriteAck = false;
        renderWorkspace();
      }).catch((err) => {
        dry = null;
        fail(err);
        renderWorkspace();
      })
    );
    body.querySelector("#lab-ow")?.addEventListener("change", (e) => {
      overwriteAck = e.target.checked;
      renderWorkspace();
    });
    body.querySelector('[data-act="apply"]').addEventListener("click", (e) => apply(e.currentTarget).catch(fail));
  }

  async function apply(btn) {
    const writes = dry.ops.filter((o) => o.op === "write").map((o) => o.path);
    if (!confirm(`Write ${writes.length} file(s) into package source?\n\n${writes.join("\n")}`)) return;
    const ow = dry.overwrites || [];
    if (ow.length && !confirm(`This REPLACES existing file(s):\n\n${ow.join("\n")}\n\nContinue?`)) return;
    try {
      applied = await U.busy(btn, "Writing…", () =>
        api(`/api/tool-drafts/${enc(draft.id)}/integrate`, {
          method: "POST",
          body: JSON.stringify({ apply: true, plan_hash: dry.plan_hash, allow_overwrite: ow.length > 0 && overwriteAck }),
        })
      );
    } catch (err) {
      // 409: plan changed on disk or in the draft since the dry-run.
      stale = true;
      overwriteAck = false;
      renderWorkspace();
      throw err;
    }
    toast(`Integrated ${applied.tool_name || draft.id}`);
    U.catalog(true).catch(() => {});
    window.VFPages.devTools?.reload?.().catch(() => {});
    await refresh();
  }

  /* ---------- draft actions ---------- */

  async function exportDraft() {
    const data = await api(`/api/tool-drafts/${enc(draft.id)}/export`);
    U.downloadJson(`tool_draft_${draft.id}.json`, data);
  }

  async function rejectDraft() {
    const reason = prompt(`Reject draft ${draft.id}? Optional reason:`, "");
    if (reason === null) return;
    await api(`/api/tool-drafts/${enc(draft.id)}/reject`, { method: "POST", body: JSON.stringify({ reason }) });
    toast(`Rejected ${draft.id}`);
    await refresh();
  }

  async function deleteDraft() {
    if (!confirm(`Delete draft ${draft.id}? Integrated files in package source are not touched.`)) return;
    await api(`/api/tool-drafts/${enc(draft.id)}`, { method: "DELETE" });
    toast("Draft deleted");
    draft = null;
    selectedId = null;
    setDirty(false);
    U.setHash("lab", "");
    await load(null);
    renderWorkspace();
  }

  async function onShow(id) {
    try {
      if (!loaded) await load();
      if (id && id !== selectedId) {
        if (guard()) await select(id);
      } else if (!draft && !creating) {
        renderWorkspace();
      } else if (selectedId) {
        U.setHash("lab", selectedId);
      }
    } catch (e) {
      fail(e);
    }
  }

  window.VFPages.devLab = {
    mount,
    render() {},
    onShow,
    onHide() {},
    async reload() {
      await load(selectedId);
      if (selectedId) await select(selectedId, { keepStep: true });
    },
  };
})();
