/**
 * /settings page controller (issue #202).
 *
 * Sections: Connections (hosts + catalog) → Models per role → Validation and MoA
 * → Budgets (per-pair override > global seed) → Sandbox. One Save for the form;
 * dirty state is tracked per section against the last loaded snapshot.
 *
 * API keys are write-only: the server returns api_key_set only, the key input is
 * never prefilled, and a host saved without api_key keeps its stored key.
 * Refresh, verify and optimize run only from their buttons.
 */
(function () {
  const $ = (sel) => document.querySelector(sel);
  const H = window.VFSettingsHelpers;
  const { refKey, parseRefKey } = H;

  const API_MODES = [
    ["chat_completions", "chat-completions"],
    ["responses", "responses"],
    ["messages", "messages"],
  ];

  const DEFAULT_HUNT_PERSPECTIVES = [
    { id: "sink_driven", prompt: "hunt_sink.md", model: "" },
    { id: "dataflow", prompt: "hunt_dataflow.md", model: "" },
    { id: "authz", prompt: "hunt_authz.md", model: "" },
  ];

  const ROLE_SELECTS = [
    ["set-model-recon", "(default)"],
    ["set-model-hunt", "(default)"],
    ["set-model-develop-poc", "(default)"],
    ["set-model-validate", "(same as hunt)"],
  ];

  // Server state from the last GET (or refresh / verify response).
  let saved = {};
  let available = [];
  // Session-only verify failures: { refKey: error }. The server does not persist them.
  const failures = {};
  // Form body right after the last load / save. Dirty = differs from this.
  let baseline = null;
  let savedAt = "";
  let busy = false;

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
      } catch {
        /* ignore */
      }
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    if (r.status === 204) return null;
    return r.json();
  }

  function toast(msg, bad) {
    if (typeof window.toast === "function") return window.toast(msg, bad);
    console[bad ? "error" : "log"](msg);
  }

  function el(tag, props, children) {
    const node = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => {
      if (v == null) return;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "dataset") Object.assign(node.dataset, v);
      else if (k in node && k !== "list") node[k] = v;
      else node.setAttribute(k, v);
    });
    (children || []).forEach((c) => c && node.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
    return node;
  }

  function cssEscape(value) {
    if (window.CSS && CSS.escape) return CSS.escape(String(value));
    return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  function hostUrl(hostId) {
    const h = (saved.hosts || []).find((x) => x.id === hostId);
    return (h && h.base_url) || hostId;
  }

  function refLabel(ref) {
    return `${hostUrl(ref.host_id)} · ${ref.model_id}`;
  }

  // ---------- Hosts ----------

  function modeSelect(selected) {
    const select = el("select", { class: "settings-select", "aria-label": "API mode" });
    select.dataset.field = "api_mode";
    API_MODES.forEach(([value, label]) => select.appendChild(el("option", { value, text: label })));
    const want = selected || "chat_completions";
    select.value = want;
    if (select.value !== want) select.value = "chat_completions";
    return select;
  }

  function hostRow(host) {
    const row = el("div", { class: "vfs-host host-row" });
    if (host?.id) row.dataset.hostId = host.id;

    const url = el("input", {
      autocomplete: "off",
      placeholder: "http://127.0.0.1:1234/v1 or 10.0.0.232:1234",
      value: host?.base_url || "",
      "aria-label": "Host base URL",
    });
    url.dataset.field = "base_url";

    // Never prefilled: the server does not send keys.
    const keySet = !!host?.api_key_set;
    const key = el("input", {
      type: "password",
      autocomplete: "new-password",
      placeholder: keySet ? "stored — leave blank to keep" : "blank or none",
      value: "",
      "aria-label": "API key",
    });
    key.dataset.field = "api_key";

    const keyState = el("span", {
      class: keySet ? "vf-pill vf-pill--confirmed" : "vf-pill",
      text: keySet ? "key set" : host?.id ? "no key" : "new",
    });
    keyState.dataset.role = "key-state";

    const actions = el("div", { class: "vfs-host-actions" });
    if (keySet) {
      const clear = el("button", {
        type: "button",
        class: "vf-btn vf-btn--ghost vfs-btn-sm",
        text: "Clear key",
        title: "Remove the stored API key on Save",
      });
      clear.dataset.action = "clear-host-key";
      actions.appendChild(clear);
    }
    const remove = el("button", { type: "button", class: "vf-btn vf-btn--ghost vfs-btn-sm", text: "Remove" });
    remove.dataset.action = "remove-host";
    actions.appendChild(remove);

    row.append(
      el("div", { class: "field vfs-host-url" }, [el("label", { class: "field-label", text: "Base URL or host:port" }), url]),
      el("div", { class: "field vfs-host-mode" }, [el("label", { class: "field-label", text: "API mode" }), modeSelect(host?.api_mode)]),
      el("div", { class: "field vfs-host-key" }, [
        el("label", { class: "field-label" }, ["API key ", keyState]),
        key,
      ]),
      actions
    );
    return row;
  }

  function renderHosts(hosts) {
    const list = $("#set-hosts");
    if (!list) return;
    list.replaceChildren();
    (hosts || []).forEach((host) => list.appendChild(hostRow(host)));
    if (!(hosts || []).length) {
      list.appendChild(el("p", { class: "vf-empty", dataset: { role: "hosts-empty" }, text: "No hosts yet. Add one, then Save." }));
    }
  }

  function readHosts() {
    const out = [];
    document.querySelectorAll("#set-hosts .host-row").forEach((row) => {
      const base_url = row.querySelector("[data-field=base_url]")?.value.trim() || "";
      if (!base_url) return;
      const host = {
        base_url,
        api_mode: row.querySelector("[data-field=api_mode]")?.value || "chat_completions",
      };
      // Omit api_key to keep the stored key; send "" only on an explicit Clear (or a new host).
      const typed = (row.querySelector("[data-field=api_key]")?.value ?? "").trim();
      if (typed) host.api_key = typed;
      else if (row.dataset.clearKey === "1" || !row.dataset.hostId) host.api_key = "";
      if (row.dataset.hostId) host.id = row.dataset.hostId;
      out.push(host);
    });
    return out;
  }

  // ---------- Catalog ----------

  const STATE_PILL = {
    verified: "vf-pill vf-pill--confirmed",
    failing: "vf-pill vfs-pill--bad",
    unchecked: "vf-pill",
  };

  function renderCatalog() {
    const root = $("#set-catalog");
    if (!root) return;
    root.replaceChildren();
    const hosts = saved.hosts || [];
    const catalog = saved.catalog || [];
    const verified = new Set(available.map((ref) => refKey(ref)));
    if (!hosts.length) {
      root.appendChild(el("p", { class: "vf-empty", text: "Save a host to list its models." }));
      return;
    }
    hosts.forEach((host) => {
      const rows = catalog.filter((row) => row.host_id === host.id);
      const sum = H.catalogSummary(rows, verified, failures);
      const counts = el("span", { class: "vfs-counts" });
      if (sum.verified) counts.appendChild(el("span", { class: STATE_PILL.verified, text: `${sum.verified} verified` }));
      if (sum.failing) counts.appendChild(el("span", { class: STATE_PILL.failing, text: `${sum.failing} failing` }));
      if (sum.unchecked) counts.appendChild(el("span", { class: STATE_PILL.unchecked, text: `${sum.unchecked} unchecked` }));
      const refresh = el("button", { type: "button", class: "vf-btn vfs-btn-sm", text: rows.length ? "Refresh" : "Refresh catalog" });
      refresh.dataset.action = "refresh-catalog";
      refresh.dataset.hostId = host.id;
      const block = el("div", { class: "vfs-cat-host" }, [
        el("div", { class: "vfs-cat-head" }, [
          el("span", { class: "vf-mono vfs-cat-url", text: host.base_url || host.id, title: host.id }),
          counts,
          refresh,
        ]),
      ]);
      if (!rows.length) {
        block.appendChild(el("p", { class: "vf-empty", text: "No models listed yet. Click Refresh catalog." }));
      } else {
        const list = el("ul", { class: "vfs-cat-list" });
        rows.forEach((row) => {
          const key = refKey(row);
          const state = H.pairState(row, verified, failures);
          const verify = el("button", {
            type: "button",
            class: "vf-btn vf-btn--ghost vfs-btn-sm",
            text: state === "unchecked" ? "Verify" : "Re-verify",
          });
          verify.dataset.action = "verify-model";
          verify.dataset.hostId = host.id;
          verify.dataset.modelId = row.model_id;
          const li = el("li", { class: "vfs-cat-row", dataset: { state } }, [
            el("span", { class: "vf-mono vfs-cat-model", text: row.model_id }),
            el("span", { class: STATE_PILL[state], text: state }),
            verify,
          ]);
          if (state === "failing") {
            li.appendChild(el("span", { class: "vfs-cat-error", text: String(failures[key] || "verify failed") }));
          }
          list.appendChild(li);
        });
        block.appendChild(list);
      }
      root.appendChild(block);
    });
  }

  // ---------- Roles ----------

  function fillRoleSelect(select, selected, allowEmpty, blankLabel) {
    if (!select) return;
    const current = refKey(selected);
    select.replaceChildren();
    const blankText = allowEmpty
      ? blankLabel || "(default)"
      : available.length
        ? "Select a verified model"
        : "No verified models";
    select.appendChild(el("option", { value: "", text: blankText }));
    available.forEach((ref) => select.appendChild(el("option", { value: refKey(ref), text: refLabel(ref) })));
    select.value = current;
    if (select.value !== current) select.value = "";
  }

  function refreshRoleOptions() {
    fillRoleSelect($("#set-model"), parseRefKey($("#set-model")?.value || ""), false);
    ROLE_SELECTS.forEach(([id, blank]) => {
      const node = document.getElementById(id);
      fillRoleSelect(node, parseRefKey(node?.value || ""), true, blank);
    });
    document.querySelectorAll("#set-hunt-perspectives [data-field=model]").forEach((select) => {
      fillRoleSelect(select, parseRefKey(select.value), true, "(hunt model)");
    });
    renderValidatePicks(readValidateRefs());
  }

  // ---------- Validation ----------

  function renderValidatePicks(selected) {
    const box = $("#set-validate-models");
    if (!box) return;
    const chosen = new Set((selected || []).map((ref) => refKey(ref)).filter(Boolean));
    box.replaceChildren();
    if (!available.length) {
      box.appendChild(el("p", { class: "vf-empty", text: "Verify a model to add it here." }));
      updateValidateWarn();
      return;
    }
    available.forEach((ref) => {
      const input = el("input", { type: "checkbox", value: refKey(ref), checked: chosen.has(refKey(ref)) });
      box.appendChild(el("label", { class: "vfs-check" }, [input, el("span", { class: "vf-mono", text: refLabel(ref) })]));
    });
    updateValidateWarn();
  }

  function readValidateRefs() {
    const out = [];
    document.querySelectorAll("#set-validate-models input[type=checkbox]:checked").forEach((input) => {
      const ref = parseRefKey(input.value);
      if (ref) out.push(ref);
    });
    return out;
  }

  function selectedRoleKey(id) {
    const node = document.getElementById(id);
    return refKey(parseRefKey(node?.value || "") || {});
  }

  function updateValidateWarn() {
    const warn = $("#set-validate-models-warn");
    if (!warn) return;
    const text = H.validateWarning({
      checked: readValidateRefs().map((ref) => refKey(ref)),
      dedicated: selectedRoleKey("set-model-validate"),
      hunt: selectedRoleKey("set-model-hunt"),
      defaultRole: selectedRoleKey("set-model"),
    });
    warn.hidden = !text;
    warn.textContent = text;
  }

  function huntPerspectiveRow(slot) {
    const idInput = el("input", {
      class: "mono",
      autocomplete: "off",
      placeholder: "sink_driven",
      value: slot?.id || "",
      "aria-label": "Perspective id",
    });
    idInput.dataset.field = "id";
    idInput.dataset.prev = idInput.value.trim();

    const modelSelect = el("select", { class: "settings-select", "aria-label": "Perspective model" });
    modelSelect.dataset.field = "model";
    fillRoleSelect(modelSelect, slot?.model, true, "(hunt model)");

    const promptInput = el("input", { type: "hidden", value: slot?.prompt || H.defaultHuntPrompt(idInput.value, DEFAULT_HUNT_PERSPECTIVES) });
    promptInput.dataset.field = "prompt";

    const remove = el("button", { type: "button", class: "vf-btn vf-btn--ghost vfs-btn-sm", text: "Remove", "aria-label": "Remove perspective" });
    remove.dataset.action = "remove";

    idInput.addEventListener("input", () => {
      const prev = idInput.dataset.prev || "";
      const cur = promptInput.value.trim();
      const auto = !cur || cur === H.defaultHuntPrompt(prev, DEFAULT_HUNT_PERSPECTIVES) || cur === `hunt_${prev}.md`;
      if (auto) promptInput.value = H.defaultHuntPrompt(idInput.value.trim(), DEFAULT_HUNT_PERSPECTIVES);
      idInput.dataset.prev = idInput.value.trim();
    });

    return el("div", { class: "vfs-persp-row hunt-perspective-row" }, [
      el("div", { class: "field" }, [idInput]),
      el("div", { class: "field" }, [modelSelect]),
      promptInput,
      remove,
    ]);
  }

  function readHuntPerspectives() {
    const out = [];
    document.querySelectorAll("#set-hunt-perspectives .hunt-perspective-row").forEach((row) => {
      const id = row.querySelector("[data-field=id]")?.value.trim() || "";
      if (!id) return;
      out.push({
        id,
        model: parseRefKey(row.querySelector("[data-field=model]")?.value || "") || "",
        prompt: row.querySelector("[data-field=prompt]")?.value.trim() || "",
      });
    });
    return out;
  }

  function updateHuntModelWarn() {
    const warn = $("#set-hunt-perspectives-warn");
    if (!warn) return;
    const text = H.perspectiveWarning(readHuntPerspectives());
    warn.hidden = !text;
    warn.textContent = text;
  }

  function renderHuntPerspectives(slots) {
    const list = $("#set-hunt-perspectives");
    if (!list) return;
    list.replaceChildren();
    (Array.isArray(slots) ? slots : []).forEach((slot) => list.appendChild(huntPerspectiveRow(slot)));
    updateHuntModelWarn();
  }

  function perspectiveSlotsForForm(s, eff) {
    const own = Array.isArray(s?.hunt_perspectives) ? s.hunt_perspectives : [];
    if (own.length) return own;
    const fromEff = Array.isArray(eff?.hunt_perspectives) ? eff.hunt_perspectives : [];
    if (fromEff.length) {
      return fromEff.map((p) => ({
        id: p.id || "",
        prompt: p.prompt || "",
        model: p.model && typeof p.model === "object" ? p.model : "",
      }));
    }
    return DEFAULT_HUNT_PERSPECTIVES.map((p) => ({ ...p }));
  }

  // ---------- Budgets ----------

  function globalSeeds() {
    return {
      context_tokens: $("#set-ctx")?.value,
      max_tokens: $("#set-maxtok")?.value,
      max_concurrent_agents: $("#set-workers")?.value,
    };
  }

  const BUDGET_COLS = [
    ["context_tokens", "Context window"],
    ["max_tokens", "Max output"],
    ["max_concurrent_agents", "Concurrent agents"],
  ];

  function renderBudgetTable(keepTyped) {
    const body = $("#set-available");
    if (!body) return;
    // Keep numbers the operator typed for rows that still exist (refresh / verify).
    const typed = {};
    if (keepTyped) {
      readAvailableBudgets().forEach((row) => {
        typed[refKey(row)] = row;
      });
    }
    body.replaceChildren();
    if (!available.length) {
      body.appendChild(
        el("tr", {}, [el("td", { colSpan: 5, class: "vf-empty", text: "No verified models yet. Verify one under Connections." })])
      );
      return;
    }
    const rows = H.budgetRowsFromAvailable(available);
    rows.forEach((ref) => {
      const src = typed[refKey(ref)] || ref;
      const tr = el("tr", { class: "vfs-pair-row", dataset: { hostId: ref.host_id, modelId: ref.model_id } });
      if (ref.verified_at) tr.dataset.verifiedAt = ref.verified_at;
      const pick = el("input", { type: "checkbox", "aria-label": `Select ${ref.model_id}` });
      pick.dataset.field = "selected";
      tr.appendChild(el("td", { class: "vfs-col-pick" }, [pick]));
      tr.appendChild(
        el("td", {}, [
          el("div", { class: "vf-mono vfs-pair-model", text: ref.model_id }),
          el("div", { class: "vf-mono vf-faint vfs-pair-host", text: hostUrl(ref.host_id) }),
        ])
      );
      BUDGET_COLS.forEach(([field, label]) => {
        const input = el("input", {
          type: "number",
          min: "1",
          step: "1",
          "aria-label": `${label} for ${ref.host_id} / ${ref.model_id}`,
        });
        input.dataset.field = field;
        if (src[field] != null) input.value = String(src[field]);
        const eff = el("span", { class: "vfs-eff" });
        eff.dataset.effFor = field;
        tr.appendChild(el("td", { class: "field" }, [input, eff]));
      });
      body.appendChild(tr);
    });
    updateBudgetEffective();
  }

  function updateBudgetEffective() {
    const seeds = globalSeeds();
    document.querySelectorAll("#set-available .vfs-pair-row").forEach((tr) => {
      const row = {};
      BUDGET_COLS.forEach(([field]) => {
        row[field] = tr.querySelector(`[data-field=${field}]`)?.value.trim();
      });
      const eff = H.pairBudget(row, seeds);
      BUDGET_COLS.forEach(([field]) => {
        const input = tr.querySelector(`[data-field=${field}]`);
        const seed = seeds[field];
        if (input) input.placeholder = seed ? `${seed}` : "seed";
        const out = tr.querySelector(`[data-eff-for=${field}]`);
        if (!out) return;
        const info = eff[field];
        out.dataset.source = info.source;
        out.textContent = info.source === "pair" ? "override" : "seed";
      });
    });
  }

  function readAvailableBudgets() {
    const out = [];
    document.querySelectorAll("#set-available .vfs-pair-row").forEach((row) => {
      const host_id = row.dataset.hostId || "";
      const model_id = row.dataset.modelId || "";
      if (!host_id || !model_id) return;
      const item = { host_id, model_id };
      if (row.dataset.verifiedAt) item.verified_at = row.dataset.verifiedAt;
      BUDGET_COLS.forEach(([field]) => {
        const raw = row.querySelector(`[data-field=${field}]`)?.value.trim() ?? "";
        const n = raw === "" ? null : parseInt(raw, 10);
        item[field] = Number.isFinite(n) ? n : null;
      });
      out.push(item);
    });
    return out;
  }

  function selectedPairs() {
    const out = [];
    document.querySelectorAll("#set-available .vfs-pair-row").forEach((row) => {
      if (!row.querySelector("[data-field=selected]")?.checked) return;
      const host_id = row.dataset.hostId || "";
      const model_id = row.dataset.modelId || "";
      if (host_id && model_id) out.push({ host_id, model_id });
    });
    return out;
  }

  // ---------- Form body / fill ----------

  function intVal(id, fallback) {
    const n = parseInt($(id)?.value, 10);
    return Number.isFinite(n) ? n : fallback;
  }

  function settingsFormBody() {
    const frac = parseFloat($("#set-frac")?.value);
    return {
      hosts: readHosts(),
      model: parseRefKey($("#set-model")?.value || ""),
      model_recon: parseRefKey($("#set-model-recon")?.value || ""),
      model_hunt: parseRefKey($("#set-model-hunt")?.value || ""),
      model_develop_poc: parseRefKey($("#set-model-develop-poc")?.value || ""),
      model_validate: parseRefKey($("#set-model-validate")?.value || ""),
      validate_models: readValidateRefs(),
      validate_consensus: $("#set-validate-consensus")?.value || "majority",
      validate_poc_referee: !!$("#set-validate-poc-referee")?.checked,
      validate_llm: !!$("#set-validate-llm")?.checked,
      hunt_moa: !!$("#set-hunt-moa")?.checked,
      hunt_perspectives: $("#set-hunt-perspectives") ? readHuntPerspectives() : [],
      max_concurrent_agents: intVal("#set-workers", null),
      context_tokens: intVal("#set-ctx", null),
      max_context_fraction: Number.isFinite(frac) ? frac : null,
      max_tokens: intVal("#set-maxtok", null),
      max_tool_rounds: intVal("#set-rounds", null),
      timeout_seconds: intVal("#set-timeout", null),
      max_tasks: intVal("#set-maxtasks", null),
      poc_iterate_max_cycles: intVal("#set-poc-iterate-cycles", 5),
      poc_iterate_wall_ttl_min: intVal("#set-poc-iterate-ttl", 15),
      available: readAvailableBudgets(),
    };
  }

  function setVal(id, value) {
    const node = $(id);
    if (node) node.value = value;
  }

  function fillForm(s, eff) {
    if (!s) return;
    saved = s;
    available = Array.isArray(s.available) ? s.available : [];
    renderHosts(s.hosts || []);
    renderCatalog();
    fillRoleSelect($("#set-model"), s.model, false);
    fillRoleSelect($("#set-model-recon"), s.model_recon, true);
    fillRoleSelect($("#set-model-hunt"), s.model_hunt, true);
    fillRoleSelect($("#set-model-develop-poc"), s.model_develop_poc, true);
    fillRoleSelect($("#set-model-validate"), s.model_validate, true, "(same as hunt)");
    renderValidatePicks(Array.isArray(s.validate_models) ? s.validate_models.filter((x) => x && typeof x === "object") : []);
    setVal("#set-validate-consensus", s.validate_consensus || "majority");
    if ($("#set-validate-poc-referee")) $("#set-validate-poc-referee").checked = s.validate_poc_referee !== false;
    if ($("#set-validate-llm")) $("#set-validate-llm").checked = s.validate_llm !== false;
    if ($("#set-hunt-moa")) $("#set-hunt-moa").checked = s.hunt_moa === true;
    renderHuntPerspectives(perspectiveSlotsForForm(s, eff));
    setVal("#set-workers", s.max_concurrent_agents || 1);
    setVal("#set-ctx", s.context_tokens || 32768);
    setVal("#set-frac", s.max_context_fraction ?? 0.25);
    setVal("#set-maxtok", s.max_tokens || 4096);
    setVal("#set-rounds", s.max_tool_rounds || 12);
    setVal("#set-timeout", s.timeout_seconds || 600);
    setVal("#set-maxtasks", s.max_tasks || 50);
    setVal("#set-poc-iterate-cycles", s.poc_iterate_max_cycles || 5);
    setVal("#set-poc-iterate-ttl", s.poc_iterate_wall_ttl_min || 15);
    renderBudgetTable(false);
    showEnvOverrides(s, eff || {});
  }

  function showEnvOverrides(s, eff) {
    const note = $("#set-validate-llm-env");
    if (!note) return;
    const differs = eff.validate_llm != null && !!eff.validate_llm !== (s.validate_llm !== false);
    note.hidden = !differs;
    note.textContent = differs
      ? `VF_VALIDATE_LLM env overrides this. Runs use: ${eff.validate_llm ? "on" : "off"}.`
      : "";
  }

  // ---------- Effective summary ----------

  function targetLabel(item) {
    if (item && typeof item === "object") {
      const hid = String(item.host_id || "").trim();
      const mid = String(item.model_id || "").trim();
      if (hid && mid) return `${hid} / ${mid}`;
      return mid || "-";
    }
    return String(item || "").trim() || "-";
  }

  function showEffective(data) {
    const box = $("#settings-effective");
    if (!box) return;
    const eff = data?.effective || {};
    const s = data?.settings || {};
    const targets =
      Array.isArray(eff.validate_targets) && eff.validate_targets.length
        ? eff.validate_targets
        : eff.validate_models && eff.validate_models.length
          ? eff.validate_models
          : [eff.model || "-"];
    const persp = (eff.hunt_perspectives || [])
      .map((p) => {
        const m = p.model && typeof p.model === "object" ? p.model.model_id : String(p.model || "").trim();
        return m ? `${p.id}:${m}` : p.id;
      })
      .join(", ");
    const caps = (s.available || [])
      .filter((r) => r && r.max_concurrent_agents != null && r.max_concurrent_agents !== "")
      .map((r) => `${r.host_id}/${r.model_id}=${r.max_concurrent_agents}`)
      .join(", ");
    const rows = [
      ["Default endpoint", `${eff.base_url || "-"} · ${eff.model || "-"} · ${eff.api_key_set ? "key set" : "no key"}`],
      ["Hunt", targetLabel(eff.hunt_model || eff.model_hunt || eff.model)],
      ["Validate slots", targets.map(targetLabel).join(", ")],
      ["Consensus", eff.validate_consensus || s.validate_consensus || "majority"],
      ["LLM disprove", (eff.validate_llm ?? s.validate_llm) ? "on" : "off"],
      ["PoC referee", (eff.validate_poc_referee ?? s.validate_poc_referee) ? "on" : "off"],
      ["Hunt MoA", `${(eff.hunt_moa ?? s.hunt_moa) === true ? "on" : "off"}${persp ? ` [${persp}]` : ""}`],
      ["Lease workers", `${eff.max_leases_parallel || 1} global · pair caps ${caps || "none"}`],
      ["Context", `${eff.context_tokens ?? "-"} × ${eff.max_context_fraction ?? "-"} · max output ${eff.max_tokens ?? "-"}`],
      ["Sandbox iterate", `${eff.poc_iterate_max_cycles ?? s.poc_iterate_max_cycles ?? 5} cycles / ${eff.poc_iterate_wall_ttl_min ?? s.poc_iterate_wall_ttl_min ?? 15} min`],
    ];
    box.replaceChildren();
    rows.forEach(([k, v]) => {
      box.appendChild(el("dt", { text: k }));
      box.appendChild(el("dd", { class: "vf-mono", text: v }));
    });
  }

  // ---------- Dirty / save state ----------

  const SECTION_LABEL = {
    connections: "Connections",
    roles: "Roles",
    validation: "Validation",
    budgets: "Budgets",
    sandbox: "Sandbox",
  };

  function currentDirty() {
    if (!baseline) return [];
    return H.dirtySections(baseline, settingsFormBody());
  }

  const IMPACT_WHY = {
    removed: "removed",
    url: "URL changed",
    key: "API key changed",
    mode: "API mode changed",
  };

  /** Server drops verification on host edits; say so before Save, not after. */
  function updateHostImpact() {
    const impact = H.hostEditImpact(saved.hosts || [], readHosts(), available);
    const note = $("#set-hosts-impact");
    if (note) {
      note.hidden = !impact.length;
      note.textContent = impact.length
        ? "Saving resets verification: " +
          impact
            .map((i) => `${i.base_url} (${IMPACT_WHY[i.reason]}): ${i.pairs} verified model${i.pairs === 1 ? "" : "s"}`)
            .join("; ") +
          ". Verify them again afterwards. Roles that use them go back to blank."
        : "";
    }
    return impact.reduce((n, i) => n + i.pairs, 0);
  }

  function updateDirty() {
    const dirty = currentDirty();
    const impacted = updateHostImpact();
    const resets = dirty.includes("connections") ? impacted : 0;
    document.querySelectorAll(".vfs-section[data-section]").forEach((section) => {
      const flag = section.querySelector(".vfs-dirty");
      if (flag) flag.hidden = !dirty.includes(section.dataset.section);
    });
    document.querySelectorAll(".vfs-nav a[data-section]").forEach((a) => {
      a.classList.toggle("is-dirty", dirty.includes(a.dataset.section));
    });
    const state = $("#settings-save-state");
    const save = $("#settings-save");
    const discard = $("#settings-discard");
    if (save) save.disabled = busy || !dirty.length;
    if (discard) discard.disabled = busy || !dirty.length;
    if (!state) return;
    const text = state.querySelector(".text");
    if (busy) {
      state.dataset.state = "busy";
      text.textContent = "Saving…";
    } else if (dirty.length) {
      state.dataset.state = "dirty";
      text.textContent =
        `Unsaved changes: ${dirty.map((d) => SECTION_LABEL[d] || d).join(", ")}` +
        (resets ? ` · re-verify ${resets} model${resets === 1 ? "" : "s"} after save` : "");
    } else {
      state.dataset.state = "clean";
      text.textContent = savedAt ? `All changes saved · ${savedAt}` : "No unsaved changes";
    }
  }

  function snapshot() {
    baseline = settingsFormBody();
    updateDirty();
  }

  function stampSaved(s) {
    const iso = s?.updated_at;
    if (!iso) return;
    const d = new Date(iso);
    savedAt = Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
  }

  async function loadSettings() {
    try {
      const data = await api("/api/settings");
      fillForm(data.settings || {}, data.effective || {});
      showEffective(data);
      stampSaved(data.settings);
      snapshot();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  /**
   * Apply a refresh / verify response without wiping unsaved edits. Keys the
   * operator had not touched follow the server; touched keys stay dirty.
   */
  async function applyServerCatalog(settings) {
    const before = settingsFormBody();
    saved = { ...saved, catalog: settings.catalog || [], available: settings.available || [] };
    available = saved.available;
    renderCatalog();
    refreshRoleOptions();
    renderBudgetTable(true);
    // Pick up any role the server cleared while dropping a pair.
    const after = settingsFormBody();
    baseline = H.rebaseline(baseline, before, after);
    try {
      showEffective(await api("/api/settings"));
    } catch {
      /* summary only */
    }
    updateDirty();
  }

  async function saveSettings(ev) {
    if (ev) ev.preventDefault();
    if (busy) return;
    const body = settingsFormBody();
    busy = true;
    updateDirty();
    let ok = false;
    try {
      await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
      const again = await api("/api/settings");
      fillForm(again?.settings || {}, again?.effective || {});
      showEffective(again);
      stampSaved(again?.settings);
      ok = true;
      toast("Settings saved");
    } catch (e) {
      // A failed save keeps the operator's edits and their dirty markers.
      toast(e.message || String(e), true);
    } finally {
      busy = false;
      if (ok) snapshot();
      else updateDirty();
    }
  }

  async function discardChanges() {
    if (!currentDirty().length) return;
    if (!window.confirm("Discard unsaved settings changes?")) return;
    await loadSettings();
  }

  function setBusyButton(btn, text) {
    if (!btn) return () => {};
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = text;
    return () => {
      btn.disabled = false;
      btn.textContent = prev;
    };
  }

  function hostsDirty() {
    return currentDirty().includes("connections");
  }

  async function refreshCatalog(hostId, btn) {
    if (!hostId) {
      toast("Save the host first", true);
      return;
    }
    if (hostsDirty()) {
      toast("Save host changes first. Refresh uses the saved URL and key.", true);
      return;
    }
    const done = setBusyButton(btn, "Refreshing…");
    try {
      const data = await api(`/api/settings/hosts/${encodeURIComponent(hostId)}/catalog`, { method: "POST", body: "{}" });
      if (!data.ok) {
        toast(data.error || "Refresh failed", true);
        return;
      }
      toast(`Catalog: ${(data.models || []).length} model(s)`);
      await applyServerCatalog(data.settings || {});
    } catch (e) {
      toast(e.message || String(e), true);
    } finally {
      done();
    }
  }

  async function verifyModel(hostId, modelId, btn) {
    if (hostsDirty()) {
      toast("Save host changes first. Verify uses the saved URL and key.", true);
      return;
    }
    const key = refKey({ host_id: hostId, model_id: modelId });
    const done = setBusyButton(btn, "Verifying…");
    try {
      const data = await api(`/api/settings/hosts/${encodeURIComponent(hostId)}/verify`, {
        method: "POST",
        body: JSON.stringify({ model_id: modelId }),
      });
      if (!data.ok) {
        failures[key] = data.error || "verify failed";
        toast(`Verify failed: ${modelId}`, true);
        renderCatalog();
        return;
      }
      delete failures[key];
      toast(`Verified ${modelId}`);
      await applyServerCatalog(data.settings || {});
    } catch (e) {
      failures[key] = e.message || String(e);
      renderCatalog();
      toast(e.message || String(e), true);
    } finally {
      done();
    }
  }

  // ---------- Optimize ----------

  function applyPairRecommendations(data) {
    for (const row of data.targets || []) {
      if (!row || !row.ok) continue;
      const tr = document.querySelector(
        `#set-available .vfs-pair-row[data-host-id="${cssEscape(row.host_id)}"][data-model-id="${cssEscape(row.model_id)}"]`
      );
      if (!tr) continue;
      const ctx = tr.querySelector("[data-field=context_tokens]");
      const maxTok = tr.querySelector("[data-field=max_tokens]");
      if (ctx && row.context_tokens != null) ctx.value = String(row.context_tokens);
      if (maxTok && row.max_tokens != null) maxTok.value = String(row.max_tokens);
    }
    updateBudgetEffective();
    updateDirty();
  }

  function formatSelectedReport(data) {
    const lines = [];
    if (data.summary) lines.push(data.summary);
    if (data.error && !(data.targets || []).length) lines.push("Error: " + data.error);
    for (const row of data.targets || []) {
      const name = `${row.host_id} · ${row.model_id}`;
      if (!row.ok) {
        lines.push(`${name}: ${row.error || "failed"}`);
        continue;
      }
      lines.push(`${name}: context window ${row.context_tokens} (${row.context_source || "heuristic"}), max output ${row.max_tokens}`);
      for (const w of row.warnings || []) lines.push(`  ⚠ ${w}`);
    }
    lines.push("Review the values, then Save to keep them.");
    return lines.join("\n");
  }

  async function optimizeSettings() {
    const report = $("#settings-optimize-report");
    const targets = selectedPairs();
    if (!targets.length) {
      toast("Select a verified model", true);
      return;
    }
    const done = setBusyButton($("#settings-optimize"), "Optimizing…");
    if (report) {
      report.hidden = false;
      report.textContent = `Probing ${targets.length} selected model${targets.length === 1 ? "" : "s"}…`;
    }
    try {
      const data = await api("/api/settings/optimize", { method: "POST", body: JSON.stringify({ targets, apply: false }) });
      applyPairRecommendations(data);
      if (report) report.textContent = formatSelectedReport(data);
      toast(data.ok ? "Budgets filled. Review, then Save" : data.error || "Optimize failed", !data.ok);
    } catch (e) {
      if (report) report.textContent = String(e.message || e);
      toast(e.message || String(e), true);
    } finally {
      done();
    }
  }

  // ---------- Boot ----------

  function boot() {
    if (document.body?.dataset?.page !== "settings") return;
    const form = $("#settings-form");
    loadSettings();
    form?.addEventListener("submit", saveSettings);
    // Any edit re-checks dirty state and the dependent warnings.
    form?.addEventListener("input", (ev) => {
      if (ev.target.closest?.("#settings-budget")) updateBudgetEffective();
      if (ev.target.closest?.("#set-hunt-perspectives")) updateHuntModelWarn();
      updateDirty();
    });
    form?.addEventListener("change", (ev) => {
      if (ev.target.closest?.("#settings-roles, #set-validate-models")) updateValidateWarn();
      if (ev.target.closest?.("#set-hunt-perspectives")) updateHuntModelWarn();
      updateDirty();
    });
    $("#settings-discard")?.addEventListener("click", discardChanges);
    $("#settings-optimize")?.addEventListener("click", optimizeSettings);
    $("#set-host-add")?.addEventListener("click", () => {
      $("#set-hosts [data-role=hosts-empty]")?.remove();
      const row = hostRow({});
      $("#set-hosts")?.appendChild(row);
      row.querySelector("[data-field=base_url]")?.focus();
      updateDirty();
    });
    $("#set-hosts")?.addEventListener("click", (ev) => {
      const clear = ev.target.closest?.("[data-action=clear-host-key]");
      if (clear) {
        const row = clear.closest(".host-row");
        if (row) row.dataset.clearKey = "1";
        const input = row?.querySelector("[data-field=api_key]");
        if (input) {
          input.value = "";
          input.placeholder = "key will be removed on Save";
        }
        const pill = row?.querySelector("[data-role=key-state]");
        if (pill) {
          pill.className = "vf-pill vf-pill--review";
          pill.textContent = "clear on save";
        }
        clear.disabled = true;
        updateDirty();
        return;
      }
      const btn = ev.target.closest?.("[data-action=remove-host]");
      if (!btn) return;
      btn.closest(".host-row")?.remove();
      updateDirty();
    });
    $("#set-catalog")?.addEventListener("click", (ev) => {
      const refresh = ev.target.closest?.("[data-action=refresh-catalog]");
      if (refresh) {
        refreshCatalog(refresh.dataset.hostId || "", refresh);
        return;
      }
      const verify = ev.target.closest?.("[data-action=verify-model]");
      if (verify) verifyModel(verify.dataset.hostId || "", verify.dataset.modelId || "", verify);
    });
    $("#set-hunt-perspective-add")?.addEventListener("click", () => {
      $("#set-hunt-perspectives")?.appendChild(huntPerspectiveRow({ id: "", prompt: "", model: "" }));
      updateDirty();
    });
    $("#set-hunt-perspectives")?.addEventListener("click", (ev) => {
      const btn = ev.target.closest?.("[data-action=remove]");
      if (!btn) return;
      btn.closest(".hunt-perspective-row")?.remove();
      updateHuntModelWarn();
      updateDirty();
    });
    document.addEventListener("keydown", (ev) => {
      if ((ev.ctrlKey || ev.metaKey) && !ev.shiftKey && !ev.altKey && ev.key.toLowerCase() === "s") {
        ev.preventDefault();
        if (currentDirty().length) form?.requestSubmit();
      }
    });
    window.addEventListener("beforeunload", (ev) => {
      if (!currentDirty().length) return;
      ev.preventDefault();
      ev.returnValue = "";
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  window.VFSettingsPage = {
    loadSettings,
    saveSettings,
    settingsFormBody,
    fillForm,
    refreshRoleOptions,
  };
})();
