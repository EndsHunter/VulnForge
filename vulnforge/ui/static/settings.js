/**
 * Dedicated /settings page — hosts, catalog verify, role pickers, per-model budgets.
 * Refresh, verify, and optimize run only from their buttons.
 */
(function () {
  const $ = (sel) => document.querySelector(sel);

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

  let available = [];

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

  function refKey(ref) {
    if (!ref || typeof ref !== "object") return "";
    const hid = String(ref.host_id || "").trim();
    const mid = String(ref.model_id || "").trim();
    if (!hid || !mid) return "";
    return `${encodeURIComponent(hid)}|${encodeURIComponent(mid)}`;
  }

  function parseRefKey(value) {
    const raw = String(value || "");
    const cut = raw.indexOf("|");
    if (cut < 0) return null;
    const host_id = decodeURIComponent(raw.slice(0, cut));
    const model_id = decodeURIComponent(raw.slice(cut + 1));
    if (!host_id || !model_id) return null;
    return { host_id, model_id };
  }

  function refLabel(ref) {
    const host = (availableHost(ref.host_id) || {}).base_url || ref.host_id;
    return `${host} · ${ref.model_id}`;
  }

  function availableHost(hostId) {
    const row = document.querySelector(`.host-row[data-host-id="${cssEscape(hostId)}"]`);
    if (!row) return null;
    return {
      id: hostId,
      base_url: row.querySelector("[data-field=base_url]")?.value.trim() || "",
    };
  }

  function cssEscape(value) {
    if (window.CSS && CSS.escape) return CSS.escape(String(value));
    return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  function defaultHuntPrompt(id) {
    const pid = String(id || "").trim();
    const known = DEFAULT_HUNT_PERSPECTIVES.find((row) => row.id === pid);
    if (known) return known.prompt;
    const safe = pid.replace(/[^A-Za-z0-9_-]/g, "_").replace(/^_+|_+$/g, "");
    return `hunt_${safe || "perspective"}.md`;
  }

  function modeSelect(selected) {
    const select = document.createElement("select");
    select.className = "settings-select";
    select.dataset.field = "api_mode";
    select.setAttribute("aria-label", "API mode");
    API_MODES.forEach(([value, label]) => {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = label;
      select.appendChild(opt);
    });
    select.value = selected || "chat_completions";
    if (select.value !== (selected || "chat_completions")) select.value = "chat_completions";
    return select;
  }

  function hostRow(host) {
    const row = document.createElement("div");
    row.className = "host-row";
    if (host?.id) row.dataset.hostId = host.id;

    const urlField = document.createElement("div");
    urlField.className = "field";
    const urlLabel = document.createElement("label");
    urlLabel.className = "field-label";
    urlLabel.textContent = "Base URL or host:port";
    const url = document.createElement("input");
    url.dataset.field = "base_url";
    url.autocomplete = "off";
    url.placeholder = "http://127.0.0.1:1234/v1 or 10.0.0.232:1234";
    url.value = host?.base_url || "";
    url.setAttribute("aria-label", "Host base URL");
    urlField.appendChild(urlLabel);
    urlField.appendChild(url);

    const modeField = document.createElement("div");
    modeField.className = "field";
    const modeLabel = document.createElement("label");
    modeLabel.className = "field-label";
    modeLabel.textContent = "API mode";
    modeField.appendChild(modeLabel);
    modeField.appendChild(modeSelect(host?.api_mode));

    const keyField = document.createElement("div");
    keyField.className = "field";
    const keyLabel = document.createElement("label");
    keyLabel.className = "field-label";
    keyLabel.textContent = "API key";
    const key = document.createElement("input");
    key.type = "password";
    key.dataset.field = "api_key";
    key.autocomplete = "off";
    key.placeholder = "blank or none";
    key.value = host?.api_key || "";
    key.setAttribute("aria-label", "API key");
    keyField.appendChild(keyLabel);
    keyField.appendChild(key);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn";
    remove.dataset.action = "remove-host";
    remove.textContent = "Remove";

    row.appendChild(urlField);
    row.appendChild(modeField);
    row.appendChild(keyField);
    row.appendChild(remove);
    return row;
  }

  function readHosts() {
    const out = [];
    document.querySelectorAll("#set-hosts .host-row").forEach((row) => {
      const base_url = row.querySelector("[data-field=base_url]")?.value.trim() || "";
      if (!base_url) return;
      const host = {
        base_url,
        api_mode: row.querySelector("[data-field=api_mode]")?.value || "chat_completions",
        api_key: row.querySelector("[data-field=api_key]")?.value ?? "",
      };
      if (row.dataset.hostId) host.id = row.dataset.hostId;
      out.push(host);
    });
    return out;
  }

  function fillRoleSelect(select, selected, allowEmpty) {
    if (!select) return;
    const current = refKey(selected);
    select.replaceChildren();
    if (allowEmpty) {
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = "(default)";
      select.appendChild(blank);
    } else {
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = available.length ? "Select a verified model" : "No verified models";
      select.appendChild(blank);
    }
    available.forEach((ref) => {
      const opt = document.createElement("option");
      opt.value = refKey(ref);
      opt.textContent = refLabel(ref);
      select.appendChild(opt);
    });
    select.value = current;
    if (select.value !== current) select.value = "";
  }

  function renderValidatePicks(selected) {
    const box = $("#set-validate-models");
    if (!box) return;
    const chosen = new Set((selected || []).map((ref) => refKey(ref)).filter(Boolean));
    box.replaceChildren();
    if (!available.length) {
      const empty = document.createElement("p");
      empty.className = "controls-hint";
      empty.textContent = "Verify a model to add it here.";
      box.appendChild(empty);
      return;
    }
    available.forEach((ref) => {
      const label = document.createElement("label");
      label.className = "settings-check";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = refKey(ref);
      input.checked = chosen.has(refKey(ref));
      input.addEventListener("change", () => updateValidateWarn());
      label.appendChild(input);
      const text = document.createElement("span");
      text.textContent = refLabel(ref);
      label.appendChild(text);
      box.appendChild(label);
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

  function huntPerspectiveRow(slot) {
    const row = document.createElement("div");
    row.className = "hunt-perspective-row";
    const idField = document.createElement("div");
    idField.className = "field";
    const idInput = document.createElement("input");
    idInput.className = "mono";
    idInput.dataset.field = "id";
    idInput.setAttribute("aria-label", "Perspective id");
    idInput.autocomplete = "off";
    idInput.placeholder = "sink_driven";
    idInput.value = slot?.id || "";
    idInput.dataset.prev = idInput.value.trim();
    idField.appendChild(idInput);

    const modelField = document.createElement("div");
    modelField.className = "field";
    const modelSelect = document.createElement("select");
    modelSelect.className = "settings-select";
    modelSelect.dataset.field = "model";
    modelSelect.setAttribute("aria-label", "Perspective model");
    fillRoleSelect(modelSelect, slot?.model, true);
    const blank = modelSelect.querySelector("option[value='']");
    if (blank) blank.textContent = "(hunt model)";
    modelField.appendChild(modelSelect);

    const promptInput = document.createElement("input");
    promptInput.type = "hidden";
    promptInput.dataset.field = "prompt";
    promptInput.value = slot?.prompt || defaultHuntPrompt(idInput.value);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn";
    remove.dataset.action = "remove";
    remove.textContent = "Remove";
    remove.setAttribute("aria-label", "Remove perspective");

    row.appendChild(idField);
    row.appendChild(modelField);
    row.appendChild(promptInput);
    row.appendChild(remove);

    idInput.addEventListener("input", () => {
      const prev = idInput.dataset.prev || "";
      const cur = promptInput.value.trim();
      const auto = !cur || cur === defaultHuntPrompt(prev) || cur === `hunt_${prev}.md`;
      if (auto) promptInput.value = defaultHuntPrompt(idInput.value.trim());
      idInput.dataset.prev = idInput.value.trim();
      updateHuntModelWarn(readHuntPerspectives());
    });
    modelSelect.addEventListener("change", () => updateHuntModelWarn(readHuntPerspectives()));
    return row;
  }

  function readHuntPerspectives() {
    const rows = document.querySelectorAll("#set-hunt-perspectives .hunt-perspective-row");
    const out = [];
    rows.forEach((row) => {
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

  function renderHuntPerspectives(slots) {
    const list = $("#set-hunt-perspectives");
    if (!list) return;
    list.replaceChildren();
    (Array.isArray(slots) ? slots : []).forEach((slot) => list.appendChild(huntPerspectiveRow(slot)));
    updateHuntModelWarn(readHuntPerspectives());
  }

  function refreshRoleOptions() {
    fillRoleSelect($("#set-model"), parseRefKey($("#set-model")?.value || ""), false);
    ["set-model-recon", "set-model-hunt", "set-model-develop-poc"].forEach((id) => {
      const el = document.getElementById(id);
      fillRoleSelect(el, parseRefKey(el?.value || ""), true);
    });
    document.querySelectorAll("#set-hunt-perspectives [data-field=model]").forEach((select) => {
      const current = parseRefKey(select.value);
      fillRoleSelect(select, current, true);
      const blank = select.querySelector("option[value='']");
      if (blank) blank.textContent = "(hunt model)";
    });
    const checked = readValidateRefs();
    renderValidatePicks(checked);
  }

  function perspectiveSlotsForForm(s, eff) {
    const saved = Array.isArray(s?.hunt_perspectives) ? s.hunt_perspectives : [];
    if (saved.length) return saved;
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

  function modelKey(ref) {
    if (!ref) return "";
    if (typeof ref === "object") return refKey(ref);
    return String(ref || "").trim().toLowerCase();
  }

  function updateHuntModelWarn(slots) {
    const warn = $("#set-hunt-perspectives-warn");
    if (!warn) return;
    const list = Array.isArray(slots) ? slots : [];
    const explicit = list.map((s) => modelKey(s.model)).filter(Boolean);
    const uniq = [...new Set(explicit)];
    if (explicit.length >= 2 && explicit.length === list.length && uniq.length <= 1) {
      warn.hidden = false;
      warn.textContent = "Same model on every hunt perspective is a weak signal.";
    } else {
      warn.hidden = true;
      warn.textContent = "";
    }
  }

  function updateValidateWarn() {
    const warn = $("#set-validate-models-warn");
    if (!warn) return;
    const refs = readValidateRefs();
    const keys = refs.map((ref) => ref.model_id.toLowerCase());
    const uniq = [...new Set(keys)];
    if (refs.length === 0 || uniq.length <= 1) {
      warn.hidden = false;
      warn.textContent =
        "Same-model disprove is a weak signal. Add a second validation model when you can.";
    } else {
      warn.hidden = true;
      warn.textContent = "";
    }
  }

  function renderHosts(hosts) {
    const list = $("#set-hosts");
    if (!list) return;
    list.replaceChildren();
    (hosts || []).forEach((host) => list.appendChild(hostRow(host)));
  }

  function renderCatalog(settings) {
    const root = $("#set-catalog");
    const avail = $("#set-available");
    if (!root || !avail) return;
    root.replaceChildren();
    const hosts = settings.hosts || [];
    const catalog = settings.catalog || [];
    const verified = new Set((settings.available || []).map((ref) => refKey(ref)));
    if (!hosts.length) {
      const empty = document.createElement("p");
      empty.className = "controls-hint";
      empty.textContent = "Add a host and save it.";
      root.appendChild(empty);
    }
    hosts.forEach((host) => {
      const block = document.createElement("div");
      block.className = "catalog-host";
      const head = document.createElement("div");
      head.className = "catalog-host-head";
      const title = document.createElement("div");
      title.className = "mono";
      title.textContent = host.base_url || host.id;
      const refresh = document.createElement("button");
      refresh.type = "button";
      refresh.className = "btn";
      refresh.dataset.action = "refresh-catalog";
      refresh.dataset.hostId = host.id;
      refresh.textContent = "Refresh catalog";
      head.appendChild(title);
      head.appendChild(refresh);
      block.appendChild(head);
      const models = catalog.filter((row) => row.host_id === host.id);
      if (!models.length) {
        const none = document.createElement("p");
        none.className = "controls-hint";
        none.textContent = "No models yet.";
        block.appendChild(none);
      } else {
        const ul = document.createElement("div");
        ul.className = "catalog-models";
        models.forEach((row) => {
          const line = document.createElement("div");
          line.className = "catalog-model";
          const name = document.createElement("span");
          name.className = "mono";
          name.textContent = row.model_id;
          const state = document.createElement("span");
          state.className = "controls-hint";
          const key = refKey(row);
          state.textContent = verified.has(key) ? "verified" : "unverified";
          const button = document.createElement("button");
          button.type = "button";
          button.className = "btn";
          button.dataset.action = "verify-model";
          button.dataset.hostId = host.id;
          button.dataset.modelId = row.model_id;
          button.textContent = "Verify";
          line.appendChild(name);
          line.appendChild(state);
          line.appendChild(button);
          ul.appendChild(line);
        });
        block.appendChild(ul);
      }
      root.appendChild(block);
    });
    const head = document.querySelector(".available-head");
    if (head) head.hidden = !available.length;
    avail.replaceChildren();
    if (!available.length) {
      const li = document.createElement("li");
      li.className = "controls-hint";
      li.textContent = "None yet.";
      avail.appendChild(li);
      return;
    }
    available.forEach((ref) => {
      const li = document.createElement("li");
      li.className = "available-row";
      li.dataset.hostId = ref.host_id;
      li.dataset.modelId = ref.model_id;
      if (ref.verified_at) li.dataset.verifiedAt = ref.verified_at;

      const pick = document.createElement("input");
      pick.type = "checkbox";
      pick.dataset.field = "selected";
      pick.setAttribute("aria-label", `Select ${ref.model_id}`);

      const name = document.createElement("span");
      name.className = "mono";
      name.textContent = refLabel(ref);

      const ctx = document.createElement("input");
      ctx.type = "number";
      ctx.min = "1";
      ctx.step = "1";
      ctx.dataset.field = "context_tokens";
      ctx.placeholder = "default";
      ctx.setAttribute("aria-label", `Context tokens for ${ref.model_id}`);
      if (ref.context_tokens != null) ctx.value = String(ref.context_tokens);

      const maxTok = document.createElement("input");
      maxTok.type = "number";
      maxTok.min = "1";
      maxTok.step = "1";
      maxTok.dataset.field = "max_tokens";
      maxTok.placeholder = "default";
      maxTok.setAttribute("aria-label", `Max tokens for ${ref.model_id}`);
      if (ref.max_tokens != null) maxTok.value = String(ref.max_tokens);

      li.appendChild(pick);
      li.appendChild(name);
      li.appendChild(ctx);
      li.appendChild(maxTok);
      avail.appendChild(li);
    });
  }

  function readAvailableBudgets() {
    const out = [];
    document.querySelectorAll("#set-available .available-row").forEach((row) => {
      const host_id = row.dataset.hostId || "";
      const model_id = row.dataset.modelId || "";
      if (!host_id || !model_id) return;
      const item = { host_id, model_id };
      if (row.dataset.verifiedAt) item.verified_at = row.dataset.verifiedAt;
      const ctxRaw = row.querySelector("[data-field=context_tokens]")?.value.trim() ?? "";
      const maxRaw = row.querySelector("[data-field=max_tokens]")?.value.trim() ?? "";
      item.context_tokens = ctxRaw === "" ? null : parseInt(ctxRaw, 10);
      item.max_tokens = maxRaw === "" ? null : parseInt(maxRaw, 10);
      out.push(item);
    });
    return out;
  }

  function selectedPairs() {
    const out = [];
    document.querySelectorAll("#set-available .available-row").forEach((row) => {
      if (!row.querySelector("[data-field=selected]")?.checked) return;
      const host_id = row.dataset.hostId || "";
      const model_id = row.dataset.modelId || "";
      if (host_id && model_id) out.push({ host_id, model_id });
    });
    return out;
  }

  function settingsFormBody() {
    return {
      hosts: readHosts(),
      model: parseRefKey($("#set-model")?.value || ""),
      model_recon: parseRefKey($("#set-model-recon")?.value || ""),
      model_hunt: parseRefKey($("#set-model-hunt")?.value || ""),
      model_develop_poc: parseRefKey($("#set-model-develop-poc")?.value || ""),
      validate_models: readValidateRefs(),
      validate_consensus: $("#set-validate-consensus")?.value || "majority",
      validate_poc_referee: !!$("#set-validate-poc-referee")?.checked,
      validate_llm: !!$("#set-validate-llm")?.checked,
      hunt_moa: !!$("#set-hunt-moa")?.checked,
      hunt_perspectives: $("#set-hunt-perspectives") ? readHuntPerspectives() : [],
      max_concurrent_agents: parseInt($("#set-workers").value, 10),
      context_tokens: parseInt($("#set-ctx").value, 10),
      max_context_fraction: parseFloat($("#set-frac").value),
      max_tokens: parseInt($("#set-maxtok").value, 10),
      max_tool_rounds: parseInt($("#set-rounds").value, 10),
      timeout_seconds: parseInt($("#set-timeout").value, 10),
      max_tasks: parseInt($("#set-maxtasks").value, 10),
      available: readAvailableBudgets(),
    };
  }

  function fillForm(s, eff) {
    if (!s) return;
    available = Array.isArray(s.available) ? s.available : [];
    renderHosts(s.hosts || []);
    renderCatalog(s);
    fillRoleSelect($("#set-model"), s.model, false);
    fillRoleSelect($("#set-model-recon"), s.model_recon, true);
    fillRoleSelect($("#set-model-hunt"), s.model_hunt, true);
    fillRoleSelect($("#set-model-develop-poc"), s.model_develop_poc, true);
    renderValidatePicks(Array.isArray(s.validate_models) ? s.validate_models.filter((x) => x && typeof x === "object") : []);
    if ($("#set-validate-consensus")) {
      $("#set-validate-consensus").value = s.validate_consensus || "majority";
    }
    if ($("#set-validate-poc-referee")) {
      $("#set-validate-poc-referee").checked = s.validate_poc_referee !== false;
    }
    if ($("#set-validate-llm")) {
      $("#set-validate-llm").checked = s.validate_llm !== false;
    }
    if ($("#set-hunt-moa")) {
      $("#set-hunt-moa").checked = s.hunt_moa === true;
    }
    if ($("#set-hunt-perspectives")) {
      renderHuntPerspectives(perspectiveSlotsForForm(s, eff));
    }
    if ($("#set-workers")) $("#set-workers").value = s.max_concurrent_agents || 1;
    if ($("#set-ctx")) $("#set-ctx").value = s.context_tokens || 32768;
    if ($("#set-frac")) $("#set-frac").value = s.max_context_fraction ?? 0.25;
    if ($("#set-maxtok")) $("#set-maxtok").value = s.max_tokens || 4096;
    if ($("#set-rounds")) $("#set-rounds").value = s.max_tool_rounds || 12;
    if ($("#set-timeout")) $("#set-timeout").value = s.timeout_seconds || 600;
    if ($("#set-maxtasks")) $("#set-maxtasks").value = s.max_tasks || 50;
  }

  function showEffective(data) {
    const eff = data.effective || {};
    const s = data.settings || {};
    const dash = "-";
    const keyNote = eff.api_key_set ? "api key set" : "no api key";
    const vList = eff.validate_models && eff.validate_models.length ? eff.validate_models : [eff.model || dash];
    const huntOn = (eff.hunt_moa ?? s.hunt_moa) === true;
    const huntList = eff.hunt_perspectives && eff.hunt_perspectives.length ? eff.hunt_perspectives : [];
    const huntBrief = huntList
      .map((p) => {
        const id = p.id || "?";
        const model = p.model && typeof p.model === "object" ? p.model.model_id : String(p.model || "").trim();
        return model ? `${id}:${model}` : id;
      })
      .join(", ");
    const el = $("#settings-effective");
    if (!el) return;
    const hostCount = (s.hosts || []).length;
    el.textContent =
      `Effective: ${eff.base_url || dash} | default ${eff.model || dash} | hosts ${hostCount} | ` +
      `available ${(s.available || []).length} | validate [${vList.join(", ")}] | ` +
      `consensus ${eff.validate_consensus || s.validate_consensus || "majority"} | ` +
      `referee ${eff.validate_poc_referee ?? s.validate_poc_referee} | ` +
      `disprove ${eff.validate_llm ?? s.validate_llm} | ` +
      `hunt MoA ${huntOn ? "on" : "off"} [${huntBrief}] | ${keyNote} | ` +
      `agents ${eff.max_leases_parallel || 1}`;
  }

  async function loadSettings() {
    try {
      const data = await api("/api/settings");
      fillForm(data.settings || {}, data.effective || {});
      showEffective(data);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function applyPairRecommendations(data) {
    for (const row of data.targets || []) {
      if (!row || !row.ok) continue;
      const el = document.querySelector(
        `#set-available .available-row[data-host-id="${cssEscape(row.host_id)}"][data-model-id="${cssEscape(row.model_id)}"]`
      );
      if (!el) continue;
      const ctx = el.querySelector("[data-field=context_tokens]");
      const maxTok = el.querySelector("[data-field=max_tokens]");
      if (ctx && row.context_tokens != null) ctx.value = String(row.context_tokens);
      if (maxTok && row.max_tokens != null) maxTok.value = String(row.max_tokens);
    }
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
      const src = row.context_source ? ` (${row.context_source})` : "";
      lines.push(`${name}: context ${row.context_tokens}, max ${row.max_tokens}${src}`);
      for (const w of row.warnings || []) lines.push(`  ⚠ ${w}`);
    }
    lines.push("Review values, then Save to persist.");
    return lines.join("\n");
  }

  async function optimizeSettings() {
    const btn = $("#settings-optimize");
    const report = $("#settings-optimize-report");
    const targets = selectedPairs();
    if (!targets.length) {
      toast("Select a verified model", true);
      return;
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Optimizing…";
    }
    if (report) {
      report.hidden = false;
      report.textContent = `Probing ${targets.length} selected model${targets.length === 1 ? "" : "s"}…`;
    }
    try {
      const data = await api("/api/settings/optimize", {
        method: "POST",
        body: JSON.stringify({ targets, apply: false }),
      });
      applyPairRecommendations(data);
      if (report) report.textContent = formatSelectedReport(data);
      toast(data.ok ? "Budgets updated — review & Save" : data.error || "Optimize failed", !data.ok);
    } catch (e) {
      if (report) report.textContent = String(e.message || e);
      toast(e.message || String(e), true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Optimize selected";
      }
    }
  }

  async function saveSettings(ev) {
    if (ev) ev.preventDefault();
    const body = settingsFormBody();
    try {
      const data = await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify(body),
      });
      toast("Settings saved");
      const again = await api("/api/settings");
      fillForm((again && again.settings) || (data && data.settings) || {}, again?.effective || {});
      showEffective(again);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function refreshCatalog(hostId) {
    if (!hostId) {
      toast("Save the host first", true);
      return;
    }
    try {
      const data = await api(`/api/settings/hosts/${encodeURIComponent(hostId)}/catalog`, {
        method: "POST",
        body: "{}",
      });
      if (!data.ok) {
        toast(data.error || "Refresh failed", true);
        return;
      }
      toast(`Catalog: ${(data.models || []).length} model(s)`);
      await loadSettings();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function verifyModel(hostId, modelId) {
    try {
      const data = await api(`/api/settings/hosts/${encodeURIComponent(hostId)}/verify`, {
        method: "POST",
        body: JSON.stringify({ model_id: modelId }),
      });
      if (!data.ok) {
        toast(data.error || "Verify failed", true);
        return;
      }
      toast(`Verified ${modelId}`);
      await loadSettings();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function boot() {
    if (document.body?.dataset?.page !== "settings") return;
    loadSettings();
    $("#settings-form")?.addEventListener("submit", saveSettings);
    $("#settings-optimize")?.addEventListener("click", optimizeSettings);
    $("#set-host-add")?.addEventListener("click", () => {
      $("#set-hosts")?.appendChild(hostRow({}));
    });
    $("#set-hosts")?.addEventListener("click", (ev) => {
      const btn = ev.target.closest?.("[data-action=remove-host]");
      if (!btn) return;
      btn.closest(".host-row")?.remove();
    });
    $("#set-catalog")?.addEventListener("click", (ev) => {
      const refresh = ev.target.closest?.("[data-action=refresh-catalog]");
      if (refresh) {
        refreshCatalog(refresh.dataset.hostId || "");
        return;
      }
      const verify = ev.target.closest?.("[data-action=verify-model]");
      if (verify) verifyModel(verify.dataset.hostId || "", verify.dataset.modelId || "");
    });
    $("#set-hunt-perspective-add")?.addEventListener("click", () => {
      $("#set-hunt-perspectives")?.appendChild(huntPerspectiveRow({ id: "", prompt: "", model: "" }));
    });
    $("#set-hunt-perspectives")?.addEventListener("click", (ev) => {
      const btn = ev.target.closest?.("[data-action=remove]");
      if (!btn) return;
      btn.closest(".hunt-perspective-row")?.remove();
      updateHuntModelWarn(readHuntPerspectives());
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
