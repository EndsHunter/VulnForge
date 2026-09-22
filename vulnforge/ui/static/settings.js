/**
 * Dedicated /settings page — load, save, optimize UI settings.
 * Relies on window.api / toast from app.js when available; has fetch fallback.
 */
(function () {
  const $ = (sel) => document.querySelector(sel);

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

  // Built-in slots match stages.hunt_moa defaults. Not validate_models.
  const DEFAULT_HUNT_PERSPECTIVES = [
    { id: "sink_driven", prompt: "hunt_sink.md", model: "" },
    { id: "dataflow", prompt: "hunt_dataflow.md", model: "" },
    { id: "authz", prompt: "hunt_authz.md", model: "" },
  ];

  function defaultHuntPrompt(id) {
    const pid = String(id || "").trim();
    const known = DEFAULT_HUNT_PERSPECTIVES.find((row) => row.id === pid);
    if (known) return known.prompt;
    const safe = pid.replace(/[^A-Za-z0-9_-]/g, "_").replace(/^_+|_+$/g, "");
    return `hunt_${safe || "perspective"}.md`;
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
    const modelInput = document.createElement("input");
    modelInput.className = "mono";
    modelInput.dataset.field = "model";
    modelInput.setAttribute("aria-label", "Perspective model");
    modelInput.autocomplete = "off";
    modelInput.placeholder = "(hunt model)";
    modelInput.value = slot?.model || "";
    modelField.appendChild(modelInput);

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
      const auto =
        !cur || cur === defaultHuntPrompt(prev) || cur === `hunt_${prev}.md`;
      if (auto) promptInput.value = defaultHuntPrompt(idInput.value.trim());
      idInput.dataset.prev = idInput.value.trim();
      updateHuntModelWarn(readHuntPerspectives());
    });
    modelInput.addEventListener("input", () => {
      updateHuntModelWarn(readHuntPerspectives());
    });
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
        model: row.querySelector("[data-field=model]")?.value.trim() || "",
        prompt: row.querySelector("[data-field=prompt]")?.value.trim() || "",
      });
    });
    return out;
  }

  function renderHuntPerspectives(slots) {
    const list = $("#set-hunt-perspectives");
    if (!list) return;
    list.replaceChildren();
    const rows = Array.isArray(slots) ? slots : [];
    rows.forEach((slot) => list.appendChild(huntPerspectiveRow(slot)));
    updateHuntModelWarn(readHuntPerspectives());
  }

  function perspectiveSlotsForForm(s, eff) {
    const saved = Array.isArray(s?.hunt_perspectives) ? s.hunt_perspectives : [];
    if (saved.length) return saved;
    const fromEff = Array.isArray(eff?.hunt_perspectives) ? eff.hunt_perspectives : [];
    if (fromEff.length) {
      return fromEff.map((p) => ({
        id: p.id || "",
        prompt: p.prompt || "",
        model: p.model || "",
      }));
    }
    return DEFAULT_HUNT_PERSPECTIVES.map((p) => ({ ...p }));
  }

  function updateHuntModelWarn(slots) {
    const warn = $("#set-hunt-perspectives-warn");
    if (!warn) return;
    const list = Array.isArray(slots) ? slots : [];
    const explicit = list.map((s) => String(s.model || "").trim()).filter(Boolean);
    const uniq = [...new Set(explicit.map((m) => m.toLowerCase()))];
    if (explicit.length >= 2 && explicit.length === list.length && uniq.length <= 1) {
      warn.hidden = false;
      warn.textContent = "Same model on every hunt perspective is a weak signal.";
    } else {
      warn.hidden = true;
      warn.textContent = "";
    }
  }

  function settingsFormBody() {
    const modelsText = ($("#set-validate-models")?.value || "").trim();
    const validate_models = modelsText
      ? modelsText
          .split(/\r?\n|,/)
          .map((s) => s.trim())
          .filter(Boolean)
      : [];
    return {
      host: $("#set-host").value.trim(),
      port: parseInt($("#set-port").value, 10),
      model: $("#set-model").value.trim(),
      api_mode: $("#set-api-mode")?.value || "chat_completions",
      api_key: ($("#set-api-key")?.value ?? "").trim(),
      model_recon: ($("#set-model-recon")?.value || "").trim(),
      model_hunt: ($("#set-model-hunt")?.value || "").trim(),
      model_develop_poc: ($("#set-model-develop-poc")?.value || "").trim(),
      validate_models,
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
    };
  }

  function fillForm(s, eff) {
    if (!s) return;
    if ($("#set-host")) $("#set-host").value = s.host || "";
    if ($("#set-port")) $("#set-port").value = s.port || 1234;
    if ($("#set-model")) $("#set-model").value = s.model || "";
    const apiModeEl = $("#set-api-mode");
    if (apiModeEl) {
      const mode = s.api_mode || "chat_completions";
      apiModeEl.value = mode;
      if (apiModeEl.value !== mode) apiModeEl.value = "chat_completions";
    }
    if ($("#set-api-key")) $("#set-api-key").value = s.api_key || "";
    if ($("#set-model-recon")) $("#set-model-recon").value = s.model_recon || "";
    if ($("#set-model-hunt")) $("#set-model-hunt").value = s.model_hunt || "";
    if ($("#set-model-develop-poc"))
      $("#set-model-develop-poc").value = s.model_develop_poc || "";
    const vm = s.validate_models;
    if ($("#set-validate-models")) {
      $("#set-validate-models").value = Array.isArray(vm)
        ? vm.join("\n")
        : String(vm || "");
      const list = Array.isArray(vm)
        ? vm
        : String(vm || "")
            .split(/\n|,/)
            .map((x) => x.trim())
            .filter(Boolean);
      updateValidateModelsWarn(
        list.length ? list : [s.model || ""],
        s.model || ""
      );
    }
    if ($("#set-validate-consensus")) {
      $("#set-validate-consensus").value = s.validate_consensus || "majority";
    }
    if ($("#set-validate-poc-referee")) {
      $("#set-validate-poc-referee").checked = s.validate_poc_referee !== false;
    }
    if ($("#set-validate-llm")) {
      // Product default is ON; only uncheck when explicitly false.
      $("#set-validate-llm").checked = s.validate_llm !== false;
    }
    if ($("#set-hunt-moa")) {
      // Product default is OFF. Only check when explicitly enabled.
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
    const vList =
      eff.validate_models && eff.validate_models.length
        ? eff.validate_models
        : s.validate_models && s.validate_models.length
          ? s.validate_models
          : [eff.model || s.model || dash];
    const vModels = vList.join(", ");
    const huntOn = (eff.hunt_moa ?? s.hunt_moa) === true;
    const huntList =
      eff.hunt_perspectives && eff.hunt_perspectives.length
        ? eff.hunt_perspectives
        : s.hunt_perspectives && s.hunt_perspectives.length
          ? s.hunt_perspectives
          : [];
    const huntBrief = huntList
      .map((p) => {
        const id = p.id || "?";
        const model = String(p.model || "").trim();
        return model ? `${id}:${model}` : id;
      })
      .join(", ");
    const el = $("#settings-effective");
    if (!el) return;
    el.textContent =
      `Effective: ${eff.base_url || dash} | default ${eff.model || dash} | ` +
      `validate [${vModels}] | consensus ${eff.validate_consensus || s.validate_consensus || "majority"} | ` +
      `referee ${eff.validate_poc_referee ?? s.validate_poc_referee} | ` +
      `disprove ${eff.validate_llm ?? s.validate_llm} | ` +
      `hunt MoA ${huntOn ? "on" : "off"} [${huntBrief}] | ${keyNote} | ` +
      `agents ${eff.max_leases_parallel || 1}`;
    updateValidateModelsWarn(vList, eff.model || s.model || "");
  }

  function updateValidateModelsWarn(models, defaultModel) {
    const warn = $("#set-validate-models-warn");
    if (!warn) return;
    const list = (models || []).map((m) => String(m || "").trim()).filter(Boolean);
    const uniq = [...new Set(list.map((m) => m.toLowerCase()))];
    const def = String(defaultModel || "").trim().toLowerCase();
    if (uniq.length <= 1) {
      warn.hidden = false;
      warn.textContent =
        "Same-model disprove is a weak signal. Add a second validation model id when you can.";
    } else {
      warn.hidden = true;
      warn.textContent = "";
    }
    void def; // reserved if we later warn when list equals only default
  }

  function applyRecommendedToSettingsForm(rec) {
    if (!rec || typeof rec !== "object") return;
    if (rec.host != null && $("#set-host")) $("#set-host").value = rec.host;
    if (rec.port != null && $("#set-port")) $("#set-port").value = rec.port;
    if (rec.model != null && $("#set-model")) $("#set-model").value = rec.model;
    const apiModeEl = $("#set-api-mode");
    if (apiModeEl && rec.api_mode) {
      apiModeEl.value = rec.api_mode;
      if (apiModeEl.value !== rec.api_mode) apiModeEl.value = "chat_completions";
    }
    if (rec.api_key != null && $("#set-api-key")) {
      $("#set-api-key").value = rec.api_key;
    }
    if (rec.max_concurrent_agents != null && $("#set-workers"))
      $("#set-workers").value = rec.max_concurrent_agents;
    if (rec.context_tokens != null && $("#set-ctx"))
      $("#set-ctx").value = rec.context_tokens;
    if (rec.max_context_fraction != null && $("#set-frac"))
      $("#set-frac").value = rec.max_context_fraction;
    if (rec.max_tokens != null && $("#set-maxtok"))
      $("#set-maxtok").value = rec.max_tokens;
    if (rec.max_tool_rounds != null && $("#set-rounds"))
      $("#set-rounds").value = rec.max_tool_rounds;
    if (rec.timeout_seconds != null && $("#set-timeout"))
      $("#set-timeout").value = rec.timeout_seconds;
    if (rec.max_tasks != null && $("#set-maxtasks"))
      $("#set-maxtasks").value = rec.max_tasks;
  }

  function formatOptimizeReport(data) {
    const lines = [];
    if (data.summary) lines.push(data.summary);
    if (data.error) lines.push("Error: " + data.error);
    if (data.measured_context_tokens != null) {
      const src = data.context_source ? ` (${data.context_source})` : "";
      lines.push(`Measured context: ${data.measured_context_tokens} tokens${src}`);
    }
    for (const w of data.warnings || []) lines.push("⚠ " + w);
    const changes = data.changes || {};
    const keys = Object.keys(changes);
    if (keys.length) {
      lines.push("Changes:");
      for (const k of keys) {
        const c = changes[k];
        lines.push(`  ${k}: ${JSON.stringify(c.from)} → ${JSON.stringify(c.to)}`);
      }
    } else if (data.ok) {
      lines.push("No field changes vs current saved settings.");
    }
    const tests = data.tests || [];
    if (tests.length) {
      lines.push("Tests:");
      for (const t of tests) {
        lines.push(`  ${t.ok ? "✓" : "✗"} ${t.id}: ${t.detail || ""} (${t.seconds ?? "?"}s)`);
      }
    }
    lines.push("Review values, then Save to persist.");
    return lines.join("\n");
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

  async function optimizeSettings() {
    const btn = $("#settings-optimize");
    const report = $("#settings-optimize-report");
    const form = settingsFormBody();
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Optimizing…";
    }
    if (report) {
      report.hidden = false;
      report.textContent = "Probing endpoint (models, completion, tool-call, context window, latency)…";
    }
    try {
      const data = await api("/api/settings/optimize", {
        method: "POST",
        body: JSON.stringify({
          host: form.host,
          port: form.port,
          model: form.model,
          api_key: form.api_key,
          apply: false,
        }),
      });
      if (data.recommended) applyRecommendedToSettingsForm(data.recommended);
      if (report) report.textContent = formatOptimizeReport(data);
      toast(data.ok ? "Optimized — review & Save" : data.error || "Optimize failed", !data.ok);
    } catch (e) {
      if (report) report.textContent = String(e.message || e);
      toast(e.message || String(e), true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Optimize AI settings";
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

  function boot() {
    if (document.body?.dataset?.page !== "settings") return;
    loadSettings();
    $("#settings-form")?.addEventListener("submit", saveSettings);
    $("#settings-optimize")?.addEventListener("click", optimizeSettings);
    $("#set-hunt-perspective-add")?.addEventListener("click", () => {
      $("#set-hunt-perspectives")?.appendChild(
        huntPerspectiveRow({ id: "", prompt: "", model: "" })
      );
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

  // Export for app.js optimize/save reuse if needed
  window.VFSettingsPage = {
    loadSettings,
    saveSettings,
    settingsFormBody,
    fillForm,
  };
})();
