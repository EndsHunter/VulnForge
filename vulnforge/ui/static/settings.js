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
      max_concurrent_agents: parseInt($("#set-workers").value, 10),
      context_tokens: parseInt($("#set-ctx").value, 10),
      max_context_fraction: parseFloat($("#set-frac").value),
      max_tokens: parseInt($("#set-maxtok").value, 10),
      max_tool_rounds: parseInt($("#set-rounds").value, 10),
      timeout_seconds: parseInt($("#set-timeout").value, 10),
      max_tasks: parseInt($("#set-maxtasks").value, 10),
    };
  }

  function fillForm(s) {
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
    const el = $("#settings-effective");
    if (!el) return;
    el.textContent =
      `Effective: ${eff.base_url || dash} | default ${eff.model || dash} | ` +
      `validate [${vModels}] | consensus ${eff.validate_consensus || s.validate_consensus || "majority"} | ` +
      `referee ${eff.validate_poc_referee ?? s.validate_poc_referee} | ` +
      `disprove ${eff.validate_llm ?? s.validate_llm} | ${keyNote} | ` +
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
      fillForm(data.settings || {});
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
      report.textContent = "Probing endpoint…";
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
      if (data && data.settings) {
        fillForm(data.settings);
      }
      // refresh effective line
      const again = await api("/api/settings");
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
