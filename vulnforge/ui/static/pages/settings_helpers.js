/*
 * Settings page helpers (issue #202). Pure functions, no DOM.
 * UMD so node --test can load them; the page reads window.VFSettingsHelpers.
 *
 * Nothing here ever sees an API key: the server returns api_key_set only.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.VFSettingsHelpers = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const SAME_MODEL_WARN =
    "Validate uses the hunt model — same-model dual disprove is a weak signal. Never auto-confirms.";
  const ONE_MODEL_WARN = "One validation model is a weaker signal than two. Never auto-confirms.";
  const SAME_PERSPECTIVE_WARN = "Same model on every hunt perspective is a weak signal.";

  // Form body keys grouped by page section (dirty markers per section).
  const SECTION_KEYS = {
    connections: ["hosts"],
    roles: ["model", "model_recon", "model_hunt", "model_develop_poc", "model_validate"],
    validation: [
      "validate_models",
      "validate_consensus",
      "validate_llm",
      "validate_poc_referee",
      "hunt_moa",
      "hunt_perspectives",
    ],
    budgets: [
      "available",
      "max_concurrent_agents",
      "context_tokens",
      "max_tokens",
      "max_context_fraction",
      "max_tool_rounds",
      "timeout_seconds",
      "max_tasks",
    ],
    sandbox: ["poc_iterate_max_cycles", "poc_iterate_wall_ttl_min"],
    // Owner toggles are sent only once set or changed here (see settings.js).
    exports: ["finding_owners", "finding_owners_redact_exports"],
  };

  // Pair knobs: the available-row number wins, blank falls back to this global.
  const PAIR_SEED = {
    context_tokens: "context_tokens",
    max_tokens: "max_tokens",
    max_concurrent_agents: "max_concurrent_agents",
  };

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
    let host_id;
    let model_id;
    try {
      host_id = decodeURIComponent(raw.slice(0, cut));
      model_id = decodeURIComponent(raw.slice(cut + 1));
    } catch {
      return null;
    }
    if (!host_id || !model_id) return null;
    return { host_id, model_id };
  }

  /**
   * Catalog row state. A failure seen this session wins over an older
   * verification (the most recent probe is what the operator needs to see).
   * failures: { [refKey]: errorText }
   */
  function pairState(ref, verifiedKeys, failures) {
    const key = refKey(ref);
    if (!key) return "unchecked";
    if (failures && Object.prototype.hasOwnProperty.call(failures, key)) return "failing";
    const set = verifiedKeys instanceof Set ? verifiedKeys : new Set(verifiedKeys || []);
    return set.has(key) ? "verified" : "unchecked";
  }

  function catalogSummary(rows, verifiedKeys, failures) {
    const out = { total: 0, verified: 0, failing: 0, unchecked: 0 };
    (rows || []).forEach((row) => {
      out.total += 1;
      out[pairState(row, verifiedKeys, failures)] += 1;
    });
    return out;
  }

  function intOrNull(v) {
    if (v === null || v === undefined || v === "") return null;
    const n = parseInt(v, 10);
    return Number.isFinite(n) ? n : null;
  }

  /** Same shape the page reads back from the budget table. */
  function budgetRowsFromAvailable(available) {
    const out = [];
    (available || []).forEach((ref) => {
      if (!ref || typeof ref !== "object") return;
      const host_id = String(ref.host_id || "");
      const model_id = String(ref.model_id || "");
      if (!host_id || !model_id) return;
      const item = { host_id, model_id };
      if (ref.verified_at) item.verified_at = ref.verified_at;
      item.context_tokens = intOrNull(ref.context_tokens);
      item.max_tokens = intOrNull(ref.max_tokens);
      item.max_concurrent_agents = intOrNull(ref.max_concurrent_agents);
      out.push(item);
    });
    return out;
  }

  /**
   * Effective budget for one verified pair: pair override > global seed.
   * max_context_fraction is global only, so it is not part of the pair.
   */
  function pairBudget(row, globals) {
    const g = globals || {};
    const out = {};
    Object.keys(PAIR_SEED).forEach((key) => {
      const own = intOrNull(row && row[key]);
      if (own != null) out[key] = { value: own, source: "pair" };
      else out[key] = { value: intOrNull(g[PAIR_SEED[key]]), source: "seed" };
    });
    return out;
  }

  function stableStringify(value) {
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
    if (value && typeof value === "object") {
      const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
    }
    if (typeof value === "number" && !Number.isFinite(value)) return "null";
    return JSON.stringify(value === undefined ? null : value);
  }

  /** Section ids whose form values differ from the last saved snapshot. */
  function dirtySections(baseline, current) {
    const a = baseline || {};
    const b = current || {};
    return Object.keys(SECTION_KEYS).filter((section) =>
      SECTION_KEYS[section].some((key) => stableStringify(a[key]) !== stableStringify(b[key]))
    );
  }

  /**
   * After a server-side change (catalog refresh / verify) re-renders parts of
   * the form: keys the operator had not touched (before === baseline) follow
   * the new form value; keys they had edited keep the old baseline, so they
   * stay dirty.
   */
  function rebaseline(baseline, before, after) {
    const base = baseline || {};
    const out = { ...base };
    Object.keys(after || {}).forEach((key) => {
      if (stableStringify(base[key]) === stableStringify((before || {})[key])) out[key] = after[key];
    });
    return out;
  }

  /**
   * What saving these host edits will unverify. Mirrors
   * settings.catalog.sync_catalog_for_host_edit: a removed host or URL change
   * drops its catalog and verified pairs; a key or API-mode change drops the
   * verified pairs only. A typed key counts as a change (the page cannot see
   * the stored key to compare). Roles on a dropped pair are reset by the server.
   */
  function hostEditImpact(savedHosts, formHosts, available) {
    const byId = {};
    (formHosts || []).forEach((h) => {
      if (h && h.id) byId[h.id] = h;
    });
    const pairsOf = (hid) => (available || []).filter((a) => a && a.host_id === hid).length;
    const out = [];
    (savedHosts || []).forEach((old) => {
      if (!old || !old.id) return;
      const now = byId[old.id];
      let reason = "";
      if (!now) reason = "removed";
      else if (String(now.base_url || "") !== String(old.base_url || "")) reason = "url";
      else if (Object.prototype.hasOwnProperty.call(now, "api_key")) reason = "key";
      else if (String(now.api_mode || "") !== String(old.api_mode || "")) reason = "mode";
      if (!reason) return;
      const pairs = pairsOf(old.id);
      if (!pairs && reason !== "url" && reason !== "removed") return;
      out.push({ host_id: old.id, base_url: old.base_url || old.id, reason, pairs });
    });
    return out;
  }

  /**
   * Validation weak-signal note. Mirrors llm_models.resolve_validate_targets:
   * checked list > dedicated Validate role > hunt role (> default role).
   */
  function validateWarning(opts) {
    const o = opts || {};
    let keys = (o.checked || []).filter(Boolean);
    if (!keys.length && o.dedicated) keys = [o.dedicated];
    const huntKey = o.hunt || o.defaultRole || "";
    if (!keys.length && huntKey) keys = [huntKey];
    const uniq = [...new Set(keys)];
    const matchesHunt = keys.length > 0 && !!huntKey && keys.every((key) => key === huntKey);
    if (!keys.length || matchesHunt) return SAME_MODEL_WARN;
    if (uniq.length <= 1) return ONE_MODEL_WARN;
    return "";
  }

  function perspectiveWarning(slots) {
    const list = Array.isArray(slots) ? slots : [];
    const keyOf = (m) => (m && typeof m === "object" ? refKey(m) : String(m || "").trim().toLowerCase());
    const explicit = list.map((s) => keyOf(s && s.model)).filter(Boolean);
    const uniq = [...new Set(explicit)];
    if (explicit.length >= 2 && explicit.length === list.length && uniq.length <= 1) {
      return SAME_PERSPECTIVE_WARN;
    }
    return "";
  }

  function defaultHuntPrompt(id, known) {
    const pid = String(id || "").trim();
    const hit = (known || []).find((row) => row.id === pid);
    if (hit) return hit.prompt;
    const safe = pid.replace(/[^A-Za-z0-9_-]/g, "_").replace(/^_+|_+$/g, "");
    return `hunt_${safe || "perspective"}.md`;
  }

  return {
    SECTION_KEYS,
    SAME_MODEL_WARN,
    ONE_MODEL_WARN,
    SAME_PERSPECTIVE_WARN,
    refKey,
    parseRefKey,
    pairState,
    catalogSummary,
    budgetRowsFromAvailable,
    pairBudget,
    stableStringify,
    dirtySections,
    rebaseline,
    hostEditImpact,
    validateWarning,
    perspectiveWarning,
    defaultHuntPrompt,
  };
});
