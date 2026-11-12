/* vulnforge dashboard client  -  security-ops UI */

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

let homeFilter = "all";
let homeQuery = "";
let homeRunsCache = [];

function toast(msg, err = false) {
  let t = $("#toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    t.className = "toast";
    t.setAttribute("role", "status");
    t.setAttribute("aria-live", "polite");
    t.setAttribute("aria-atomic", "true");
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.toggle("err", !!err);
  t.classList.add("show");
  clearTimeout(t._hide);
  t._hide = setTimeout(() => t.classList.remove("show"), 3500);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = { detail: await res.text() };
  }
  if (!res.ok) {
    const msg = data.detail || data.error || res.statusText;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}

/** Operator-facing state labels (CSS class still uses raw state). */
const STATE_LABELS = {
  needs_human: "Needs review",
  candidate: "Candidate",
  confirmed: "Accepted (human)",
  rejected_mech: "Rejected (mechanical)",
  rejected_llm: "Rejected (disprove)",
  rejected_human: "Rejected (human)",
  superseded: "Superseded",
  idle: "Idle",
  queued: "Queued",
  leased: "Running",
  paused: "Paused",
  succeeded: "Succeeded",
  failed_task: "Failed",
  failed_infra: "Infra failure",
  deadletter: "Deadletter",
  cancelled: "Cancelled",
};

function stateLabel(state, finding) {
  const s = (state || "idle").toLowerCase();
  if (s === "needs_human" && finding) {
    const b = finding.body || {};
    if (b.validation_mech?.pending_llm) return "Pending disprove";
  }
  return STATE_LABELS[s] || state || "idle";
}

/** Hover copy for finding-state badges. Confirmed stays human-only. */
const STATE_TIPS = {
  needs_human:
    "Mechanical gates passed. Waiting for a human. Not confirmed.",
  candidate:
    "Proposed candidate. Mechanical gates have not passed. Not confirmed.",
  confirmed:
    "Confirmed is human-only. An operator accepted this finding. The harness never auto-confirms. An LLM stand or self-grade is not confirmed.",
  rejected_mech:
    "Mechanical gates rejected this finding. Not a human decision.",
  rejected_llm:
    "LLM disprove rejected this finding. Not a human confirm. The harness never auto-confirms.",
  rejected_human: "A human rejected this finding. Not an LLM self-grade.",
  superseded: "Superseded by another finding. Not confirmed.",
};

function stateTip(state, finding) {
  const s = (state || "idle").toLowerCase();
  if (s === "needs_human" && finding) {
    const b = finding.body || {};
    if (b.validation_mech?.pending_llm) {
      return "Dual LLM disprove is still running. Pending is not confirmed. The harness never auto-confirms.";
    }
  }
  return STATE_TIPS[s] || STATE_LABELS[s] || s;
}

function badge(state, finding) {
  const s = (state || "idle").toLowerCase();
  const label = stateLabel(s, finding);
  const tip = stateTip(s, finding);
  return `<span class="badge ${esc(s)}" title="${esc(tip)}">${esc(label)}</span>`;
}

/** Humanize validate_mech / validate_llm reason codes for operator UI. */
function humanizeValidationReason(raw) {
  const s = String(raw ?? "").trim();
  if (!s) return "";
  const split = s.indexOf(":");
  const code = split >= 0 ? s.slice(0, split) : s;
  const rest = split >= 0 ? s.slice(split + 1) : "";
  const map = {
    target_mutated:
      "Cited file changed after inventory (target mutated). Re-init or re-scan so citations match disk.",
    cited_missing: "Cited path is missing on disk under the target tree.",
    missing_path: "Citation path does not exist under the target.",
    citation_escape: "Citation path escapes the target tree (path jail).",
    citation_not_object: "A citation entry is not a valid object.",
    citation_missing_line:
      "Citation lacks start_line — cite a concrete source line for the claim.",
    citation_empty_slice: "Cited line range is empty or unreadable.",
    citation_content_mismatch:
      "Cited lines do not mention the claimed sink/symbol (or title tokens). Point citations at the real code.",
    unreadable: "Cited file could not be read.",
    line_oob: "Citation start_line is outside the file.",
    bad_line_range: "Citation line range is invalid.",
    missing_manifest: "target_manifest.json missing; cannot verify target hashes.",
    hash_fail: "Could not hash a cited file for mutation check.",
    missing_evidence_id: "No evidence_id and no valid no_poc justification.",
    missing_evidence: "Evidence pack directory is missing or empty.",
    missing_poc: "Declared poc_relpath is missing from the evidence pack.",
    poc_without_evidence_id: "poc_relpath set without evidence_id.",
    weak_no_poc_justification: "no_poc justification is too short or missing.",
    vacuous_impact: "Threat model impact looks vacuous / circular.",
    vacuous_attacker: "Threat model attacker is empty or placeholder (n/a, none, unknown).",
    vacuous_boundary: "Threat model boundary is empty or placeholder (n/a, none, unknown).",
    vacuous_impact_for_severity:
      "HIGH/CRITICAL requires a concrete impact class (e.g. authz bypass, data leak, RCE).",
    title_too_short: "Finding title is too short.",
    summary_too_short: "Finding summary is empty or too short.",
    bad_severity:
      "severity_claim must be CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL (not free text).",
    no_run: "Run row missing in harness.db.",
    schema: "Candidate body failed schema checks.",
  };
  const base = map[code] || s;
  if (rest && map[code]) return `${base} (${rest})`;
  if (rest && !map[code]) return `${code}: ${rest}`;
  return base;
}

function validationReasonsOf(finding) {
  const body = (finding && finding.body) || {};
  const raw = body.validation_reasons || body.validation_mech?.reasons || [];
  if (!Array.isArray(raw)) return [];
  return raw.map((r) => String(typeof r === "string" ? r : JSON.stringify(r))).filter(Boolean);
}

function formatValidationReasonsHtml(finding, { heading } = {}) {
  const reasons = validationReasonsOf(finding);
  if (!reasons.length) return "";
  const st = String((finding && finding.state) || "").toLowerCase();
  const rejected = st.startsWith("rejected") || st === "superseded";
  const title =
    heading ||
    (rejected ? "Rejected because" : "Validation notes");
  const items = reasons
    .map(
      (r) =>
        `<li><span class="reason-code mono">${esc(r)}</span><span class="reason-human">${esc(
          humanizeValidationReason(r)
        )}</span></li>`
    )
    .join("");
  return `<div class="finding-reject-box${rejected ? " is-reject" : ""}">
    <div class="finding-reject-title">${esc(title)}</div>
    <ul class="finding-reasons">${items}</ul>
  </div>`;
}

window.STATE_LABELS = STATE_LABELS;
window.STATE_TIPS = STATE_TIPS;
window.stateLabel = stateLabel;
window.stateTip = stateTip;
window.humanizeValidationReason = humanizeValidationReason;
window.validationReasonsOf = validationReasonsOf;
window.formatValidationReasonsHtml = formatValidationReasonsHtml;

function sevBadge(sev) {
  const s = (sev || "unknown").toLowerCase();
  return `<span class="badge sev-${esc(s)}">${esc(s)}</span>`;
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function progressBar(p, thin = false) {
  const pct = Math.round((p || 0) * 100);
  return `<div class="progress${thin ? " thin" : ""}" title="${pct}%"><i style="width:${pct}%"></i></div>`;
}

function fmtCounts(obj) {
  if (!obj || !Object.keys(obj).length) return " - ";
  return Object.entries(obj)
    .map(([k, v]) => `${k}:${v}`)
    .join(" | ");
}

function relativeTime(isoOrTs) {
  if (isoOrTs == null || isoOrTs === "") return " - ";
  let ms;
  if (typeof isoOrTs === "number") {
    ms = isoOrTs < 1e12 ? isoOrTs * 1000 : isoOrTs;
  } else {
    const t = Date.parse(isoOrTs);
    if (Number.isNaN(t)) return String(isoOrTs).slice(0, 19);
    ms = t;
  }
  const diff = Date.now() - ms;
  if (diff < 0) return "just now";
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const d = Math.floor(hr / 24);
  return `${d}d ago`;
}

function statusChip(r) {
  const runner = r.runner || {};
  const st = (runner.state || (r.active ? "busy" : "idle")).toLowerCase();
  if (r.incomplete) return "incomplete";
  return st;
}

function matchesFilter(r, filter) {
  if (filter === "all") return true;
  const st = statusChip(r);
  if (filter === "running") return st === "running" || st === "busy" || st === "pausing";
  if (filter === "incomplete") return !!r.incomplete;
  if (filter === "idle") return st === "idle" || st === "paused";
  return true;
}

function matchesQuery(r, q) {
  if (!q) return true;
  const blob = [
    r.target_id,
    r.run_id,
    r.target_path,
    r.profile,
    r.key,
  ]
    .join(" ")
    .toLowerCase();
  return blob.includes(q.toLowerCase());
}

function classifyRun(r) {
  const runner = r.runner || {};
  const st = String(runner.state || "").toLowerCase();
  const last = r.last_event && typeof r.last_event === "object" ? r.last_event : {};
  const lastKind = String(last.event || last.kind || "").toLowerCase();
  if (st === "failed" || lastKind === "failed_infra") return "failed";
  if (["busy", "running", "paused", "pausing"].includes(st) || r.active || r.has_work) {
    return "live";
  }
  return "settled";
}

function lastEventLine(r) {
  const ev = r.last_event;
  if (!ev || typeof ev !== "object") return "";
  const raw = ev.message || ev.event || ev.kind || ev.stage || "";
  return String(raw).replace(/_/g, " ").trim();
}

function shortAge(isoOrTs) {
  const full = relativeTime(isoOrTs);
  if (!full || full === " - ") return "";
  return full.replace(/ ago$/, "");
}

function runStatusLabel(r, group) {
  if (group === "failed") return { text: "Failed", cls: "st fail" };
  const st = String((r.runner || {}).state || (r.active ? "busy" : "idle")).toLowerCase();
  if (st === "running" || st === "busy" || st === "pausing") {
    return { text: "Running", cls: "st run" };
  }
  if (st === "paused") return { text: "Paused", cls: "st" };
  if (group === "live") return { text: "Idle", cls: "st" };
  const cardStatus = String(r.status || "").toLowerCase();
  if (
    cardStatus === "idle" ||
    (group === "settled" && !r.has_work && cardStatus !== "paused")
  ) {
    return { text: "Idle", cls: "st" };
  }
  return { text: "", cls: "st" };
}

function renderRunRow(r, group) {
  // Home redesign (docs/ui/REDESIGN.md): status pill | run | pipeline | last activity | tokens.
  const H = globalThis.HomeHelpers;
  const tpath = r.target_path || "";
  const runLabel = `${r.target_id || ""} / ${r.run_id || ""}`;
  const last = lastEventLine(r);
  const st = H ? H.runStatus(r) : statusChip(r);
  const stLabel = (H && H.STATUS_LABEL[st]) || runStatusLabel(r, group).text || st;
  const tone = (H && H.STATUS_TONE[st]) || "";
  const pipe = H
    ? H.runPipeline(r)
    : {
        tasks: String(r.done_tasks || 0),
        review: Number((r.findings || {}).needs_human || 0),
        confirmed: Number((r.findings || {}).confirmed || 0),
      };
  const age = shortAge(r.updated_at || r.created_at || r.mtime);
  const usage = llmUsageOf(r);
  const tokTitle = modelUsageTooltipSafe(usage);
  const total = tokenCountsSafe(usage).total;
  return `
      <a class="run-row" data-status="${esc(st)}" href="/runs/${encodeURIComponent(r.target_id)}/${encodeURIComponent(r.run_id)}" title="${esc(runLabel)}">
        <span class="vf-run-status"><span class="vf-runner-pill ${tone}"><span class="dot" aria-hidden="true"></span>${esc(stLabel)}</span></span>
        <span class="vf-run-id">
          <span class="title">${esc(runLabel)}</span>
          <span class="meta vf-mono">${esc(tpath)}</span>
        </span>
        <span class="vf-run-pipe" aria-label="Pipeline">
          <span>Tasks <b>${esc(pipe.tasks)}</b></span>
          <span class="${pipe.review > 0 ? "is-review" : ""}">Review <b>${pipe.review}</b></span>
          <span class="${pipe.confirmed > 0 ? "is-confirmed" : ""}">Confirmed <b>${pipe.confirmed}</b></span>
        </span>
        <span class="vf-run-last">
          <span class="vf-run-last-ev">${esc(last || "—")}</span>
          ${age ? `<span class="ago">${esc(age)} ago</span>` : ""}
        </span>
        <span class="vf-run-tok vf-mono"${tokTitle ? ` title="${esc(tokTitle)}"` : ""}>${total ? esc(fmtTokens(total)) : "—"}</span>
      </a>`;
}

/* ---------- Home ---------- */

function fmtTokens(n) {
  const helpers = globalThis.MissionOverviewHelpers;
  if (helpers?.formatTokenCount) return helpers.formatTokenCount(n);
  const v = Number(n) || 0;
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}k`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return String(v);
}

function llmUsageOf(r) {
  return (r && r.llm_usage) || {};
}

function tokenCountsSafe(usage) {
  const helpers = globalThis.MissionOverviewHelpers;
  if (helpers?.tokenCountsOf) return helpers.tokenCountsOf(usage);
  return { input: 0, output: 0, total: 0, calls: 0 };
}

function modelUsageTooltipSafe(usage) {
  const helpers = globalThis.MissionOverviewHelpers;
  if (!helpers?.modelUsageRows || !helpers.modelUsageTooltip) return "";
  return helpers.modelUsageTooltip(helpers.modelUsageRows(usage));
}

function renderTokenCountsHtml(usageOrCounts, opts) {
  const counts = tokenCountsSafe(usageOrCounts);
  const cls = (opts && opts.className) || "tok-counts";
  const title = (opts && opts.title) || "";
  const titleAttr = title ? ` title="${esc(title)}"` : "";
  const bits = [
    ["In", counts.input],
    ["Out", counts.output],
    ["Total", counts.total],
  ];
  const inner = bits
    .map(
      ([lab, n]) =>
        `<span class="tok-k"><span class="tok-lab">${lab}</span><span class="tok-val mono">${esc(fmtTokens(n))}</span></span>`
    )
    .join("");
  return `<div class="${cls}"${titleAttr}>${inner}</div>`;
}

function renderHomeStats(runs) {
  const box = $("#home-stats");
  if (!box) return;
  const ok = (runs || []).filter((r) => !r.error);
  if (!ok.length) {
    box.hidden = true;
    box.removeAttribute("title");
    box.innerHTML = "";
    return;
  }
  const helpers = globalThis.MissionOverviewHelpers;
  const agg = helpers?.aggregateRunUsage
    ? helpers.aggregateRunUsage(ok)
    : { input: 0, output: 0, total: 0, models: [] };
  const tip = helpers?.modelUsageTooltip ? helpers.modelUsageTooltip(agg.models || []) : "";
  box.hidden = false;
  if (tip) box.title = tip;
  else box.removeAttribute("title");
  box.innerHTML = `
    <span class="tok-strip-label">Tokens</span>
    ${renderTokenCountsHtml(agg, { className: "tok-counts" })}
  `;
}

function sevPills(sev) {
  const s = sev || {};
  const parts = [
    ["crit", s.critical, "crit"],
    ["high", s.high, "high"],
    ["med", s.medium, "med"],
    ["low", s.low, "low"],
  ];
  return (
    `<div class="sev-row">${parts
      .map(
        ([lab, n, cls]) =>
          `<span class="sev-pill ${cls} ${n ? "has" : ""}"><span class="sev-lab">${lab}</span><span class="sev-n">${n || 0}</span></span>`
      )
      .join("")}</div>`
  );
}

function renderRunCards(runs) {
  const box = $("#run-list");
  if (!box) return;
  const filtered = runs.filter((r) => !r.error && matchesQuery(r, homeQuery));
  const errors = runs.filter((r) => r.error);
  const attention = $("#home-attention");
  if (attention && globalThis.HomeHelpers) {
    const html = globalThis.HomeHelpers.renderAttentionHtml(
      globalThis.HomeHelpers.attentionItems(runs),
      esc
    );
    attention.innerHTML = html;
    attention.hidden = !html;
  }
  if (!runs.length) {
    box.innerHTML = `<div class="empty">No runs yet. Start a new audit to begin recon -> hunt -> validate.</div>`;
    return;
  }
  if (!filtered.length && !errors.length) {
    const clear = homeQuery
      ? ` <button type="button" class="btn btn-ghost" id="home-search-clear">Clear</button>`
      : "";
    box.innerHTML = `<div class="empty">No runs match.${clear}</div>`;
    $("#home-search-clear")?.addEventListener("click", () => {
      homeQuery = "";
      const input = $("#home-search");
      if (input) input.value = "";
      renderRunCards(homeRunsCache);
    });
    return;
  }
  const H = globalThis.HomeHelpers;
  const ordered = H ? H.sortRuns(filtered) : filtered;
  const parts = [
    `<div class="vf-run-head" aria-hidden="true"><span>Status</span><span>Run</span><span>Pipeline</span><span>Last activity</span><span>Tokens</span></div>`,
  ];
  parts.push(...ordered.map((r) => renderRunRow(r, classifyRun(r))));
  const errHtml = errors
    .map(
      (r) =>
        `<div class="run-row"><span><div class="title">${esc(r.key || "error")}</div><div class="meta" style="color:var(--bad)">${esc(r.error)}</div></span></div>`
    )
    .join("");
  box.innerHTML = parts.join("") + errHtml;
}

async function deleteRun(target_id, run_id, opts = {}) {
  const redirectHome = opts.redirectHome !== false;
  if (!target_id || !run_id) return;
  const label = `${target_id}/${run_id}`;
  const ok = confirm(
    `Permanently delete run ${label}?\n\nThis removes harness.db, evidence/, transcripts/, and project/. This cannot be undone.`
  );
  if (!ok) return;
  const ok2 = confirm(`Type-confirm: delete ${label} forever?`);
  if (!ok2) return;
  try {
    await api(
      `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}?force=true`,
      { method: "DELETE" }
    );
    toast(`Deleted ${label}`);
    if (redirectHome || document.body.dataset.page === "run") {
      location.href = "/";
    } else {
      await loadRuns();
    }
  } catch (e) {
    toast(e.message, true);
  }
}

async function loadRuns() {
  const box = $("#run-list");
  if (!box) return;
  if (!homeRunsCache.length) {
    box.innerHTML = `<div class="empty">Loading runs...</div>`;
  }
  try {
    const data = await api("/api/runs");
    homeRunsCache = data.runs || [];
    renderHomeStats(homeRunsCache);
    renderRunCards(homeRunsCache);
  } catch (e) {
    box.innerHTML = `<div class="empty">Failed to load: ${esc(e.message)}</div>`;
  }
}

const STRATEGY_LABELS = {
  discovery: "Discovery recon",
  file_by_file: "File-by-file",
  recon_docs: "Recon with docs",
};

function selectedInitStrategy() {
  const el = document.querySelector('input[name="init-strategy"]:checked');
  return el?.value || "discovery";
}

function syncInitDocsField() {
  const field = $("#init-docs-field");
  if (!field) return;
  const needDocs = selectedInitStrategy() === "recon_docs";
  field.hidden = !needDocs;
  const input = $("#init-docs-path");
  if (input) {
    input.required = needDocs;
    if (!needDocs) input.setCustomValidity("");
  }
}

/** Show recon agent picker + brief for strategies that enqueue recon. */
function syncInitReconFields() {
  const field = $("#init-recon-fields");
  if (!field) return;
  const strategy = selectedInitStrategy();
  const show = strategy === "discovery" || strategy === "recon_docs";
  field.hidden = !show;
  syncInitDynamicSkillsField();
}

function syncInitDynamicSkillsField() {
  const wrap = $("#init-dynamic-skill-count-wrap");
  const cb = $("#init-dynamic-skills");
  if (!cb) return;
  const strategy = selectedInitStrategy();
  const reconOk = strategy === "discovery" || strategy === "recon_docs";
  if (!reconOk) {
    cb.checked = false;
  }
  if (wrap) wrap.hidden = !(cb.checked && reconOk);
}

let reconAgentsCache = null;
let reconAgentsCacheAt = 0;
const RECON_AGENTS_TTL_MS = 60_000;

async function fetchReconAgents({ force = false } = {}) {
  const now = Date.now();
  if (!force && reconAgentsCache && now - reconAgentsCacheAt < RECON_AGENTS_TTL_MS) {
    return reconAgentsCache;
  }
  const data = await api("/api/recon-agents?include_body=0");
  const agents = Array.isArray(data?.agents) ? data.agents : [];
  agents.sort((a, b) => {
    const oa = a.order ?? 100;
    const ob = b.order ?? 100;
    if (oa !== ob) return oa - ob;
    return String(a.id || "").localeCompare(String(b.id || ""));
  });
  reconAgentsCache = agents;
  reconAgentsCacheAt = now;
  return agents;
}

/**
 * Render multi-select recon agent checkboxes into a container.
 * @param {HTMLElement} container
 * @param {object} opts
 * @param {string} opts.namePrefix - data attribute / name prefix for checkboxes
 * @param {boolean} opts.precheckActive - check agents marked active in collection
 * @param {string[]|null} opts.selectedIds - if set, precheck these ids instead
 */
function renderReconAgentPicker(container, opts = {}) {
  if (!container) return;
  const namePrefix = opts.namePrefix || "recon-agent";
  const agents = opts.agents || [];
  if (!agents.length) {
    container.innerHTML = `<div class="controls-hint">No recon agents in collection. Open Dev → Recon agents to seed or create some.</div>`;
    return;
  }
  const selected = opts.selectedIds
    ? new Set(opts.selectedIds.map((x) => String(x).toLowerCase()))
    : null;
  const precheckActive = opts.precheckActive !== false;
  container.innerHTML = agents
    .map((a) => {
      const id = String(a.id || "");
      const title = a.title || id;
      const desc = a.description || "";
      const active = !!a.active;
      let checked = false;
      if (selected) {
        checked = selected.has(id.toLowerCase());
      } else if (precheckActive) {
        checked = active;
      }
      const activeBadge = active
        ? `<span class="recon-agent-active-badge" title="Active by default">active</span>`
        : "";
      return `
        <label class="recon-agent-option" title="${esc(desc || title)}">
          <input type="checkbox" data-recon-agent-id="${esc(id)}" name="${esc(namePrefix)}" value="${esc(id)}" ${checked ? "checked" : ""} />
          <span class="recon-agent-option-main">
            <span class="recon-agent-option-title mono">${esc(id)}</span>
            ${activeBadge}
            <span class="recon-agent-option-desc">${esc(title)}${desc ? " — " + esc(desc) : ""}</span>
          </span>
        </label>`;
    })
    .join("");
}

function selectedReconAgentIds(root) {
  const scope = root || document;
  return Array.from(scope.querySelectorAll("input[data-recon-agent-id]:checked"))
    .map((el) => (el.getAttribute("data-recon-agent-id") || el.value || "").trim())
    .filter(Boolean);
}

/* ---------- Hunt skill mode (init + operator re-run) ---------- */

let huntProfilesCache = null;
let huntProfilesCacheAt = 0;
const HUNT_PROFILES_TTL_MS = 60_000;

async function fetchHuntProfiles({ force = false } = {}) {
  const now = Date.now();
  if (!force && huntProfilesCache && now - huntProfilesCacheAt < HUNT_PROFILES_TTL_MS) {
    return huntProfilesCache;
  }
  const data = await api("/api/hunt-profiles?include_body=0");
  const profiles = Array.isArray(data?.profiles) ? data.profiles : [];
  profiles.sort((a, b) => String(a.id || "").localeCompare(String(b.id || "")));
  huntProfilesCache = profiles;
  huntProfilesCacheAt = now;
  return profiles;
}

function selectedHuntSkillMode(name) {
  const el = document.querySelector(`input[name="${name}"]:checked`);
  return (el && el.value) || "all_active";
}

function selectedHuntSkillIds(root) {
  const scope = root || document;
  return Array.from(scope.querySelectorAll("input[data-hunt-skill-id]:checked"))
    .map((el) => (el.getAttribute("data-hunt-skill-id") || el.value || "").trim())
    .filter(Boolean);
}

/**
 * Multi-select hunt skill checkboxes (for mode=explicit).
 */
function renderHuntSkillPicker(container, opts = {}) {
  if (!container) return;
  const namePrefix = opts.namePrefix || "hunt-skill";
  const profiles = opts.profiles || [];
  if (!profiles.length) {
    container.innerHTML = `<div class="controls-hint">No hunt skills in collection. Open Dev → Hunt skills to seed or create some.</div>`;
    return;
  }
  const selected = opts.selectedIds
    ? new Set(opts.selectedIds.map((x) => String(x).toLowerCase()))
    : null;
  const precheckActive = opts.precheckActive === true;
  container.innerHTML = profiles
    .map((p) => {
      const id = String(p.id || "");
      const title = p.title || id;
      const desc = p.description || "";
      const active = !!p.active;
      const source = p.source || "";
      let checked = false;
      if (selected) {
        checked = selected.has(id.toLowerCase());
      } else if (precheckActive) {
        checked = active;
      }
      const badges = [];
      if (active) badges.push(`<span class="recon-agent-active-badge" title="Active">active</span>`);
      if (source) {
        badges.push(
          `<span class="recon-agent-active-badge" style="opacity:0.75" title="source">${esc(source)}</span>`
        );
      }
      return `
        <label class="recon-agent-option" title="${esc(desc || title)}">
          <input type="checkbox" data-hunt-skill-id="${esc(id)}" name="${esc(namePrefix)}" value="${esc(id)}" ${checked ? "checked" : ""} />
          <span class="recon-agent-option-main">
            <span class="recon-agent-option-title mono">${esc(id)}</span>
            ${badges.join(" ")}
            <span class="recon-agent-option-desc">${esc(title)}${desc ? " — " + esc(desc) : ""}</span>
          </span>
        </label>`;
    })
    .join("");
}

function syncHuntSkillPickerVisibility(modeName, pickerId) {
  const mode = selectedHuntSkillMode(modeName);
  const picker = document.getElementById(pickerId);
  if (picker) picker.hidden = mode !== "explicit";
}

function wireHuntSkillModeRadios(modeName, pickerId) {
  document.querySelectorAll(`input[name="${modeName}"]`).forEach((el) => {
    el.addEventListener("change", () => syncHuntSkillPickerVisibility(modeName, pickerId));
  });
  syncHuntSkillPickerVisibility(modeName, pickerId);
}

async function loadInitHuntSkills() {
  const box = $("#init-hunt-skills");
  if (!box) return;
  try {
    const profiles = await fetchHuntProfiles();
    renderHuntSkillPicker(box, {
      namePrefix: "init-hunt-skill",
      profiles,
      precheckActive: false,
    });
  } catch (e) {
    box.innerHTML = `<div class="controls-hint" style="color:var(--bad)">Failed to load hunt skills: ${esc(e.message)}</div>`;
  }
}

function collectHuntSkillPolicy(modeName, pickerRoot) {
  const mode = selectedHuntSkillMode(modeName);
  const out = { hunt_skill_mode: mode };
  if (mode === "explicit") {
    out.hunt_skill_ids = selectedHuntSkillIds(pickerRoot);
  }
  return out;
}

async function loadInitReconAgents() {
  const box = $("#init-recon-agents");
  if (!box) return;
  try {
    const agents = await fetchReconAgents();
    renderReconAgentPicker(box, {
      namePrefix: "init-recon-agent",
      agents,
      precheckActive: true,
    });
  } catch (e) {
    box.innerHTML = `<div class="controls-hint" style="color:var(--bad)">Failed to load recon agents: ${esc(e.message)}</div>`;
  }
}

function selectedInitProfile() {
  const el = document.querySelector('input[name="init-profile"]:checked');
  return (el?.value || "code_static").trim().toLowerCase();
}

function setInitProfile(profile) {
  const id = (profile || "code_static").trim().toLowerCase();
  const radio = document.querySelector(`input[name="init-profile"][value="${id}"]`);
  if (radio) {
    radio.checked = true;
    syncInitProfileFields();
  }
}

/** Keep target hint in sync with the (source-only) profile. */
function syncInitProfileFields() {
  const hint = $("#init-target-hint");
  if (hint) {
    hint.textContent = "Source folder or single source file (source analysis only)";
  }
  const fbf = document.querySelector('input[name="init-strategy"][value="file_by_file"]');
  if (fbf) fbf.disabled = false;
}

/** Source-only profile: always code_static. */
function suggestInitProfileFromPath(_path) {
  setInitProfile("code_static");
}

function openInitModal() {
  $("#init-modal")?.classList.add("open");
  const disc = document.querySelector('input[name="init-strategy"][value="discovery"]');
  if (disc) disc.checked = true;
  const notes = $("#init-recon-notes");
  if (notes) notes.value = "";
  const dyn = $("#init-dynamic-skills");
  if (dyn) dyn.checked = false;
  const dynCount = $("#init-dynamic-skill-count");
  if (dynCount) dynCount.value = "3";
  const modeDefault = document.querySelector(
    'input[name="init-hunt-skill-mode"][value="all_active"]'
  );
  if (modeDefault) modeDefault.checked = true;
  setInitProfile("code_static");
  syncInitDocsField();
  syncInitReconFields();
  syncInitProfileFields();
  loadInitReconAgents();
  loadInitHuntSkills();
  wireHuntSkillModeRadios("init-hunt-skill-mode", "init-hunt-skill-picker");
  syncHuntSkillPickerVisibility("init-hunt-skill-mode", "init-hunt-skill-picker");
}
function closeInitModal() {
  $("#init-modal")?.classList.remove("open");
  hideInitFloatingTip();
}

/* Floating help tip. Shared by New audit ? buttons and Mission funnel /
   presence bits. position:fixed so overflow:auto on the page does not clip it. */
let _initTipAnchor = null;
let _floatingTipViewportWired = false;
const FLOATING_TIP_ID = "init-floating-tip";

function ensureInitFloatingTip() {
  let el = $("#init-floating-tip");
  if (!el) {
    el = document.createElement("div");
    el.id = FLOATING_TIP_ID;
    el.className = "init-floating-tip";
    el.setAttribute("role", "tooltip");
    el.hidden = true;
    document.body.appendChild(el);
  }
  return el;
}

function releaseTipAnchor(anchor) {
  if (!anchor) return;
  if (anchor.dataset.tipTitle != null) {
    anchor.setAttribute("title", anchor.dataset.tipTitle);
    delete anchor.dataset.tipTitle;
  }
  if (anchor.dataset.tipDescribedby != null) {
    const prev = anchor.dataset.tipDescribedby;
    if (prev) anchor.setAttribute("aria-describedby", prev);
    else anchor.removeAttribute("aria-describedby");
    delete anchor.dataset.tipDescribedby;
  } else if (anchor.getAttribute("aria-describedby") === FLOATING_TIP_ID) {
    anchor.removeAttribute("aria-describedby");
  }
}

function claimTipAnchor(anchor) {
  const label = anchor.getAttribute("aria-label") || "";
  const tipText = (anchor.getAttribute("data-tip") || "").trim();
  const named = !!(tipText && label.includes(tipText));
  if (!named) {
    if (anchor.dataset.tipDescribedby == null) {
      const prev = anchor.getAttribute("aria-describedby") || "";
      if (prev !== FLOATING_TIP_ID) anchor.dataset.tipDescribedby = prev;
    }
    anchor.setAttribute("aria-describedby", FLOATING_TIP_ID);
  }
  if (anchor.hasAttribute("title")) {
    if (anchor.dataset.tipTitle == null) {
      anchor.dataset.tipTitle = anchor.getAttribute("title") || "";
    }
    anchor.removeAttribute("title");
  }
}

function positionInitFloatingTip(anchor) {
  const tip = ensureInitFloatingTip();
  if (tip.hidden || !anchor) return;
  const r = anchor.getBoundingClientRect();
  const pad = 8;
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  // Measure after content is set
  tip.style.left = "0px";
  tip.style.top = "0px";
  const tw = tip.offsetWidth;
  const th = tip.offsetHeight;
  // Prefer above the icon; flip below if clipped
  let top = r.top - th - 8;
  if (top < pad) top = r.bottom + 8;
  if (top + th > vh - pad) top = Math.max(pad, vh - th - pad);
  // Align to icon, keep on-screen
  let left = r.left + r.width / 2 - tw / 2;
  if (left < pad) left = pad;
  if (left + tw > vw - pad) left = Math.max(pad, vw - tw - pad);
  tip.style.left = `${Math.round(left)}px`;
  tip.style.top = `${Math.round(top)}px`;
}

function showInitFloatingTip(anchor) {
  const text = (anchor?.getAttribute("data-tip") || "").trim();
  if (!text || !anchor) return;
  if (_initTipAnchor && _initTipAnchor !== anchor) releaseTipAnchor(_initTipAnchor);
  const tip = ensureInitFloatingTip();
  tip.textContent = text;
  tip.hidden = false;
  _initTipAnchor = anchor;
  claimTipAnchor(anchor);
  positionInitFloatingTip(anchor);
}

function hideInitFloatingTip(anchor) {
  if (anchor && _initTipAnchor && anchor !== _initTipAnchor) return;
  const tip = $("#init-floating-tip");
  if (tip) tip.hidden = true;
  if (_initTipAnchor) {
    releaseTipAnchor(_initTipAnchor);
    _initTipAnchor = null;
  }
}

function wireFloatingTipViewport() {
  if (_floatingTipViewportWired) return;
  _floatingTipViewportWired = true;
  window.addEventListener(
    "scroll",
    () => {
      if (_initTipAnchor) positionInitFloatingTip(_initTipAnchor);
    },
    true
  );
  window.addEventListener("resize", () => {
    if (_initTipAnchor) positionInitFloatingTip(_initTipAnchor);
  });
}

/** Event delegation for .init-help buttons inside New audit modal. */
function wireInitHelpTips() {
  const modal = $("#init-modal");
  if (!modal || modal.dataset.helpWired === "1") return;
  modal.dataset.helpWired = "1";

  const onEnter = (e) => {
    const btn = e.target.closest?.(".init-help");
    if (!btn || !modal.contains(btn)) return;
    showInitFloatingTip(btn);
  };
  const onLeave = (e) => {
    const btn = e.target.closest?.(".init-help");
    if (!btn || !modal.contains(btn)) return;
    // Keep tip if focus moves into related target that is the same help (rare)
    const next = e.relatedTarget;
    if (next && (next === btn || btn.contains(next))) return;
    hideInitFloatingTip(btn);
  };

  modal.addEventListener("mouseover", onEnter);
  modal.addEventListener("mouseout", onLeave);
  modal.addEventListener("focusin", onEnter);
  modal.addEventListener("focusout", onLeave);

  // Clicking ? inside a strategy <label> should not flip selection awkwardly
  // (label still works via the radio); stop activation when using the help control.
  modal.addEventListener(
    "click",
    (e) => {
      const btn = e.target.closest?.(".init-help");
      if (!btn || !modal.contains(btn)) return;
      e.preventDefault();
      e.stopPropagation();
      // Toggle tip on click for touch / explicit open
      if (_initTipAnchor === btn && !$("#init-floating-tip")?.hidden) {
        hideInitFloatingTip(btn);
      } else {
        showInitFloatingTip(btn);
      }
    },
    true
  );

  wireFloatingTipViewport();
}

/** Immediate hover tips for Mission funnel stages and who/why-paused bits. */
window.showInitFloatingTip = showInitFloatingTip;
window.hideInitFloatingTip = hideInitFloatingTip;
window.wireFloatingTipViewport = wireFloatingTipViewport;


/* ---------- Host path picker (New audit) ---------- */

let pathPicker = {
  mode: "dirs", // dirs | any
  targetId: null, // input element id to fill
  path: "",
  allowFiles: false,
  selectedIsFile: false,
};

function _updatePathPickerSelectLabel() {
  const selBtn = $("#path-picker-select");
  if (!selBtn) return;
  if (!pathPicker.allowFiles) {
    selBtn.textContent = "Select this folder";
    return;
  }
  selBtn.textContent = pathPicker.selectedIsFile ? "Select this file" : "Select this folder";
}

function openPathPicker({ mode, targetId, startPath, title, hint }) {
  pathPicker.mode = mode === "any" ? "any" : "dirs";
  pathPicker.allowFiles = pathPicker.mode === "any";
  pathPicker.targetId = targetId;
  pathPicker.path = (startPath || "").trim();
  pathPicker.selectedIsFile = false;
  const modal = $("#path-picker-modal");
  if (!modal) return;
  const titleEl = $("#path-picker-title");
  const hintEl = $("#path-picker-hint");
  if (titleEl) titleEl.textContent = title || (pathPicker.allowFiles ? "Select file or folder" : "Select folder");
  if (hintEl) {
    hintEl.textContent =
      hint ||
      (pathPicker.allowFiles
        ? "Double-click a folder to open it, or a file to select it. Or select the current folder."
        : "Double-click a folder to open it, then Select this folder.");
  }
  _updatePathPickerSelectLabel();
  modal.classList.add("open");
  loadPathPicker(pathPicker.path);
}

function closePathPicker() {
  $("#path-picker-modal")?.classList.remove("open");
  pathPicker.targetId = null;
  pathPicker.selectedIsFile = false;
}

async function loadPathPicker(path) {
  const list = $("#path-picker-list");
  const status = $("#path-picker-status");
  const pathInput = $("#path-picker-path");
  if (!list) return;
  list.innerHTML = `<div class="empty" style="padding:0.75rem">Loading...</div>`;
  if (status) status.textContent = "";
  pathPicker.selectedIsFile = false;
  _updatePathPickerSelectLabel();
  try {
    const q = new URLSearchParams({
      path: path || "",
      mode: pathPicker.mode,
    });
    const data = await api(`/api/fs/browse?${q}`);
    pathPicker.path = data.path || "";
    if (pathInput) pathInput.value = pathPicker.path;
    const entries = data.entries || [];
    if (!entries.length) {
      list.innerHTML = `<div class="empty" style="padding:0.75rem">${
        data.is_root ? "No drives found." : "Empty folder."
      }</div>`;
    } else {
      list.innerHTML = entries
        .map((e) => {
          const kind = e.is_dir ? "dir" : "file";
          const ico = e.is_dir ? "folder" : "file";
          return `<button type="button" class="path-picker-item ${kind}" role="option"
            data-path="${esc(e.path)}" data-dir="${e.is_dir ? "1" : "0"}" data-file="${e.is_file ? "1" : "0"}"
            title="${esc(e.path)}">
            <span class="tree-ico tree-ico-${ico}" aria-hidden="true"></span>
            <span class="path-picker-name">${esc(e.name)}</span>
            <span class="path-picker-kind">${e.is_dir ? "folder" : "file"}</span>
          </button>`;
        })
        .join("");
      list.querySelectorAll(".path-picker-item").forEach((btn) => {
        btn.addEventListener("click", () => {
          list.querySelectorAll(".path-picker-item").forEach((b) => b.classList.remove("selected"));
          btn.classList.add("selected");
          const p = btn.getAttribute("data-path") || "";
          const isDir = btn.getAttribute("data-dir") === "1";
          const isFile = btn.getAttribute("data-file") === "1";
          if (pathInput) pathInput.value = p;
          if (isDir) {
            pathPicker.path = p;
            pathPicker.selectedIsFile = false;
          } else if (isFile && pathPicker.allowFiles) {
            pathPicker.path = p;
            pathPicker.selectedIsFile = true;
          }
          _updatePathPickerSelectLabel();
          if (status) {
            status.textContent = isFile
              ? `File: ${p}`
              : isDir
                ? `Folder: ${p}`
                : "";
          }
        });
        btn.addEventListener("dblclick", () => {
          const p = btn.getAttribute("data-path") || "";
          const isDir = btn.getAttribute("data-dir") === "1";
          const isFile = btn.getAttribute("data-file") === "1";
          if (isDir) {
            loadPathPicker(p);
          } else if (isFile && pathPicker.allowFiles) {
            applyPathPickerSelection(p);
          }
        });
      });
    }
    if (data.selected_file && pathPicker.allowFiles) {
      if (pathInput) pathInput.value = data.selected_file;
      pathPicker.path = data.selected_file;
      pathPicker.selectedIsFile = true;
      _updatePathPickerSelectLabel();
      if (status) status.textContent = `File: ${data.selected_file}`;
      // Highlight matching entry when browse was opened on a file path
      const sel = String(data.selected_file).toLowerCase();
      list.querySelectorAll(".path-picker-item").forEach((btn) => {
        if ((btn.getAttribute("data-path") || "").toLowerCase() === sel) {
          btn.classList.add("selected");
        }
      });
    }
    const up = $("#path-picker-up");
    if (up) {
      up.disabled = data.is_root || data.parent === null || data.parent === undefined;
      up.dataset.parent = data.parent != null ? String(data.parent) : "";
    }
  } catch (e) {
    list.innerHTML = `<div class="empty" style="padding:0.75rem;color:var(--bad)">${esc(e.message || e)}</div>`;
    if (status) status.textContent = "";
  }
}

function applyPathPickerSelection(explicitPath) {
  const pathInput = $("#path-picker-path");
  const chosen = (explicitPath || pathInput?.value || pathPicker.path || "").trim();
  if (!chosen) {
    toast("Select a path first", true);
    return;
  }
  if (!pathPicker.targetId) {
    closePathPicker();
    return;
  }
  // dirs-only picker: reject file selection (defense in depth)
  if (!pathPicker.allowFiles && pathPicker.selectedIsFile) {
    toast("Select a folder", true);
    return;
  }
  const input = document.getElementById(pathPicker.targetId);
  if (input) {
    input.value = chosen;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }
  if (pathPicker.targetId === "init-target") {
    suggestInitProfileFromPath(chosen);
  }
  closePathPicker();
}

function wirePathPicker() {
  $("#btn-browse-target")?.addEventListener("click", () => {
    openPathPicker({
      mode: "any",
      targetId: "init-target",
      startPath: ($("#init-target")?.value || "").trim(),
      title: "Select target",
      hint: "Double-click a folder to open it, or a file (.exe/.dll) to select it. Select this folder uses the current directory.",
    });
  });
  $("#btn-browse-docs")?.addEventListener("click", () => {
    openPathPicker({
      mode: "any",
      targetId: "init-docs-path",
      startPath: ($("#init-docs-path")?.value || "").trim(),
      title: "Select docs path",
      hint: "Folder or file (md, html, docx, pdf, xlsx) for recon with docs.",
    });
  });
  $("#path-picker-cancel")?.addEventListener("click", closePathPicker);
  $("#path-picker-select")?.addEventListener("click", () => applyPathPickerSelection());
  $("#path-picker-go")?.addEventListener("click", () => {
    loadPathPicker(($("#path-picker-path")?.value || "").trim());
  });
  $("#path-picker-path")?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      loadPathPicker(($("#path-picker-path")?.value || "").trim());
    }
  });
  $("#path-picker-up")?.addEventListener("click", () => {
    const up = $("#path-picker-up");
    const parent = up?.dataset?.parent;
    if (parent === "") loadPathPicker("");
    else if (parent) loadPathPicker(parent);
    else loadPathPicker("");
  });
  // Profile radios + target path typing
  document.querySelectorAll('input[name="init-profile"]').forEach((el) => {
    el.addEventListener("change", () => syncInitProfileFields());
  });
  $("#init-target")?.addEventListener("change", () => {
    suggestInitProfileFromPath(($("#init-target")?.value || "").trim());
  });
  // Debounced suggestion while typing a PE path
  let _initTargetSuggestTimer = null;
  $("#init-target")?.addEventListener("input", () => {
    clearTimeout(_initTargetSuggestTimer);
    _initTargetSuggestTimer = setTimeout(() => {
      const v = ($("#init-target")?.value || "").trim();
      if (/\.(exe|dll)$/i.test(v)) suggestInitProfileFromPath(v);
    }, 400);
  });
}

let _initElapsedTimer = null;
let _initStartedAt = 0;
let _initLastPct = 0;

function _clearInitElapsed() {
  if (_initElapsedTimer) {
    clearInterval(_initElapsedTimer);
    _initElapsedTimer = null;
  }
}

function _fmtElapsed(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}m ${r}s`;
}

function _mapInitPhase(phase, status) {
  const p = String(phase || "").toLowerCase();
  const st = String(status || "").toLowerCase();
  if (st === "done" || p === "done" || p === "complete") return "done";
  if (p.includes("ralph")) return "ralph";
  if (p.includes("db") || p.includes("database") || p.includes("harness")) return "database";
  if (
    p.includes("invent") ||
    p.includes("scan") ||
    p.includes("hash") ||
    p.includes("index") ||
    p.includes("prompt")
  )
    return "inventory";
  if (p.includes("queue") || p === "working" || p === "prepare") return "queued";
  if (p.includes("start")) return "ralph";
  return "inventory";
}

function setInitPhase(phaseKey) {
  const steps = $$("#init-phase-steps li");
  if (!steps.length) return;
  const order = ["queued", "inventory", "database", "ralph", "done"];
  const idx = Math.max(0, order.indexOf(phaseKey));
  steps.forEach((li) => {
    const ph = li.getAttribute("data-phase");
    const i = order.indexOf(ph);
    li.classList.toggle("active", i === idx);
    li.classList.toggle("done", i >= 0 && i < idx);
  });
}

function openInitLoading(targetPath, { start } = {}) {
  closeInitModal();
  const modal = $("#init-loading-modal");
  if (!modal) return;
  modal.classList.add("open");
  modal.classList.remove("is-success");
  modal.setAttribute("aria-busy", "true");
  const title = $("#init-loading-title");
  if (title) {
    title.textContent = start ? "Starting audit run" : "Creating audit run";
  }
  const tEl = $("#init-loading-target");
  if (tEl) tEl.textContent = targetPath || "";
  const hint = $("#init-loading-hint");
  if (hint) {
    hint.textContent = start
      ? "Inventory → harness.db → start Ralph. Large trees take longer."
      : "Inventory → harness.db. Large trees take longer.";
    hint.hidden = false;
  }
  const actions = $("#init-loading-actions");
  if (actions) actions.hidden = true;
  const box = $(".init-status-loading");
  if (box) {
    box.classList.remove("error", "success");
  }
  const metrics = $("#init-metrics");
  if (metrics) metrics.hidden = false;
  _initStartedAt = Date.now();
  _initLastPct = 0;
  _clearInitElapsed();
  const tickElapsed = () => {
    const el = $("#init-metric-elapsed");
    if (el) el.textContent = _fmtElapsed(Date.now() - _initStartedAt);
  };
  tickElapsed();
  _initElapsedTimer = setInterval(tickElapsed, 500);
  setInitPhase("queued");
  setInitStatus("Starting inventory…", null, { indeterminate: true });
}

function closeInitLoading() {
  _clearInitElapsed();
  const modal = $("#init-loading-modal");
  modal?.classList.remove("open", "is-success");
}

function setInitStatus(msg, pct, { error, success, indeterminate, files, phase } = {}) {
  const bar = $("#init-status-bar");
  const text = $("#init-status-text");
  const meta = $("#init-status-meta");
  const track = bar?.parentElement;
  const box = $(".init-status-loading");
  const modal = $("#init-loading-modal");
  if (text) text.textContent = msg || "";
  if (error) {
    box?.classList.add("error");
    box?.classList.remove("success");
  } else if (success) {
    box?.classList.add("success");
    box?.classList.remove("error");
  } else {
    box?.classList.remove("error", "success");
  }
  if (files != null) {
    const fEl = $("#init-metric-files");
    if (fEl) fEl.textContent = String(files);
  }
  const mapped = phase
    ? _mapInitPhase(phase, success ? "done" : error ? "error" : "running")
    : null;
  if (mapped) setInitPhase(mapped);

  const knownPct = pct != null && Number.isFinite(Number(pct));
  let p = knownPct ? Math.max(0, Math.min(100, Number(pct))) : null;
  // Smooth monotonic progress (avoid bar jumping backward)
  if (p != null) {
    p = Math.max(_initLastPct, p);
    _initLastPct = p;
  }
  const useIndeterminate =
    !!indeterminate || (!knownPct && !success && !error) || (p != null && p > 0 && p < 4 && !success);

  if (track) {
    track.classList.toggle("is-indeterminate", useIndeterminate && !success && !error);
  }
  if (bar && !useIndeterminate && p != null) {
    bar.style.width = `${p}%`;
    track?.setAttribute("aria-valuenow", String(p));
  } else if (bar && useIndeterminate) {
    track?.setAttribute("aria-valuenow", "0");
  }
  if (meta) {
    if (success) meta.textContent = "done";
    else if (error) meta.textContent = "error";
    else if (p != null && !useIndeterminate) meta.textContent = `${Math.round(p)}%`;
    else meta.textContent = "working…";
  }
  if (success) {
    modal?.classList.add("is-success");
    modal?.setAttribute("aria-busy", "false");
    setInitPhase("done");
  }
}

function showInitLoadingError(msg) {
  _clearInitElapsed();
  const modal = $("#init-loading-modal");
  if (modal) {
    modal.setAttribute("aria-busy", "false");
    modal.classList.remove("is-success");
  }
  setInitStatus(msg || "Failed", 100, { error: true });
  const hint = $("#init-loading-hint");
  if (hint) {
    hint.textContent = "Fix the path or settings and try again.";
    hint.hidden = false;
  }
  const actions = $("#init-loading-actions");
  if (actions) actions.hidden = false;
}

function goToRunPage(targetId, runId) {
  if (targetId && runId) {
    location.href = `/runs/${encodeURIComponent(targetId)}/${encodeURIComponent(runId)}`;
  } else {
    closeInitLoading();
    loadRuns();
  }
}

async function pollInitJob(jobId, { start } = {}) {
  const deadline = Date.now() + 30 * 60 * 1000;
  while (Date.now() < deadline) {
    const job = await api(`/api/runs/init-jobs/${encodeURIComponent(jobId)}`);
    const pct = job.percent != null ? Number(job.percent) : null;
    const files = job.files_seen != null ? job.files_seen : null;
    const phase = String(job.phase || "");
    const msg =
      job.message ||
      (phase
        ? `${phase}${files != null ? ` · ${files} files` : ""}`
        : "Working…");
    let phaseKey = phase;
    const phaseL = phase.toLowerCase();
    if (job.status === "done") {
      phaseKey = "done";
    } else if (phaseL.includes("ralph")) {
      phaseKey = "ralph";
    } else if (phaseL.includes("database") || phaseL.includes("prompt")) {
      phaseKey = phaseL.includes("prompt") ? "inventory" : "database";
    } else if (pct != null && pct >= 97 && start) {
      phaseKey = "ralph";
    } else if (pct != null && pct >= 70) {
      phaseKey = "database";
    }
    setInitStatus(msg, pct, {
      files,
      phase: phaseKey,
      indeterminate: pct == null || (pct < 3 && job.status === "running"),
    });
    if (job.status === "done" && job.key) {
      setInitStatus(
        start ? "Ralph starting — opening cockpit…" : "Run ready — opening cockpit…",
        100,
        { success: true, files: files ?? undefined, phase: "done" }
      );
      await new Promise((r) => setTimeout(r, 480));
      toast(start ? `Started ${job.key}` : `Created ${job.key}`);
      goToRunPage(job.target_id, job.run_id);
      return;
    }
    if (job.status === "error") {
      throw new Error(job.error || job.message || "init failed");
    }
    await new Promise((r) => setTimeout(r, 320));
  }
  throw new Error("Init timed out waiting for inventory (try a smaller target folder)");
}

async function submitInit(ev) {
  ev.preventDefault();
  const target = $("#init-target").value.trim();
  const start = $("#init-start").checked;
  const max_tasks = parseInt($("#init-max-tasks").value || "50", 10);
  const strategy = selectedInitStrategy();
  // Sync profile from path before reading (paste + Create races the 400ms debounce)
  suggestInitProfileFromPath(target);
  const profile = selectedInitProfile();
  const docs_path = ($("#init-docs-path")?.value || "").trim();
  if (!target) {
    toast("Target path is required", true);
    $("#init-target")?.focus();
    return;
  }
  if (/\.(exe|dll)$/i.test(target.replace(/[\\/]+$/, ""))) {
    toast("PE binaries are not supported — choose a source tree", true);
    $("#init-target")?.focus();
    return;
  }
  if (strategy === "recon_docs" && !docs_path) {
    toast("Docs path is required for Recon with docs", true);
    $("#init-docs-path")?.focus();
    return;
  }
  const btn = $("#init-submit");
  if (btn) btn.disabled = true;
  openInitLoading(target, { start });
  const body = {
    target,
    profile: profile || "code_static",
    start,
    max_tasks,
    task_timeout: 900,
    strategy,
  };
  if (docs_path) body.docs_path = docs_path;
  if (strategy === "discovery" || strategy === "recon_docs") {
    const agent_ids = selectedReconAgentIds($("#init-recon-agents"));
    if (agent_ids.length) body.agent_ids = agent_ids;
    const notes = ($("#init-recon-notes")?.value || "").trim();
    if (notes) body.operator_notes = notes;
    if ($("#init-dynamic-skills")?.checked) {
      body.dynamic_skills = true;
      let n = parseInt($("#init-dynamic-skill-count")?.value || "3", 10);
      if (!Number.isFinite(n)) n = 3;
      body.dynamic_skill_count = Math.max(1, n);
    }
  }
  const skillPolicy = collectHuntSkillPolicy("init-hunt-skill-mode", $("#init-hunt-skills"));
  body.hunt_skill_mode = skillPolicy.hunt_skill_mode;
  // Default true when control missing (older cached HTML)
  body.enqueue_hunts = $("#init-enqueue-hunts") ? !!$("#init-enqueue-hunts").checked : true;
  body.sandbox_poc_validate = !!$("#init-sandbox-poc")?.checked;
  if (skillPolicy.hunt_skill_mode === "explicit" && body.enqueue_hunts) {
    body.hunt_skill_ids = skillPolicy.hunt_skill_ids || [];
    if (!body.hunt_skill_ids.length) {
      toast("Pick at least one hunt skill, or choose another skill mode", true);
      if (btn) btn.disabled = false;
      closeInitLoading();
      $("#init-modal")?.classList.add("open");
      return;
    }
  } else if (skillPolicy.hunt_skill_mode === "explicit") {
    body.hunt_skill_ids = skillPolicy.hunt_skill_ids || [];
  }
  try {
    const r = await api("/api/runs/init", {
      method: "POST",
      body: JSON.stringify(body),
    });
    // Async job (default): poll status while inventory runs
    if (r.async && r.job_id) {
      await pollInitJob(r.job_id, { start });
      return;
    }
    // Blocking response fallback
    setInitStatus(start ? "Ready - opening cockpit..." : "Ready - opening cockpit...", 100);
    await new Promise((r) => setTimeout(r, 350));
    toast(start ? `Started ${r.key}` : `Created ${r.key}`);
    goToRunPage(r.target_id, r.run_id);
  } catch (e) {
    toast(e.message, true);
    showInitLoadingError(e.message || "Failed");
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---------- Run detail ---------- */

let eventOffset = 0;
let es = null;
let currentKey = null;
/** Run key the current EventSource is attached to (avoid tear-down on refresh). */
let streamAttachedKey = null;
/** Debounce Offline so brief SSE reconnect blips do not flicker the Live light. */
let liveOfflineTimer = null;
const LIVE_OFFLINE_MS = 2500;

/**
 * Live UI used to only call loadRunFull() on a short event allowlist that
 * omitted `lease`. Completing a task fired task_done (UI showed completed),
 * then Ralph leased the next task without a UI refresh until manual Refresh.
 *
 * Fix: (1) refresh on lease + other queue events, (2) detect task/finding
 * counter drift on the lightweight SSE snapshot, (3) debounce full reloads.
 */
let lastLiveTaskSig = "";
let loadRunFullTimer = null;
let loadRunFullInFlight = false;
let loadRunFullPending = false;
const LOAD_RUN_FULL_DEBOUNCE_MS = 350;

/** Events that mean queue/runner/findings UI should re-fetch full snap. */
const LIVE_REFRESH_EVENTS = new Set([
  "lease",
  "lease_cap",
  "task_done",
  "failed_task",
  "failed_infra",
  "deadletter",
  "idle",
  "runner_start",
  "runner_pause",
  "runner_resume",
  "runner_stop_hard",
  "hunt_split",
  "shallow_requeue",
  "operator_cancel",
  "operator_requeue",
  "operator_priority",
  "operator_recon_rerun",
  "selection_hunt",
  "human_review",
  "apply_candidate",
  "poc_agent_enqueued",
  "poc_developed",
  "poc_saved",
  "not_implemented",
  "recon_auto_retry",
  "validate_llm_done",
  "coverage_mode",
  // Architecture map updates (recon merge / manual edit / restore)
  "architecture_merge",
  "architecture_updated",
]);

function liveTaskCounts(cardOrSnap) {
  /** Normalize task counters from full snap (tasks[]) or run_card (tasks{}). */
  const counts = {
    leased: 0,
    queued: 0,
    paused: 0,
    succeeded: 0,
    failed_task: 0,
    deadletter: 0,
    cancelled: 0,
    blocked: 0,
  };
  // Prefer explicit summary maps when present (full snap + SSE card).
  const summary = cardOrSnap?.tasks_summary;
  const raw =
    summary && typeof summary === "object" && !Array.isArray(summary)
      ? summary
      : cardOrSnap?.tasks;
  if (Array.isArray(raw)) {
    for (const x of raw) {
      const st = String(x?.state || "").toLowerCase();
      if (st in counts) counts[st] += 1;
    }
  } else if (raw && typeof raw === "object") {
    for (const k of Object.keys(counts)) {
      counts[k] = Number(raw[k]) || 0;
    }
  }
  return counts;
}

function liveFindingCounts(cardOrSnap) {
  const counts = {
    needs_human: 0,
    candidate: 0,
    confirmed: 0,
    rejected_mech: 0,
  };
  // Full snap overwrites card findings dict with a finding *list*; prefer summary.
  const summary = cardOrSnap?.findings_summary;
  const raw =
    summary && typeof summary === "object" && !Array.isArray(summary)
      ? summary
      : cardOrSnap?.findings;
  if (Array.isArray(raw)) {
    for (const x of raw) {
      const st = String(x?.state || "").toLowerCase();
      if (st in counts) counts[st] += 1;
    }
    return counts;
  }
  if (raw && typeof raw === "object") {
    for (const k of Object.keys(counts)) {
      counts[k] = Number(raw[k]) || 0;
    }
  }
  return counts;
}

function liveTaskSig(cardOrSnap) {
  if (!cardOrSnap || typeof cardOrSnap !== "object") return "";
  const t = liveTaskCounts(cardOrSnap);
  const f = liveFindingCounts(cardOrSnap);
  // Prefer explicit done/total when present; otherwise derive a stable proxy.
  const done =
    cardOrSnap.done_tasks != null
      ? Number(cardOrSnap.done_tasks) || 0
      : t.succeeded + t.failed_task + t.deadletter + t.cancelled + t.blocked;
  const total =
    cardOrSnap.total_tasks != null
      ? Number(cardOrSnap.total_tasks) || 0
      : done + t.leased + t.queued + t.paused;
  // Do not include runner.state here — it can flip independently of task rows
  // and would thrash full reloads without changing the tasks table.
  return [
    done,
    total,
    t.leased,
    t.queued,
    t.paused,
    t.succeeded,
    t.failed_task,
    t.deadletter,
    t.cancelled,
    f.needs_human,
    f.candidate,
    f.confirmed,
    f.rejected_mech,
    Number(cardOrSnap.event_count) || 0,
    cardOrSnap.has_work ? 1 : 0,
  ].join("|");
}

function noteLiveTaskSig(cardOrSnap) {
  const sig = liveTaskSig(cardOrSnap);
  if (sig) lastLiveTaskSig = sig;
}

function scheduleLoadRunFull(reason) {
  if (!currentKey) return;
  if (loadRunFullTimer) clearTimeout(loadRunFullTimer);
  loadRunFullTimer = setTimeout(() => {
    loadRunFullTimer = null;
    if (loadRunFullInFlight) {
      loadRunFullPending = true;
      return;
    }
    loadRunFullInFlight = true;
    loadRunFull()
      .catch(() => {})
      .finally(() => {
        loadRunFullInFlight = false;
        // Re-attach only if the stream fully died while we were busy.
        connectStream();
        if (loadRunFullPending) {
          loadRunFullPending = false;
          scheduleLoadRunFull("coalesced");
        }
      });
  }, LOAD_RUN_FULL_DEBOUNCE_MS);
}

function setLive(on) {
  const d = $("#live-dot");
  if (d) d.classList.toggle("on", !!on);
  const l = $("#live-label");
  if (l) l.textContent = on ? "Live" : "Offline";
}

function markLiveConnected() {
  if (liveOfflineTimer) {
    clearTimeout(liveOfflineTimer);
    liveOfflineTimer = null;
  }
  setLive(true);
}

function markLiveDisconnected() {
  if (liveOfflineTimer) return;
  liveOfflineTimer = setTimeout(() => {
    liveOfflineTimer = null;
    // Browser may have auto-reconnected during the debounce window.
    if (es && es.readyState === EventSource.OPEN) {
      setLive(true);
      return;
    }
    setLive(false);
  }, LIVE_OFFLINE_MS);
}

function renderRunner(runner, snap = {}) {
  const el = $("#runner-status");
  if (!el) return;
  const st = (runner?.state || "idle").toLowerCase();
  const incomplete = !!snap.incomplete;
  const pid = runner?.pid;
  const workersAlive = runner?.workers_alive ?? (Array.isArray(runner?.pids) ? runner.pids.length : 0);
  const workersCfg = runner?.workers ?? runner?.meta?.workers ?? 1;
  const meta = [];
  if (workersAlive > 1 || workersCfg > 1) {
    meta.push(`agents ${workersAlive || 0}/${workersCfg}`);
  } else if (pid != null && pid !== "" && pid !== "-") {
    meta.push(`pid ${pid}`);
  }
  if (runner?.stop) meta.push("STOP set");
  if (incomplete) meta.push("residual work");
  const label = st.charAt(0).toUpperCase() + st.slice(1);
  const tone = st === "running" ? "is-running"
    : st === "paused" || st === "pausing" ? `is-${st}`
      : st === "error" || st === "dead" || st === "crashed" ? "is-error" : "";
  const tip = `Ralph (task loop) ${label.toLowerCase()}${meta.length ? ` — ${meta.join(" | ")}` : ""}`;
  el.innerHTML = `<span class="vf-runner-pill ${tone}" title="${esc(tip)}"><span class="dot" aria-hidden="true"></span>${esc(label)}${incomplete && st !== "running" ? " · residual" : ""}</span>`;

  // One primary runner action visible: Start | Pause | Resume
  const running = st === "running";
  const pausing = st === "pausing";
  const startBtn = $("#btn-start");
  const pauseBtn = $("#btn-pause");
  const resumeBtn = $("#btn-resume");
  if (startBtn && pauseBtn && resumeBtn) {
    if (running) {
      startBtn.hidden = true;
      resumeBtn.hidden = true;
      pauseBtn.hidden = false;
      pauseBtn.disabled = false;
    } else if (pausing) {
      startBtn.hidden = true;
      pauseBtn.hidden = false;
      pauseBtn.disabled = true;
      resumeBtn.hidden = true;
    } else if (st === "paused" || st === "idle" || st === "busy") {
      // Prefer Resume when STOP / paused; Start when never started
      const preferResume = st === "paused" || !!runner?.stop || incomplete;
      startBtn.hidden = preferResume;
      resumeBtn.hidden = !preferResume;
      pauseBtn.hidden = true;
      startBtn.disabled = false;
      resumeBtn.disabled = false;
    } else {
      startBtn.hidden = false;
      pauseBtn.hidden = true;
      resumeBtn.hidden = true;
      startBtn.disabled = false;
    }
  }
}


/** Campaign KPI / work-lane helpers — see mission_overview_helpers.js */
const {
  buildMissionCockpit,
  summarizeHuntQueue,
  listNeedsHumanFindings,
  summarizeCoverageResidual,
} = globalThis.MissionOverviewHelpers;

/** Compact Hunts strip: live hunt feed + needs_human above coverage matrix. */
const CAMPAIGN_LANE_STATES = new Set(["idle", "running", "idle-with-results", "failed"]);


/**
 * Finding counts: ingested → screened → needs_human → confirmed.
 * Arrows are the funnel, not work-lane progress. Lanes stay concurrent.
 */


/**
 * Recon / Hunt / Validate are concurrent lanes. Ralph stays on #runner-status.
 * The funnel and who/why line sit on this strip; they are not lane lights.
 */





function runApiBase() {
  const [target_id, run_id] = currentKey.split("/");
  return `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}`;
}

/** Coverage UI lives in coverage.js (loaded after this file). Fallbacks until then. */
function covDepthClass(d) {
  const x = (d || "planned").toLowerCase();
  if (x === "shallow") return "cov-shallow";
  if (x === "none") return "cov-none";
  if (x === "candidate" || x === "confirmed" || x === "needs_human") return "cov-candidate";
  if (x === "aborted") return "cov-aborted";
  if (x === "planned") return "cov-planned";
  return "cov-empty";
}

function renderCoverageHtml(cov, opts = {}) {
  // Prefer full cockpit module once loaded
  if (window.VulnForgeCoverage?.renderPreviewHtml && opts.interactive === false) {
    return window.VulnForgeCoverage.renderPreviewHtml(cov);
  }
  if (!cov || (!(cov.cells || []).length && !(cov.areas || []).length)) {
    return `<div class="empty" style="padding:1rem">No architecture areas yet — run recon to map the app, then plan hunts.</div>`;
  }
  if ((cov.areas || []).length && !(cov.classes || []).length) {
    return `<div class="empty" style="padding:1rem">${esc(String((cov.areas || []).length))} architecture area(s) mapped — no hunts planned yet. Open Hunts to queue skills.</div>`;
  }
  // Minimal non-interactive fallback (mission preview before coverage.js paints)
  const areas = cov.areas || [];
  const classes = cov.classes || [];
  const map = {};
  for (const c of cov.cells || []) map[`${c.area}\0${c.class}`] = c;
  const head =
    `<tr><th class="row-head">Area</th>` +
    classes.map((c) => `<th>${esc(c)}</th>`).join("") +
    `</tr>`;
  const rows = areas
    .map((a) => {
      const cells = classes
        .map((cl) => {
          const cell = map[`${a}\0${cl}`];
          const d = (cell?.last_depth || "").toLowerCase();
          const cls = covDepthClass(d);
          const label = !cell || !d ? "—" : `${d} · ${cell.visit_count || 0}`;
          return `<td><span class="cov-cell ${cls}">${esc(label)}</span></td>`;
        })
        .join("");
      return `<tr><td class="row-head mono">${esc(a)}</td>${cells}</tr>`;
    })
    .join("");
  return `<div class="coverage-wrap"><table class="coverage-grid">${head}${rows}</table></div>`;
}

function formatTaskLoop(t, maxAttempts) {
  const maxA = maxAttempts || window.__VF_max_task_attempts || 3;
  const lease = Number(t.attempt) || 0;
  const p = t.payload || {};
  const parts = [];
  const gen =
    p.recon_generation != null
      ? Number(p.recon_generation)
      : p.split_depth != null
        ? Number(p.split_depth) + 1
        : null;
  if (gen != null && !Number.isNaN(gen) && gen > 0) {
    parts.push(`Gen ${gen}`);
  }
  // One recon agent (profile) per Ralph task when multi-select is used
  const aids = Array.isArray(p.agent_ids) ? p.agent_ids.filter(Boolean) : [];
  if (aids.length === 1) {
    parts.push(String(aids[0]));
  } else if (aids.length > 1) {
    parts.push(aids.slice(0, 2).join("+") + (aids.length > 2 ? "…" : ""));
  }
  const bSize = Number(p.recon_batch_size);
  const bIdx = Number(p.recon_batch_index);
  if (bSize > 1 && !Number.isNaN(bSize)) {
    const n = (!Number.isNaN(bIdx) ? bIdx : 0) + 1;
    parts.push(`${n}/${bSize}`);
  }
  parts.push(`Lease ${lease}/${maxA}`);
  if (p.parent_task_id != null) {
    parts.push(`<- #${p.parent_task_id}`);
  } else if (p.shallow_requeued || p.recon_auto_retry) {
    parts.push("retry");
  }
  const title =
    "Lease n/m counts how many times this row has been leased, out of the attempt budget. " +
    "A new lease increments the count. " +
    "When the count reaches the max, an infra failure deadletters the row and it is not leased again. " +
    "Gen or a parent id is a Ralph follow-up after a terminal failure or an operator re-run. " +
    "An agent id and a batch fraction mark a multi-profile recon batch. Each profile is its own task.";
  return { label: parts.join(" · "), title };
}

/** @type {"active"|"all"|"done"} */
let tasksFilter = "active";
let tasksCache = [];
const TASKS_PAGE_SIZE = 50;
/** How many filtered rows to show (grows via Show more / Show all). */
let tasksVisibleCount = TASKS_PAGE_SIZE;

function priorityTierLabel(priority) {
  const p = Number(priority);
  if (Number.isNaN(p)) return { tier: "normal", label: "normal" };
  if (p <= 15) return { tier: "run_next", label: "next" };
  if (p <= 40) return { tier: "high", label: "high" };
  if (p <= 60) return { tier: "normal", label: "normal" };
  return { tier: "low", label: "low" };
}

/** Running (leased) | paused | queue | terminal states — used for grouping + sort. */
function taskListGroup(t) {
  const st = (t.state || "").toLowerCase();
  if (st === "leased") return "running";
  if (st === "paused") return "paused";
  if (st === "queued") return "queued";
  return "done";
}

function taskMatchesFilter(t, ftr) {
  const st = (t.state || "").toLowerCase();
  if (ftr === "all") return true;
  // Merged running + paused + queue (legacy chip ids map here too)
  if (ftr === "active" || ftr === "queued" || ftr === "leased") {
    return st === "queued" || st === "leased" || st === "paused";
  }
  if (ftr === "done") {
    return (
      st === "succeeded" ||
      st === "failed_task" ||
      st === "deadletter" ||
      st === "cancelled"
    );
  }
  return true;
}

function sortTasksForView(tasks, ftr) {
  const list = [...tasks];
  const groupRank = { running: 0, paused: 1, queued: 2, done: 3 };
  if (ftr === "active" || ftr === "queued" || ftr === "leased" || ftr === "all") {
    // Running first, then paused, then queued by priority, then (for All) done
    list.sort((a, b) => {
      const ga = groupRank[taskListGroup(a)] ?? 9;
      const gb = groupRank[taskListGroup(b)] ?? 9;
      if (ga !== gb) return ga - gb;
      if (taskListGroup(a) === "queued" || taskListGroup(a) === "paused") {
        return (
          (Number(a.priority) || 100) - (Number(b.priority) || 100) ||
          (Number(a.id) || 0) - (Number(b.id) || 0)
        );
      }
      // running / done: newest id first
      return (Number(b.id) || 0) - (Number(a.id) || 0);
    });
  } else {
    list.sort((a, b) => (Number(b.id) || 0) - (Number(a.id) || 0));
  }
  return list;
}

function setupTasksFilter() {
  const bar = $("#tasks-filter");
  if (!bar || bar.dataset.bound) return;
  bar.dataset.bound = "1";
  bar.querySelectorAll("[data-tfilter]").forEach((chip) => {
    chip.addEventListener("click", () => {
      tasksFilter = chip.getAttribute("data-tfilter") || "active";
      tasksVisibleCount = TASKS_PAGE_SIZE;
      bar.querySelectorAll(".chip").forEach((c) => {
        c.classList.toggle(
          "active",
          (c.getAttribute("data-tfilter") || "") === tasksFilter
        );
      });
      renderTasks(tasksCache);
    });
  });
}

function setupTasksMore() {
  const more = $("#tasks-more");
  if (!more || more.dataset.bound) return;
  more.dataset.bound = "1";
  more.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-tasks-more]");
    if (!btn || !more.contains(btn)) return;
    const action = btn.getAttribute("data-tasks-more");
    if (action === "more") {
      tasksVisibleCount += TASKS_PAGE_SIZE;
      renderTasks(tasksCache);
    } else if (action === "all") {
      // Large sentinel; renderTasks clamps to filtered length
      tasksVisibleCount = Number.MAX_SAFE_INTEGER;
      renderTasks(tasksCache);
    }
  });
}

function updateTasksMoreBar(visible, total) {
  const more = $("#tasks-more");
  if (!more) return;
  // Hide when empty, or when the full list fits in one page
  if (!total || (total <= TASKS_PAGE_SIZE && visible >= total)) {
    more.hidden = true;
    more.innerHTML = "";
    return;
  }
  more.hidden = false;
  if (total > visible) {
    more.innerHTML = `
      <span class="tasks-more-label controls-hint">Showing ${visible} of ${total}</span>
      <button type="button" class="btn btn-sm" data-tasks-more="more">Show more</button>
      <button type="button" class="btn btn-sm btn-ghost" data-tasks-more="all">Show all</button>
    `;
  } else {
    more.innerHTML = `<span class="tasks-more-label controls-hint">Showing ${total} tasks</span>`;
  }
}

async function setTaskPriority(taskId, tier) {
  try {
    const r = await api(`${runApiBase()}/tasks/${encodeURIComponent(taskId)}/priority`, {
      method: "POST",
      body: JSON.stringify({ tier }),
    });
    const labels = {
      run_next: "Run next",
      high: "High",
      normal: "Normal",
      low: "Low",
    };
    toast(
      `#${taskId} → ${labels[r.tier] || r.tier} (priority ${r.priority})`
    );
    if (typeof loadRunFull === "function") await loadRunFull();
  } catch (e) {
    toast(e.message || String(e), true);
  }
}

/**
 * Remove a queued task from the queue (marks cancelled).
 * @param {string|number} taskId
 * @param {{ confirm?: boolean, reason?: string, silent?: boolean }} [opts]
 * @returns {Promise<object|null>}
 */
async function cancelQueuedTask(taskId, opts = {}) {
  const id = Number(taskId);
  if (!Number.isFinite(id) || id <= 0) {
    toast("Invalid task id", true);
    return null;
  }
  if (opts.confirm !== false) {
    const ok = window.confirm(
      `Remove queued task #${id} from the queue?\n\nIt will be marked cancelled and will not run.`
    );
    if (!ok) return null;
  }
  try {
    const r = await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason: opts.reason || "operator_cancel" }),
    });
    if (!opts.silent) toast(`Removed task #${id} from queue`);
    if (typeof loadRunFull === "function") await loadRunFull();
    return r;
  } catch (e) {
    toast(e.message || String(e), true);
    return null;
  }
}
window.cancelQueuedTask = cancelQueuedTask;

/**
 * Pause a queued or leased task so the next queued can begin.
 * @param {string|number} taskId
 * @param {{ confirm?: boolean, reason?: string, silent?: boolean }} [opts]
 * @returns {Promise<object|null>}
 */
async function pauseTask(taskId, opts = {}) {
  const id = Number(taskId);
  if (!Number.isFinite(id) || id <= 0) {
    toast("Invalid task id", true);
    return null;
  }
  if (opts.confirm !== false) {
    const ok = window.confirm(
      `Pause task #${id}?\n\n` +
        `If it is running, the current agent is stopped and the next queued task can start.\n` +
        `This task will run again when you Resume it, or when it is the last work left.`
    );
    if (!ok) return null;
  }
  try {
    const r = await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/pause`, {
      method: "POST",
      body: JSON.stringify({ reason: opts.reason || "operator_pause" }),
    });
    if (!opts.silent) {
      const killed = r.killed ? " (agent stopped)" : "";
      toast(`Paused task #${id}${killed}`);
    }
    if (typeof loadRunFull === "function") await loadRunFull();
    return r;
  } catch (e) {
    toast(e.message || String(e), true);
    return null;
  }
}
window.pauseTask = pauseTask;

/**
 * Resume a paused task back to the queue (default: run next).
 * @param {string|number} taskId
 * @param {{ confirm?: boolean, tier?: string, reason?: string, silent?: boolean }} [opts]
 * @returns {Promise<object|null>}
 */
async function resumePausedTask(taskId, opts = {}) {
  const id = Number(taskId);
  if (!Number.isFinite(id) || id <= 0) {
    toast("Invalid task id", true);
    return null;
  }
  const tier = opts.tier || "run_next";
  try {
    const r = await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/resume`, {
      method: "POST",
      body: JSON.stringify({
        tier,
        reason: opts.reason || "operator_resume",
      }),
    });
    if (!opts.silent) {
      toast(`Resumed task #${id} → queue (${tier}, priority ${r.priority})`);
    }
    if (typeof loadRunFull === "function") await loadRunFull();
    return r;
  } catch (e) {
    toast(e.message || String(e), true);
    return null;
  }
}
window.resumePausedTask = resumePausedTask;

/**
 * Halt (terminal cancel) a queued, paused, or leased task.
 * @param {string|number} taskId
 * @param {{ confirm?: boolean, reason?: string, silent?: boolean }} [opts]
 * @returns {Promise<object|null>}
 */
async function haltTask(taskId, opts = {}) {
  const id = Number(taskId);
  if (!Number.isFinite(id) || id <= 0) {
    toast("Invalid task id", true);
    return null;
  }
  if (opts.confirm !== false) {
    const ok = window.confirm(
      `Halt task #${id}?\n\n` +
        `This permanently cancels it. If running, the agent is stopped so the next queued task can start.\n` +
        `Unlike Pause, it will not come back.`
    );
    if (!ok) return null;
  }
  try {
    const r = await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/halt`, {
      method: "POST",
      body: JSON.stringify({ reason: opts.reason || "operator_halt" }),
    });
    if (!opts.silent) {
      const killed = r.killed ? " (agent stopped)" : "";
      toast(`Halted task #${id}${killed}`);
    }
    if (typeof loadRunFull === "function") await loadRunFull();
    return r;
  } catch (e) {
    toast(e.message || String(e), true);
    return null;
  }
}
window.haltTask = haltTask;

/** @type {{ taskId: number } | null} */
let livePane = null;
let livePaneTimer = null;
let liveQueryOpened = false;

function maybeOpenLiveFromQuery() {
  if (liveQueryOpened || livePane) return;
  let id = "";
  try {
    id = new URLSearchParams(window.location.search).get("live") || "";
  } catch {
    id = "";
  }
  if (!id) return;
  liveQueryOpened = true;
  openLiveTask(id);
}

async function openLiveTask(taskId) {
  const id = Number(taskId);
  if (!Number.isFinite(id) || id <= 0) {
    toast("Invalid task id", true);
    return;
  }
  livePane = { taskId: id };
  $("#live-task-modal")?.classList.add("open");
  const title = $("#live-task-title");
  if (title) title.textContent = `Live task #${id}`;
  await refreshLivePane();
  if (livePaneTimer) clearInterval(livePaneTimer);
  livePaneTimer = setInterval(() => {
    if (livePane) refreshLivePane();
  }, 1500);
}
window.openLiveTask = openLiveTask;

function closeLiveTask() {
  livePane = null;
  if (livePaneTimer) {
    clearInterval(livePaneTimer);
    livePaneTimer = null;
  }
  if (typeof globalThis !== "undefined" && globalThis.__vfLiveThinkTimer) {
    clearInterval(globalThis.__vfLiveThinkTimer);
    globalThis.__vfLiveThinkTimer = null;
  }
  $("#live-task-modal")?.classList.remove("open");
}
window.closeLiveTask = closeLiveTask;

async function refreshLivePane() {
  if (!livePane || !currentKey) return;
  const id = livePane.taskId;
  try {
    const data = await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/live`);
    if (!livePane || livePane.taskId !== id) return;
    renderLivePane(data);
  } catch (e) {
    if (!livePane || livePane.taskId !== id) return;
    const meta = $("#live-task-meta");
    if (meta) meta.textContent = e.message || String(e);
  }
}

function renderLivePane(data) {
  const id = data.task_id;
  const kind = data.kind || "task";
  const state = data.state || "";
  const round = Number(data.round) || 0;
  const maxRounds = Number(data.max_rounds) || 0;
  const leased = String(state).toLowerCase() === "leased";
  const title = $("#live-task-title");
  if (title) title.textContent = `Live task #${id}`;
  const meta = $("#live-task-meta");
  if (meta) {
    meta.textContent = `${kind} · ${state || "unknown"}${leased ? "" : " · steer is only available while running"}`;
  }
  const tool = data.tool ? String(data.tool) : "";
  const args = data.args_summary ? String(data.args_summary) : "";
  const now = $("#live-task-now");
  function formatLiveWait(iso) {
    const t = Date.parse(String(iso || ""));
    if (!Number.isFinite(t)) return "";
    const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
    return `${s}s`;
  }
  if (now) {
    const roundLabel = maxRounds > 0 ? `${round || 0}/${maxRounds}` : String(round || 0);
    const phase = String(data.phase || "");
    const thinking = !tool && (phase === "thinking" || leased);
    now.className = thinking ? "live-task-now is-thinking" : "live-task-now";
    const g = typeof globalThis !== "undefined" ? globalThis : null;
    if (g && g.__vfLiveThinkTimer) {
      clearInterval(g.__vfLiveThinkTimer);
      g.__vfLiveThinkTimer = null;
    }
    if (tool) {
      now.innerHTML = `<div class="live-task-round mono">Round ${esc(roundLabel)}</div>
         <div><strong class="live-tool">${esc(tool)}</strong></div>
         <div class="mono">${esc(args || "—")}</div>`;
    } else if (thinking) {
      const started = data.wait_started_at || data.updated_at || "";
      const elapsed = formatLiveWait(started);
      const elapsedText = elapsed ? `Waiting for model · ${elapsed}` : "Waiting for model";
      now.innerHTML = `<div class="live-task-round mono">Round ${esc(roundLabel)}</div>
         <div class="live-task-wait"><span class="live-task-pulse" aria-hidden="true"></span><strong>Thinking…</strong> <span class="live-task-elapsed" data-wait-start="${esc(started)}" aria-hidden="true">${esc(elapsedText)}</span></div>`;
      if (g && started && typeof setInterval === "function") {
        g.__vfLiveThinkTimer = setInterval(() => {
          const el =
            typeof document !== "undefined"
              ? document.querySelector("#live-task-now .live-task-elapsed")
              : null;
          if (!el) return;
          const next = formatLiveWait(el.getAttribute("data-wait-start") || "");
          el.textContent = next ? `Waiting for model · ${next}` : "Waiting for model";
        }, 1000);
      }
    } else {
      now.innerHTML = `<div class="live-task-round mono">Round ${esc(roundLabel)}</div>
         <div>Waiting for the next tool round.</div>`;
    }
  }
  const list = $("#live-task-steps");
  const steps = Array.isArray(data.steps) ? data.steps : [];
  if (list) {
    list.innerHTML = steps.length
      ? steps
          .map((step, i) => {
            const call = Number(step.call) > 0 ? Number(step.call) : i + 1;
            const stepRound = Number(step.round);
            const roundBadge =
              Number.isFinite(stepRound) && stepRound > 0
                ? `<span class="live-step-round" title="Round ${esc(String(stepRound))}">round ${esc(String(stepRound))}</span>`
                : "";
            const mark = step.ok === false ? " · failed" : "";
            return `<li>
              <span class="live-step-meta">${roundBadge}<span class="mono live-step-call">call ${esc(String(call))}</span></span>
              <span class="live-tool">${esc(step.tool || "tool")}${esc(mark)}</span>
              <span class="mono">${esc(step.args_summary || "")}</span>
            </li>`;
          })
          .join("")
      : `<li><span class="controls-hint">No tool calls yet.</span></li>`;
    list.scrollTop = list.scrollHeight;
  }
  const steer = data.steer || {};
  const pending = Array.isArray(steer.pending_notes) ? steer.pending_notes : [];
  const force = steer.force_submit_none || null;
  const abort = steer.abort || null;
  const hint = $("#live-task-steer-hint");
  if (hint) {
    const bits = ["Confirm required. These actions never auto-confirm findings."];
    if (pending.length) {
      const preview = pending
        .map((n) => String(n.text || "").trim())
        .filter(Boolean)
        .join(" · ");
      bits.push(
        `${pending.length} note${pending.length === 1 ? "" : "s"} waiting for the next round${
          preview ? `: ${preview}` : ""
        }.`
      );
    }
    if (force && force.requested && !force.applied) bits.push("submit_none is queued for the next round.");
    if (force && force.applied) {
      bits.push(force.ok === false ? "submit_none was rejected." : "submit_none was applied.");
    }
    if (abort && abort.requested) bits.push("Abort requested.");
    hint.textContent = bits.join(" ");
  }
  const hunt = String(kind) === "hunt";
  const noteBtn = $("#live-steer-note");
  const noneBtn = $("#live-steer-none");
  const abortBtn = $("#live-steer-abort");
  if (noteBtn) noteBtn.disabled = !leased;
  if (abortBtn) abortBtn.disabled = !leased;
  if (noneBtn) {
    noneBtn.disabled = !leased || !hunt;
    noneBtn.title = hunt
      ? "Call submit_none at the next round. Does not confirm a finding."
      : "submit_none is hunt-only. Abort to stop this task.";
  }
}

async function sendLiveNote() {
  if (!livePane) return;
  const id = livePane.taskId;
  const note = ($("#live-task-note")?.value || "").trim();
  if (!note) {
    toast("Write a note first", true);
    return;
  }
  const ok = window.confirm(
    `Send this note into task #${id} on the next tool round?\n\n` +
      `It is injected as an operator note. It does not confirm, reject, or edit findings.\n\n` +
      note.slice(0, 500)
  );
  if (!ok) return;
  try {
    await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/steer/note`, {
      method: "POST",
      body: JSON.stringify({ note }),
    });
    const box = $("#live-task-note");
    if (box) box.value = "";
    toast(`Note queued for task #${id}`);
    await refreshLivePane();
  } catch (e) {
    toast(e.message || String(e), true);
  }
}

async function forceLiveSubmitNone() {
  if (!livePane) return;
  const id = livePane.taskId;
  const typed = ($("#live-task-note")?.value || "").trim();
  const reason = typed || "operator forced submit_none";
  const ok = window.confirm(
    `Force task #${id} to call submit_none at the next round boundary?\n\n` +
      `The hunt ends with no candidate. This does not confirm any finding.\n\n` +
      `Reason: ${reason.slice(0, 500)}`
  );
  if (!ok) return;
  try {
    await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/steer/submit_none`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
    const box = $("#live-task-note");
    if (box && typed) box.value = "";
    toast(`submit_none queued for task #${id}`);
    await refreshLivePane();
  } catch (e) {
    toast(e.message || String(e), true);
  }
}

async function abortLiveTask() {
  if (!livePane) return;
  const id = livePane.taskId;
  const ok = window.confirm(
    `Abort task #${id}?\n\n` +
      `This permanently stops the running agent (halt). ` +
      `It does not confirm or reject findings. The task will not resume.`
  );
  if (!ok) return;
  try {
    await api(`${runApiBase()}/tasks/${encodeURIComponent(id)}/steer/abort`, {
      method: "POST",
      body: JSON.stringify({ reason: "operator_abort" }),
    });
    toast(`Aborted task #${id}`);
    await refreshLivePane();
    if (typeof loadRunFull === "function") await loadRunFull();
  } catch (e) {
    toast(e.message || String(e), true);
  }
}

const DEAD_LEASE_REQUEUE_COPY = "Worker died; task requeued";

/**
 * Dead-owner reclaim is a queue note, not a task failure.
 * Older rows still store error=dead_lease_owner; new rows set worker_died.
 * Any other error (no_submit, operator halt, infra) stays a real result.
 */
function isDeadLeaseRequeueResult(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return false;
  const err = result.error == null ? "" : String(result.error);
  if (err && err !== "dead_lease_owner") return false;
  if (result.worker_died === true) return true;
  return err === "dead_lease_owner";
}

function formatTaskResult(task) {
  const result = task && task.result;
  if (isDeadLeaseRequeueResult(result)) {
    return {
      text: DEAD_LEASE_REQUEUE_COPY,
      title: "The worker that held this lease is gone. The task is back on the queue.",
    };
  }
  const res = result ? JSON.stringify(result, null, 0) : "";
  return { text: res, title: res };
}

function renderTasks(tasks) {
  const tb = $("#tasks-body");
  if (!tb) return;
  setupTasksFilter();
  setupTasksMore();
  if (Array.isArray(tasks)) tasksCache = tasks;
  const all = Array.isArray(tasks) ? tasks : tasksCache;
  if (!all?.length) {
    tb.innerHTML = `<tr><td colspan="10" class="empty">No tasks</td></tr>`;
    updateTasksMoreBar(0, 0);
    return;
  }

  const filtered = sortTasksForView(
    all.filter((t) => taskMatchesFilter(t, tasksFilter)),
    tasksFilter
  );
  if (!filtered.length) {
    tb.innerHTML = `<tr><td colspan="10" class="empty">No tasks match this filter.</td></tr>`;
    updateTasksMoreBar(0, 0);
    return;
  }

  // Progressive pagination: slice after filter+sort; group headers only for visible rows
  const visibleCount = Math.min(tasksVisibleCount, filtered.length);
  const visible = filtered.slice(0, visibleCount);
  updateTasksMoreBar(visibleCount, filtered.length);

  // Queue position among currently queued tasks (global, not filtered)
  const queuedOrdered = [...all]
    .filter((t) => (t.state || "") === "queued")
    .sort(
      (a, b) =>
        (Number(a.priority) || 100) - (Number(b.priority) || 100) ||
        (Number(a.id) || 0) - (Number(b.id) || 0)
    );
  const posById = new Map(queuedOrdered.map((t, i) => [Number(t.id), i + 1]));

  const maxA = window.__VF_max_task_attempts || 3;
  const showGroups =
    tasksFilter === "active" ||
    tasksFilter === "queued" ||
    tasksFilter === "leased" ||
    tasksFilter === "all";
  const groupLabels = {
    running: "Running",
    paused: "Paused",
    queued: "Queued",
    done: "Done / failed",
  };
  const rows = [];
  let lastGroup = null;
  for (const t of visible) {
    const group = taskListGroup(t);
    if (showGroups && group !== lastGroup) {
      rows.push(
        `<tr class="task-group-header" data-group="${esc(group)}">` +
          `<td colspan="10">${esc(groupLabels[group] || group)}</td></tr>`
      );
      lastGroup = group;
    }
    const shown = formatTaskResult(t);
    const payload = t.payload ? JSON.stringify(t.payload) : "";
    const hasT = !!t.has_transcript;
    const loop = formatTaskLoop(t, maxA);
    const st = (t.state || "").toLowerCase();
    const queued = st === "queued";
    const running = st === "leased";
    const paused = st === "paused";
    const pos = posById.get(Number(t.id));
    const tier = priorityTierLabel(t.priority);
    const prioBadge = `<span class="prio-badge prio-${esc(tier.tier)}" title="priority ${esc(String(t.priority ?? ""))}">${esc(tier.label)} <span class="mono prio-num">${esc(String(t.priority ?? "—"))}</span></span>`;
    let actions = `<span class="controls-hint">—</span>`;
    if (queued) {
      actions = `<div class="task-prio-actions">
            <button type="button" class="btn btn-sm btn-primary task-prio-btn" data-tier="run_next" data-tid="${t.id}" title="Jump to front of queue">Run next</button>
            <button type="button" class="btn btn-sm task-prio-btn" data-tier="high" data-tid="${t.id}">High</button>
            <button type="button" class="btn btn-sm task-prio-btn" data-tier="normal" data-tid="${t.id}">Normal</button>
            <button type="button" class="btn btn-sm task-prio-btn" data-tier="low" data-tid="${t.id}">Low</button>
            <button type="button" class="btn btn-sm task-pause-btn" data-tid="${t.id}" title="Park this task; next queued can run first">Pause</button>
            <button type="button" class="btn btn-sm btn-bad task-cancel-btn" data-tid="${t.id}" title="Remove from queue (cancel)">Remove</button>
          </div>`;
    } else if (running) {
      actions = `<div class="task-prio-actions">
            <button type="button" class="btn btn-sm btn-primary task-live-btn" data-tid="${t.id}" title="Live tool rounds and mid-task steer">Live</button>
            <button type="button" class="btn btn-sm task-pause-btn" data-tid="${t.id}" title="Stop this agent; next queued starts. Runs again when resumed or last left.">Pause</button>
            <button type="button" class="btn btn-sm btn-bad task-halt-btn" data-tid="${t.id}" title="Stop and permanently cancel this lease">Halt</button>
          </div>`;
    } else if (paused) {
      actions = `<div class="task-prio-actions">
            <button type="button" class="btn btn-sm btn-primary task-resume-btn" data-tid="${t.id}" title="Return to queue (run next)">Resume</button>
            <button type="button" class="btn btn-sm btn-bad task-halt-btn" data-tid="${t.id}" title="Permanently cancel">Halt</button>
          </div>`;
    }
    const rowClass = [
      "task-row",
      queued ? "is-queued" : "",
      running ? "is-running" : "",
      paused ? "is-paused" : "",
    ]
      .filter(Boolean)
      .join(" ");
    rows.push(`<tr class="${rowClass}" data-task-id="${t.id}" data-has-t="${hasT ? "1" : "0"}">
        <td class="mono task-pos">${pos != null ? pos : "—"}</td>
        <td class="mono">${t.id}</td>
        <td><strong>${esc(t.kind)}</strong></td>
        <td>${badge(t.state)}</td>
        <td>${prioBadge}</td>
        <td class="mono task-loop" title="${esc(loop.title)}">${esc(loop.label)}</td>
        <td class="mono" title="${esc(payload)}">${esc(payload.slice(0, 80))}${payload.length > 80 ? "..." : ""}</td>
        <td><div class="task-result" title="${esc(shown.title)}">${esc(shown.text.slice(0, 200))}</div></td>
        <td>${
          hasT
            ? `<button type="button" class="llm-pill llm-log-btn" data-tid="${t.id}" title="Open the LLM transcript">LLM log</button>`
            : `<span class="llm-pill none"> - </span>`
        }</td>
        <td class="task-actions-cell">${actions}</td>
      </tr>`);
  }
  tb.innerHTML = rows.join("");

  tb.querySelectorAll(".task-prio-btn").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tid = btn.getAttribute("data-tid");
      const tier = btn.getAttribute("data-tier");
      if (tid && tier) setTaskPriority(tid, tier);
    });
  });
  tb.querySelectorAll(".task-cancel-btn").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tid = btn.getAttribute("data-tid");
      if (tid) cancelQueuedTask(tid);
    });
  });
  tb.querySelectorAll(".task-pause-btn").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tid = btn.getAttribute("data-tid");
      if (tid) pauseTask(tid);
    });
  });
  tb.querySelectorAll(".task-resume-btn").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tid = btn.getAttribute("data-tid");
      if (tid) resumePausedTask(tid);
    });
  });
  tb.querySelectorAll(".task-halt-btn").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tid = btn.getAttribute("data-tid");
      if (tid) haltTask(tid);
    });
  });
  tb.querySelectorAll(".task-live-btn").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tid = btn.getAttribute("data-tid");
      if (tid) openLiveTask(tid);
    });
  });
  tb.querySelectorAll(".llm-log-btn").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const tid = btn.getAttribute("data-tid");
      if (!tid) return;
      closeLiveTask();
      openTranscript(tid);
    });
  });
  tb.querySelectorAll("tr.task-row").forEach((row) => {
    row.addEventListener("click", () => {
      const id = row.getAttribute("data-task-id");
      if (row.classList.contains("is-running")) {
        openLiveTask(id);
        return;
      }
      const has = row.getAttribute("data-has-t") === "1";
      if (!has) {
        toast("No LLM transcript for this task (mech-only or pre-logging run)");
        return;
      }
      openTranscript(id);
    });
    row.addEventListener("dblclick", (ev) => {
      const id = row.getAttribute("data-task-id");
      const has = row.getAttribute("data-has-t") === "1";
      if (!id || !has) return;
      ev.preventDefault();
      closeLiveTask();
      openTranscript(id);
    });
  });
  maybeOpenLiveFromQuery();
}

/** @type {{ taskId: number|string, data: object, tab: string, passKey: string|null } | null} */
let _stepIoState = null;

async function openTranscript(taskId) {
  return openStepIO(taskId);
}

async function openStepIO(taskId, passKey) {
  const [target_id, run_id] = currentKey.split("/");
  try {
    let url = `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}/tasks/${taskId}/io`;
    if (passKey) url += `?pass_key=${encodeURIComponent(passKey)}`;
    const data = await api(url);
    const keepTab =
      _stepIoState && String(_stepIoState.taskId) === String(taskId) ? _stepIoState.tab : "";
    const preferTurns = globalThis.TranscriptTurns?.prefersTurnsTab?.(data);
    _stepIoState = {
      taskId,
      data,
      tab: keepTab || (preferTurns ? "turns" : "input"),
      passKey: passKey || null,
    };
    renderStepIOModal();
    $("#transcript-modal")?.classList.add("open");
  } catch (e) {
    // Fallback to raw transcript for older runs / edge cases
    try {
      const data = await api(
        `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}/tasks/${taskId}/transcript`
      );
      $("#transcript-title").textContent = `Task #${taskId} | ${data.kind || "agent"}`;
      $("#transcript-meta").textContent = `model ${data.model_id || " — "} | ${data.message_count || 0} messages | ${data.saved_at || ""}`;
      $("#transcript-passes")?.setAttribute("hidden", "");
      const body = $("#transcript-body");
      body.innerHTML = (data.messages || [])
        .map((m) => renderTurnHtml(m))
        .join("");
      $("#transcript-modal")?.classList.add("open");
    } catch (e2) {
      toast(e.message || e2.message, true);
    }
  }
}

function renderTurnHtml(m) {
  const api = globalThis.TranscriptTurns;
  if (api && typeof api.renderTurnHtml === "function") return api.renderTurnHtml(m);
  const role = (m && m.role) || "unknown";
  const content = m && m.content != null ? m.content : "";
  const text = typeof content === "string" ? content : JSON.stringify(content);
  return `<div class="transcript-turn role-${esc(role)}"><div class="role">${esc(role)}</div><pre>${esc(
    text || ""
  )}</pre></div>`;
}

function renderStepIOModal() {
  if (!_stepIoState) return;
  const { taskId, data, tab } = _stepIoState;
  const modelId = data.model?.id || data.model_id || "—";
  $("#transcript-title").textContent = `Task #${taskId} | ${data.kind || "agent"} · ${data.state || ""}`;
  $("#transcript-meta").textContent = `model ${modelId} | ${data.message_count || (data.turns || []).length || 0} messages | ${data.saved_at || ""} | run artifacts only (target RO)`;

  const passBar = $("#transcript-passes");
  const passes = data.passes || [];
  if (passBar) {
    if (passes.length > 1) {
      passBar.hidden = false;
      passBar.innerHTML = passes
        .map((p) => {
          const pk = p.pass_key || "";
          const active =
            (!_stepIoState.passKey && p === passes[passes.length - 1]) ||
            String(_stepIoState.passKey || "") === String(pk);
          return `<button type="button" class="chip${active ? " active" : ""}" data-pass="${esc(pk)}">${esc(
            pk || p.kind || "pass"
          )}</button>`;
        })
        .join("");
      passBar.querySelectorAll("[data-pass]").forEach((btn) => {
        btn.addEventListener("click", () => {
          openStepIO(taskId, btn.getAttribute("data-pass") || undefined);
        });
      });
    } else {
      passBar.hidden = true;
      passBar.innerHTML = "";
    }
  }

  document.querySelectorAll("#transcript-tabs .tab").forEach((t) => {
    t.classList.toggle("active", t.getAttribute("data-iotab") === tab);
  });

  const body = $("#transcript-body");
  if (!body) return;
  if (tab === "input") {
    const inp = data.input || {};
    const sources = (inp.sources || [])
      .map((s) => {
        if (s.type === "md_body") {
          return `<li><strong>MD body</strong> <code>${esc(s.ref || "")}</code> ${esc(s.label || "")}</li>`;
        }
        if (s.type === "manual") {
          return `<li><strong>Manual</strong> (${esc(s.field || "")}): <pre class="inline-pre">${esc(
            s.preview || ""
          )}</pre></li>`;
        }
        return `<li><strong>${esc(s.type || "source")}</strong> ${esc(
          JSON.stringify(s).slice(0, 200)
        )}</li>`;
      })
      .join("");
    body.innerHTML = `
      <div class="step-io-section">
        <h4>Sources</h4>
        <ul class="step-io-sources">${sources || "<li class='controls-hint'>No structured sources</li>"}</ul>
      </div>
      <div class="step-io-section">
        <h4>Tools available / used</h4>
        <pre>${esc((inp.tools || []).join(", ") || "—")}</pre>
      </div>
      <div class="step-io-section">
        <h4>System</h4>
        <pre>${esc(inp.system || "(empty)")}</pre>
      </div>
      <div class="step-io-section">
        <h4>User / packet</h4>
        <pre>${esc(inp.user || "(empty)")}</pre>
      </div>
      <div class="step-io-section">
        <h4>Task payload</h4>
        <pre>${esc(JSON.stringify(inp.payload || {}, null, 2))}</pre>
      </div>`;
  } else if (tab === "turns") {
    const turns = data.turns || [];
    body.innerHTML = turns.length
      ? turns.map((m) => renderTurnHtml(m)).join("")
      : '<p class="empty">No LLM turns (mechanical task or empty transcript).</p>';
  } else if (tab === "output") {
    const out = data.output || {};
    body.innerHTML = `
      <div class="step-io-section">
        <h4>Submit</h4>
        <pre>${esc(out.submit || "—")}</pre>
      </div>
      <div class="step-io-section">
        <h4>Classification / ok</h4>
        <pre>ok=${esc(String(out.ok))} classification=${esc(out.classification || "—")} error=${esc(
      out.error || "—"
    )}</pre>
      </div>
      <div class="step-io-section">
        <h4>Content</h4>
        <pre>${esc(out.content || "")}</pre>
      </div>
      <div class="step-io-section">
        <h4>Result JSON</h4>
        <pre>${esc(JSON.stringify(out.result || {}, null, 2))}</pre>
      </div>`;
  } else if (tab === "files") {
    const files = data.files || {};
    const created = files.created || [];
    const modified = files.modified || [];
    body.innerHTML = `
      <p class="controls-hint">Run artifacts only (evidence / project). Target tree is read-only for agents.</p>
      <div class="step-io-section">
        <h4>Created (${created.length})</h4>
        <ul>${
          created.length
            ? created.map((f) => `<li><code>${esc(f)}</code></li>`).join("")
            : "<li class='controls-hint'>None recorded</li>"
        }</ul>
      </div>
      <div class="step-io-section">
        <h4>Modified (${modified.length})</h4>
        <ul>${
          modified.length
            ? modified.map((f) => `<li><code>${esc(f)}</code></li>`).join("")
            : "<li class='controls-hint'>None recorded</li>"
        }</ul>
      </div>`;
  } else if (tab === "usage") {
    const u = data.usage || {};
    const events = data.usage_events || [];
    body.innerHTML = `
      <div class="step-io-section">
        <h4>Totals</h4>
        <pre>${esc(JSON.stringify(u, null, 2))}</pre>
      </div>
      <div class="step-io-section">
        <h4>Events (${events.length})</h4>
        <pre>${esc(JSON.stringify(events, null, 2))}</pre>
      </div>`;
  }
}

function closeTranscript() {
  $("#transcript-modal")?.classList.remove("open");
  _stepIoState = null;
}

window.openStepIO = openStepIO;
window.openTranscript = openTranscript;

/** Navigate to the dedicated Settings page (modal kept only as legacy fallback). */
async function openSettings() {
  // Prefer full settings page — multi-model + stage routing no longer fit a modal.
  if (document.body?.dataset?.page !== "settings") {
    window.location.href = "/settings";
    return;
  }
  // On /settings, page script owns the form.
  if (window.VFSettingsPage?.loadSettings) {
    return window.VFSettingsPage.loadSettings();
  }
  try {
    const data = await api("/api/settings");
    const s = data.settings || {};
    if ($("#set-host")) $("#set-host").value = s.host || "";
    if ($("#set-port")) $("#set-port").value = s.port || 1234;
    if ($("#set-model")) $("#set-model").value = s.model || "";
    $("#settings-modal")?.classList.add("open");
  } catch (e) {
    toast(e.message, true);
  }
}

function closeSettings() {
  $("#settings-modal")?.classList.remove("open");
}

function settingsFormBody() {
  return {
    host: $("#set-host").value.trim(),
    port: parseInt($("#set-port").value, 10),
    model: $("#set-model").value.trim(),
    api_mode: $("#set-api-mode")?.value || "chat_completions",
    // Always send (may be blank / "none") so Save can clear a stored key.
    api_key: ($("#set-api-key")?.value ?? "").trim(),
    max_concurrent_agents: parseInt($("#set-workers").value, 10),
    context_tokens: parseInt($("#set-ctx").value, 10),
    max_context_fraction: parseFloat($("#set-frac").value),
    max_tokens: parseInt($("#set-maxtok").value, 10),
    max_tool_rounds: parseInt($("#set-rounds").value, 10),
    timeout_seconds: parseInt($("#set-timeout").value, 10),
    max_tasks: parseInt($("#set-maxtasks").value, 10),
  };
}

function applyRecommendedToSettingsForm(rec) {
  if (!rec || typeof rec !== "object") return;
  if (rec.host != null) $("#set-host").value = rec.host;
  if (rec.port != null) $("#set-port").value = rec.port;
  if (rec.model != null) $("#set-model").value = rec.model;
  const apiModeEl = $("#set-api-mode");
  if (apiModeEl && rec.api_mode) {
    apiModeEl.value = rec.api_mode;
    if (apiModeEl.value !== rec.api_mode) apiModeEl.value = "chat_completions";
  }
  // Preserve form key if optimize omitted; otherwise apply recommended (may be blank).
  if (rec.api_key != null && $("#set-api-key")) {
    $("#set-api-key").value = rec.api_key;
  }
  if (rec.max_concurrent_agents != null) $("#set-workers").value = rec.max_concurrent_agents;
  if (rec.context_tokens != null) $("#set-ctx").value = rec.context_tokens;
  if (rec.max_context_fraction != null) $("#set-frac").value = rec.max_context_fraction;
  if (rec.max_tokens != null) $("#set-maxtok").value = rec.max_tokens;
  if (rec.max_tool_rounds != null) $("#set-rounds").value = rec.max_tool_rounds;
  if (rec.timeout_seconds != null) $("#set-timeout").value = rec.timeout_seconds;
  if (rec.max_tasks != null) $("#set-maxtasks").value = rec.max_tasks;
}

function formatOptimizeReport(data) {
  const lines = [];
  if (data.summary) lines.push(data.summary);
  if (data.error) lines.push("Error: " + data.error);
  if (data.recommended && data.recommended.context_tokens != null) {
    const src = data.context_source ? ` (${data.context_source})` : "";
    lines.push(`Context window: ${data.recommended.context_tokens} tokens${src}`);
  }
  if (data.recommended && data.recommended.max_tokens != null) {
    lines.push(`Max output: ${data.recommended.max_tokens} tokens`);
  }
  if (data.measured_context_tokens != null) {
    const src = data.context_source ? ` (${data.context_source})` : "";
    lines.push(`Measured context window: ${data.measured_context_tokens} tokens${src}`);
  }
  const warns = data.warnings || [];
  for (const w of warns) lines.push("⚠ " + w);
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
      const mark = t.ok ? "✓" : "✗";
      lines.push(`  ${mark} ${t.id}: ${t.detail || ""} (${t.seconds ?? "?"}s)`);
    }
  }
  lines.push("Review values, then Save to persist.");
  return lines.join("\n");
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
    if (data.ok) {
      toast(data.tool_calls_ok ? "Optimized — review & Save" : "Optimized with warnings — review & Save");
      const eff = $("#settings-effective");
      if (eff && data.recommended) {
        const r = data.recommended;
        const base =
          data.base_url ||
          (String(r.host || "").includes("://")
            ? String(r.host).replace(/\/$/, "")
            : `http://${r.host}:${r.port}/v1`);
        eff.textContent =
          `Recommended: ${base} | model ${r.model} | api ${r.api_mode} | ` +
          `agents ${r.max_concurrent_agents} | context window ${r.context_tokens} × ${r.max_context_fraction} | ` +
          `max output ${r.max_tokens} | tools ${data.tool_calls_ok ? "ok" : "weak"}`;
      }
    } else {
      toast(data.error || "Optimize failed", true);
    }
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
  ev.preventDefault();
  const body = settingsFormBody();
  try {
    await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    toast("Settings saved");
    closeSettings();
  } catch (e) {
    toast(e.message, true);
  }
}

const EVENT_ICONS = {
  lease: ">",
  lease_cap: "=",
  task_done: "OK",
  failed_task: "X",
  failed_infra: "!",
  deadletter: "!",
  idle: "o",
  init: "*",
  runner_start: ">",
  runner_pause: "||",
  runner_resume: ">",
  runner_stop_hard: "x",
  hunt_split: "2",
  shallow_requeue: "requeue",
  apply_candidate: "+",
  operator_requeue: "requeue",
  operator_cancel: "x",
  operator_priority: "^",
  operator_recon_rerun: "*",
  selection_hunt: "x",
  human_review: "?",
  coverage_mode: "#",
  poc_agent_enqueued: "p",
  poc_developed: "p",
  poc_saved: "p",
};

function appendEvents(events) {
  const list = Array.isArray(events) ? events : [];
  if (list.length) {
    // Activity feeds on page modules (Campaign) listen for this.
    try {
      window.dispatchEvent(new CustomEvent("vf:events", { detail: list }));
    } catch (err) {
      console.error("vf:events listener failed", err);
    }
  }
  const tl = $("#timeline");
  if (tl && list.length) {
    const frag = document.createDocumentFragment();
    for (const ev of list) {
      const name = ev.event || ev.type || "event";
      const div = document.createElement("div");
      div.className = `ev ${name}`;
      const copy = { ...ev };
      delete copy._line;
      delete copy.event;
      delete copy.ts;
      delete copy.source;
      const ico = EVENT_ICONS[name] || " | ";
      div.innerHTML = `<div class="ico" title="${esc(name)}">${ico}</div>
      <div class="body">
        <span class="ts">${esc(ev.ts || "")}</span>
        <span class="name">${esc(name)}</span>
        <div class="detail">${esc(JSON.stringify(copy).slice(0, 320))}</div>
      </div>`;
      frag.appendChild(div);
    }
    tl.appendChild(frag);
    if ($("#autoscroll")?.checked) {
      tl.scrollTop = tl.scrollHeight;
    }
  }
}

/* ---------- Markdown (lightweight, no deps) ---------- */

/**
 * Escape HTML, then apply a small set of markdown constructs.
 * Safe for untrusted agent/report text (no raw HTML passthrough).
 */
function renderMarkdown(md) {
  if (md == null || md === "") return "";
  let src = String(md).replace(/\r\n/g, "\n");

  // Extract fenced code blocks first (placeholders survive escaping)
  const fences = [];
  src = src.replace(/```([^\n`]*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const i = fences.length;
    fences.push({ lang: (lang || "").trim(), code });
    return `\n\n%%FENCE${i}%%\n\n`;
  });

  // Escape remaining text
  let text = esc(src);

  // Restore fenced blocks as pre/code
  text = text.replace(/%%FENCE(\d+)%%/g, (_, n) => {
    const f = fences[Number(n)];
    if (!f) return "";
    const langCls = f.lang ? ` class="language-${esc(f.lang)}"` : "";
    return `<pre class="md-code"><code${langCls}>${esc(f.code.replace(/\n$/, ""))}</code></pre>`;
  });

  // Horizontal rules
  text = text.replace(/^(?:-{3,}|\*{3,}|_{3,})\s*$/gm, "<hr />");

  // Headings
  text = text.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  text = text.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  text = text.replace(/^# (.+)$/gm, "<h1>$1</h1>");

  // Blockquotes (simple single-line / consecutive)  -  apply inline MD inside
  text = text.replace(/^(?:&gt; .+(\n|$))+/gm, (block) => {
    const inner = block
      .split("\n")
      .filter((l) => l.startsWith("&gt;"))
      .map((l) => inlineMd(l.replace(/^&gt;\s?/, "")))
      .join("<br />");
    return `<blockquote>${inner}</blockquote>`;
  });

  // Tables: consecutive lines starting with |
  text = text.replace(/(?:^\|.+\|[ \t]*\n?)+/gm, (block) => {
    const rows = block.trim().split("\n").filter(Boolean);
    if (rows.length < 1) return block;
    const parseRow = (row) =>
      row
        .replace(/^\|/, "")
        .replace(/\|$/, "")
        .split("|")
        .map((c) => c.trim());
    const isSep = (row) => /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$/.test(row);
    let html = "<table class=\"md-table\"><thead>";
    let i = 0;
    const header = parseRow(rows[0]);
    html += "<tr>" + header.map((c) => `<th>${inlineMd(c)}</th>`).join("") + "</tr></thead><tbody>";
    i = 1;
    if (rows[1] && isSep(rows[1])) i = 2;
    for (; i < rows.length; i++) {
      if (isSep(rows[i])) continue;
      const cells = parseRow(rows[i]);
      html += "<tr>" + cells.map((c) => `<td>${inlineMd(c)}</td>`).join("") + "</tr>";
    }
    html += "</tbody></table>";
    return html;
  });

  // Lists  -  process line-by-line for ul/ol blocks
  const lines = text.split("\n");
  const out = [];
  let listType = null; // "ul" | "ol"
  const flushList = () => {
    if (listType) {
      out.push(`</${listType}>`);
      listType = null;
    }
  };
  for (const line of lines) {
    const ul = line.match(/^[\-\*] (.+)$/);
    const ol = line.match(/^\d+\. (.+)$/);
    if (ul) {
      if (listType !== "ul") {
        flushList();
        out.push("<ul>");
        listType = "ul";
      }
      out.push(`<li>${inlineMd(ul[1])}</li>`);
    } else if (ol) {
      if (listType !== "ol") {
        flushList();
        out.push("<ol>");
        listType = "ol";
      }
      out.push(`<li>${inlineMd(ol[1])}</li>`);
    } else {
      flushList();
      out.push(line);
    }
  }
  flushList();
  text = out.join("\n");

  // Paragraphs: wrap loose text blocks (skip block-level tags)
  const blocks = text.split(/\n{2,}/);
  text = blocks
    .map((block) => {
      const t = block.trim();
      if (!t) return "";
      if (/^<(h[1-6]|ul|ol|li|pre|blockquote|table|hr|div|p)\b/i.test(t)) return t;
      // Single-line already-block
      if (/^<\/?(h[1-6]|ul|ol|pre|blockquote|table|hr)/i.test(t)) return t;
      const withBreaks = t
        .split("\n")
        .map((ln) => inlineMd(ln))
        .join("<br />");
      // Don't double-wrap if already mostly HTML block
      if (/^<(h[1-6]|ul|ol|pre|blockquote|table|hr)/i.test(withBreaks)) return withBreaks;
      return `<p>${withBreaks}</p>`;
    })
    .filter(Boolean)
    .join("\n");

  return text;
}

/** Inline markdown on already-escaped text (bold, code, links). */
function inlineMd(s) {
  if (!s) return "";
  let t = String(s);
  // Inline code (avoid matching across)
  t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
  // Bold
  t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  t = t.replace(/__([^_]+)__/g, "<strong>$1</strong>");
  // Optional links [text](url)  -  only http(s)
  t = t.replace(
    /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
    '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
  );
  return t;
}

/* ---------- Architecture (Mission page) ---------- */


/**
 * @param {string} title
 * @param {number|null|undefined} count
 * @param {string} bodyHtml
 * @param {string} [extraClass]
 * @param {string} [tone]  arch-tone-* key: components | surfaces | boundaries | focus | agents | sinks
 */


/* ---------- Target Explorer ---------- */

let explorerBrowsePath = ".";
let explorerOpenFile = null;
let explorerSelRange = null;
let explorerMounted = false;
let explorerTreeLoaded = false;

/** Thin fallback if run snapshot has no hunt_classes yet. */
const FALLBACK_HUNT_CLASSES = [
  "injection",
  "access-control",
  "business-logic",
  "cryptography",
  "wildcard",
];

function allHuntClasses() {
  const cat = window.__VF_hunt_classes;
  if (cat && Array.isArray(cat.all) && cat.all.length) return cat.all;
  return FALLBACK_HUNT_CLASSES;
}

function activeHuntClasses() {
  const cat = window.__VF_hunt_classes;
  if (cat && Array.isArray(cat.active) && cat.active.length) return cat.active;
  return allHuntClasses();
}

function huntClassOptionsHtml(selected) {
  const sel = selected || "wildcard";
  const cat = window.__VF_hunt_classes || {};
  const active =
    Array.isArray(cat.active) && cat.active.length
      ? cat.active
      : activeHuntClasses();
  const all = allHuntClasses();
  const bySource = cat.by_source || {};
  const customGen = new Set(
    [...(bySource.custom || []), ...(bySource.generated || []), ...(bySource.import || [])].map(
      String
    )
  );
  if (Array.isArray(cat.profiles)) {
    for (const p of cat.profiles) {
      if (!p?.id) continue;
      const src = String(p.source || "").toLowerCase();
      if (src === "custom" || src === "generated" || src === "import") {
        customGen.add(String(p.id));
      }
    }
  }
  const inactiveCustom = all.filter((c) => !active.includes(c) && customGen.has(c));
  const inactiveSeed = all.filter((c) => !active.includes(c) && !customGen.has(c));
  const opt = (c) => {
    const tag = customGen.has(c) ? " (custom)" : "";
    return `<option value="${esc(c)}"${c === sel ? " selected" : ""}>${esc(c)}${tag}</option>`;
  };
  let html = `<optgroup label="Active skills">${active.map(opt).join("")}</optgroup>`;
  if (inactiveCustom.length) {
    html += `<optgroup label="Custom & generated">${inactiveCustom.map(opt).join("")}</optgroup>`;
  }
  if (inactiveSeed.length) {
    html += `<optgroup label="Optional seed skills">${inactiveSeed.map(opt).join("")}</optgroup>`;
  }
  return html;
}

function mountExplorer() {
  const el = $("#explorer-panel");
  if (!el) return;
  // Preserve class choice across remounts (loadRunFull rebuilds the shell)
  const prevClass = $("#explorer-hunt-class")?.value || "wildcard";
  // Keep open file / path across remounts; rebuild shell once structure is known
  el.innerHTML = `
    <div class="card explorer-card">
      <h2>Target explorer</h2>
      <p class="controls-hint">Browse the audit target. Select lines in the viewer, then enqueue a focused hunt.</p>
      <div class="arch-explorer explorer-layout">
        <div class="arch-tree explorer-tree-pane">
          <div class="explorer-pwd-bar" title="Current directory">
            <span class="explorer-pwd-label">pwd</span>
            <code class="explorer-pwd-path mono" id="explorer-cwd">${esc(formatExplorerPwd(explorerBrowsePath))}</code>
          </div>
          <div class="explorer-tree-toolbar">
            <button type="button" class="btn btn-ghost" id="explorer-up" title="Parent directory">Up Up</button>
            <button type="button" class="btn btn-ghost" id="explorer-root" title="Target root"> Root</button>
          </div>
          <div id="explorer-tree-list" class="arch-tree-list explorer-tree-list">Loading...</div>
        </div>
        <div class="arch-viewer">
          <div class="toolbar explorer-viewer-toolbar">
            <span class="mono" id="explorer-file-label">${esc(explorerOpenFile || "No file open")}</span>
            <select id="explorer-hunt-class" title="Hunt skill">
              ${huntClassOptionsHtml(prevClass)}
            </select>
            <button type="button" class="btn btn-primary" id="explorer-hunt-sel" disabled>Hunt selection</button>
          </div>
          <div class="field" style="padding:0.4rem 0.65rem 0;margin:0">
            <label for="explorer-op-notes" class="controls-hint">Notes for hunt (optional)</label>
            <input id="explorer-op-notes" type="text" placeholder="Extra guidance for this selection hunt..." style="width:100%" />
          </div>
          <div class="code-view monaco-host" id="explorer-monaco" tabindex="0" role="region" aria-label="Target file viewer">Open a file from the tree...</div>
          <div class="controls-hint" id="explorer-sel-meta">Select text to set a line range for a candidate hunt.</div>
        </div>
      </div>
    </div>`;

  $("#explorer-up")?.addEventListener("click", () => {
    if (explorerBrowsePath === "." || !explorerBrowsePath) return;
    const parts = explorerBrowsePath.replace(/\\/g, "/").split("/").filter(Boolean);
    parts.pop();
    explorerBrowsePath = parts.length ? parts.join("/") : ".";
    loadExplorerTree();
  });
  $("#explorer-root")?.addEventListener("click", () => {
    explorerBrowsePath = ".";
    loadExplorerTree();
  });
  $("#explorer-hunt-sel")?.addEventListener("click", enqueueSelectionHunt);
  const code = $("#explorer-code");
  code?.addEventListener("mouseup", updateExplorerSelection);
  code?.addEventListener("keyup", updateExplorerSelection);
  explorerMounted = true;
  explorerTreeLoaded = false;
  loadExplorerTree();
  if (explorerOpenFile) loadExplorerFile(explorerOpenFile);
}

/** Alias used by loadRunFull  -  ensures explorer shell exists. */
function renderExplorer() {
  mountExplorer();
}

function formatExplorerPwd(path) {
  const p = (path || ".").replace(/\\/g, "/");
  if (!p || p === ".") return "/ (target root)";
  return "/" + p.replace(/^\//, "");
}

function setExplorerPwdDisplay() {
  const el = $("#explorer-cwd");
  if (el) el.textContent = formatExplorerPwd(explorerBrowsePath);
  const up = $("#explorer-up");
  if (up) up.disabled = !explorerBrowsePath || explorerBrowsePath === ".";
}

async function loadExplorerTree() {
  const list = $("#explorer-tree-list");
  if (!list) return;
  list.textContent = "Loading...";
  setExplorerPwdDisplay();
  try {
    const data = await api(
      `${runApiBase()}/target/list?path=${encodeURIComponent(explorerBrowsePath || ".")}`
    );
    const entries = [...(data.entries || [])];
    // Directories first, then files  -  alpha within each group
    entries.sort((a, b) => {
      if (!!a.is_dir !== !!b.is_dir) return a.is_dir ? -1 : 1;
      return String(a.name).localeCompare(String(b.name), undefined, {
        sensitivity: "base",
      });
    });
    explorerTreeLoaded = true;
    setExplorerPwdDisplay();
    if (!entries.length) {
      list.innerHTML = `<div class="empty" style="padding:0.5rem">Empty folder</div>`;
      return;
    }
    const dirs = entries.filter((e) => e.is_dir);
    const files = entries.filter((e) => !e.is_dir);
    const row = (e) => {
      const full =
        !explorerBrowsePath || explorerBrowsePath === "."
          ? e.name
          : `${explorerBrowsePath.replace(/\\/g, "/").replace(/\/$/, "")}/${e.name}`;
      if (e.is_dir) {
        return `<button type="button" class="tree-item dir" data-path="${esc(full)}" data-dir="1" title="Open folder">
          <span class="tree-ico tree-ico-folder" aria-hidden="true">ðŸ“</span>
          <span class="tree-name">${esc(e.name)}</span>
          <span class="tree-badge">folder</span>
          <span class="tree-chevron" aria-hidden="true">></span>
        </button>`;
      }
      return `<button type="button" class="tree-item file" data-path="${esc(full)}" data-dir="0" title="Open file">
          <span class="tree-ico tree-ico-file" aria-hidden="true">ðŸ“„</span>
          <span class="tree-name">${esc(e.name)}</span>
        </button>`;
    };
    let html = "";
    if (dirs.length) {
      html += `<div class="tree-section-label">Folders (${dirs.length})</div>`;
      html += dirs.map(row).join("");
    }
    if (files.length) {
      html += `<div class="tree-section-label">Files (${files.length})</div>`;
      html += files.map(row).join("");
    }
    list.innerHTML = html;
    list.querySelectorAll(".tree-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = btn.getAttribute("data-path");
        const isDir = btn.getAttribute("data-dir") === "1";
        if (isDir) {
          explorerBrowsePath = p;
          setExplorerPwdDisplay();
          loadExplorerTree();
        } else {
          loadExplorerFile(p);
        }
      });
    });
  } catch (e) {
    list.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message)}</div>`;
  }
}

// Back-compat aliases
const loadArchTree = loadExplorerTree;

async function loadExplorerFile(path) {
  explorerOpenFile = path;
  explorerSelRange = null;
  const label = $("#explorer-file-label");
  const code = $("#explorer-code");
  const huntBtn = $("#explorer-hunt-sel");
  if (label) label.textContent = path;
  if (code) code.textContent = "Loading...";
  if (huntBtn) huntBtn.disabled = true;
  try {
    const data = await api(
      `${runApiBase()}/target/read?path=${encodeURIComponent(path)}`
    );
    const lines = (data.content || "").split("\n");
    const base = data.start_line || 1;
    if (code) {
      code.innerHTML = lines
        .map((ln, i) => {
          const n = base + i;
          return `<div class="code-line" data-line="${n}"><span class="ln">${n}</span><span class="tx">${esc(ln)}</span></div>`;
        })
        .join("");
    }
    $("#explorer-sel-meta") &&
      ($("#explorer-sel-meta").textContent =
        "Select text to set a line range for a candidate hunt.");
  } catch (e) {
    if (code) code.textContent = e.message;
  }
}

const loadArchFile = loadExplorerFile;

function updateExplorerSelection() {
  const code = $("#explorer-code");
  const huntBtn = $("#explorer-hunt-sel");
  const meta = $("#explorer-sel-meta");
  if (!code || !explorerOpenFile) return;
  const sel = window.getSelection();
  if (!sel || sel.isCollapsed || !code.contains(sel.anchorNode)) {
    explorerSelRange = null;
    if (huntBtn) huntBtn.disabled = true;
    if (meta)
      meta.textContent = "Select text to set a line range for a candidate hunt.";
    return;
  }
  const getLine = (node) => {
    let el = node.nodeType === 3 ? node.parentElement : node;
    while (el && el !== code) {
      if (el.dataset && el.dataset.line) return parseInt(el.dataset.line, 10);
      el = el.parentElement;
    }
    return null;
  };
  let a = getLine(sel.anchorNode);
  let b = getLine(sel.focusNode);
  if (a == null || b == null) {
    explorerSelRange = null;
    if (huntBtn) huntBtn.disabled = true;
    return;
  }
  const start = Math.min(a, b);
  const end = Math.max(a, b);
  explorerSelRange = { start_line: start, end_line: end };
  if (huntBtn) huntBtn.disabled = false;
  if (meta)
    meta.textContent = `Selection: lines ${start}-${end} in ${explorerOpenFile}`;
}

async function enqueueSelectionHunt() {
  if (!explorerOpenFile) {
    toast("Open a file first", true);
    return;
  }
  const cls = $("#explorer-hunt-class")?.value || "wildcard";
  const notes = ($("#explorer-op-notes")?.value || "").trim();
  const body = {
    path: explorerOpenFile,
    attack_class: cls,
    note: notes || "operator selection from target explorer",
    operator_notes: notes || "operator selection from target explorer",
  };
  if (explorerSelRange) {
    body.start_line = explorerSelRange.start_line;
    body.end_line = explorerSelRange.end_line;
  }
  try {
    const r = await api(`${runApiBase()}/hunts/from-selection`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    toast(`Enqueued hunt #${r.task_id} on ${explorerOpenFile}`);
    await loadRunFull();
  } catch (e) {
    toast(e.message, true);
  }
}

/* ---------- Evidence ---------- */

let evidenceSelected = null; // { pack, rel }
let evidencePacksCache = [];

function selectEvidencePack(pack, rel) {
  if (!pack) return;
  evidenceSelected = { pack: String(pack), rel: rel || null };
}

function preferredRelForPack(packId, preferredRel) {
  const pack = evidencePacksCache.find((p) => String(p.id) === String(packId));
  const names = ((pack && pack.files) || []).map((f) => f.relpath || f);
  if (preferredRel && names.includes(preferredRel)) return preferredRel;
  const md = names.find((n) => /\.md$/i.test(n));
  return md || names[0] || preferredRel || null;
}

/** Map evidence pack id → linked finding(s) for left-rail labels. */
function findingsForEvidencePack(packId) {
  const findings = window.__VF_last_snap?.findings || [];
  const pid = String(packId);
  return findings.filter((f) => {
    const eid = f.evidence_id || f.body?.evidence_id;
    return eid != null && String(eid) === pid;
  });
}

/** Left-rail label: "#3 — Unauthenticated API with…" */
function evidencePackLabel(packId) {
  const linked = findingsForEvidencePack(packId);
  if (!linked.length) {
    return {
      html: `<span class="mono">pack ${esc(String(packId))}</span>`,
      title: `evidence/${packId}`,
    };
  }
  // Prefer lowest finding id when multiple findings share a pack
  const sorted = [...linked].sort((a, b) => Number(a.id) - Number(b.id));
  const primary = sorted[0];
  const fullTitle =
    (primary.body && primary.body.title) ||
    primary.stable_key ||
    `Finding #${primary.id}`;
  const maxLen = 48;
  const short =
    fullTitle.length > maxLen ? fullTitle.slice(0, maxLen - 1).trimEnd() + "…" : fullTitle;
  const extra =
    sorted.length > 1
      ? ` <span class="controls-hint">+${sorted.length - 1}</span>`
      : "";
  const ids = sorted.map((f) => `#${f.id}`).join(", ");
  return {
    html: `<span class="ev-finding-id">#${esc(String(primary.id))}</span><span class="ev-finding-sep"> — </span><span class="ev-finding-title">${esc(short)}</span>${extra}`,
    title: `${ids} — ${fullTitle} (pack ${packId})`,
  };
}

function renderEvidence(packs) {
  const el = $("#evidence-list");
  if (!el) return;
  if (Array.isArray(packs)) evidencePacksCache = packs;
  const list = Array.isArray(packs) ? packs : evidencePacksCache;
  if (!list?.length) {
    el.innerHTML = `<div class="empty">No evidence packs yet.<br/><span class="controls-hint">Packs appear under <span class="mono">evidence/</span> when hunts write proof notes.</span></div>`;
    return;
  }
  const packsHtml = list
    .map((p) => {
      const packOn =
        evidenceSelected && String(evidenceSelected.pack) === String(p.id)
          ? " selected"
          : "";
      const label = evidencePackLabel(p.id);
      const files = (p.files || [])
        .map((f) => {
          const active =
            evidenceSelected &&
            String(evidenceSelected.pack) === String(p.id) &&
            evidenceSelected.rel === f.relpath
              ? " active"
              : "";
          return `<button type="button" class="ev-file-chip${active}" data-ev="${esc(p.id)}" data-rel="${esc(f.relpath)}" title="${esc(f.relpath)} (${f.size} B)">${esc(f.relpath)}</button>`;
        })
        .join("");
      return `
        <div class="ev-pack-card${packOn}" data-pack-id="${esc(p.id)}">
          <div class="ev-pack-title" title="${esc(label.title)}">${label.html}</div>
          <div class="ev-file-chips">${files || `<span class="controls-hint">empty</span>`}</div>
        </div>`;
    })
    .join("");

  el.innerHTML = `
    <div class="evidence-layout">
      <div class="ev-pack-list">${packsHtml}</div>
      <div class="ev-content-panel" id="ev-content-panel">
        <div class="empty">Select a file from a pack...</div>
      </div>
    </div>`;

  el.querySelectorAll("[data-ev]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pack = btn.getAttribute("data-ev");
      const rel = btn.getAttribute("data-rel");
      openEvidenceFile(pack, rel, btn);
    });
  });

  // Re-open previously selected file after refresh / deep-link
  if (evidenceSelected && evidenceSelected.pack) {
    const rel =
      evidenceSelected.rel || preferredRelForPack(evidenceSelected.pack);
    if (rel) openEvidenceFile(evidenceSelected.pack, rel);
  }
}

async function openEvidenceFile(pack, rel, btn) {
  if (!pack || !rel) return;
  const panel = $("#ev-content-panel");
  evidenceSelected = { pack: String(pack), rel };
  // Layout may not exist yet (navigating before first paint)
  if (!panel) {
    if (typeof window.renderEvidence === "function" && evidencePacksCache.length) {
      renderEvidence(evidencePacksCache);
    }
    return;
  }
  $$(".ev-file-chip").forEach((c) => {
    const on =
      c.getAttribute("data-ev") === String(pack) && c.getAttribute("data-rel") === rel;
    c.classList.toggle("active", on);
  });
  $$(".ev-pack-card").forEach((card) => {
    card.classList.toggle(
      "selected",
      card.getAttribute("data-pack-id") === String(pack)
    );
  });
  panel.innerHTML = `<div class="controls-hint">Loading...</div>`;
  const [target_id, run_id] = currentKey.split("/");
  try {
    const data = await api(
      `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}/evidence/${encodeURIComponent(pack)}/${rel.split("/").map(encodeURIComponent).join("/")}`
    );
    const content = data.content ?? "";
    const isMd = /\.md$/i.test(rel);
    let body;
    if (isMd) {
      body = `<div class="md-prose">${renderMarkdown(content)}</div>`;
    } else {
      body = `<pre class="ev-code-view">${esc(content)}</pre>`;
    }
    panel.innerHTML = `
      <div class="ev-content-head">
        <span class="mono">${esc(pack)} / ${esc(rel)}</span>
      </div>
      ${body}
      <details class="ev-source">
        <summary>View source</summary>
        <pre class="arch-box">${esc(content)}</pre>
      </details>`;
    // Scroll pack into view when deep-linked from Report
    const card = [...document.querySelectorAll(".ev-pack-card")].find(
      (c) => c.getAttribute("data-pack-id") === String(pack)
    );
    card?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  } catch (e) {
    panel.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message)}</div>`;
  }
}

window.renderEvidence = renderEvidence;
window.openEvidenceFile = openEvidenceFile;
window.selectEvidencePack = selectEvidencePack;

/* ---------- Project / Report ---------- */

let runSwitchBound = false;

function fillRunSwitch(snap) {
  const sel = $("#run-switch");
  if (!sel) return;
  const current = `${snap.target_id}/${snap.run_id}`;
  const keep = sel.dataset.filled === "1";
  if (!keep) {
    sel.innerHTML = `<option value="/runs/${encodeURIComponent(snap.target_id)}/${encodeURIComponent(snap.run_id)}" selected>${esc(current)}</option>`;
  }
  api("/api/runs")
    .then((data) => {
      const runs = (data.runs || []).filter((r) => !r.error && r.target_id && r.run_id);
      if (!runs.length) return;
      const opts = runs
        .map((r) => {
          const key = `${r.target_id}/${r.run_id}`;
          const href = `/runs/${encodeURIComponent(r.target_id)}/${encodeURIComponent(r.run_id)}`;
          return `<option value="${href}" ${key === current ? "selected" : ""}>${esc(key)}</option>`;
        })
        .join("");
      sel.innerHTML = opts;
      sel.dataset.filled = "1";
    })
    .catch(() => {});
  if (!runSwitchBound) {
    runSwitchBound = true;
    sel.addEventListener("change", () => {
      const href = sel.value;
      if (!href) return;
      const hash = location.hash || "";
      location.href = href + hash;
    });
  }
}

async function refreshHitlInbox() {
  const Hitl = window.VulnForgeHitl;
  if (!Hitl || !currentKey) return;
  const [target_id, run_id] = currentKey.split("/");
  const base = `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}`;
  try {
    const data = await api(`${base}/hitl/inbox`);
    Hitl.mountAll(data, {
      onRespond: async ({ reportId, blockId, value, note }) => {
        await api(`${base}/hitl/reports/${encodeURIComponent(reportId)}/respond`, {
          method: "POST",
          body: JSON.stringify({
            block_id: blockId,
            value,
            note: note || "",
            operator: "operator",
          }),
        });
        toast(
          value === "approved"
            ? "Accepted — confirmed by explicit human review"
            : value === "changes-requested"
              ? "Rejected by explicit human review"
              : "Response saved"
        );
        if (typeof loadRunFull === "function") await loadRunFull();
      },
      onOpenFinding: (findingId) => {
        window.VulnForgeModes?.goReport?.("needs_human");
        if (findingId != null && window.VulnForgeReport?.openFinding) {
          window.VulnForgeReport.openFinding(findingId);
        }
      },
      onError: (message) => toast(message || "Response needs a value", true),
    });
  } catch (e) {
    Hitl.mountError(e.message || String(e));
  }
}

async function loadRunFull() {
  const [target_id, run_id] = currentKey.split("/");
  const snap = await api(
    `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}`
  );
  fillRunSwitch(snap);
  $("#run-subtitle") &&
    ($("#run-subtitle").textContent = snap.target_path || snap.path || "");
  window.__VF_cov_policy = snap.coverage_policy || { mode: "auto" };
  window.__VF_hunt_classes = snap.hunt_classes || window.__VF_hunt_classes || {};
  // Shared for report mode + evidence deep-links
  window.__VF_last_snap = snap;
  window.currentKey = currentKey;
  window.api = api;
  window.loadRunFull = loadRunFull;
  // Chat mutators / operator UI refresh alias
  window.refreshSnapshot = loadRunFull;
  window.__VF_max_task_attempts = Number(snap.max_task_attempts) || 3;
  renderRunner(snap.runner || {}, snap);
  renderTasks(snap.tasks || []);
  renderExplorer();
  renderEvidence(snap.evidence || []);
  window.__VF_cov_policy = snap.coverage_policy;
  window.__VF_hunt_classes = snap.hunt_classes;
  if (window.VulnForgeCoverage?.render) {
    window.VulnForgeCoverage.render(snap);
  } else {
    const cov = $("#coverage-panel");
    if (cov) cov.innerHTML = renderCoverageHtml(snap.coverage, { interactive: false });
  }
  if (typeof window.renderReport === "function") {
    window.renderReport(snap);
  } else if (window.VulnForgeReport?.render) {
    window.VulnForgeReport.render(snap);
  }
  await refreshHitlInbox();
  renderHeaderStrip(snap);
  // Page modules (static/pages/*.js) subscribe to this instead of patching app.js.
  try {
    window.dispatchEvent(new CustomEvent("vf:snapshot", { detail: snap }));
  } catch (err) {
    console.error("vf:snapshot listener failed", err);
  }
  // Align live drift detector with the snap we just applied.
  noteLiveTaskSig(snap);
  return snap;
}

/** Run token usage for the header strip; in/out split + per-model rows in the tooltip. */
function renderHeaderTokensHtml(snap, helpers) {
  if (!helpers?.buildMissionUsage || !helpers?.formatTokenCount) return "";
  const u = helpers.buildMissionUsage(snap || {});
  if (!u.total) return "";
  const lines = [`In ${helpers.formatTokenCount(u.input)} · Out ${helpers.formatTokenCount(u.output)}`];
  for (const m of u.models || []) {
    lines.push(`${m.id}: ${helpers.formatTokenCount(m.total)}`);
  }
  return `<span class="sep" aria-hidden="true">·</span><span class="vf-strip-tokens" id="run-token-usage" title="${esc(lines.join("\n"))}">Tokens <b>${esc(helpers.formatTokenCount(u.total))}</b></span>`;
}

/** Header pipeline strip + Review tab badge (single source of run totals). */
function renderHeaderStrip(snap) {
  const el = $("#run-pipeline-strip");
  const helpers = window.MissionOverviewHelpers;
  if (!el || !helpers?.buildHeaderStrip) return;
  const items = helpers.buildHeaderStrip(snap || {});
  el.innerHTML = items
    .map(
      (it, i) =>
        `${i ? '<span class="sep" aria-hidden="true">›</span>' : ""}<button type="button" class="is-${esc(it.id)}" data-strip="${esc(it.id)}">${esc(it.label)} <b>${esc(it.value)}</b></button>`
    )
    .join("") + renderHeaderTokensHtml(snap, helpers);
  if (!el.dataset.bound) {
    el.dataset.bound = "1";
    el.addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-strip]");
      if (!btn) return;
      const it = helpers
        .buildHeaderStrip(window.__VF_last_snap || {})
        .find((row) => row.id === btn.dataset.strip);
      const modes = window.VulnForgeModes;
      if (!it || !modes) return;
      if (it.nav.mode === "report") modes.goReport(it.nav.filter);
      else modes.setMode(it.nav.mode);
    });
  }
  const review = items.find((it) => it.id === "review");
  window.VulnForgeModes?.setReviewBadge?.(review ? review.count : 0);
}

function connectStream() {
  if (!currentKey) return;
  // Keep an existing healthy (or reconnecting) stream for this run.
  // Avoid close/reopen on loadRunFull / refresh paths that re-call connectStream.
  if (
    es &&
    streamAttachedKey === currentKey &&
    es.readyState !== EventSource.CLOSED
  ) {
    return;
  }
  if (es) {
    es.onopen = null;
    es.onmessage = null;
    es.onerror = null;
    es.close();
    es = null;
  }
  const [target_id, run_id] = currentKey.split("/");
  const url = `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}/stream?after=${eventOffset}`;
  es = new EventSource(url);
  streamAttachedKey = currentKey;
  es.onopen = () => {
    markLiveConnected();
  };
  es.onmessage = (msg) => {
    // Any SSE payload means the socket is healthy (also cancels offline debounce).
    markLiveConnected();
    try {
      const data = JSON.parse(msg.data);
      if (data.type === "snapshot") {
        const card = data.card || {};
        renderRunner(data.runner || card.runner || {}, card);
        if (livePane) refreshLivePane();
        // Lightweight card includes task state counters (leased/queued/done).
        // When they drift from the last full snap, pull tasks/report/coverage.
        const sig = liveTaskSig(card);
        if (sig && lastLiveTaskSig && sig !== lastLiveTaskSig) {
          scheduleLoadRunFull("snapshot-drift");
        } else if (sig && !lastLiveTaskSig) {
          lastLiveTaskSig = sig;
        }
      } else if (data.type === "events") {
        appendEvents(data.events || []);
        if (typeof data.next === "number") eventOffset = data.next;
        const events = data.events || [];
        if (events.some((e) => LIVE_REFRESH_EVENTS.has(e.event))) {
          // Debounced full refresh; do not tear down SSE (connectStream sticky).
          scheduleLoadRunFull("event");
        }
        if (
          livePane &&
          events.some(
            (e) =>
              (e.event === "task_step" ||
                e.event === "operator_task_note" ||
                e.event === "operator_force_submit_none" ||
                e.event === "operator_abort_task") &&
              Number(e.task_id) === livePane.taskId
          )
        ) {
          refreshLivePane();
        }
      } else if (data.type === "error") {
        // Server-sent application error over a live channel — stay Live.
        console.warn(data.error);
      }
    } catch (e) {
      // Parse blips must not flip the indicator offline.
      console.warn(e);
    }
  };
  es.onerror = () => {
    // EventSource fires error on transient disconnects and auto-reconnects.
    // Only show Offline after a sustained outage (see markLiveDisconnected).
    markLiveDisconnected();
  };
}

/**
 * Build start/resume ControlBody from dashboard UI settings.
 * Operator Mission Start/Resume (real audits):
 * - no loop_profile_id (dev-only via API)
 * - max_tasks: null → Ralph runs until idle / Pause (Settings max_tasks is
 *   hunt *enqueue* planning only, not Ralph budget)
 * - no wall clock
 * - workers: settings.max_concurrent_agents when set
 * - task_timeout: 900 hung-task kill (not a campaign wall)
 *
 * Contract table (keep in sync): tests/test_control_body_contract.py
 */
function controlBodyFromSettings(settings) {
  const s = settings || {};
  // Real audits: unlimited Ralph progress budget, no wall, no loop profile.
  // Settings.max_tasks remains for Coverage/init enqueue caps only.
  const body = {
    max_tasks: null,
    max_wall_seconds: null,
    task_timeout: 900,
    max_iterations: 10000,
  };
  const w = parseInt(s.max_concurrent_agents, 10);
  if (Number.isFinite(w) && w > 0) {
    body.workers = w;
  }
  return body;
}

async function control(action) {
  const [target_id, run_id] = currentKey.split("/");
  const path = `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}/${action}`;
  const startBtn = $("#btn-start");
  const resumeBtn = $("#btn-resume");
  const pauseBtn = $("#btn-pause");
  const busyBtn =
    action === "start" ? startBtn : action === "resume" ? resumeBtn : action === "pause" ? pauseBtn : null;
  if (busyBtn) {
    busyBtn.classList.add("is-busy");
    busyBtn.disabled = true;
  }
  try {
    const opts = { method: "POST" };
    // start/resume honor Settings; pause/stop ignore body on the server
    if (action === "start" || action === "resume") {
      try {
        const data = await api("/api/settings");
        opts.body = JSON.stringify(controlBodyFromSettings(data.settings || {}));
      } catch {
        // Do not block Start/Resume if Settings is unavailable. Null max_tasks/
        // workers let the server apply ui_settings (ControlBody default=None).
        opts.body = JSON.stringify({
          max_tasks: null,
          max_wall_seconds: null,
          workers: null,
          task_timeout: 900,
          max_iterations: 10000,
        });
        toast("Settings unavailable; using server defaults", true);
      }
    }
    const r = await api(path, opts);
    const workers = r.workers || r.status?.meta?.workers || 1;
    const note = r.note ? ` — ${r.note}` : "";
    if (action === "start" || action === "resume") {
      const meta = r.status?.meta || r.meta || {};
      const tto = meta.task_timeout != null ? ` · ${meta.task_timeout}s/task` : "";
      toast(
        workers > 1
          ? `${action}: ${r.status?.state || "ok"} · ${workers} agents${tto}${note}`
          : `${action}: ${r.status?.state || "ok"}${tto}${note}`
      );
    } else {
      toast(`${action}: ${r.status?.state || "ok"}`);
    }
    renderRunner(r.status || {});
    await loadRunFull();
  } catch (e) {
    toast(e.message, true);
  } finally {
    if (busyBtn) {
      busyBtn.classList.remove("is-busy");
      // renderRunner re-enables the correct primary control
    }
  }
}

function setupTabs() {
  if ($("[data-run-rail]")) return;
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => t.classList.remove("active"));
      $$(".tab-panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const id = tab.getAttribute("data-tab");
      $(`#panel-${id}`)?.classList.add("active");
      if (id === "explorer") {
        if (window.VulnForgeExplorer?.ensureMounted) {
          window.VulnForgeExplorer.ensureMounted();
        } else if (!explorerMounted) mountExplorer();
        else if (!explorerTreeLoaded) loadExplorerTree();
      }
    });
  });
}


/* ---------- tool gaps (Home summary + /tool-gaps page) ---------- */

function toolGapsSummaryLine(data) {
  const caps = data.capability_count ?? (data.capabilities || []).length;
  const runs = data.runs_scanned ?? 0;
  const when = data.generated_at || "-";
  return `${caps} capabilities across ${runs} run(s) | ${when}`;
}

function renderHomeToolGapsSummary(data) {
  const meta = $("#home-tool-gaps-meta");
  if (!meta) return;
  meta.textContent = toolGapsSummaryLine(data);
}

/** Per-run swallowed-error count cell (issue #173). Top contexts go in the tooltip. */
function swallowedCell(sw) {
  const n = Number((sw && sw.count) || 0);
  if (!n) return "0";
  const top = ((sw && sw.by_context) || [])
    .map((c) => `${c.context} x${c.count}`)
    .join(", ");
  const tip = top + (sw.last_ts ? ` | last ${sw.last_ts}` : "") + (sw.truncated ? " | log truncated" : "");
  return `<span class="warn" title="${esc(tip)}">${esc(String(n))}${sw.truncated ? "+" : ""}</span>`;
}

function renderToolGapsPage(data) {
  const meta = $("#home-tool-gaps-meta");
  const body = $("#home-tool-gaps-body");
  const perRun = $("#tool-gaps-per-run");
  if (meta) {
    meta.textContent =
      `Generated ${data.generated_at || "-"} | runs=${data.runs_scanned ?? 0} | ` +
      `capabilities=${data.capability_count ?? (data.capabilities || []).length} | ` +
      `gap_rows=${data.total_gap_rows ?? 0} | ` +
      `swallowed_errors=${data.total_swallowed_errors ?? 0}` +
      (data.mode ? ` | mode=${data.mode}` : "");
  }
  if (body) {
    const caps = data.capabilities || [];
    if (!caps.length) {
      body.innerHTML = `<tr><td colspan="7" class="empty">No tool-gap signals yet. Click Analyze with AI after a campaign with transcripts.</td></tr>`;
    } else {
      body.innerHTML = caps
        .map((g, idx) => {
          const sev = String(g.severity || "info");
          const sevClass = sev === "high" ? "bad" : sev === "medium" ? "warn" : "";
          const runs = g.runs_hit ?? (g.run_keys || []).length ?? 0;
          return `<tr>
            <td><span class="${sevClass}">${esc(sev)}</span></td>
            <td><code>${esc(g.tool_or_capability || "")}</code></td>
            <td>${esc(String(runs))}</td>
            <td>${esc(String(g.count ?? 0))}</td>
            <td>${esc(g.source || "")}</td>
            <td>${esc(g.suggestion || "")}</td>
            <td><button type="button" class="btn" data-create-tool="${idx}">Create tool…</button></td>
          </tr>`;
        })
        .join("");
      body.querySelectorAll("[data-create-tool]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const i = parseInt(btn.getAttribute("data-create-tool"), 10);
          const gap = caps[i];
          if (!gap) return;
          btn.disabled = true;
          try {
            const r = await api("/api/tool-drafts/from-gap", {
              method: "POST",
              body: JSON.stringify({
                brief: gap.suggestion || `Implement ${gap.tool_or_capability}`,
                gap,
                suggested_id: String(gap.tool_or_capability || "new_tool")
                  .split(":")
                  .pop()
                  .replace(/[^a-z0-9_]+/gi, "_")
                  .toLowerCase(),
                stages: ["hunt"],
                risk_class: "read_only",
              }),
            });
            const id = r.draft?.id || r.draft?.meta?.id;
            toast(id ? `Draft ${id} created` : "Draft created");
            if (id) window.location.href = `/dev#tools/${encodeURIComponent(id)}`;
          } catch (e) {
            toast(e.message || String(e), true);
            btn.disabled = false;
          }
        });
      });
    }
  }
  if (perRun) {
    const rows = data.per_run || [];
    if (!rows.length) {
      perRun.innerHTML = `<div class="empty">No runs scanned.</div>`;
    } else {
      perRun.innerHTML = `<div class="table-wrap"><table class="data">
        <thead><tr><th>Target</th><th>Run</th><th>Gaps</th><th title="Exceptions caught and logged instead of crashing the loop (swallowed_errors.jsonl)">Swallowed errors</th><th>Mode</th><th></th></tr></thead>
        <tbody>${rows
          .map((r) => {
            if (r.error) {
              return `<tr><td colspan="6" class="empty">${esc(r.target_id || "")}/${esc(r.run_id || "")}: ${esc(r.error)}</td></tr>`;
            }
            const href =
              r.target_id && r.run_id
                ? `/runs/${encodeURIComponent(r.target_id)}/${encodeURIComponent(r.run_id)}`
                : "#";
            return `<tr>
              <td class="mono">${esc(r.target_id || "")}</td>
              <td class="mono">${esc(r.run_id || "")}</td>
              <td>${esc(String(r.gap_count ?? 0))}</td>
              <td>${swallowedCell(r.swallowed_errors)}</td>
              <td>${esc(r.mode || (r.cached ? "cached" : "-"))}</td>
              <td>${href !== "#" ? `<a class="btn" href="${href}">Open run</a>` : ""}</td>
            </tr>`;
          })
          .join("")}</tbody></table></div>`;
    }
  }
}

async function loadHomeToolGapsSummary() {
  const meta = $("#home-tool-gaps-meta");
  if (!meta || !$("#home-tool-gaps-cta, .home-tool-gaps-cta")) {
    // full page uses same card id without cta class sometimes
  }
  try {
    const data = await api("/api/tool-gaps");
    if ($("#home-tool-gaps-body")) {
      renderToolGapsPage(data);
    } else {
      renderHomeToolGapsSummary(data);
    }
  } catch (e) {
    if (meta) meta.textContent = `Tool gaps unavailable: ${e.message || e}`;
  }
}

async function loadToolGapsPage() {
  const body = $("#home-tool-gaps-body");
  const meta = $("#home-tool-gaps-meta");
  if (!body) return;
  if (meta) meta.textContent = "Loading...";
  try {
    const data = await api("/api/tool-gaps");
    renderToolGapsPage(data);
  } catch (e) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${esc(e.message || e)}</td></tr>`;
    if (meta) meta.textContent = "";
  }
}

async function analyzeToolGapsPage() {
  const body = $("#home-tool-gaps-body");
  const meta = $("#home-tool-gaps-meta");
  if (!body) return;
  if (meta) meta.textContent = "Analyzing with AI (hybrid) across runs...";
  body.innerHTML = `<tr><td colspan="6" class="empty">Working...</td></tr>`;
  try {
    const data = await api("/api/tool-gaps/analyze", {
      method: "POST",
      body: JSON.stringify({ mode: "hybrid", all_runs: true }),
    });
    renderToolGapsPage(data);
    if (data.errors?.length && meta) {
      meta.textContent += ` | ${data.errors.length} run error(s)`;
    }
    toast("Tool gaps updated");
  } catch (e) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${esc(e.message || e)}</td></tr>`;
    if (meta) meta.textContent = "Analyze failed";
  }
}

window.loadToolGapsPage = loadToolGapsPage;
window.analyzeToolGapsPage = analyzeToolGapsPage;
window.loadHomeToolGaps = loadHomeToolGapsSummary;

/* ---------- boot ---------- */

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  // Settings is a dedicated page (/settings). Only bind if still a button (legacy).
  const settingsBtn = $("#btn-settings");
  if (settingsBtn && settingsBtn.tagName === "BUTTON") {
    settingsBtn.addEventListener("click", openSettings);
  }
  // Dedicated /settings page owns form via settings.js — avoid double-submit.
  if (page !== "settings") {
    $("#settings-cancel")?.addEventListener("click", closeSettings);
    $("#settings-optimize")?.addEventListener("click", () => optimizeSettings());
    $("#settings-form")?.addEventListener("submit", saveSettings);
  }
  // Settings / New-run modals stay open until Cancel or Save/Create -
  // do not dismiss on backdrop click (unstable form entry).
  $("#live-task-close")?.addEventListener("click", closeLiveTask);
  $("#live-steer-note")?.addEventListener("click", () => sendLiveNote());
  $("#live-steer-none")?.addEventListener("click", () => forceLiveSubmitNone());
  $("#live-steer-abort")?.addEventListener("click", () => abortLiveTask());
  $("#live-task-steer")?.addEventListener("submit", (e) => {
    e.preventDefault();
    sendLiveNote();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && $("#live-task-modal")?.classList.contains("open")) {
      closeLiveTask();
    }
  });
  $("#transcript-close")?.addEventListener("click", closeTranscript);
  $("#transcript-modal")?.addEventListener("click", (e) => {
    if (e.target.id === "transcript-modal") closeTranscript();
  });
  document.querySelectorAll("#transcript-tabs .tab").forEach((t) => {
    t.addEventListener("click", () => {
      if (!_stepIoState) return;
      _stepIoState.tab = t.getAttribute("data-iotab") || "input";
      renderStepIOModal();
    });
  });

  if (page === "home") {
    loadRuns();
    setInterval(loadRuns, 5000);
    wirePathPicker();
    wireInitHelpTips();
    $("#btn-new-run")?.addEventListener("click", openInitModal);
    $("#init-cancel")?.addEventListener("click", closeInitModal);
    $("#init-form")?.addEventListener("submit", submitInit);
    $("#init-loading-dismiss")?.addEventListener("click", () => {
      closeInitLoading();
      openInitModal();
    });
    $("#init-dynamic-skills")?.addEventListener("change", syncInitDynamicSkillsField);
    document.querySelectorAll('input[name="init-strategy"]').forEach((r) => {
      r.addEventListener("change", () => {
        syncInitDocsField();
        syncInitReconFields();
      });
    });
    $("#home-search")?.addEventListener("input", (e) => {
      homeQuery = e.target.value || "";
      renderRunCards(homeRunsCache);
    });
  }
  if (page === "tool-gaps") {
    loadToolGapsPage();
    $("#btn-tool-gaps-refresh")?.addEventListener("click", () => loadToolGapsPage());
    $("#btn-tool-gaps-analyze")?.addEventListener("click", () => analyzeToolGapsPage());
  }
  if (page === "run") {
    currentKey = document.body.dataset.runKey;
    setupTabs();
    eventOffset = 0;
    loadRunFull()
      .then(async () => {
        const [target_id, run_id] = currentKey.split("/");
        const ev = await api(
          `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}/events?after=0&limit=2000`
        );
        $("#timeline") && ($("#timeline").innerHTML = "");
        appendEvents(ev.events || []);
        eventOffset = ev.next || 0;
        connectStream();
      })
      .catch((e) => toast(e.message, true));
    $("#btn-start")?.addEventListener("click", () => control("start"));
    $("#btn-pause")?.addEventListener("click", () => control("pause"));
    $("#btn-resume")?.addEventListener("click", () => control("resume"));
    $("#btn-stop")?.addEventListener("click", () => {
      if (confirm("Hard stop Ralph process for this run?")) control("stop");
    });
    $("#btn-delete-run")?.addEventListener("click", () => {
      const [target_id, run_id] = (currentKey || "").split("/");
      deleteRun(target_id, run_id, { redirectHome: true });
    });
    $("#btn-refresh")?.addEventListener("click", () =>
      loadRunFull().catch((e) => toast(e.message, true))
    );
  }
});

window.addEventListener("beforeunload", () => {
  if (liveOfflineTimer) {
    clearTimeout(liveOfflineTimer);
    liveOfflineTimer = null;
  }
  if (es) {
    es.onopen = null;
    es.onmessage = null;
    es.onerror = null;
    es.close();
    es = null;
  }
  streamAttachedKey = null;
});
