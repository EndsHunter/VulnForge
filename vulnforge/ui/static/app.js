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

function badge(state) {
  const s = (state || "idle").toLowerCase();
  return `<span class="badge ${esc(s)}">${esc(s)}</span>`;
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
    vacuous_boundary: "Threat model boundary is empty or placeholder (n/a, none, unknown).",
    title_too_short: "Finding title is too short.",
    bad_severity: "severity_claim is not an allowed value.",
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

/* ---------- Home ---------- */

function fmtTokens(n) {
  const v = Number(n) || 0;
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}k`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return String(v);
}

function llmUsageOf(r) {
  return r?.llm_usage || {};
}

function renderHomeStats(runs) {
  const box = $("#home-stats");
  if (!box) return;
  const ok = runs.filter((r) => !r.error);
  const running = ok.filter((r) => ["running", "busy", "pausing"].includes(statusChip(r))).length;
  const incomplete = ok.filter((r) => r.incomplete).length;
  const confirmed = ok.reduce((a, r) => a + ((r.findings || {}).confirmed || 0), 0);
  const tokens = ok.reduce((a, r) => a + (llmUsageOf(r).total_tokens || 0), 0);
  const calls = ok.reduce((a, r) => a + (llmUsageOf(r).llm_calls || 0), 0);
  box.style.display = "grid";
  box.innerHTML = `
    <div class="stat info"><div class="label">Runs</div><div class="value">${ok.length}</div></div>
    <div class="stat good"><div class="label">Running</div><div class="value">${running}</div></div>
    <div class="stat warn"><div class="label">Incomplete</div><div class="value">${incomplete}</div></div>
    <div class="stat good"><div class="label">Confirmed</div><div class="value">${confirmed}</div></div>
    <div class="stat info" title="${calls} LLM calls"><div class="label">LLM tokens</div><div class="value">${fmtTokens(tokens)}</div></div>
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
  const filtered = runs.filter(
    (r) => !r.error && matchesFilter(r, homeFilter) && matchesQuery(r, homeQuery)
  );
  const errors = runs.filter((r) => r.error);
  if (!runs.length) {
    box.innerHTML = `<div class="empty"><div class="empty-ico">*</div>No runs yet. Start a new audit to begin recon -> hunt -> validate.</div>`;
    return;
  }
  if (!filtered.length && !errors.length) {
    box.innerHTML = `<div class="empty"><div class="empty-ico">x</div>No runs match this filter.</div>`;
    return;
  }
  const cards = filtered
    .map((r) => {
      const runner = r.runner || {};
      const incomplete = !!r.incomplete;
      const st = runner.state || (r.active ? "busy" : "idle");
      const when = relativeTime(r.updated_at || r.created_at || r.mtime);
      const tpath = r.target_path || "";
      const runLabel = `${r.target_id || ""} / ${r.run_id || ""}`;
      return `
      <a class="run-row" href="/runs/${encodeURIComponent(r.target_id)}/${encodeURIComponent(r.run_id)}" title="${esc(runLabel)} — ${esc(tpath)}">
        <div class="row-top">
          <div>
            <div class="title" title="${esc(runLabel)}">${esc(r.target_id)} <span class="mono" style="color:var(--muted);font-weight:500">/${esc(r.run_id)}</span></div>
            <div class="meta path-meta" title="${esc(tpath)}">${esc(tpath)}</div>
          </div>
          <div class="chips">
            ${badge(st)}
            ${incomplete ? badge("incomplete") : ""}
          </div>
        </div>
        ${progressBar(r.progress)}
        <div class="meta">${r.done_tasks || 0}/${r.total_tasks || 0} tasks | findings ${esc(fmtCounts(r.findings))}${
          llmUsageOf(r).total_tokens
            ? ` | ${fmtTokens(llmUsageOf(r).total_tokens)} tok`
            : ""
        }</div>
        <div class="sev-row">${sevPills(r.severity)}
          <span style="margin-left:auto">${esc(when)} | ${esc(r.profile || " - ")}</span>
        </div>
      </a>`;
    })
    .join("");
  const errHtml = errors
    .map(
      (r) =>
        `<div class="run-row" style="cursor:default;opacity:0.85"><div class="title">${esc(r.key || "error")}</div><div class="meta" style="color:var(--bad)">${esc(r.error)}</div></div>`
    )
    .join("");
  box.innerHTML = cards + errHtml;
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
  syncInitDocsField();
  syncInitReconFields();
  loadInitReconAgents();
  loadInitHuntSkills();
  wireHuntSkillModeRadios("init-hunt-skill-mode", "init-hunt-skill-picker");
  syncHuntSkillPickerVisibility("init-hunt-skill-mode", "init-hunt-skill-picker");
}
function closeInitModal() {
  $("#init-modal")?.classList.remove("open");
  hideInitFloatingTip();
}

/* Floating help tips for #init-modal (avoids overflow:auto clipping) */
let _initTipAnchor = null;

function ensureInitFloatingTip() {
  let el = $("#init-floating-tip");
  if (!el) {
    el = document.createElement("div");
    el.id = "init-floating-tip";
    el.className = "init-floating-tip";
    el.setAttribute("role", "tooltip");
    el.hidden = true;
    document.body.appendChild(el);
  }
  return el;
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
  const tip = ensureInitFloatingTip();
  tip.textContent = text;
  tip.hidden = false;
  _initTipAnchor = anchor;
  const tipId = "init-floating-tip";
  anchor.setAttribute("aria-describedby", tipId);
  positionInitFloatingTip(anchor);
}

function hideInitFloatingTip(anchor) {
  if (anchor && _initTipAnchor && anchor !== _initTipAnchor) return;
  const tip = $("#init-floating-tip");
  if (tip) tip.hidden = true;
  if (_initTipAnchor) {
    _initTipAnchor.removeAttribute("aria-describedby");
    _initTipAnchor = null;
  }
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

/* ---------- Host path picker (New audit) ---------- */

let pathPicker = {
  mode: "dirs", // dirs | any
  targetId: null, // input element id to fill
  path: "",
  allowFiles: false,
};

function openPathPicker({ mode, targetId, startPath, title, hint }) {
  pathPicker.mode = mode === "any" ? "any" : "dirs";
  pathPicker.allowFiles = pathPicker.mode === "any";
  pathPicker.targetId = targetId;
  pathPicker.path = (startPath || "").trim();
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
  const selBtn = $("#path-picker-select");
  if (selBtn) {
    selBtn.textContent = pathPicker.allowFiles ? "Select this path" : "Select this folder";
  }
  modal.classList.add("open");
  loadPathPicker(pathPicker.path);
}

function closePathPicker() {
  $("#path-picker-modal")?.classList.remove("open");
  pathPicker.targetId = null;
}

async function loadPathPicker(path) {
  const list = $("#path-picker-list");
  const status = $("#path-picker-status");
  const pathInput = $("#path-picker-path");
  if (!list) return;
  list.innerHTML = `<div class="empty" style="padding:0.75rem">Loading...</div>`;
  if (status) status.textContent = "";
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
          if (pathInput) pathInput.value = p;
          if (isDir) {
            pathPicker.path = p;
          } else if (pathPicker.allowFiles) {
            pathPicker.path = p;
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
      if (status) status.textContent = `File: ${data.selected_file}`;
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
  const input = document.getElementById(pathPicker.targetId);
  if (input) {
    input.value = chosen;
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }
  closePathPicker();
}

function wirePathPicker() {
  $("#btn-browse-target")?.addEventListener("click", () => {
    openPathPicker({
      mode: "dirs",
      targetId: "init-target",
      startPath: ($("#init-target")?.value || "").trim(),
      title: "Select target directory",
      hint: "Choose the code tree VulnForge should audit (read-only).",
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
  if (p.includes("ralph") || p.includes("start")) return "ralph";
  if (p.includes("db") || p.includes("database") || p.includes("harness") || p.includes("create"))
    return "database";
  if (p.includes("invent") || p.includes("scan") || p.includes("hash") || p.includes("index"))
    return "inventory";
  if (p.includes("queue") || p.includes("start") || p === "working") return "queued";
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
  if (title) title.textContent = start ? "Starting audit run" : "Creating audit run";
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
  if (phase) setInitPhase(_mapInitPhase(phase, success ? "done" : error ? "error" : "running"));

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
  const deadline = Date.now() + 30 * 60 * 1000; // 30 min max for huge trees
  while (Date.now() < deadline) {
    const job = await api(`/api/runs/init-jobs/${encodeURIComponent(jobId)}`);
    const pct = job.percent != null ? Number(job.percent) : null;
    const files = job.files_seen != null ? job.files_seen : null;
    const phase = job.phase || "";
    const msg =
      job.message ||
      (phase
        ? `${phase}${files != null ? ` · ${files} files` : ""}`
        : "Working…");
    // Map inventing phases; when start=true and job is finishing, show ralph step
    let phaseKey = phase;
    if (job.status === "done") phaseKey = "done";
    else if (pct != null && pct >= 90 && start) phaseKey = "ralph";
    else if (pct != null && pct >= 70) phaseKey = "database";
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
  const docs_path = ($("#init-docs-path")?.value || "").trim();
  if (!target) {
    toast("Target directory is required", true);
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
]);

function liveTaskCounts(cardOrSnap) {
  /** Normalize task counters from full snap (tasks[]) or run_card (tasks{}). */
  const counts = {
    leased: 0,
    queued: 0,
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
      : done + t.leased + t.queued;
  // Do not include runner.state here — it can flip independently of task rows
  // and would thrash full reloads without changing the tasks table.
  return [
    done,
    total,
    t.leased,
    t.queued,
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
  const bits = [];
  bits.push(badge(st));
  if (incomplete) bits.push(badge("incomplete"));
  const meta = [];
  if (workersAlive > 1 || workersCfg > 1) {
    meta.push(`agents ${workersAlive || 0}/${workersCfg}`);
  } else if (pid != null && pid !== "" && pid !== "-") {
    meta.push(`pid ${pid}`);
  }
  if (runner?.stop) meta.push("STOP set");
  if (incomplete) meta.push("residual work");
  if (meta.length) {
    bits.push(`<span class="controls-hint runner-meta">${esc(meta.join(" | "))}</span>`);
  }
  el.innerHTML = bits.join(" ");

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

function goStatLink(nav) {
  const modes = window.VulnForgeModes;
  const report = window.VulnForgeReport;
  switch (nav) {
    case "progress":
      modes?.setMode?.("mission", "overview");
      break;
    case "tasks":
      modes?.setMode?.("audit", "tasks");
      break;
    case "confirmed":
      modes?.setMode?.("report", "report");
      report?.setFilter?.("confirmed");
      break;
    case "candidates":
    case "needs_human":
      modes?.setMode?.("report", "report");
      report?.setFilter?.("needs_human");
      break;
    case "rejected":
      modes?.setMode?.("report", "report");
      report?.setFilter?.("rejected");
      break;
    case "high":
      modes?.setMode?.("report", "report");
      report?.setFilter?.("all");
      break;
    case "events":
      modes?.setMode?.("audit", "timeline");
      break;
    default:
      break;
  }
}

function renderStats(snap) {
  const s = $("#stats");
  if (!s) return;
  // findings may be a list (full snap) or counts object (SSE card)
  let f = snap.findings || {};
  if (Array.isArray(f)) {
    f = f.reduce((acc, x) => {
      const st = (x.state || "unknown").toLowerCase();
      acc[st] = (acc[st] || 0) + 1;
      return acc;
    }, {});
  }
  const sev = snap.severity || {};
  const rejected =
    (f.rejected_mech || 0) +
    (f.rejected_llm || 0) +
    (f.rejected_human || 0) +
    (f.superseded || 0);
  const needsHuman = (f.needs_human || 0) + (f.candidate || 0);
  s.innerHTML = `
    <button type="button" class="stat info stat-link" data-stat="progress" title="Open Mission overview">
      <div class="label">Progress</div>
      <div class="value">${Math.round((snap.progress || 0) * 100)}%</div>
    </button>
    <button type="button" class="stat stat-link" data-stat="tasks" title="Open Tasks">
      <div class="label">Tasks done</div>
      <div class="value">${snap.done_tasks || 0}<span style="font-size:0.7em;color:var(--muted)">/${snap.total_tasks || 0}</span></div>
    </button>
    <button type="button" class="stat warn stat-link" data-stat="needs_human" title="Open Report: needs human review">
      <div class="label">Needs human</div>
      <div class="value">${needsHuman}</div>
    </button>
    <button type="button" class="stat good stat-link" data-stat="confirmed" title="Open Report: confirmed">
      <div class="label">Confirmed</div>
      <div class="value">${f.confirmed || 0}</div>
    </button>
    <button type="button" class="stat bad stat-link" data-stat="rejected" title="Open Report: rejected">
      <div class="label">Rejected</div>
      <div class="value">${rejected}</div>
    </button>
    <button type="button" class="stat stat-link" data-stat="high" title="Open Report">
      <div class="label">High+</div>
      <div class="value">${(sev.critical || 0) + (sev.high || 0)}</div>
    </button>
    <button type="button" class="stat stat-link" data-stat="events" title="Open event timeline">
      <div class="label">Events</div>
      <div class="value">${snap.event_count || 0}</div>
    </button>
    <button type="button" class="stat info stat-link" data-stat="progress" title="LLM token usage (see overview)">
      <div class="label">LLM tokens</div>
      <div class="value">${fmtTokens(llmUsageOf(snap).total_tokens || 0)}</div>
    </button>
  `;
  s.querySelectorAll("[data-stat]").forEach((btn) => {
    btn.addEventListener("click", () => goStatLink(btn.getAttribute("data-stat")));
  });
  const p = $("#main-progress");
  if (p) p.innerHTML = progressBar(snap.progress);
}

function renderLlmUsageCard(snap) {
  const u = llmUsageOf(snap);
  const total = u.total_tokens || 0;
  const calls = u.llm_calls || 0;
  const byKind = u.by_kind || {};
  const byModel = u.by_model || {};
  const kindRows = Object.entries(byKind)
    .sort((a, b) => (b[1].total_tokens || 0) - (a[1].total_tokens || 0))
    .map(
      ([k, v]) =>
        `<div class="k">${esc(k)}</div><div class="v mono">${fmtTokens(v.total_tokens || 0)} <span style="color:var(--muted)">(${v.llm_calls || 0} calls)</span></div>`
    )
    .join("");
  const modelRows = Object.entries(byModel)
    .sort((a, b) => (b[1].total_tokens || 0) - (a[1].total_tokens || 0))
    .slice(0, 6)
    .map(
      ([k, v]) =>
        `<div class="k mono">${esc(k)}</div><div class="v mono">${fmtTokens(v.total_tokens || 0)}</div>`
    )
    .join("");
  const source = u.source && u.source !== "none" ? u.source : "—";
  return `
    <div class="card" style="margin-top:1rem">
      <h2>LLM usage</h2>
      <div class="kv">
        <div class="k">Total tokens</div><div class="v mono">${fmtTokens(total)} <span style="color:var(--muted)">(${calls} calls)</span></div>
        <div class="k">Prompt / completion</div><div class="v mono">${fmtTokens(u.prompt_tokens || 0)} / ${fmtTokens(u.completion_tokens || 0)}</div>
        <div class="k">Source</div><div class="v">${esc(source)}${u.reasoning_tokens ? ` · reasoning ${fmtTokens(u.reasoning_tokens)}` : ""}</div>
      </div>
      ${
        kindRows
          ? `<div class="kv" style="margin-top:0.75rem"><div class="k" style="grid-column:1/-1;color:var(--muted);font-size:0.85em">By stage</div>${kindRows}</div>`
          : `<p class="controls-hint" style="margin:0.5rem 0 0">No LLM calls recorded yet for this run.</p>`
      }
      ${modelRows ? `<div class="kv" style="margin-top:0.75rem"><div class="k" style="grid-column:1/-1;color:var(--muted);font-size:0.85em">By model</div>${modelRows}</div>` : ""}
    </div>`;
}

function findingStateCounts(snap) {
  const list = Array.isArray(snap.findings) ? snap.findings : [];
  if (list.length) {
    return list.reduce((acc, x) => {
      const st = String(x.state || "unknown").toLowerCase();
      acc[st] = (acc[st] || 0) + 1;
      return acc;
    }, {});
  }
  const f = snap.findings || {};
  return typeof f === "object" && !Array.isArray(f) ? f : {};
}

function renderOverview(snap) {
  const el = $("#overview-panel");
  if (!el) return;
  const t = snap.tasks_summary || snap.tasks || {};
  // tasks may be array on full snap  -  use card task counts
  const taskCounts = Array.isArray(snap.tasks)
    ? snap.tasks.reduce((acc, x) => {
        acc[x.state] = (acc[x.state] || 0) + 1;
        return acc;
      }, {})
    : t;
  const fCounts = findingStateCounts(snap);
  const needsHuman =
    (fCounts.needs_human || 0) + (fCounts.candidate || 0);
  const confirmed = fCounts.confirmed || 0;
  const rejected =
    (fCounts.rejected_mech || 0) +
    (fCounts.rejected_llm || 0) +
    (fCounts.rejected_human || 0) +
    (fCounts.superseded || 0);
  const evidenceN = Array.isArray(snap.evidence) ? snap.evidence.length : 0;
  const archSum = snap.architecture_summary || {};
  const archText = (archSum.summary || snap.architecture?.summary || "").trim();
  const runner = snap.runner || {};
  const runnerState = runner.state || "idle";
  // Trust line in the page header is the single mech disclaimer.
  // Only surface validate_llm footgun here when that flag is on.
  const vllmFootgun = snap.validate_llm_on
    ? `<div class="disclaimer-banner"><span>!</span><div><strong>validate_llm is ON</strong> - mech-pass is <code>needs_human</code>; disprove may <code>rejected_llm</code> only (never auto-confirm). Same-model signal is weak.</div></div>`
    : "";
  el.innerHTML = `
    ${vllmFootgun}
    <div class="overview-grid overview-grid-3">
      <div class="card">
        <h2>Campaign</h2>
        <div class="kv">
          <div class="k">Target</div><div class="v mono">${esc(snap.target_path || " - ")}</div>
          <div class="k">Profile</div><div class="v">${esc(snap.profile || " - ")}</div>
          ${(() => {
            const strategy = snap.strategy || snap.config?.strategy || "";
            if (!strategy) return "";
            const label = STRATEGY_LABELS[strategy] || strategy;
            const docs = snap.docs_path || snap.config?.docs_path || "";
            const docsRow = docs
              ? `<div class="k">Docs path</div><div class="v mono">${esc(docs)}</div>`
              : "";
            return `<div class="k">Strategy</div><div class="v">${esc(label)} <span class="mono" style="color:var(--muted);font-size:0.85em">(${esc(strategy)})</span></div>${docsRow}`;
          })()}
          <div class="k">Runner</div><div class="v">${badge(runnerState)}${runner.pid ? ` <span class="mono controls-hint">pid ${esc(String(runner.pid))}</span>` : ""}</div>
          <div class="k">Created</div><div class="v">${esc(snap.created_at || " - ")} | ${esc(relativeTime(snap.created_at || snap.mtime))}</div>
          <div class="k">Pin</div><div class="v mono">${esc(snap.prompt_pin || " - ")}</div>
          <div class="k">Queue</div><div class="v">${snap.has_work ? "work remaining (queued/leased)" : "idle"} ${snap.incomplete ? badge("incomplete") : ""}</div>
        </div>
      </div>
      <div class="card">
        <h2>Findings queue</h2>
        <div class="overview-findings-stats">
          <button type="button" class="stat warn stat-link overview-stat" data-stat="needs_human">
            <div class="label">Needs human</div><div class="value">${needsHuman}</div>
          </button>
          <button type="button" class="stat good stat-link overview-stat" data-stat="confirmed">
            <div class="label">Confirmed</div><div class="value">${confirmed}</div>
          </button>
          <button type="button" class="stat bad stat-link overview-stat" data-stat="rejected">
            <div class="label">Rejected</div><div class="value">${rejected}</div>
          </button>
        </div>
        <div class="task-mix-sev" style="margin-top:0.75rem">
          <div class="sev-heading">Severity (open + confirmed)</div>
          ${sevPills(snap.severity)}
        </div>
        <div class="overview-quick-links" style="margin-top:0.75rem">
          <button type="button" class="btn btn-primary btn-sm" id="overview-go-report">Open Report</button>
          <button type="button" class="btn btn-sm" id="overview-go-evidence">Evidence (${evidenceN})</button>
        </div>
      </div>
      <div class="card">
        <h2>Task progress</h2>
        <div class="meta" style="color:var(--muted);margin-bottom:0.5rem">${esc(fmtCounts(taskCounts))}</div>
        ${progressBar(snap.progress)}
        <p class="controls-hint" style="margin:0.65rem 0 0">
          Ralph drains the queue (recon → hunts → validate). Start/Resume in the mission bar keeps the loop going.
        </p>
      </div>
    </div>
    ${renderTargetInventoryCard(snap.target_inventory || snap.inventory_honesty, snap)}
    ${renderArchitectureBriefCard(archText, archSum, snap)}
    ${renderLlmUsageCard(snap)}
    ${renderOperatorRerunCard(snap)}
    <div class="card" style="margin-top:1rem">
      <div class="toolbar" style="margin-bottom:0.5rem">
        <h2 style="margin:0;flex:1">Coverage (area × class)</h2>
        <button type="button" class="btn" id="overview-go-coverage">Open Coverage</button>
      </div>
      <p class="controls-hint" style="margin-top:0">Preview only. Open Coverage to re-queue residual cells.</p>
      <div id="coverage-inline">${renderCoverageHtml(snap.coverage, { interactive: false })}</div>
    </div>
  `;
  bindOperatorRerunHandlers();
  $("#overview-go-coverage")?.addEventListener("click", () => {
    window.VulnForgeModes?.goCoverage?.() || window.VulnForgeModes?.setMode?.("coverage");
  });
  $("#overview-go-report")?.addEventListener("click", () => {
    window.VulnForgeModes?.goReport?.("all") || window.VulnForgeModes?.setMode?.("report");
  });
  $("#overview-go-evidence")?.addEventListener("click", () => {
    window.VulnForgeModes?.goEvidence?.() || window.VulnForgeModes?.setMode?.("evidence");
  });
  $("#overview-go-arch")?.addEventListener("click", () => {
    window.VulnForgeModes?.setMode?.("mission", "arch");
  });
  el.querySelectorAll(".overview-stat").forEach((btn) => {
    btn.addEventListener("click", () => goStatLink(btn.getAttribute("data-stat")));
  });
}

function reconFailureHint(snap) {
  const lr = snap?.target_inventory?.last_recon || snap?.inventory_honesty?.last_recon;
  if (!lr || lr.state === "succeeded") return "";
  const err = lr.error || lr.state || "failed";
  const gen = lr.recon_generation != null ? ` (generation ${esc(String(lr.recon_generation))})` : "";
  const retry = lr.recon_requeued
    ? ` A follow-up recon was queued${lr.child_task_id != null ? ` as task ${esc(String(lr.child_task_id))}` : ""}.`
    : " Auto-retries may be exhausted — check Tasks / transcript for submit_architecture.";
  let tip = "";
  if (err === "no_submit" || err === "max_tool_rounds") {
    tip =
      " The model never called submit_architecture (or exhausted tool rounds). Architecture is only stored after a non-empty summary.";
  } else if (err === "no_architecture") {
    tip = " Recon finished without a usable architecture summary.";
  } else if (err === "no_hunt_tasks") {
    tip =
      " Architecture may exist, but hunt planning produced zero tasks (check run.max_tasks and active hunt skills).";
  }
  return `<p class="controls-hint" style="margin:0.5rem 0 0;color:var(--danger, #c44)"><strong>Last recon:</strong> <span class="mono">${esc(String(err))}</span>${gen}.${tip}${retry}</p>`;
}

function renderArchitectureBriefCard(archText, archSum, snap) {
  if (!archText && !(archSum && archSum.has_architecture)) {
    return `
    <div class="card" style="margin-top:1rem">
      <h2>Architecture</h2>
      <p class="controls-hint" style="margin:0">No architecture yet — run recon (or use Operator re-run below). Map lives under Mission → Architecture after recon succeeds. Architecture is stored in the run DB only (not under project/).</p>
      ${reconFailureHint(snap)}
    </div>`;
  }
  const comps = Array.isArray(archSum?.components) ? archSum.components.length : 0;
  const focus = Array.isArray(archSum?.hunt_focus) ? archSum.hunt_focus.length : 0;
  const agentsRun = Array.isArray(archSum?.recon_agents_run) ? archSum.recon_agents_run : [];
  const agentsLabel = agentsRun.length
    ? agentsRun
        .map((a) => {
          const id = a?.id || "?";
          const ok = a?.ok === false ? "✗" : a?.ok === true ? "✓" : "";
          return ok ? `${id}${ok}` : id;
        })
        .join(", ")
    : "";
  const snippet = archText
    ? esc(archText.length > 420 ? archText.slice(0, 420) + "…" : archText)
    : "<span class='controls-hint'>Architecture present (see Architecture tab).</span>";
  return `
    <div class="card" style="margin-top:1rem">
      <div class="toolbar" style="margin-bottom:0.35rem">
        <h2 style="margin:0;flex:1">Architecture</h2>
        <button type="button" class="btn btn-sm" id="overview-go-arch">Architecture tab</button>
      </div>
      <p class="overview-arch-snippet">${snippet}</p>
      <div class="controls-hint">${comps ? `${comps} component(s)` : "components n/a"} · ${focus ? `${focus} hunt_focus item(s)` : "no hunt_focus yet"}${agentsLabel ? ` · agents: <span class="mono">${esc(agentsLabel)}</span>` : ""}</div>
    </div>`;
}

function renderOperatorRerunCard(snap) {
  const hasArch = !!(snap.architecture || snap.architecture_summary?.has_architecture);
  const rawMode =
    (snap.config && snap.config.run && snap.config.run.hunt_skill_mode) ||
    (snap.run_config && snap.run_config.hunt_skill_mode) ||
    "all_active";
  const runMode = ["all_active", "seed_active", "custom_only", "explicit"].includes(
    String(rawMode)
  )
    ? String(rawMode)
    : "all_active";
  return `
    <div class="card operator-rerun-card" style="margin-top:1rem">
      <h2>Operator re-run</h2>
      <p class="controls-hint" style="margin-top:-0.25rem">
        Re-run <strong>recon</strong> with extra guidance to strengthen the foundation, or re-queue hunts from Coverage with notes.
        Ralph must be <strong>Start</strong>/<strong>Resume</strong> to execute queued tasks.
      </p>
      <div class="field">
        <label>Recon agents</label>
        <p class="controls-hint" style="margin:0.15rem 0 0.4rem">
          Select one or more profiles — each gets its own Ralph loop; architecture accumulates into one map. Leave all unchecked for the active collection set.
        </p>
        <div id="op-recon-agents" class="recon-agent-picker" role="group" aria-label="Recon agents">
          <div class="controls-hint">Loading agents…</div>
        </div>
      </div>
      <div class="field">
        <label for="op-recon-notes">Recon brief (what to map, fix, or deepen)</label>
        <textarea id="op-recon-notes" class="op-notes" rows="4" placeholder="e.g. Focus on auth middleware and SQL entrypoints under vh/ and packages/api; prior hunt_focus missed deep paths."></textarea>
      </div>
      <div class="field">
        <label for="op-recon-paths">Focus paths (optional, comma-separated)</label>
        <input id="op-recon-paths" type="text" placeholder="vh/stages/hunt.py, vh/db.py" />
      </div>
      <div class="field" id="op-hunt-skill-mode-field">
        <label>Hunt skills for re-run</label>
        <p class="controls-hint" style="margin:0.15rem 0 0.4rem">
          Run-scoped policy for hunts enqueued after this recon (does not change Dev active toggles).
        </p>
        <div class="strategy-list hunt-skill-mode-list" role="radiogroup" aria-label="Hunt skill mode for re-run">
          <label class="strategy-option">
            <input type="radio" name="op-hunt-skill-mode" value="all_active" ${runMode === "all_active" ? "checked" : ""} />
            <span class="strategy-option-main">
              <span class="strategy-option-title">Default active</span>
              <span class="strategy-option-desc">Active hunt skills from Dev.</span>
            </span>
          </label>
          <label class="strategy-option">
            <input type="radio" name="op-hunt-skill-mode" value="seed_active" ${runMode === "seed_active" ? "checked" : ""} />
            <span class="strategy-option-main">
              <span class="strategy-option-title">Seed only</span>
              <span class="strategy-option-desc">Active seed skills only.</span>
            </span>
          </label>
          <label class="strategy-option">
            <input type="radio" name="op-hunt-skill-mode" value="custom_only" ${runMode === "custom_only" ? "checked" : ""} />
            <span class="strategy-option-main">
              <span class="strategy-option-title">Custom only</span>
              <span class="strategy-option-desc">Active custom/generated/import — no seeds.</span>
            </span>
          </label>
          <label class="strategy-option">
            <input type="radio" name="op-hunt-skill-mode" value="explicit" ${runMode === "explicit" ? "checked" : ""} />
            <span class="strategy-option-main">
              <span class="strategy-option-title">Pick skills</span>
              <span class="strategy-option-desc">Choose exact skill ids.</span>
            </span>
          </label>
        </div>
        <div id="op-hunt-skill-picker" class="hunt-skill-picker" hidden>
          <p class="controls-hint" style="margin:0.4rem 0">Select one or more hunt skills:</p>
          <div id="op-hunt-skills" class="recon-agent-picker" role="group" aria-label="Hunt skills for re-run">
            <div class="controls-hint">Loading skills…</div>
          </div>
        </div>
      </div>
      <div class="op-rerun-options">
        <label class="controls-hint"><input type="checkbox" id="op-recon-prior" checked /> Include prior architecture (refine)</label>
        <label class="controls-hint"><input type="checkbox" id="op-recon-hunts" checked /> Enqueue new hunts after recon</label>
      </div>
      <div class="toolbar" style="margin-top:0.65rem;gap:0.5rem">
        <button type="button" class="btn btn-primary" id="op-recon-rerun">${hasArch ? "Re-run recon + refine" : "Run recon with brief"}</button>
        <button type="button" class="btn" id="op-recon-arch-only">Update architecture only</button>
      </div>
      <p class="controls-hint" style="margin:0.5rem 0 0">
        <strong>Architecture only</strong> refreshes the map without flooding the hunt queue.
        After re-run, use Coverage to re-queue shallow/aborted cells with more notes.
      </p>
    </div>`;
}

function bindOperatorRerunHandlers() {
  const agentsBox = $("#op-recon-agents");
  if (agentsBox) {
    fetchReconAgents()
      .then((agents) => {
        // Preserve any user selection if the card remounted mid-edit is rare;
        // re-check active agents as a sensible default for re-runs.
        renderReconAgentPicker(agentsBox, {
          namePrefix: "op-recon-agent",
          agents,
          precheckActive: true,
        });
      })
      .catch((e) => {
        agentsBox.innerHTML = `<div class="controls-hint" style="color:var(--bad)">Failed to load recon agents: ${esc(e.message)}</div>`;
      });
  }
  const skillsBox = $("#op-hunt-skills");
  if (skillsBox) {
    fetchHuntProfiles()
      .then((profiles) => {
        renderHuntSkillPicker(skillsBox, {
          namePrefix: "op-hunt-skill",
          profiles,
          precheckActive: false,
        });
      })
      .catch((e) => {
        skillsBox.innerHTML = `<div class="controls-hint" style="color:var(--bad)">Failed to load hunt skills: ${esc(e.message)}</div>`;
      });
  }
  wireHuntSkillModeRadios("op-hunt-skill-mode", "op-hunt-skill-picker");
  syncHuntSkillPickerVisibility("op-hunt-skill-mode", "op-hunt-skill-picker");

  const submit = async (enqueueHunts) => {
    const notes = ($("#op-recon-notes")?.value || "").trim();
    const pathsRaw = ($("#op-recon-paths")?.value || "").trim();
    const focus_paths = pathsRaw
      ? pathsRaw.split(",").map((s) => s.trim()).filter(Boolean)
      : null;
    const include_prior = !!$("#op-recon-prior")?.checked;
    const agent_ids = selectedReconAgentIds($("#op-recon-agents"));
    const skillPolicy = collectHuntSkillPolicy("op-hunt-skill-mode", $("#op-hunt-skills"));
    if (
      skillPolicy.hunt_skill_mode === "explicit" &&
      !(skillPolicy.hunt_skill_ids || []).length
    ) {
      toast("Pick at least one hunt skill, or choose another skill mode", true);
      return;
    }
    const body = {
      operator_notes: notes,
      focus_paths,
      include_prior_architecture: include_prior,
      enqueue_hunts: enqueueHunts,
      reason: enqueueHunts ? "operator_recon_rerun" : "operator_recon_arch_only",
      hunt_skill_mode: skillPolicy.hunt_skill_mode,
    };
    if (skillPolicy.hunt_skill_mode === "explicit") {
      body.hunt_skill_ids = skillPolicy.hunt_skill_ids || [];
    }
    if (agent_ids.length) body.agent_ids = agent_ids;
    try {
      const r = await api(`${runApiBase()}/recon/rerun`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      const ids = Array.isArray(r.task_ids) && r.task_ids.length
        ? r.task_ids
        : r.task_id != null
          ? [r.task_id]
          : [];
      const idLabel = ids.length ? ids.map((n) => `#${n}`).join(", ") : "recon";
      const agentN = Array.isArray(r.agent_ids) ? r.agent_ids.length : ids.length;
      const multi = agentN > 1 ? ` (${agentN} agent loops)` : "";
      toast(
        enqueueHunts
          ? `Queued recon ${idLabel}${multi} (hunts after batch)`
          : `Queued recon ${idLabel}${multi} (architecture only)`
      );
      await loadRunFull();
    } catch (e) {
      toast(e.message, true);
    }
  };
  $("#op-recon-rerun")?.addEventListener("click", () => submit(true));
  $("#op-recon-arch-only")?.addEventListener("click", () => submit(false));
}

function renderTargetInventoryCard(inv, snap) {
  const i = inv || {};
  const fc = i.file_count;
  const cap = i.planning_seed_cap ?? i.sample_paths_cap ?? 500;
  const partial = !!(i.planning_seed_partial ?? i.sample_truncated);
  const filesLabel = fc == null ? "—" : String(fc);
  const seedLabel = partial
    ? `stratified seed of ${cap} paths (tree has ${esc(filesLabel)} files)`
    : fc == null
      ? `up to ${cap} paths (packet seed)`
      : `full tree in seed (${esc(filesLabel)} files)`;
  const hps = i.hunt_plan_source;
  let planLabel = i.recon_done ? "unknown" : "waiting for recon";
  let planHint = "";
  if (hps === "hunt_focus") {
    planLabel = "LLM hunt_focus";
    planHint = "Recon submitted hunt areas; preferred path.";
  } else if (hps === "active_fallback" || hps === "defaults_fallback") {
    planLabel = "active fallback";
    planHint =
      "Recon did not yield usable hunt_focus — mechanical areas × active hunt skills.";
  } else if (hps) {
    planLabel = String(hps);
  }
  const enq =
    i.hunt_enqueued != null
      ? `<div class="k">Hunts from recon</div><div class="v">${esc(String(i.hunt_enqueued))}</div>`
      : "";
  const lr = i.last_recon;
  const lastReconRow =
    lr && lr.state && lr.state !== "succeeded"
      ? `<div class="k">Last recon</div><div class="v mono" style="color:var(--danger, #c44)">${esc(
          String(lr.error || lr.state)
        )}${
          lr.recon_generation != null
            ? ` · gen ${esc(String(lr.recon_generation))}`
            : ""
        }${lr.recon_requeued ? " · retry queued" : ""}</div>`
      : "";
  const eps = Array.isArray(i.entrypoints) ? i.entrypoints : [];
  const epsRow = eps.length
    ? `<div class="k">Entrypoints</div><div class="v mono">${esc(eps.slice(0, 6).join(", "))}${eps.length > 6 ? "…" : ""}</div>`
    : "";
  return `
    <div class="card" style="margin-top:1rem">
      <h2>Target inventory</h2>
      <p class="controls-hint" style="margin-top:-0.2rem">
        Full tree is counted and huntable. The planning seed is only a size budget for the
        recon packet / default path hints — <strong>not</strong> a cap on Ralph or how far hunts can go.
      </p>
      <div class="kv">
        <div class="k">Files on disk</div><div class="v mono">${esc(filesLabel)}</div>
        <div class="k">Planning seed</div><div class="v">${seedLabel}</div>
        <div class="k">Hunt plan</div><div class="v mono" title="${esc(planHint)}">${esc(planLabel)}</div>
        ${enq}
        ${lastReconRow}
        ${epsRow}
      </div>
      ${
        partial
          ? `<p class="controls-hint" style="margin:0.65rem 0 0">
              Seed is stratified across top-level folders (not “first N alphabetical”).
              Hunters still <code>list_dir</code> / <code>grep</code> / <code>read_file</code> the whole tree.
              Use Operator re-run or Explorer enqueues to deepen coverage — Ralph keeps looping while work remains.
            </p>`
          : ""
      }
    </div>`;
}

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
  if (!cov || !(cov.cells || []).length) {
    return `<div class="empty" style="padding:1rem">No coverage facts yet — appear after recon enqueues hunts.</div>`;
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
    "Lease = times this task row was leased (infra budget). " +
    "Gen / parent = Ralph follow-up after terminal failure or operator re-run. " +
    "Agent id + n/m = multi-profile recon batch (each profile is its own task).";
  return { label: parts.join(" · "), title };
}

/** @type {"active"|"all"|"done"} */
let tasksFilter = "active";
let tasksCache = [];

function priorityTierLabel(priority) {
  const p = Number(priority);
  if (Number.isNaN(p)) return { tier: "normal", label: "normal" };
  if (p <= 15) return { tier: "run_next", label: "next" };
  if (p <= 40) return { tier: "high", label: "high" };
  if (p <= 60) return { tier: "normal", label: "normal" };
  return { tier: "low", label: "low" };
}

/** Running (leased) | queue | terminal states — used for grouping + sort. */
function taskListGroup(t) {
  const st = (t.state || "").toLowerCase();
  if (st === "leased") return "running";
  if (st === "queued") return "queued";
  return "done";
}

function taskMatchesFilter(t, ftr) {
  const st = (t.state || "").toLowerCase();
  if (ftr === "all") return true;
  // Merged running + queue (legacy chip ids map here too)
  if (ftr === "active" || ftr === "queued" || ftr === "leased") {
    return st === "queued" || st === "leased";
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
  const groupRank = { running: 0, queued: 1, done: 2 };
  if (ftr === "active" || ftr === "queued" || ftr === "leased" || ftr === "all") {
    // Running group first, then queued by priority, then (for All) done by id desc
    list.sort((a, b) => {
      const ga = groupRank[taskListGroup(a)] ?? 9;
      const gb = groupRank[taskListGroup(b)] ?? 9;
      if (ga !== gb) return ga - gb;
      if (taskListGroup(a) === "queued") {
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

function renderTasks(tasks) {
  const tb = $("#tasks-body");
  if (!tb) return;
  setupTasksFilter();
  if (Array.isArray(tasks)) tasksCache = tasks;
  const all = Array.isArray(tasks) ? tasks : tasksCache;
  if (!all?.length) {
    tb.innerHTML = `<tr><td colspan="10" class="empty">No tasks</td></tr>`;
    return;
  }

  const filtered = sortTasksForView(
    all.filter((t) => taskMatchesFilter(t, tasksFilter)),
    tasksFilter
  );
  if (!filtered.length) {
    tb.innerHTML = `<tr><td colspan="10" class="empty">No tasks match this filter.</td></tr>`;
    return;
  }

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
    queued: "Queued",
    done: "Done / failed",
  };
  const rows = [];
  let lastGroup = null;
  for (const t of filtered) {
    const group = taskListGroup(t);
    if (showGroups && group !== lastGroup) {
      rows.push(
        `<tr class="task-group-header" data-group="${esc(group)}">` +
          `<td colspan="10">${esc(groupLabels[group] || group)}</td></tr>`
      );
      lastGroup = group;
    }
    const res = t.result ? JSON.stringify(t.result, null, 0) : "";
    const payload = t.payload ? JSON.stringify(t.payload) : "";
    const hasT = !!t.has_transcript;
    const loop = formatTaskLoop(t, maxA);
    const st = (t.state || "").toLowerCase();
    const queued = st === "queued";
    const running = st === "leased";
    const pos = posById.get(Number(t.id));
    const tier = priorityTierLabel(t.priority);
    const prioBadge = `<span class="prio-badge prio-${esc(tier.tier)}" title="priority ${esc(String(t.priority ?? ""))}">${esc(tier.label)} <span class="mono prio-num">${esc(String(t.priority ?? "—"))}</span></span>`;
    const actions = queued
      ? `<div class="task-prio-actions">
            <button type="button" class="btn btn-sm btn-primary task-prio-btn" data-tier="run_next" data-tid="${t.id}" title="Jump to front of queue">Run next</button>
            <button type="button" class="btn btn-sm task-prio-btn" data-tier="high" data-tid="${t.id}">High</button>
            <button type="button" class="btn btn-sm task-prio-btn" data-tier="normal" data-tid="${t.id}">Normal</button>
            <button type="button" class="btn btn-sm task-prio-btn" data-tier="low" data-tid="${t.id}">Low</button>
            <button type="button" class="btn btn-sm btn-bad task-cancel-btn" data-tid="${t.id}" title="Remove from queue (cancel)">Remove</button>
          </div>`
      : `<span class="controls-hint">—</span>`;
    const rowClass = [
      "task-row",
      queued ? "is-queued" : "",
      running ? "is-running" : "",
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
        <td><div class="task-result" title="${esc(res)}">${esc(res.slice(0, 200))}</div></td>
        <td>${hasT ? `<span class="llm-pill">LLM log ></span>` : `<span class="llm-pill none"> - </span>`}</td>
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
  tb.querySelectorAll("tr.task-row").forEach((row) => {
    row.addEventListener("click", () => {
      const id = row.getAttribute("data-task-id");
      const has = row.getAttribute("data-has-t") === "1";
      if (!has) {
        toast("No LLM transcript for this task (mech-only or pre-logging run)");
        return;
      }
      openTranscript(id);
    });
  });
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
    _stepIoState = {
      taskId,
      data,
      tab: (_stepIoState && String(_stepIoState.taskId) === String(taskId) && _stepIoState.tab) || "input",
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
  const role = m.role || "unknown";
  let content = m.content;
  if (m.tool_calls) {
    content = (content || "") + "\n" + JSON.stringify(m.tool_calls, null, 2);
  }
  if (m.reasoning_content) {
    content =
      `[reasoning]\n${m.reasoning_content}\n\n[content]\n` + (content || "");
  }
  if (m.name) content = `[tool ${m.name}]\n` + (content || "");
  return `<div class="transcript-turn role-${esc(role)}">
    <div class="role">${esc(role)}</div>
    <pre>${esc(content || "")}</pre>
  </div>`;
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

async function openSettings() {
  try {
    const data = await api("/api/settings");
    const s = data.settings || {};
    $("#set-host").value = s.host || "";
    $("#set-port").value = s.port || 1234;
    $("#set-model").value = s.model || "";
    const apiModeEl = $("#set-api-mode");
    if (apiModeEl) {
      const mode = s.api_mode || "chat_completions";
      apiModeEl.value = mode;
      if (apiModeEl.value !== mode) apiModeEl.value = "chat_completions";
    }
    $("#set-workers").value = s.max_concurrent_agents || 1;
    $("#set-ctx").value = s.context_tokens || 32768;
    $("#set-frac").value = s.max_context_fraction ?? 0.25;
    $("#set-maxtok").value = s.max_tokens || 4096;
    $("#set-rounds").value = s.max_tool_rounds || 12;
    $("#set-timeout").value = s.timeout_seconds || 600;
    $("#set-maxtasks").value = s.max_tasks || 50;
    const eff = data.effective || {};
    const dash = "-";
    $("#settings-effective").textContent =
      `Effective: ${eff.base_url || dash} | model ${eff.model || dash} | api ${eff.api_mode || "chat_completions"} | concurrent agents ${eff.max_leases_parallel || 1} | ctx ${eff.context_tokens || dash} × ${eff.max_context_fraction ?? dash}`;
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
    report.textContent = "Probing endpoint (models, completion, tool-call, latency)…";
  }
  try {
    const data = await api("/api/settings/optimize", {
      method: "POST",
      body: JSON.stringify({
        host: form.host,
        port: form.port,
        model: form.model,
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
        eff.textContent =
          `Recommended: http://${r.host}:${r.port}/v1 | model ${r.model} | api ${r.api_mode} | ` +
          `agents ${r.max_concurrent_agents} | ctx ${r.context_tokens} × ${r.max_context_fraction} | ` +
          `tools ${data.tool_calls_ok ? "ok" : "weak"}`;
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
  const tl = $("#timeline");
  if (!tl || !events?.length) return;
  const frag = document.createDocumentFragment();
  for (const ev of events) {
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

/* ---------- Architecture (summary only) ---------- */

function renderArchitecture(arch, summary, snap) {
  const el = $("#arch-panel");
  if (!el) return;
  const s = summary || {};
  const has = !!(s.has_architecture || arch);
  if (!has) {
    el.innerHTML = `<div class="card">
      <div class="empty empty-cta">
        <p><strong>No architecture yet</strong></p>
        <p class="controls-hint">Recon has not finished (or has not run). Architecture is stored in the run DB after submit_architecture (or free-text salvage) — not under project/. Map the target first, then hunt from Explorer or Coverage.</p>
        ${reconFailureHint(snap)}
        <div class="empty-cta-actions">
          <button type="button" class="btn btn-primary" id="arch-go-mission">Run recon with brief</button>
          <button type="button" class="btn" id="arch-go-explorer">Open Explorer</button>
        </div>
      </div>
    </div>`;
    $("#arch-go-mission")?.addEventListener("click", () => {
      if (window.VulnForgeModes?.setMode) {
        window.VulnForgeModes.setMode("mission", "overview");
      }
      setTimeout(() => $("#op-recon-notes")?.focus(), 50);
    });
    $("#arch-go-explorer")?.addEventListener("click", () => {
      window.VulnForgeModes?.setMode?.("explorer");
    });
    return;
  }
  const comps = (s.components || [])
    .map(
      (c) =>
        `<li><strong>${esc(c.name)}</strong>${
          c.role ? `  -  ${esc(c.role)}` : ""
        }${
          (c.path_hints || []).length
            ? ` <span class="mono controls-hint">${esc((c.path_hints || []).slice(0, 3).join(", "))}</span>`
            : ""
        }</li>`
    )
    .join("");
  const surfaces = (s.input_surfaces || [])
    .map((x) => `<li>${esc(typeof x === "string" ? x : JSON.stringify(x))}</li>`)
    .join("");
  const bounds = (s.trust_boundaries || [])
    .map((x) => `<li>${esc(typeof x === "string" ? x : JSON.stringify(x))}</li>`)
    .join("");
  const agentsRun = Array.isArray(s.recon_agents_run) ? s.recon_agents_run : [];
  const agentsHtml = agentsRun.length
    ? agentsRun
        .map((a) => {
          const id = esc(a?.id || "?");
          const title = a?.title ? esc(a.title) : "";
          const ok =
            a?.ok === true ? "ok" : a?.ok === false ? "fail" : "";
          const badge = ok
            ? ` <span class="badge ${ok === "ok" ? "good" : "bad"}">${ok}</span>`
            : "";
          return `<li><span class="mono">${id}</span>${title ? ` — ${title}` : ""}${badge}</li>`;
        })
        .join("")
    : "";

  const summaryHtml = renderMarkdown(s.summary || "(no summary)");

  el.innerHTML = `
    <div class="card arch-summary-card">
      <div class="toolbar" style="margin-bottom:0.35rem;flex-wrap:wrap;gap:0.4rem">
        <h2 style="margin:0;flex:1">Architecture</h2>
        <button type="button" class="btn btn-sm" id="arch-edit-toggle">Edit architecture</button>
        <button type="button" class="btn btn-sm" id="arch-history-toggle">History</button>
      </div>
      <div class="arch-summary-text md-prose">${summaryHtml}</div>
      ${
        agentsHtml
          ? `<div style="margin:0.65rem 0 0.25rem"><h3 style="margin:0 0 0.35rem">Recon agents (merged)</h3><ul class="arch-list">${agentsHtml}</ul></div>`
          : ""
      }
      <div class="arch-meta-grid">
        <div>
          <h3>Components</h3>
          <ul class="arch-list">${comps || "<li class='controls-hint'> - </li>"}</ul>
        </div>
        <div>
          <h3>Input surfaces</h3>
          <ul class="arch-list">${surfaces || "<li class='controls-hint'> - </li>"}</ul>
        </div>
        <div>
          <h3>Trust boundaries</h3>
          <ul class="arch-list">${bounds || "<li class='controls-hint'> - </li>"}</ul>
        </div>
      </div>
      <details class="arch-raw">
        <summary>Raw architecture JSON</summary>
        <pre class="arch-box">${esc(JSON.stringify(arch || s, null, 2))}</pre>
      </details>
      <div id="arch-history-panel" class="arch-history-panel" style="display:none;margin-top:1rem;padding-top:0.85rem;border-top:1px solid var(--border)">
        <h3 style="margin:0 0 0.4rem">Architecture history</h3>
        <p class="controls-hint">Prior maps (last 50). Click a revision to view that version. Restore replaces the current map and archives it.</p>
        <div id="arch-history-list" class="controls-hint">Loading…</div>
        <div id="arch-history-detail" class="arch-history-detail" style="display:none;margin-top:0.85rem;padding:0.75rem;border:1px solid var(--border);border-radius:6px;background:var(--surface-2, transparent)"></div>
      </div>
      <div id="arch-edit-panel" class="arch-edit-panel" style="display:none;margin-top:1rem;padding-top:0.85rem;border-top:1px solid var(--border)">
        <h3 style="margin:0 0 0.4rem">Edit architecture</h3>
        <p class="controls-hint">Edit summary and/or full JSON. Saved as source <span class="mono">manual</span> (DB only).</p>
        <div class="field">
          <label for="arch-edit-summary">Summary</label>
          <textarea id="arch-edit-summary" class="op-notes" rows="4" placeholder="Architecture summary…"></textarea>
        </div>
        <div class="field" style="margin-top:0.5rem">
          <label for="arch-edit-json">Full architecture JSON</label>
          <textarea id="arch-edit-json" class="op-notes mono" rows="12" spellcheck="false"></textarea>
        </div>
        <div class="field" style="margin-top:0.5rem">
          <label for="arch-edit-note">Note (optional)</label>
          <input type="text" id="arch-edit-note" class="op-notes" placeholder="Why this edit?" style="width:100%" />
        </div>
        <div class="toolbar" style="gap:0.5rem;margin-top:0.5rem">
          <button type="button" class="btn btn-primary" id="arch-edit-save">Save</button>
          <button type="button" class="btn" id="arch-edit-cancel">Cancel</button>
        </div>
      </div>
      <div class="arch-refine" style="margin-top:1rem;padding-top:0.85rem;border-top:1px solid var(--border)">
        <h3 style="margin:0 0 0.4rem">Refine recon</h3>
        <p class="controls-hint">Re-run recon with guidance. Prior architecture is included so the model can correct and deepen the map.</p>
        <div class="field">
          <label for="arch-recon-notes">Operator brief</label>
          <textarea id="arch-recon-notes" class="op-notes" rows="3" placeholder="What did recon miss? Which areas need better path_hints?"></textarea>
        </div>
        <div class="toolbar" style="gap:0.5rem;margin-top:0.5rem">
          <button type="button" class="btn btn-primary" id="arch-recon-rerun">Re-run recon</button>
          <button type="button" class="btn" id="arch-recon-only">Architecture only</button>
        </div>
      </div>
    </div>`;
  $("#arch-recon-rerun")?.addEventListener("click", () =>
    submitArchRecon(true)
  );
  $("#arch-recon-only")?.addEventListener("click", () =>
    submitArchRecon(false)
  );
  $("#arch-history-toggle")?.addEventListener("click", () =>
    toggleArchHistory()
  );
  $("#arch-edit-toggle")?.addEventListener("click", () =>
    toggleArchEdit(arch || s)
  );
  $("#arch-edit-cancel")?.addEventListener("click", () => {
    const p = $("#arch-edit-panel");
    if (p) p.style.display = "none";
  });
  $("#arch-edit-save")?.addEventListener("click", () => saveArchEdit());
}

async function toggleArchHistory() {
  const panel = $("#arch-history-panel");
  if (!panel) return;
  const show = panel.style.display === "none";
  panel.style.display = show ? "block" : "none";
  if (!show) return;
  const list = $("#arch-history-list");
  const detail = $("#arch-history-detail");
  if (detail) {
    detail.style.display = "none";
    detail.innerHTML = "";
  }
  if (!list) return;
  list.innerHTML = "Loading…";
  try {
    const r = await api(`${runApiBase()}/architecture/history?limit=50`);
    const revs = Array.isArray(r.revisions) ? r.revisions : [];
    if (!revs.length) {
      list.innerHTML = "<p class='controls-hint' style='margin:0'>No prior revisions yet.</p>";
      return;
    }
    list.innerHTML = `<ul class="arch-list" style="list-style:none;padding:0;margin:0">${revs
      .map((rev) => {
        const id = rev.id;
        const src = esc(rev.source || "—");
        const when = esc(rev.created_at || "");
        const note = rev.note ? esc(String(rev.note).slice(0, 120)) : "";
        const gen =
          rev.recon_generation != null
            ? ` · gen ${esc(String(rev.recon_generation))}`
            : "";
        const agents = Array.isArray(rev.agent_ids) && rev.agent_ids.length
          ? ` · agents: <span class="mono">${esc(rev.agent_ids.join(", "))}</span>`
          : "";
        return `<li style="display:flex;flex-wrap:wrap;gap:0.4rem;align-items:center;margin:0.35rem 0;padding:0.35rem 0;border-bottom:1px solid var(--border)">
          <a href="#arch-rev-${esc(String(id))}" class="mono arch-rev-link" data-rev-id="${esc(String(id))}" title="View this revision">#${esc(String(id))}</a>
          <span class="badge">${src}</span>
          <span class="controls-hint">${when}${gen}${agents}</span>
          ${note ? `<span class="controls-hint">— ${note}</span>` : ""}
          <button type="button" class="btn btn-sm arch-view-btn" data-rev-id="${esc(String(id))}">View</button>
          <button type="button" class="btn btn-sm arch-restore-btn" data-rev-id="${esc(String(id))}">Restore</button>
        </li>`;
      })
      .join("")}</ul>`;
    list.querySelectorAll(".arch-rev-link, .arch-view-btn").forEach((el) => {
      el.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const revId = el.getAttribute("data-rev-id");
        if (revId) await showArchRevision(revId);
      });
    });
    list.querySelectorAll(".arch-restore-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const revId = btn.getAttribute("data-rev-id");
        if (!revId) return;
        if (!confirm(`Restore architecture revision #${revId}? Current map will be archived.`)) {
          return;
        }
        try {
          await api(`${runApiBase()}/architecture/restore/${revId}`, {
            method: "POST",
            body: JSON.stringify({ note: `restored from #${revId}` }),
          });
          toast(`Restored architecture #${revId}`);
          await loadRunFull();
        } catch (e) {
          toast(e.message, true);
        }
      });
    });
  } catch (e) {
    list.innerHTML = `<p class="controls-hint" style="color:var(--danger,#c44)">${esc(e.message)}</p>`;
  }
}

function renderArchSnapshotHtml(snap, title) {
  const s = snap && typeof snap === "object" ? snap : {};
  const comps = (s.components || [])
    .map((c) => {
      if (typeof c === "string") return `<li>${esc(c)}</li>`;
      const name = esc(c?.name || "?");
      const role = c?.role ? ` — ${esc(c.role)}` : "";
      const paths =
        Array.isArray(c?.path_hints) && c.path_hints.length
          ? ` <span class="mono controls-hint">${esc(c.path_hints.slice(0, 4).join(", "))}</span>`
          : "";
      return `<li><strong>${name}</strong>${role}${paths}</li>`;
    })
    .join("");
  const surfaces = (s.input_surfaces || [])
    .map((x) => `<li>${esc(typeof x === "string" ? x : JSON.stringify(x))}</li>`)
    .join("");
  const bounds = (s.trust_boundaries || [])
    .map((x) => `<li>${esc(typeof x === "string" ? x : JSON.stringify(x))}</li>`)
    .join("");
  const focus = (s.hunt_focus || [])
    .map((x) => {
      if (typeof x === "string") return `<li>${esc(x)}</li>`;
      const area = esc(x?.area || "?");
      const cls = x?.class ? ` / ${esc(x.class)}` : "";
      return `<li><span class="mono">${area}${cls}</span></li>`;
    })
    .join("");
  const summaryHtml = renderMarkdown(s.summary || "(no summary)");
  return `
    <div class="toolbar" style="margin:0 0 0.5rem;flex-wrap:wrap;gap:0.4rem">
      <h4 style="margin:0;flex:1">${title}</h4>
      <button type="button" class="btn btn-sm" id="arch-history-detail-close">Close</button>
    </div>
    <div class="arch-summary-text md-prose">${summaryHtml}</div>
    <div class="arch-meta-grid" style="margin-top:0.65rem">
      <div>
        <h3>Components</h3>
        <ul class="arch-list">${comps || "<li class='controls-hint'>—</li>"}</ul>
      </div>
      <div>
        <h3>Input surfaces</h3>
        <ul class="arch-list">${surfaces || "<li class='controls-hint'>—</li>"}</ul>
      </div>
      <div>
        <h3>Trust boundaries</h3>
        <ul class="arch-list">${bounds || "<li class='controls-hint'>—</li>"}</ul>
      </div>
      <div>
        <h3>Hunt focus</h3>
        <ul class="arch-list">${focus || "<li class='controls-hint'>—</li>"}</ul>
      </div>
    </div>
    <details class="arch-raw" style="margin-top:0.65rem">
      <summary>Raw revision JSON</summary>
      <pre class="arch-box">${esc(JSON.stringify(s, null, 2))}</pre>
    </details>`;
}

async function showArchRevision(revId) {
  const detail = $("#arch-history-detail");
  if (!detail) return;
  detail.style.display = "block";
  detail.innerHTML = `<p class="controls-hint" style="margin:0">Loading revision #${esc(String(revId))}…</p>`;
  try {
    const rev = await api(`${runApiBase()}/architecture/history/${encodeURIComponent(revId)}`);
    const snap = rev.snapshot && typeof rev.snapshot === "object" ? rev.snapshot : {};
    const src = esc(rev.source || "—");
    const when = esc(rev.created_at || "");
    const note = rev.note ? ` — ${esc(String(rev.note).slice(0, 200))}` : "";
    const gen =
      rev.recon_generation != null
        ? ` · gen ${esc(String(rev.recon_generation))}`
        : "";
    const title = `Revision <span class="mono">#${esc(String(rev.id ?? revId))}</span> <span class="badge">${src}</span> <span class="controls-hint">${when}${gen}${note}</span>`;
    detail.innerHTML = renderArchSnapshotHtml(snap, title);
    detail.id = "arch-history-detail";
    // Ensure the detail node stays addressable if innerHTML replaced id on a child only
    $("#arch-history-detail-close")?.addEventListener("click", () => {
      const d = $("#arch-history-detail");
      if (d) {
        d.style.display = "none";
        d.innerHTML = "";
      }
    });
    detail.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    detail.innerHTML = `<p class="controls-hint" style="color:var(--danger,#c44);margin:0">${esc(e.message)}</p>`;
  }
}

function toggleArchEdit(arch) {
  const panel = $("#arch-edit-panel");
  if (!panel) return;
  const show = panel.style.display === "none";
  panel.style.display = show ? "block" : "none";
  if (!show) return;
  const base = arch && typeof arch === "object" ? arch : {};
  const sumEl = $("#arch-edit-summary");
  const jsonEl = $("#arch-edit-json");
  if (sumEl) sumEl.value = String(base.summary || "");
  if (jsonEl) {
    try {
      jsonEl.value = JSON.stringify(base, null, 2);
    } catch {
      jsonEl.value = "{}";
    }
  }
}

async function saveArchEdit() {
  const jsonEl = $("#arch-edit-json");
  const sumEl = $("#arch-edit-summary");
  const noteEl = $("#arch-edit-note");
  let arch;
  try {
    arch = JSON.parse((jsonEl?.value || "{}").trim() || "{}");
  } catch (e) {
    toast("Invalid JSON: " + e.message, true);
    return;
  }
  if (!arch || typeof arch !== "object" || Array.isArray(arch)) {
    toast("Architecture must be a JSON object", true);
    return;
  }
  // Prefer summary textarea if the operator edited it
  if (sumEl) {
    arch.summary = sumEl.value;
  }
  try {
    await api(`${runApiBase()}/architecture`, {
      method: "PUT",
      body: JSON.stringify({
        architecture: arch,
        note: (noteEl?.value || "").trim(),
      }),
    });
    toast("Architecture saved");
    await loadRunFull();
  } catch (e) {
    toast(e.message, true);
  }
}

async function submitArchRecon(enqueueHunts) {
  const notes = ($("#arch-recon-notes")?.value || "").trim();
  try {
    const r = await api(`${runApiBase()}/recon/rerun`, {
      method: "POST",
      body: JSON.stringify({
        operator_notes: notes,
        include_prior_architecture: true,
        enqueue_hunts: enqueueHunts,
        reason: enqueueHunts ? "operator_recon_from_arch" : "operator_recon_arch_only",
      }),
    });
    const ids = Array.isArray(r.task_ids) && r.task_ids.length
      ? r.task_ids
      : r.task_id != null
        ? [r.task_id]
        : [];
    const idLabel = ids.length ? ids.map((n) => `#${n}`).join(", ") : "recon";
    const multi =
      ids.length > 1 ? ` (${ids.length} agent loops)` : "";
    toast(`Queued recon ${idLabel}${multi}`);
    await loadRunFull();
  } catch (e) {
    toast(e.message, true);
  }
}

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
          <pre class="code-view" id="explorer-code" tabindex="0">Open a file from the tree...</pre>
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

async function loadRunFull() {
  const [target_id, run_id] = currentKey.split("/");
  const snap = await api(
    `/api/runs/${encodeURIComponent(target_id)}/${encodeURIComponent(run_id)}`
  );
  $("#run-title") &&
    ($("#run-title").textContent = `${snap.target_id} / ${snap.run_id}`);
  $("#run-subtitle") &&
    ($("#run-subtitle").textContent = snap.target_path || snap.path || "");
  window.__VF_cov_policy = snap.coverage_policy || { mode: "auto" };
  window.__VF_hunt_classes = snap.hunt_classes || window.__VF_hunt_classes || {};
  // Shared for report mode + evidence deep-links
  window.__VF_last_snap = snap;
  window.currentKey = currentKey;
  window.api = api;
  window.loadRunFull = loadRunFull;
  window.__VF_max_task_attempts = Number(snap.max_task_attempts) || 3;
  renderStats(snap);
  renderRunner(snap.runner || {}, snap);
  renderOverview(snap);
  renderTasks(snap.tasks || []);
  renderArchitecture(snap.architecture, snap.architecture_summary, snap);
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
  // Align live drift detector with the snap we just applied.
  noteLiveTaskSig(snap);
  return snap;
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
        renderStats(card);
        renderRunner(data.runner || card.runner || {}, card);
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
        if (
          (data.events || []).some((e) => LIVE_REFRESH_EVENTS.has(e.event))
        ) {
          // Debounced full refresh; do not tear down SSE (connectStream sticky).
          scheduleLoadRunFull("event");
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
 * - max_tasks: settings.max_tasks (fallback 50)
 * - workers: settings.max_concurrent_agents when set
 * - task_timeout: Ralph per-task budget (default 900). Not the same as
 *   settings.timeout_seconds (LLM HTTP timeout). No dedicated UI field yet.
 *
 * Contract table (keep in sync): tests/test_control_body_contract.py
 */
function controlBodyFromSettings(settings) {
  const s = settings || {};
  // Prefer Harness loop profile when selected (Start/Resume)
  const profileId =
    (window.VulnForgeHarness &&
      typeof window.VulnForgeHarness.getSelectedLoopProfileId === "function" &&
      window.VulnForgeHarness.getSelectedLoopProfileId()) ||
    (typeof localStorage !== "undefined" && localStorage.getItem("vf_loop_profile_id")) ||
    null;
  if (profileId) {
    const body = { loop_profile_id: profileId };
    // Optional worker override from settings still applies when set
    const w = parseInt(s.max_concurrent_agents, 10);
    if (Number.isFinite(w) && w > 0) {
      body.workers = w;
    }
    return body;
  }
  const mt = parseInt(s.max_tasks, 10);
  const max_tasks = Number.isFinite(mt) && mt > 0 ? mt : 50;
  const body = { max_tasks, task_timeout: 900 };
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
          workers: null,
          task_timeout: 900,
        });
        toast("Settings unavailable; using server defaults", true);
      }
    }
    const r = await api(path, opts);
    const workers = r.workers || r.status?.meta?.workers || 1;
    const note = r.note ? ` — ${r.note}` : "";
    if (action === "start" || action === "resume") {
      toast(
        workers > 1
          ? `${action}: ${r.status?.state || "ok"} · ${workers} agents${note}`
          : `${action}: ${r.status?.state || "ok"}${note}`
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
  // Mode-nav UI (modes.js) owns tab switching on the run page.
  if ($(".mode-nav")) return;
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

function renderToolGapsPage(data) {
  const meta = $("#home-tool-gaps-meta");
  const body = $("#home-tool-gaps-body");
  const perRun = $("#tool-gaps-per-run");
  if (meta) {
    meta.textContent =
      `Generated ${data.generated_at || "-"} | runs=${data.runs_scanned ?? 0} | ` +
      `capabilities=${data.capability_count ?? (data.capabilities || []).length} | ` +
      `gap_rows=${data.total_gap_rows ?? 0}` +
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
        <thead><tr><th>Target</th><th>Run</th><th>Gaps</th><th>Mode</th><th></th></tr></thead>
        <tbody>${rows
          .map((r) => {
            if (r.error) {
              return `<tr><td colspan="5" class="empty">${esc(r.target_id || "")}/${esc(r.run_id || "")}: ${esc(r.error)}</td></tr>`;
            }
            const href =
              r.target_id && r.run_id
                ? `/runs/${encodeURIComponent(r.target_id)}/${encodeURIComponent(r.run_id)}`
                : "#";
            return `<tr>
              <td class="mono">${esc(r.target_id || "")}</td>
              <td class="mono">${esc(r.run_id || "")}</td>
              <td>${esc(String(r.gap_count ?? 0))}</td>
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
  $("#btn-settings")?.addEventListener("click", openSettings);
  $("#settings-cancel")?.addEventListener("click", closeSettings);
  $("#settings-optimize")?.addEventListener("click", () => optimizeSettings());
  $("#settings-form")?.addEventListener("submit", saveSettings);
  // Settings / New-run modals stay open until Cancel or Save/Create -
  // do not dismiss on backdrop click (unstable form entry).
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
    loadHomeToolGapsSummary();
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
    $$(".chip[data-filter]").forEach((chip) => {
      chip.addEventListener("click", () => {
        $$(".chip[data-filter]").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        homeFilter = chip.getAttribute("data-filter") || "all";
        renderRunCards(homeRunsCache);
      });
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
