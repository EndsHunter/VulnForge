/* VulnForge Review (Triage Desk, mode id "report"): queue | finding | verdict rail, export,
 * Develop PoC workshop. Pure helpers live in pages/review.js (window.ReviewHelpers). */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  let cache = [];
  /** Default queue: needs_human. `filterChosen` stops the empty-filter fallback once the operator picks. */
  let filter = "needs_human";
  let filterChosen = false;
  let openId = null;
  /** Exclusive Report book page. Invalid combo: not findings without openId. */
  let reviewPage = "findings";
  /** Bumps on each context-pane render to ignore stale async fetches. */
  let contextToken = 0;
  /** Finding id open in the Develop POC workshop modal (not a mode tab). */
  let pocFindingId = null;
  let pocSessionTimer = null;
  let pocChromeBound = false;
  let meta = { target_id: "", run_id: "", target_path: "" };
  /** Multi-member overlap clusters from GET /findings/clusters */
  let clustersCache = [];
  /** Map finding_id -> cluster member meta */
  let clusterByFinding = {};
  let reportPanelsBound = false;
  /** Basename list from snap.project_files (project/* on disk). */
  let projectFiles = [];
  /** Client-side search (case-insensitive substring) */
  let searchQuery = "";
  let searchDebounceTimer = null;
  /**
   * Column sort. Default matches historical order: state priority asc, then id desc.
   * sortKey: id | title | class | severity | state | location
   * sortDir: asc | desc
   */
  let sortKey = "severity";
  let sortDir = "desc";

  /** Pure helpers from pages/review.js (loaded later; read at call time). */
  function RH() {
    return window.ReviewHelpers || null;
  }

  const STATE_ORDER = {
    needs_human: 0,
    candidate: 1,
    confirmed: 2,
    rejected_mech: 3,
    rejected_llm: 4,
    rejected_human: 5,
    superseded: 6,
  };

  /** Higher = more severe; default sortDir desc puts critical first. */
  const SEVERITY_ORDER = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
    unknown: 0,
    "": -1,
  };

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badge(state, finding) {
    if (typeof window.badge === "function") return window.badge(state, finding);
    const s = String(state || "").toLowerCase();
    let label = s;
    if (typeof window.stateLabel === "function") label = window.stateLabel(s, finding);
    const tip =
      typeof window.stateTip === "function" ? window.stateTip(s, finding) : s;
    return `<span class="badge ${esc(s)}" title="${esc(tip)}">${esc(label)}</span>`;
  }

  /** Progression trail for a finding row. Falls back to the single state badge. */
  function stateTrailHtml(f) {
    const H = window.ReportStateBadges;
    if (H && typeof H.findingStateTrailHtml === "function") {
      return H.findingStateTrailHtml(f);
    }
    return badge(f && f.state, f);
  }

  function sevBadge(sev) {
    if (typeof window.sevBadge === "function") return window.sevBadge(sev);
    return `<span class="badge">${esc(sev || "unknown")}</span>`;
  }

  function toast(msg, err) {
    if (typeof window.toast === "function") window.toast(msg, err);
  }

  function bodyOf(f) {
    return f.body || {};
  }

  function primaryPath(f) {
    const b = bodyOf(f);
    if (b.sink_path) return { path: b.sink_path, start_line: null, end_line: null };
    const cits = b.citations || [];
    for (const c of cits) {
      if (c && c.path) return c;
    }
    return null;
  }

  function pathLabel(c) {
    if (!c || !c.path) return "-";
    let s = c.path;
    if (c.start_line != null) s += `:${c.start_line}`;
    if (c.end_line != null && c.end_line !== c.start_line) s += `-${c.end_line}`;
    return s;
  }

  /** Longest path-prefix module from snap.codemap (client-side, no extra API). */
  function nearestModuleForPath(path) {
    if (!path) return null;
    const snap = window.__VF_last_snap || {};
    const codemap = snap.codemap;
    if (!codemap || !Array.isArray(codemap.modules)) return null;
    const norm = (p) =>
      String(p || "")
        .replace(/\\/g, "/")
        .replace(/^\/+/, "")
        .replace(/\/+$/, "");
    const p = norm(path);
    if (!p) return null;
    let best = null;
    let bestLen = -1;
    for (const m of codemap.modules) {
      if (!m || typeof m !== "object") continue;
      const mp = norm(m.path);
      if (!mp) continue;
      if (p === mp || p.startsWith(mp + "/")) {
        if (mp.length > bestLen) {
          best = m;
          bestLen = mp.length;
        }
      }
    }
    return best;
  }

  /**
   * Dual LLM disprove signal: stood/total where stand = could not kill.
   * Returns { stood, total, label, verifiers } or null if not dual-run.
   */
  function llmVerifyMeta(f) {
    const v = bodyOf(f).validation_llm;
    if (!v || typeof v !== "object") return null;
    const verifiers = Array.isArray(v.verifiers) ? v.verifiers : null;
    if (verifiers && verifiers.length) {
      const total =
        v.total != null ? Number(v.total) : verifiers.length;
      const stood =
        v.stood != null
          ? Number(v.stood)
          : verifiers.filter(
              (x) => String(x && x.verdict || "").toLowerCase() === "stand"
            ).length;
      const label = v.label || `${stood}/${total}`;
      return { stood, total, label, verifiers, status: v.status };
    }
    return null;
  }

  function llmVerifyBadge(f) {
    const m = llmVerifyMeta(f);
    if (!m) return "";
    const llm = bodyOf(f).validation_llm;
    const signal =
      window.ReportStateBadges && typeof window.ReportStateBadges.llmSignal === "function"
        ? window.ReportStateBadges.llmSignal(llm)
        : null;
    let tone = "llm-verify-mid";
    let word = m.stood <= 0 ? "disprove rejected" : "disprove stood";
    let title =
      "LLM disprove signal — not exploit proof and not confirmed. Confirmed is human-only. The harness never auto-confirms.";
    if (signal) {
      tone = signal.tone || tone;
      word = signal.word || word;
      title = signal.title || title;
    } else if (m.stood <= 0) {
      tone = "llm-verify-none";
    } else if (m.stood >= m.total) {
      tone = "llm-verify-all";
    }
    const multi =
      f?.body?.validation_llm?.multi_model_label ||
      f?.body?.validation_llm?.multi_model?.label ||
      "";
    if (multi) title += ` · ${multi}`;
    return `<span class="badge llm-verify ${tone}" title="${esc(title)}" data-tip="${esc(
      title
    )}" tabindex="0">${esc(m.label)} ${esc(word)}${
      multi ? " · " + esc(String(multi)) : ""
    }</span>`;
  }

  function llmVerifyDetailHtml(f) {
    const m = llmVerifyMeta(f);
    if (!m) return "";
    const rows = (m.verifiers || [])
      .map((vr) => {
        const vid = esc(vr.id || "?");
        const vv = esc(vr.verdict || "?");
        const model = vr.model_id ? esc(String(vr.model_id)) : "—";
        const prompt = vr.prompt ? esc(String(vr.prompt)) : "";
        const reason = esc(String(vr.reasoning || "").slice(0, 1200));
        return `<details class="report-llm-slot">
          <summary><span class="mono">${vid}</span> · <span class="badge">${vv}</span>
            <span class="controls-hint mono">${model}${
              prompt ? " · " + prompt : ""
            }</span></summary>
          <pre class="report-llm-reasoning mono">${reason || "(no reasoning)"}</pre>
        </details>`;
      })
      .join("");
    const signal =
      window.ReportStateBadges && typeof window.ReportStateBadges.llmSignal === "function"
        ? window.ReportStateBadges.llmSignal(bodyOf(f).validation_llm)
        : null;
    const word = signal
      ? signal.word
      : m.stood <= 0
        ? "disprove rejected"
        : "disprove stood";
    const badges = window.ReportStateBadges;
    const sameModel =
      badges && typeof badges.sameModelOnBothPerspectives === "function"
        ? badges.sameModelOnBothPerspectives(m.verifiers)
        : false;
    const weakNote = sameModel
      ? `<p class="controls-hint" data-llm-weak-signal="same-model">${esc(
          badges.SAME_MODEL_WEAK_SIGNAL ||
            "Same model on both perspectives — weak signal; not exploit proof."
        )}</p>`
      : "";
    return `<div class="report-llm-verify">
      <h4>LLM disprove <span class="badge llm-verify">${esc(m.label)} ${esc(word)}</span></h4>
      <p class="controls-hint">Each verifier tries to <strong>disprove</strong> the finding. Score = how many returned <span class="mono">stand</span> (could not kill). All slots must <span class="mono">reject</span> for auto <span class="mono">rejected_llm</span>. Not exploit proof. Stand is not confirmed — confirmed is human-only.</p>
      ${weakNote}
      ${rows}
    </div>`;
  }


  function huntMoaBadgeHtml(f) {
    const H = window.ReportHuntMoa;
    if (H && typeof H.huntMoaBadgeHtml === "function") return H.huntMoaBadgeHtml(f);
    return "";
  }

  function huntMoaDetailHtml(f) {
    const H = window.ReportHuntMoa;
    if (H && typeof H.huntMoaDetailHtml === "function") return H.huntMoaDetailHtml(f);
    return "";
  }

  function matchesFilter(f) {
    const H = RH();
    const near = (x) => !!(x && (x.near_dup || clusterByFinding[x.id]));
    if (H) return H.matchesQueueFilter(f, filter, near);
    const st = (f.state || "").toLowerCase();
    const ftr = (filter || "all").toLowerCase();
    if (ftr === "all") return true;
    if (ftr === "rejected") return st.startsWith("rejected") || st === "superseded";
    if (ftr === "near_dup" || ftr === "overlaps") return near(f);
    return st === ftr;
  }

  function matchesSearch(f) {
    const q = (searchQuery || "").trim().toLowerCase();
    if (!q) return true;
    const b = bodyOf(f);
    const sev = f.severity || b.severity_claim || "";
    const loc = pathLabel(primaryPath(f));
    const hay = [
      f.id,
      b.title,
      f.stable_key,
      b.weakness_class,
      sev,
      f.state,
      loc,
      b.summary,
      b.area,
      f.area,
    ]
      .map((x) => String(x ?? "").toLowerCase())
      .join("\n");
    return hay.includes(q);
  }

  function apiBase() {
    if (!meta.target_id || !meta.run_id) return null;
    return `/api/runs/${encodeURIComponent(meta.target_id)}/${encodeURIComponent(meta.run_id)}`;
  }

  function callApi(path, opts) {
    const api = typeof window.api === "function" ? window.api : null;
    if (!api) return Promise.reject(new Error("API unavailable"));
    return api(path, opts);
  }

  function sortValue(f, key) {
    const b = bodyOf(f);
    switch (key) {
      case "id":
        return Number(f.id) || 0;
      case "title":
        return String(b.title || f.stable_key || "").toLowerCase();
      case "class":
        return String(b.weakness_class || "").toLowerCase();
      case "severity": {
        const sev = String(f.severity || b.severity_claim || "")
          .toLowerCase()
          .trim();
        return SEVERITY_ORDER[sev] ?? SEVERITY_ORDER.unknown;
      }
      case "state":
        return STATE_ORDER[f.state] ?? 9;
      case "location":
        return pathLabel(primaryPath(f)).toLowerCase();
      default:
        return 0;
    }
  }

  function nearDupFilterActive() {
    const ftr = (filter || "all").toLowerCase();
    return ftr === "near_dup" || ftr === "overlaps";
  }

  function clusterMetaForId(id) {
    if (id == null || id === "") return null;
    return (
      clusterByFinding[id] ||
      clusterByFinding[Number(id)] ||
      clusterByFinding[String(id)] ||
      null
    );
  }

  /** Group key so near-dup filter rows from one overlap sit together. */
  function nearDupGroupKey(f) {
    const cm = clusterMetaForId(f && f.id);
    if (cm && cm.cluster_id) return "c:" + cm.cluster_id;
    const keeper = bodyOf(f).superseded_by;
    if (keeper != null && keeper !== "") {
      const km = clusterMetaForId(keeper);
      if (km && km.cluster_id) return "c:" + km.cluster_id;
      return "k:" + keeper;
    }
    const b = bodyOf(f);
    const sink = primaryPath(f);
    let symbol = String(b.sink_symbol || "").trim();
    if (!symbol) {
      const cites = b.citations || [];
      if (cites[0] && cites[0].symbol) symbol = String(cites[0].symbol).trim();
    }
    if (sink && sink.path && symbol) {
      return "s:" + String(sink.path) + "|" + symbol.toLowerCase();
    }
    return "id:" + (f && f.id);
  }

  function compareFindings(a, b) {
    if (nearDupFilterActive()) {
      const ga = nearDupGroupKey(a);
      const gb = nearDupGroupKey(b);
      if (ga !== gb) return ga < gb ? -1 : 1;
    }
    const dir = sortDir === "desc" ? -1 : 1;
    const key = sortKey || "severity";
    const H = RH();
    if (key === "severity" && H) {
      // Evidence tier desc, severity desc, needs review first, newest (asc flips it).
      const q = H.compareQueue(a, b);
      return sortDir === "asc" ? -q : q;
    }
    let cmp = 0;
    if (key === "id") {
      cmp = (Number(a.id) || 0) - (Number(b.id) || 0);
    } else if (key === "severity" || key === "state") {
      cmp = sortValue(a, key) - sortValue(b, key);
    } else {
      const sa = String(sortValue(a, key));
      const sb = String(sortValue(b, key));
      cmp = sa.localeCompare(sb, undefined, { sensitivity: "base", numeric: true });
    }
    if (cmp !== 0) return cmp * dir;
    // Stable secondary: id desc (matches historical default)
    return (Number(b.id) || 0) - (Number(a.id) || 0);
  }

  function sortedFindings() {
    return [...cache].filter(matchesFilter).filter(matchesSearch).sort(compareFindings);
  }

  function searchOrFilterActive() {
    return (
      (filter || "all").toLowerCase() !== "all" || !!(searchQuery || "").trim()
    );
  }

  function updateSearchCount() {
    const el = $("#report-search-count");
    if (!el) return;
    if (!searchOrFilterActive()) {
      el.hidden = true;
      el.textContent = "";
      return;
    }
    const n = sortedFindings().length;
    const m = cache.length;
    el.hidden = false;
    el.textContent = `${n} of ${m} matching`;
  }

  function updateSortHeaders() {
    const sel = $("#report-sort");
    if (sel && sel.value !== sortKey) sel.value = sortKey;
  }

  function defaultDirForSortKey(key) {
    if (key === "id" || key === "severity") return "desc";
    return "asc";
  }

  function setSort(key, opts) {
    if (!key) return;
    if (opts && opts.fromSelect) {
      sortKey = key;
      sortDir = defaultDirForSortKey(key);
    } else if (sortKey === key) {
      sortDir = sortDir === "asc" ? "desc" : "asc";
    } else {
      sortKey = key;
      sortDir = defaultDirForSortKey(key);
    }
    refreshTablePreserveDetail();
  }

  function setSearch(q) {
    searchQuery = q == null ? "" : String(q);
    refreshTablePreserveDetail();
  }

  /** Re-render table; keep open detail only if the finding is still visible. */
  function refreshTablePreserveDetail() {
    if (openId != null) {
      const stillVisible = sortedFindings().some(
        (f) => Number(f.id) === Number(openId)
      );
      if (!stillVisible) {
        clearFindingPanes();
      }
    }
    renderTable();
    if (openId != null && reviewPage !== "findings") {
      const f = cache.find((x) => Number(x.id) === Number(openId));
      if (f) {
        fillFindingPanes(f);
        setReviewPage(reviewPage);
      }
    }
    updateSearchCount();
    updateSortHeaders();
  }

  function summaryCounts() {
    const H = RH();
    const near = (x) => !!(x && (x.near_dup || clusterByFinding[x.id]));
    if (H) {
      const c = H.queueCounts(cache, near);
      return { ...c, total: c.all };
    }
    return { all: cache.length, total: cache.length, needs_human: 0, candidate: 0, confirmed: 0, rejected: 0, near_dup: 0 };
  }

  /** Queue filter chips (replaces the old summary cards). */
  function renderSummary() {
    const el = $("#report-summary");
    if (!el) return;
    const c = summaryCounts();
    const ftr = (filter || "all").toLowerCase();
    const H = RH();
    const chips = (H && H.FILTERS) || [
      { id: "needs_human", label: "Needs review" },
      { id: "all", label: "All" },
    ];
    el.innerHTML = chips
      .map((chip) => {
        const on = ftr === chip.id;
        const n = chip.id === "all" ? c.total : c[chip.id] || 0;
        const warn = chip.id === "needs_human" ? " vf-chip--warn" : "";
        return `<button type="button" class="vf-chip${warn}" data-rfilter="${chip.id}" aria-pressed="${on}">${esc(chip.label)} <span class="rv-chip-n">${n}</span></button>`;
      })
      .join("");
    el.querySelectorAll("[data-rfilter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        filterChosen = true;
        setFilter(btn.getAttribute("data-rfilter") || "all");
      });
    });
  }

  function emptyDetailHtml() {
    if (!cache.length) {
      return `<div class="rv-empty-cta">
        <h2>No findings yet</h2>
        <p class="vf-faint">Hunts file findings here. Steer work from Campaign or Atlas.</p>
        <div class="rv-row">
          <button type="button" class="vf-btn vf-btn--primary" data-rv-go="hunts">Open Campaign</button>
          <button type="button" class="vf-btn" data-rv-go="explorer">Open Atlas</button>
        </div>
      </div>`;
    }
    return `<div class="vf-empty">${
      sortedFindings().length ? "Select a finding to review." : "Nothing in this filter. Pick another chip."
    }</div>`;
  }

  function emptyContextHtml() {
    return `<div class="vf-empty">Gates, disprove results and the verdict appear here.</div>`;
  }

  /** Kept for callers; the desk has no separate pages. */
  function setReviewPage(page) {
    reviewPage = page === "evidence" ? "evidence" : openId != null ? "detail" : "findings";
    const shell = $("#report-shell");
    if (shell) {
      shell.setAttribute("data-review-page", reviewPage);
      shell.classList.toggle("has-selection", openId != null);
    }
  }

  function goReviewPage(page) {
    const f = cache.find((x) => Number(x.id) === Number(openId));
    if (!f) {
      clearFindingPanes();
      renderTable();
      return;
    }
    fillFindingPanes(f);
    setReviewPage(page);
    if (page === "evidence") {
      $("#rv-evidence-preview")?.setAttribute("open", "");
      $("#rv-evidence-preview")?.scrollIntoView({ block: "nearest" });
    }
  }

  function clearFindingPanes() {
    openId = null;
    contextToken += 1;
    $$(".rv-queue-row.is-open").forEach((el) => el.classList.remove("is-open"));
    const d = $("#report-detail");
    if (d) {
      d.hidden = false;
      d.innerHTML = emptyDetailHtml();
    }
    const c = $("#report-context");
    if (c) c.innerHTML = emptyContextHtml();
    setReviewPage("findings");
  }

  function fillFindingPanes(f) {
    const d = $("#report-detail");
    if (!d || !f) return;
    d.hidden = false;
    d.innerHTML = detailHtml(f);
    bindDetailActions(d);
    renderContext(f);
    loadOwners(f);
  }

  /* Suggested owners (issue #190). Opt-in; read-only git on the server.
   * Cached per finding so snapshot re-renders do not re-run git. */
  const ownersCache = new Map();
  const OWNER_REASONS = {
    not_a_git_repo: "Target is not a git repository (or is a subdirectory of one; see owners.allow_parent_repo).",
    git_missing: "git is not installed on the dashboard host.",
    unsafe_repository: "git refused this repository (ownership or work tree outside the target).",
    no_head: "Repository has no commits.",
    untracked: "Cited file is not tracked at HEAD.",
    no_citations: "Finding has no usable citations.",
    timeout: "git timed out.",
    target_missing: "Target path is missing.",
  };

  function ownerIdent(o) {
    const name = String(o.name || "");
    const email = String(o.email || "");
    return name && email ? `${name} <${email}>` : name || email || "?";
  }

  function ownersHtml(o) {
    if (!o || o.reason === "disabled") return "";
    const head = `<h3 class="vf-section-label">Suggested owners <button type="button" class="vf-btn vf-btn--ghost report-owners-refresh" title="Re-run git for this finding">Refresh</button></h3>`;
    if (o.loading) return `${head}<p class="controls-hint">Reading git history…</p>`;
    if (!o.available) {
      const why = OWNER_REASONS[o.reason] || `Unavailable (${o.reason || "error"}).`;
      return `${head}<p class="controls-hint">${esc(why)}</p>`;
    }
    const co = o.codeowners;
    const coLine =
      co && Array.isArray(co.owners) && co.owners.length
        ? `<p class="mono">CODEOWNERS <span class="controls-hint">${esc(co.file || "")} · ${esc(co.pattern || "")}</span><br>${co.owners
            .map((x) => esc(x))
            .join(" ")}</p>`
        : `<p class="controls-hint">No CODEOWNERS rule matches this file.</p>`;
    const rows = (o.suggestions || [])
      .map(
        (s) =>
          `<tr><td>${esc(ownerIdent(s))}</td><td class="mono">${esc(s.blame_lines || 0)}</td><td class="mono">${esc(
            s.file_commits || 0
          )}</td><td class="mono">${esc(s.module_commits || 0)}</td><td class="mono">${esc(
            String(s.last_commit_at || "").slice(0, 10)
          )}</td></tr>`
      )
      .join("");
    const table = rows
      ? `<table class="report-owners-table"><thead><tr><th>Author</th><th title="Blamed cited lines">Blame</th><th title="Recent commits to the file">File</th><th title="Recent commits to ${esc(
          o.module || "module"
        )}">Module</th><th>Last</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<p class="controls-hint">No authors found in history.</p>`;
    const redact = o.redact_in_exports
      ? "Exports show pseudonyms."
      : "Exports show these identities.";
    return `${head}${coLine}${table}<p class="controls-hint">${esc(o.note || "")} ${esc(redact)}</p>`;
  }

  function paintOwners(fid) {
    const host = document.querySelector(`#report-detail .report-owners[data-fid="${fid}"]`);
    if (!host) return;
    const o = ownersCache.get(String(fid));
    host.innerHTML = ownersHtml(o);
    host.hidden = !host.innerHTML;
    host.querySelector(".report-owners-refresh")?.addEventListener("click", () => {
      ownersCache.delete(String(fid));
      loadOwners({ id: fid });
    });
  }

  async function loadOwners(f) {
    const fid = String(f && f.id);
    const base = apiBase();
    if (!base || !fid) return;
    if (ownersCache.has(fid)) {
      paintOwners(fid);
      return;
    }
    ownersCache.set(fid, { loading: true });
    paintOwners(fid);
    try {
      const o = await callApi(`${base}/findings/${encodeURIComponent(fid)}/owners`);
      ownersCache.set(fid, o || { available: false, reason: "error" });
    } catch (e) {
      ownersCache.set(fid, { available: false, reason: "error" });
    }
    paintOwners(fid);
  }

  function showFindingDetail(f, opts) {
    if (!f) return;
    openId = Number(f.id);
    fillFindingPanes(f);
    setReviewPage((opts && opts.page) || "detail");
  }

  /** Verdict rail: gates, disprove judges, evidence + PoC, reviewer note, Accept / Reject. */
  function verdictHtml(f) {
    const H = RH();
    const b = bodyOf(f);
    const gates = H ? H.mechGates(f) : { status: "pending", gates: [], other: [], passed: 0, total: 0 };
    const gateIcon = (s) =>
      `<span class="rv-gate-dot is-${s}" aria-hidden="true"></span>`;
    const gateRows = gates.gates
      .map(
        (g) => `<li class="rv-gate is-${g.status}">${gateIcon(g.status)}<span>${esc(g.label)}</span>${
          g.reasons.length
            ? `<span class="rv-gate-why mono">${esc(g.reasons.join(", "))}</span>`
            : ""
        }<span class="visually-hidden"> — ${g.status}</span></li>`
      )
      .join("");
    const otherRows = gates.other
      .map((r) => `<li class="rv-gate is-failed">${gateIcon("failed")}<span class="mono">${esc(r)}</span></li>`)
      .join("");
    const gateHead =
      gates.status === "pending"
        ? `<span class="vf-faint">not run yet</span>`
        : `<span class="rv-gate-count is-${gates.status}">${gates.passed}/${gates.total}</span>`;

    const judges = H ? H.disproveJudges(f) : [];
    const badges = window.ReportStateBadges;
    const llm = llmVerifyMeta(f);
    const sameModel =
      llm && badges && typeof badges.sameModelOnBothPerspectives === "function"
        ? badges.sameModelOnBothPerspectives(llm.verifiers)
        : false;
    const weak = sameModel
      ? (badges.SAME_MODEL_WEAK_SIGNAL || "Same model on both perspectives — weak signal; not exploit proof.")
      : "Disprove can only demote a finding. It is not exploit proof and never confirms.";
    const judgeCards = judges.length
      ? judges
          .map(
            (j) => `<div class="rv-judge is-${j.tone}">
              <div class="rv-judge-head"><span class="vf-faint">${esc(j.name)}${j.model ? ` · <span class="mono">${esc(j.model)}</span>` : ""}</span><strong>${esc(j.label)}</strong></div>
              ${
                j.note
                  ? `<details class="rv-judge-note"><summary>${esc(j.note.slice(0, 160))}${j.note.length > 160 ? "…" : ""}</summary><pre class="mono">${esc(j.note.slice(0, 2000))}</pre></details>`
                  : `<p class="vf-faint">No reasoning recorded.</p>`
              }
            </div>`
          )
          .join("")
      : `<p class="vf-faint">${
          b.validation_mech && b.validation_mech.pending_llm
            ? "Dual disprove is queued or running."
            : "Disprove has not run for this finding."
        }</p>`;

    const eid = f.evidence_id || b.evidence_id;
    const evRel = preferredEvidenceRel(f);
    const poc = H ? H.pocStatus(f) : { text: "" };
    const st = String(f.state || "").toLowerCase();
    const decided = !(st === "needs_human" || st === "candidate");
    const reviews = Array.isArray(b.human_review) ? b.human_review : [];
    const reviewHist =
      reviews.length > 0
        ? `<details class="rv-history"><summary>Review history (${reviews.length})</summary><ul>${reviews
            .slice()
            .reverse()
            .slice(0, 10)
            .map(
              (r) =>
                `<li class="mono">${esc(r.at || "")} · ${esc(r.from_state || "?")} → ${esc(
                  r.to_state || "?"
                )} · ${esc(r.action || "")}${
                  r.evidence_tier ? ` · tier ${esc(r.evidence_tier)}` : ""
                }${
                  r.notes ? ` — ${esc(String(r.notes).slice(0, 160))}` : ""
                }</li>`
            )
            .join("")}</ul></details>`
        : "";
    const tierPill = tierPillHtml(f);
    const tierInfo = H && typeof H.tierOf === "function" ? H.tierOf(f) : null;
    const tierSection = tierPill
      ? `<section class="rv-tier-block">
          <h3 class="vf-section-label">Evidence tier</h3>
          <div class="rv-row">${tierPill}</div>
          <p class="rv-note">${esc(tierInfo ? tierInfo.summary : "")}</p>
          <p class="rv-note vf-faint">A label for queue order. It does not change state or severity and does not confirm.</p>
        </section>`
      : "";
    return `
      <div class="rv-verdict-inner" data-fid="${f.id}">
        ${tierSection}
        <section>
          <h3 class="vf-section-label">Mechanical gates ${gateHead}</h3>
          <ul class="rv-gates">${gateRows}${otherRows}</ul>
        </section>
        <section>
          <h3 class="vf-section-label">Adversarial disprove ${llm ? `<span class="mono rv-llm-label">${esc(llm.label)}</span>` : ""}</h3>
          <div class="rv-judges">${judgeCards}</div>
          <p class="rv-note" ${sameModel ? 'data-llm-weak-signal="same-model"' : ""}>${esc(weak)}</p>
        </section>
        <section>
          <h3 class="vf-section-label">Evidence &amp; PoC</h3>
          ${
            eid
              ? `<button type="button" class="rv-link mono report-open-ev" data-pack="${esc(String(eid))}" data-rel="${esc(evRel || "")}">evidence/${esc(String(eid))}/</button>`
              : `<p class="vf-faint">${b.no_poc ? "no_poc recorded" : "No evidence pack linked."}</p>`
          }
          <p class="rv-poc is-${esc(poc.tone || "none")}">${esc(poc.text || "")}</p>
          <div class="rv-row">
            <button type="button" class="vf-btn report-develop-poc" data-fid="${f.id}" title="Open the PoC workshop: draft, run in sandbox, iterate">Develop PoC</button>
            <button type="button" class="vf-btn vf-btn--ghost report-track-one" data-fid="${f.id}" title="Preview, then publish this finding as an external issue (outward-facing)">Track…</button>
          </div>
          ${trackedLinksHtml(f)}
        </section>
        <section class="rv-decide vf-card">
          <label class="rv-note-label" for="report-review-notes-${f.id}">Reviewer note (optional)</label>
          <textarea id="report-review-notes-${f.id}" class="report-review-notes" rows="3" placeholder="Why you accepted or rejected this finding…"></textarea>
          <label class="rv-check">
            <input type="checkbox" id="report-review-write-ev-${f.id}" checked />
            Also write the note into the evidence pack
          </label>
          ${acceptPendingHintHtml(f)}
          <div class="rv-decide-actions">
            <button type="button" class="vf-btn vf-btn--primary vf-btn--lg report-review-btn" data-action="confirm" data-fid="${f.id}"${acceptButtonAttrs(f)}>Accept <kbd class="vf-kbd">A</kbd></button>
            <button type="button" class="vf-btn vf-btn--danger vf-btn--lg report-review-btn" data-action="reject" data-fid="${f.id}">Reject <kbd class="vf-kbd">R</kbd></button>
          </div>
          ${
            decided
              ? `<button type="button" class="vf-btn vf-btn--ghost report-review-btn" data-action="needs_human" data-fid="${f.id}">Move back to needs review</button>`
              : ""
          }
          ${
            window.ReportPolicyPromote && window.ReportPolicyPromote.canPromote(f)
              ? `<button type="button" class="vf-btn vf-btn--ghost report-promote-policy-btn" data-fid="${f.id}" title="Draft a security-policy rule from this reject (edit, then Save; nothing is applied until you save)">Promote to policy</button>`
              : ""
          }
          <p class="rv-note">Accepting marks the finding confirmed. It does not prove the finding is exploitable.</p>
          ${reviewHist}
        </section>
      </div>`;
  }

  async function loadContextCode(f, token) {
    const host = $("#report-ctx-code");
    if (!host) return;
    const b = bodyOf(f);
    const cites = (b.citations || []).filter((c) => c && c.path);
    const primary = cites[0];
    if (!primary) return;
    const tid = meta.target_id;
    const rid = meta.run_id;
    if (!tid || !rid) {
      host.innerHTML = `<div class="controls-hint">No run loaded.</div>`;
      return;
    }
    try {
      const data = await callApi(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/target/read?path=${encodeURIComponent(primary.path)}`
      );
      if (token !== contextToken) return;
      const lines = String(data.content || "").split("\n");
      const base = data.start_line || 1;
      // Every citation in this file, tagged by its data-flow role (source / sink / flow).
      const H = RH();
      const trace = H ? H.buildTrace(b) : [];
      const ranges = cites
        .filter((c) => c.path === primary.path && c.start_line != null)
        .map((c, i) => {
          const s = Number(c.start_line);
          const e = c.end_line != null ? Number(c.end_line) : s;
          const step = trace.find((x) => x.path === c.path && x.line === s);
          return { s, e, kind: step ? step.kind : i === 0 ? "source" : "sink" };
        });
      const focus = ranges.length ? Math.min(...ranges.map((r) => r.s)) : null;
      const end = ranges.length ? Math.max(...ranges.map((r) => r.e)) : focus;
      const windowPad = 4;
      let from = 0;
      let to = Math.min(lines.length, 40);
      if (focus != null) {
        from = Math.max(0, focus - base - windowPad);
        to = Math.min(lines.length, Math.min(end, focus + 80) - base + 1 + windowPad);
      }
      const roleOf = (n) => {
        const hit = ranges.filter((r) => n >= r.s && n <= r.e);
        if (!hit.length) return "";
        return hit.some((r) => r.kind === "sink" || r.kind === "cited") ? " is-cite is-sink" : " is-cite is-src";
      };
      const slice = lines.slice(from, to);
      if (!slice.length || (focus != null && focus - base >= lines.length)) {
        host.innerHTML = `<div class="vf-empty">Cited line ${esc(String(focus ?? ""))} is outside the file (${lines.length} lines).</div>`;
        return;
      }
      host.innerHTML = `
        <pre class="report-ctx-pre rv-code-pre">${slice
          .map((ln, i) => {
            const n = base + from + i;
            const hl = roleOf(n);
            return `<div class="code-line${hl}" data-line="${n}"><span class="ln">${n}</span><span class="tx">${esc(ln)}</span></div>`;
          })
          .join("")}</pre>`;
    } catch (e) {
      if (token !== contextToken) return;
      host.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message || e)}</div>`;
    }
  }

  async function loadContextEvidence(pack, rel, token) {
    const host = $("#report-ctx-evidence");
    if (!host || !pack || !rel) return;
    const tid = meta.target_id;
    const rid = meta.run_id;
    if (!tid || !rid) return;
    const myToken = token == null ? contextToken : token;
    host.innerHTML = `<div class="controls-hint">Loading ${esc(rel)}…</div>`;
    try {
      const data = await callApi(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/evidence/${encodeURIComponent(pack)}/${rel
          .split("/")
          .map(encodeURIComponent)
          .join("/")}`
      );
      if (myToken !== contextToken) return;
      const content = String(data.content ?? "");
      const clipped = content.length > 4000 ? content.slice(0, 4000) + "\n…" : content;
      host.innerHTML = `
        <div class="report-ctx-code-head mono">${esc(pack)} / ${esc(rel)}</div>
        <pre class="report-ctx-pre report-ctx-ev-pre">${esc(clipped)}</pre>`;
    } catch (e) {
      if (myToken !== contextToken) return;
      host.innerHTML = `<div class="empty" style="color:var(--bad)">${esc(e.message || e)}</div>`;
    }
  }

  function renderContext(f) {
    const c = $("#report-context");
    if (!c) return;
    if (!f) {
      c.innerHTML = emptyContextHtml();
      return;
    }
    contextToken += 1;
    const token = contextToken;
    c.innerHTML = verdictHtml(f);
    bindDetailActions(c);
    loadContextCode(f, token);
    const rel = preferredEvidenceRel(f);
    const eid = f.evidence_id || bodyOf(f).evidence_id;
    if (eid && rel) loadContextEvidence(String(eid), rel, token);
  }


    function preferredEvidenceRel(f) {
    const b = bodyOf(f);
    const eid = f.evidence_id || b.evidence_id;
    if (!eid) return null;
    const packs = window.__VF_last_snap?.evidence || [];
    const pack = packs.find((p) => String(p.id) === String(eid));
    const names = ((pack && pack.files) || []).map((x) => x.relpath || x);
    if (b.poc_relpath && names.includes(b.poc_relpath)) return b.poc_relpath;
    const md = names.find((n) => /\.md$/i.test(n));
    if (md) return md;
    return names[0] || null;
  }

  function sevTagHtml(f) {
    const H = RH();
    const k = H ? H.sevKey(f) : "";
    const label = H ? H.sevLabel(f) : String(f.severity || bodyOf(f).severity_claim || "unknown");
    return `<span class="vf-sev${k ? " vf-sev--" + k : ""}">${esc(label)}</span>`;
  }

  /**
   * Evidence tier pill (derived label from the server; never a state). A PoC run that
   * did not raise the tier is shown beside it. Empty when the API sent no tier.
   */
  function tierPillHtml(f, opts) {
    const H = RH();
    const t = H && typeof H.tierPill === "function" ? H.tierPill(f) : null;
    if (!t) return "";
    const bars = [1, 2, 3]
      .map((i) => `<i class="${i <= t.steps ? "is-on" : ""}"></i>`)
      .join("");
    const side =
      t.side && !(opts && opts.noSide)
        ? ` <span class="rv-tier-side mono" title="Latest sandbox run did not raise the tier">${esc(t.side)}</span>`
        : "";
    return `<span class="vf-pill rv-tier is-${esc(t.tier)}" data-tier="${esc(t.tier)}" title="${esc(
      t.title
    )}"><span class="rv-tier-bars" aria-hidden="true">${bars}</span>${esc(t.label)}</span>${side}`;
  }

  /** Current state only (never the trail) — queue rows and the finding header. */
  function statePill(f) {
    const H = RH();
    const p = H ? H.statePill(f) : { tone: "candidate", label: String(f.state || "") };
    const tip =
      typeof window.stateTip === "function" ? window.stateTip(String(f.state || ""), f) : "";
    return `<span class="vf-pill vf-pill--${p.tone}" title="${esc(tip)}">${esc(p.label)}</span>`;
  }

  function overlapsHtml(f) {
    const cm = clusterByFinding[f.id];
    if (!cm) return "";
    const c = clustersCache.find((x) => String(x.cluster_id) === String(cm.cluster_id));
    if (!c) return "";
    const others = (c.members || []).filter((m) => Number(m.id) !== Number(f.id));
    if (!others.length) return "";
    const isPrimary = Number(c.primary_id) === Number(f.id);
    const rows = others
      .map(
        (m) =>
          `<li><button type="button" class="rv-link report-open-related" data-fid="${m.id}">#${m.id}</button> <span class="vf-faint">${esc(m.title || "")}</span></li>`
      )
      .join("");
    return `<section class="vf-card rv-overlaps" aria-label="Overlapping findings">
      <h3 class="vf-section-label">Overlaps with ${others.length} finding${others.length === 1 ? "" : "s"} <span class="mono vf-faint">${esc(c.strength || "overlap")}</span></h3>
      <ul>${rows}</ul>
      <div class="rv-row">
        ${
          isPrimary
            ? ""
            : `<button type="button" class="vf-btn report-merge-into" data-keep="${c.primary_id}" data-drop="${f.id}" title="Supersede this finding by the cluster primary">Merge into #${c.primary_id}</button>`
        }
        <button type="button" class="vf-btn vf-btn--ghost report-ask-ai-cluster" data-cluster="${esc(c.cluster_id || "")}">Ask AI to compare</button>
      </div>
    </section>`;
  }

  /** Finding column: header, summary, data flow, cited code, overlaps, evidence preview. */
  /** Operator security policy effects on this finding (exclusion, severity cap, disprove cites). */
  function policyDetailHtml(b) {
    const items = [];
    const m = b && b.policy_match;
    if (m && typeof m === "object") {
      const kind = m.kind === "out_of_scope" ? "Out of scope" : "Excluded";
      const paths = (m.matched_paths || []).map((p) => `<code>${esc(p)}</code>`).join(", ");
      items.push(
        `<li><strong>${esc(kind)}</strong> by rule <code>${esc(m.rule_id || "?")}</code>` +
          (m.policy_revision != null ? ` (policy rev ${esc(m.policy_revision)})` : "") +
          `: ${esc(m.reason || "")}${paths ? `<br><span class="vf-faint">Cited paths: ${paths}</span>` : ""}</li>`
      );
    }
    const sr = b && b.severity_rubric;
    if (sr && typeof sr === "object" && sr.action === "capped") {
      items.push(
        `<li><strong>Severity capped</strong> ${esc(sr.from || b.severity_claim_original || "?")} → ${esc(
          sr.to || b.severity_claim || "?"
        )} by rubric rule <code>${esc(sr.rule_id || "?")}</code>${sr.criteria ? ` — ${esc(sr.criteria)}` : ""}</li>`
      );
    } else if (sr && typeof sr === "object" && sr.rule_id) {
      items.push(
        `<li>Severity within rubric rule <code>${esc(sr.rule_id)}</code> (max ${esc(sr.max_severity || "?")})</li>`
      );
    }
    const cited = (b && b.validation_llm && b.validation_llm.policy_rules_cited) || [];
    if (Array.isArray(cited) && cited.length) {
      items.push(
        `<li>Disprove cited policy rule(s): ${cited.map((r) => `<code>${esc(r)}</code>`).join(", ")}</li>`
      );
    }
    if (!items.length) return "";
    return `<section class="vf-card rv-policy" aria-label="Security policy"><h3 class="vf-section-label">Security policy</h3><ul class="report-reasons report-policy">${items.join("")}</ul></section>`;
  }

  function detailHtml(f) {
    const H = RH();
    const b = bodyOf(f);
    const tm = b.threat_model || {};
    const st = String(f.state || "").toLowerCase();
    const rejected = st.startsWith("rejected") || st === "superseded";
    const reasonsBox =
      rejected && typeof window.formatValidationReasonsHtml === "function"
        ? window.formatValidationReasonsHtml(f)
        : "";
    const cm = clusterByFinding[f.id];
    const near =
      f.near_dup || cm
        ? `<span class="vf-pill" title="Near-duplicate / overlap">near-dup${cm && cm.label ? " " + esc(cm.label) : ""}</span>`
        : "";
    const age = H ? H.ageLabel(f.created_at) : "";
    const hunt = b.task_id ?? b.hunt_task_id ?? b.source_task_id;
    const filed = [hunt != null ? `filed by hunt #${esc(String(hunt))}` : "", age]
      .filter(Boolean)
      .join(" · ");
    const trace = H ? H.buildTrace(b) : [];
    const traceCards = trace
      .map(
        (s) => `<li><button type="button" class="rv-trace-card report-cite" data-path="${esc(s.path)}" data-line="${s.line ?? ""}" title="Open in Atlas">
            <span class="rv-trace-kind is-${esc(s.kind)}">${esc(s.kind)}</span>
            <span class="mono rv-trace-what">${esc(s.what)}</span>
            <span class="mono vf-faint rv-trace-where">${esc(s.where)}</span>
          </button></li>`
      )
      .join("");
    const primary = (b.citations || []).find((c) => c && c.path) || null;
    const eid = f.evidence_id || b.evidence_id;
    const packs = window.__VF_last_snap?.evidence || [];
    const pack = eid ? packs.find((x) => String(x.id) === String(eid)) : null;
    const files = ((pack && pack.files) || []).map((x) => x.relpath || x);
    const fileChips = files
      .slice(0, 12)
      .map(
        (rel) =>
          `<button type="button" class="vf-chip report-ctx-ev" data-pack="${esc(String(eid))}" data-rel="${esc(rel)}">${esc(rel)}</button>`
      )
      .join(" ");
    const nearMod = nearestModuleForPath(primary && primary.path);
    const moa = huntMoaDetailHtml(f);
    // Policy fields are harness-written by validate_mech; ignore them before it ran.
    const policyTrusted = st !== "candidate";
    const policyBox = policyTrusted ? policyDetailHtml(b) : "";
    const policyPill =
      policyTrusted && b.policy_match
        ? `<span class="vf-pill badge policy" title="Matched an operator security policy rule">policy ${esc(b.policy_match.rule_id || "")}</span>`
        : "";
    return `
      <div class="report-detail-inner rv-finding-inner" data-fid="${f.id}">
        <header class="rv-finding-head">
          <div class="rv-row rv-meta">
            ${sevTagHtml(f)}
            ${statePill(f)}
            <span class="vf-faint">${esc(b.weakness_class || "unclassified")}</span>
            ${near}
            ${huntMoaBadgeHtml(f)}
            ${policyPill}
            <span class="vf-faint">#${f.id}${filed ? " · " + filed : ""}</span>
          </div>
          <h2 class="rv-title">${esc(b.title || f.stable_key || "Finding #" + f.id)}</h2>
          <p class="rv-summary">${esc(b.summary || "No summary.")}</p>
          ${reasonsBox}
        </header>
        ${policyBox}
        <dl class="rv-threat">
          <div><dt>Attacker</dt><dd>${esc(tm.attacker || "—")}</dd></div>
          <div><dt>Boundary</dt><dd>${esc(tm.boundary || "—")}</dd></div>
          <div><dt>Impact</dt><dd>${esc(tm.impact || "—")}</dd></div>
        </dl>
        <section class="vf-card" aria-label="Data flow">
          <h3 class="vf-section-label">Data flow ${
            trace.length && trace[0].derived ? '<span class="rv-derived">from citations</span>' : ""
          }</h3>
          ${traceCards ? `<ol class="rv-trace">${traceCards}</ol>` : '<p class="vf-faint">No citations or trace recorded.</p>'}
        </section>
        <section class="rv-code" aria-label="Cited code">
          <div class="rv-code-head">
            <span class="mono">${esc(primary ? pathLabel(primary) : "No cited file")}</span>
            ${
              primary
                ? `<button type="button" class="rv-link report-cite" data-path="${esc(primary.path)}" data-line="${primary.start_line ?? ""}">Open in Atlas</button>`
                : ""
            }
          </div>
          <div id="report-ctx-code" class="report-ctx-code">${
            primary ? `<div class="vf-empty">Loading ${esc(pathLabel(primary))}…</div>` : ""
          }</div>
        </section>
        <section class="vf-card report-owners" data-fid="${f.id}" aria-label="Suggested owners" hidden></section>
        ${overlapsHtml(f)}
        ${moa ? `<details class="rv-more"><summary>Hunt perspectives</summary>${moa}</details>` : ""}
        <details class="rv-more" id="rv-evidence-preview">
          <summary>Evidence preview${eid ? ` <span class="mono vf-faint">${esc(String(eid))}</span>` : ""}</summary>
          ${fileChips ? `<div class="rv-row rv-wrap">${fileChips}</div>` : '<p class="vf-faint">No files in the pack.</p>'}
          <div id="report-ctx-evidence" class="report-ctx-evidence"></div>
        </details>
        <p class="vf-faint rv-ident mono">${esc(f.stable_key || "")}${nearMod && nearMod.path ? " · module " + esc(String(nearMod.path)) : ""}</p>
      </div>`;
  }
  /** Same sentence as report_state_badges.js ACCEPT_PENDING_COPY. */
  const ACCEPT_PENDING_COPY =
    "Dual disprove still running — Accept after it settles, or Reject now.";

  function acceptPendingCopy() {
    const H = window.ReportStateBadges;
    if (H && typeof H.ACCEPT_PENDING_COPY === "string" && H.ACCEPT_PENDING_COPY) {
      return H.ACCEPT_PENDING_COPY;
    }
    return ACCEPT_PENDING_COPY;
  }

  function acceptBlockedByPending(f) {
    const H = window.ReportStateBadges;
    if (H && typeof H.acceptBlockedByPendingLlm === "function") {
      return !!H.acceptBlockedByPendingLlm(f);
    }
    const b = bodyOf(f);
    return !!(b.validation_mech && b.validation_mech.pending_llm);
  }

  function acceptPendingHintHtml(f) {
    if (!acceptBlockedByPending(f)) return "";
    return `<p class="controls-hint report-accept-pending" role="status">${esc(acceptPendingCopy())}</p>`;
  }

  function acceptButtonAttrs(f) {
    if (!acceptBlockedByPending(f)) return "";
    return ` disabled aria-disabled="true" title="${esc(acceptPendingCopy())}"`;
  }

  async function submitReview(fid, action, root) {
    const finding = cache.find((x) => Number(x.id) === Number(fid));
    if (
      (action === "confirm" || action === "accept") &&
      finding &&
      acceptBlockedByPending(finding)
    ) {
      toast(acceptPendingCopy(), true);
      return;
    }
    const notesEl = root.querySelector(`#report-review-notes-${fid}`);
    const writeEl = root.querySelector(`#report-review-write-ev-${fid}`);
    const notes = notesEl ? notesEl.value : "";
    const write_note_to_evidence = writeEl ? !!writeEl.checked : true;
    const tid = meta.target_id;
    const rid = meta.run_id;
    if (!tid || !rid) {
      toast("No run loaded", true);
      return;
    }
    const api = typeof window.api === "function" ? window.api : null;
    if (!api) {
      toast("API unavailable", true);
      return;
    }
    try {
      const r = await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/review`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action,
            notes,
            write_note_to_evidence,
            operator: "operator",
          }),
        }
      );
      toast(
        action === "confirm"
          ? `Finding #${fid} confirmed`
          : action === "reject"
            ? `Finding #${fid} rejected`
            : `Finding #${fid} marked needs human review`
      );
      // Move to the next undecided finding (triage flow); stay put for reclassify.
      const H = RH();
      const next =
        action === "needs_human" || !H ? null : H.nextUndecided(sortedFindings(), fid);
      openId = next != null ? Number(next) : Number(fid);
      if (typeof window.loadRunFull === "function") {
        await window.loadRunFull();
      } else if (r && r.finding) {
        const idx = cache.findIndex((x) => Number(x.id) === Number(fid));
        if (idx >= 0) {
          cache[idx] = {
            ...cache[idx],
            state: r.to_state,
            evidence_id: r.evidence_id || cache[idx].evidence_id,
            body: r.finding.body || cache[idx].body,
            evidence_tier: r.finding.evidence_tier || cache[idx].evidence_tier,
          };
        }
        renderSummary();
        renderTable();
        const f = cache.find((x) => Number(x.id) === Number(fid));
        if (f) showFindingDetail(f);
      }
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  const POC_CODE_RE = /\.(py|sh|ps1|c|go|js|rb|rs)$/i;
  /** Last GET /poc payload for artifacts (pack_files / poc_code_files). */
  let pocLastLoad = null;

  function setPocStatus(msg, isErr) {
    const el = $("#poc-status");
    if (!el) return;
    el.textContent = msg || "";
    el.classList.toggle("err", !!isErr);
  }

  function isPocCodeFile(name) {
    return POC_CODE_RE.test(String(name || ""));
  }

  function openPocEvidence(pack, rel) {
    if (!pack) {
      toast("Save first to create an evidence pack", true);
      return;
    }
    // Leave workshop when jumping to Evidence
    if (isPocOpen()) {
      closeDevelopPoc({ stayOnReport: false, skipHash: true });
    }
    if (window.VulnForgeModes?.goEvidence) {
      window.VulnForgeModes.goEvidence(String(pack), rel || undefined);
    } else {
      window.VulnForgeModes?.setMode?.("evidence");
      if (rel && typeof window.openEvidenceFile === "function") {
        window.openEvidenceFile(String(pack), rel);
      }
    }
  }

  function buildPocOperatorNotes() {
    const notesEl = $("#poc-notes");
    const langEl = $("#poc-lang");
    const raw = notesEl ? String(notesEl.value || "").trim() : "";
    const lang = langEl ? String(langEl.value || "auto") : "auto";
    const parts = [];
    if (lang && lang !== "auto") {
      const map = {
        python: "Language preference: python (write poc.py)",
        bash: "Language preference: bash (write poc.sh)",
        powershell: "Language preference: powershell (write poc.ps1)",
        c: "Language preference: c (write poc.c)",
      };
      parts.push(map[lang] || `Language preference: ${lang}`);
    }
    if (raw) parts.push(raw);
    return parts.join("\n");
  }

  function renderPocArtifacts(r, f) {
    const box = $("#poc-artifacts");
    const meta = $("#poc-artifacts-meta");
    if (!box) return;
    const b = f ? bodyOf(f) : {};
    const pack =
      (r && (r.evidence_id || r.pack_id_proposed)) ||
      (f && (f.evidence_id || b.evidence_id)) ||
      null;
    const packFiles = Array.isArray(r?.pack_files)
      ? r.pack_files
      : [];
    const bodyCodes = Array.isArray(b.poc_code_files) ? b.poc_code_files.map(String) : [];
    const apiCodes = Array.isArray(r?.poc_code_files) ? r.poc_code_files.map(String) : [];
    const codeSet = new Set(
      [...apiCodes, ...bodyCodes, ...packFiles.filter(isPocCodeFile)].map(String)
    );
    const codes = [...codeSet].sort();
    const others = packFiles
      .map(String)
      .filter((n) => !codeSet.has(n) && n !== "poc_develop.md");
    const hubName = (r && r.poc_relpath) || b.poc_relpath || "poc_develop.md";
    const hasHub = packFiles.includes(hubName) || !!(r && r.exists);

    if (meta) {
      const nCode = codes.length;
      meta.textContent =
        nCode > 0
          ? `${nCode} script${nCode === 1 ? "" : "s"} in pack`
          : "no scripts yet";
    }

    if (!codes.length && !hasHub && !others.length) {
      box.innerHTML =
        '<p class="controls-hint poc-artifacts-empty">No pack files yet. Choose a language and click <strong>Write working PoC code</strong> to queue the agent.</p>';
      return;
    }

    const chip = (name, kind) => {
      const cls =
        kind === "code"
          ? "poc-artifact-chip poc-artifact-code"
          : kind === "hub"
            ? "poc-artifact-chip poc-artifact-hub"
            : "poc-artifact-chip";
      const label = kind === "code" ? "script" : kind === "hub" ? "hub" : "file";
      return `<button type="button" class="${cls}" data-pack="${esc(
        pack || ""
      )}" data-rel="${esc(name)}" title="Open in Evidence">
        <span class="poc-artifact-kind">${label}</span>
        <span class="mono poc-artifact-name">${esc(name)}</span>
      </button>`;
    };

    const parts = [];
    if (codes.length) {
      parts.push(
        `<div class="poc-artifact-group"><span class="poc-artifact-group-label">Scripts</span><div class="poc-artifact-chips">${codes
          .map((n) => chip(n, "code"))
          .join("")}</div></div>`
      );
    } else {
      parts.push(
        `<div class="poc-artifact-group"><span class="poc-artifact-group-label">Scripts</span><p class="controls-hint poc-artifacts-empty" style="margin:0.25rem 0 0">None yet — agent should write <span class="mono">poc.py</span> / <span class="mono">.sh</span> / <span class="mono">.ps1</span> / <span class="mono">.c</span>.</p></div>`
      );
    }
    parts.push(
      `<div class="poc-artifact-group"><span class="poc-artifact-group-label">Hub</span><div class="poc-artifact-chips">${
        hasHub
          ? chip(hubName, "hub")
          : `<span class="controls-hint">not saved yet</span>`
      }</div></div>`
    );
    if (others.length) {
      parts.push(
        `<div class="poc-artifact-group"><span class="poc-artifact-group-label">Other</span><div class="poc-artifact-chips">${others
          .map((n) => chip(n, "other"))
          .join("")}</div></div>`
      );
    }
    box.innerHTML = parts.join("");
    box.querySelectorAll(".poc-artifact-chip").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = btn.getAttribute("data-pack");
        const rel = btn.getAttribute("data-rel");
        if (!p) {
          toast("Save first to create an evidence pack", true);
          return;
        }
        openPocEvidence(p, rel);
      });
    });
  }

  function isPocOpen() {
    const modal = $("#poc-modal");
    if (!modal) return false;
    // Visibility is driven by CSS .modal-backdrop.open { display:flex }
    return modal.classList.contains("open");
  }

  function showPocModal() {
    const modal = $("#poc-modal");
    if (!modal) return;
    modal.hidden = false;
    modal.classList.add("open");
  }

  // Ensure closed state on load (hidden attr + no .open)
  (function bootPocModalClosed() {
    const modal = $("#poc-modal");
    if (!modal) return;
    if (!modal.classList.contains("open")) {
      modal.hidden = true;
    }
  })();

  /**
   * @param {{ stayOnReport?: boolean, skipHash?: boolean }} [opts]
   */
  function closeDevelopPoc(opts) {
    if (pocSessionTimer) {
      clearInterval(pocSessionTimer);
      pocSessionTimer = null;
    }
    const modal = $("#poc-modal");
    if (modal) {
      modal.classList.remove("open");
      modal.hidden = true;
    }
    const fid = pocFindingId;
    pocFindingId = null;
    if (!opts || !opts.skipHash) {
      try {
        history.replaceState(null, "", "#report/report");
      } catch {
        /* ignore */
      }
    }
    if (opts && opts.stayOnReport === false) {
      return;
    }
    window.VulnForgeModes?.setMode?.("report", "report");
    if (fid != null) openFinding(fid);
  }

  function setupPocChrome() {
    if (pocChromeBound) return;
    const shell = $("#poc-modal") || $(".poc-shell");
    if (!shell) return;
    pocChromeBound = true;
    $("#poc-back-report")?.addEventListener("click", () => {
      closeDevelopPoc();
    });
    $("#poc-modal")?.addEventListener("click", (ev) => {
      // Click backdrop (not dialog) closes
      if (ev.target && ev.target.id === "poc-modal") closeDevelopPoc();
    });
    $("#poc-generate")?.addEventListener("click", () => {
      if (pocFindingId != null) savePocDraft(pocFindingId, { enqueue_agent: true });
    });
    $("#poc-save")?.addEventListener("click", () => {
      if (pocFindingId != null) savePocDraft(pocFindingId, { enqueue_agent: false });
    });
    $("#poc-reload")?.addEventListener("click", () => {
      if (pocFindingId != null) loadPocDraft(pocFindingId);
    });
    $("#poc-open-ev")?.addEventListener("click", () => {
      if (pocFindingId == null) return;
      const f = cache.find((x) => Number(x.id) === Number(pocFindingId));
      if (!f) {
        toast("Finding not loaded", true);
        return;
      }
      const b = bodyOf(f);
      const pack = f.evidence_id || b.evidence_id || pocLastLoad?.evidence_id;
      const codes = (pocLastLoad?.poc_code_files || b.poc_code_files || []).filter(
        Boolean
      );
      const rel =
        (codes && codes[0]) || b.poc_relpath || "poc_develop.md";
      openPocEvidence(pack, rel);
    });
    $("#poc-validate")?.addEventListener("click", () => {
      if (pocFindingId != null) enqueueValidatePoc(pocFindingId);
    });
    $("#poc-iterate")?.addEventListener("click", () => {
      if (pocFindingId != null) enqueueIteratePoc(pocFindingId);
    });
    $("#poc-steer-send")?.addEventListener("click", () => {
      if (pocFindingId != null) sendPocSteer(pocFindingId);
    });
    $("#poc-session-stop")?.addEventListener("click", () => {
      if (pocFindingId != null) stopPocSession(pocFindingId);
    });
    $("#poc-export-job")?.addEventListener("click", () => {
      if (pocFindingId != null) exportValidationJob(pocFindingId);
    });
  }

  function renderPocReadiness(r) {
    const el = $("#poc-readiness");
    if (!el) return;
    const ready = r && (r.harness_ready || r.readiness?.ready);
    const readiness = (r && r.readiness) || {};
    const issues = readiness.issues || [];
    const warnings = readiness.warnings || [];
    const latest = r && r.poc_validation_latest;
    const harness = (r && r.harness) || (latest && latest.harness) || {};
    const parts = [];
    if (ready) {
      parts.push('<span class="badge ok">Harness ready</span>');
    } else {
      parts.push('<span class="badge warn">Not harness-ready</span>');
    }
    if (harness.iterate_max_cycles || harness.iterate_wall_ttl_min) {
      parts.push(
        `<span class="controls-hint">iterate cap ${esc(
          String(harness.iterate_max_cycles || 5)
        )} cycles · ${esc(String(harness.iterate_wall_ttl_min || 15))} min</span>`
      );
    }
    if (harness.runner || harness.network || harness.isolation) {
      const runLabel = harness.isolation || harness.runtime || harness.runner || "sandbox";
      const netLabel = harness.network || "none";
      let harnessBadge = `<span class="badge info mono" title="Sandbox one-shot (microVM or gVisor). Does not confirm.">${esc(
        runLabel
      )} · net=${esc(netLabel)}</span>`;
      if (harness.sandbox_available === false) {
        const tip = harness.operator_hint || "Install Kata or gVisor runsc. Host exec is refused.";
        harnessBadge += ` <span class="badge warn" title="${esc(tip)}">Sandbox unavailable</span>`;
      }
      parts.push(harnessBadge);
    }
    if (issues.length) {
      parts.push(
        `<span class="controls-hint">issues: ${esc(issues.join(", "))}</span>`
      );
    }
    if (warnings.length) {
      parts.push(
        `<span class="controls-hint">warnings: ${esc(warnings.join(", "))}</span>`
      );
    }
    if (latest && latest.verdict) {
      const hint =
        latest.operator_hint || latest.spawn_error
          ? ` (${esc(String(latest.operator_hint || latest.spawn_error))})`
          : "";
      const phrase =
        String(latest.verdict) === "signal_observed"
          ? "sandbox reproduced · signal observed"
          : String(latest.verdict).split("_").join(" ");
      parts.push(
        `<span class="controls-hint">last run: <span class="mono">${esc(
          phrase
        )}</span>${hint}</span>`
      );
    } else if (latest && latest.action === "enqueue_validate" && latest.task_id) {
      parts.push(
        `<span class="controls-hint">validate_poc queued #${esc(
          String(latest.task_id)
        )}</span>`
      );
    }
    el.innerHTML = parts.join(" · ");
  }

  async function enqueueValidatePoc(fid) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const api = typeof window.api === "function" ? window.api : null;
    if (!tid || !rid || !api) {
      toast("API unavailable", true);
      return;
    }
    const notes = buildPocOperatorNotes();
    setPocStatus("Queuing sandbox one-shot…");
    try {
      const r = await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/validate-poc`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            operator: "operator",
            operator_notes: notes,
          }),
        }
      );
      const msg = r.task_id
        ? `Queued sandbox one-shot #${r.task_id} — evidence only, does not confirm`
        : "sandbox one-shot enqueued";
      toast(msg);
      setPocStatus(msg);
      if (typeof window.loadRunFull === "function") {
        await window.loadRunFull();
        loadPocDraft(fid).catch(() => {});
      }
    } catch (e) {
      setPocStatus(e.message || String(e), true);
      toast(e.message || String(e), true);
    }
  }

  function renderPocSession(view) {
    const metaEl = $("#poc-session-meta");
    const logEl = $("#poc-session-log");
    if (!logEl) return;
    const session = view && view.session;
    const steers = (view && view.steers) || [];
    if (!session) {
      if (metaEl) metaEl.textContent = steers.length ? "Steer queued" : "No session yet";
      const queued = steers.map((s) => `steer #${s.seq}: ${s.text}`).join("\n");
      logEl.textContent = queued || "No sandbox session yet.";
      return;
    }
    const state = session.state || "unknown";
    const reason = session.end_reason ? ` · ${session.end_reason}` : "";
    const cap = `${session.cycles_run || 0}/${session.max_cycles || 5}`;
    const iso = session.isolation || session.runtime || "sandbox";
    if (metaEl) {
      metaEl.textContent = `${state}${reason} · ${iso} · cycles ${cap} · ttl ${session.wall_ttl_min || 15}m`;
    }
    const lines = [];
    lines.push(
      `${iso} guest ${session.guest_id || "—"} · ${session.hold_mode || "session"} · host exec no · confirms no`
    );
    (session.cycles || []).forEach((c) => {
      lines.push(
        `#${c.n} ${c.verdict || "?"} exit=${c.exit_code == null ? "—" : c.exit_code}` +
          (c.rewrite_files && c.rewrite_files.length ? ` rewrite ${c.rewrite_files.join(",")}` : "") +
          (c.steer_seqs && c.steer_seqs.length ? ` steer ${c.steer_seqs.join(",")}` : "")
      );
      if (c.stdout_excerpt) lines.push(String(c.stdout_excerpt).slice(0, 500));
    });
    if (!session.cycles || !session.cycles.length) {
      lines.push(session.operator_hint || "Session has no cycles yet.");
    }
    steers.forEach((s) => {
      lines.push(`steer #${s.seq} ${s.operator || ""}: ${s.text}`);
    });
    logEl.textContent = lines.join("\n");
  }

  function startPocSessionPoll() {
    if (pocSessionTimer) clearInterval(pocSessionTimer);
    const tick = () => {
      if (!isPocOpen() || pocFindingId == null) return;
      refreshPocSession(pocFindingId);
    };
    tick();
    pocSessionTimer = setInterval(tick, 2000);
  }

  async function refreshPocSession(fid) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const api = typeof window.api === "function" ? window.api : null;
    if (!tid || !rid || !api || fid == null) return;
    try {
      const r = await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/poc-session`
      );
      renderPocSession(r);
    } catch {
      /* session poll is best-effort while the workshop is open */
    }
  }

  async function enqueueIteratePoc(fid) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const api = typeof window.api === "function" ? window.api : null;
    if (!tid || !rid || !api) {
      toast("API unavailable", true);
      return;
    }
    const notes = buildPocOperatorNotes();
    setPocStatus("Queuing sandbox iterate session…");
    try {
      const r = await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/iterate-poc`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ operator: "operator", operator_notes: notes }),
        }
      );
      const msg = r.task_id
        ? `Queued iterate session #${r.task_id} — same sandbox, does not confirm`
        : "sandbox iterate enqueued";
      toast(msg);
      setPocStatus(msg);
      startPocSessionPoll();
      if (typeof window.loadRunFull === "function") {
        await window.loadRunFull();
        loadPocDraft(fid).catch(() => {});
      }
    } catch (e) {
      setPocStatus(e.message || String(e), true);
      toast(e.message || String(e), true);
    }
  }

  async function sendPocSteer(fid) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const api = typeof window.api === "function" ? window.api : null;
    const box = $("#poc-steer");
    const text = (box && box.value ? box.value : "").trim();
    if (!text) {
      toast("Write a steer note first", true);
      return;
    }
    if (!tid || !rid || !api) {
      toast("API unavailable", true);
      return;
    }
    try {
      await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/poc-session/steer`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text, operator: "operator" }),
        }
      );
      if (box) box.value = "";
      toast("Steer queued for this sandbox session");
      refreshPocSession(fid);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function stopPocSession(fid) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const api = typeof window.api === "function" ? window.api : null;
    if (!tid || !rid || !api) {
      toast("API unavailable", true);
      return;
    }
    try {
      await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/poc-session/stop`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ operator: "operator" }),
        }
      );
      toast("Stop requested — session ends without confirming");
      refreshPocSession(fid);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function exportValidationJob(fid) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const api = typeof window.api === "function" ? window.api : null;
    if (!tid || !rid || !api) {
      toast("API unavailable", true);
      return;
    }
    setPocStatus("Exporting validation job…");
    try {
      const r = await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/export-validation-job`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ as_zip: true, include_citations: true }),
        }
      );
      const ready = r.readiness?.ready ? "ready" : "not ready";
      const msg = r.zip_path
        ? `Exported zip (${ready}): ${r.zip_path}`
        : `Exported dir (${ready}): ${r.out_dir || "?"}`;
      toast(msg);
      setPocStatus(msg);
      if (r.readiness) {
        renderPocReadiness({ readiness: r.readiness, harness_ready: r.readiness.ready });
      }
    } catch (e) {
      setPocStatus(e.message || String(e), true);
      toast(e.message || String(e), true);
    }
  }

  function renderPocHistory(f) {
    const histEl = $("#poc-history");
    if (!histEl) return;
    const b = bodyOf(f);
    const hist = Array.isArray(b.poc_development) ? b.poc_development : [];
    const latest = b.poc_development_latest;
    if (!hist.length && !latest) {
      histEl.hidden = true;
      histEl.innerHTML = "";
      return;
    }
    const rows = (hist.length ? hist : latest ? [latest] : [])
      .slice()
      .reverse()
      .slice(0, 12)
      .map((e) => {
        const action = esc(e.action || e.event || "?");
        const at = esc(e.at || e.ts || "");
        const tid = e.task_id != null ? ` · task #${esc(String(e.task_id))}` : "";
        const codes = Array.isArray(e.poc_code_files) && e.poc_code_files.length
          ? ` · ${esc(e.poc_code_files.join(", "))}`
          : "";
        const note = e.notes
          ? ` — ${esc(String(e.notes).slice(0, 120))}`
          : e.operator_notes
            ? ` — ${esc(String(e.operator_notes).slice(0, 120))}`
            : "";
        return `<li class="mono">${at} · ${action}${tid}${codes}${note}</li>`;
      })
      .join("");
    histEl.hidden = false;
    histEl.innerHTML = `<h3 class="poc-section-title" style="margin-top:1rem">Activity</h3><ul class="report-reasons">${rows}</ul>
      <p class="controls-hint">After <span class="mono">develop_poc</span> finishes (Tasks tab), use <strong>Reload from disk</strong> — scripts appear under Code artifacts.</p>`;
  }

  function fillPocWorkshopHeader(f, loadResult) {
    const b = bodyOf(f);
    const title = $("#poc-title");
    const badges = $("#poc-badges");
    const pathHint = $("#poc-path-hint");
    if (title) {
      title.textContent = b.title || f.stable_key || `Finding #${f.id}`;
    }
    if (badges) {
      badges.innerHTML = `${badge(f.state, f)} ${sevBadge(
        f.severity || b.severity_claim || "unknown"
      )} <span class="badge info">${esc(b.weakness_class || "-")}</span>
        <span class="badge">#${f.id}</span>`;
    }
    const eid =
      (loadResult && (loadResult.evidence_id || loadResult.pack_id_proposed)) ||
      f.evidence_id ||
      b.evidence_id;
    const rel = (loadResult && loadResult.poc_relpath) || b.poc_relpath || "poc_develop.md";
    if (pathHint) {
      pathHint.innerHTML = eid
        ? `Pack: <span class="mono">evidence/${esc(String(eid))}/</span> · hub <span class="mono">${esc(
            rel
          )}</span>`
        : `Pack: <span class="mono">evidence/&lt;pack&gt;/</span> (created on first save) · hub <span class="mono">${esc(
            rel
          )}</span>`;
    }
    renderPocArtifacts(loadResult || pocLastLoad, f);
    renderPocHistory(f);
  }

  /**
   * Open the Develop POC workshop modal for a finding (not a workspace tab).
   * @param {number|string} fid
   * @param {{ skipLoad?: boolean }} [opts]
   */
  function openDevelopPoc(fid, opts) {
    setupPocChrome();
    const id = Number(fid);
    if (!Number.isFinite(id) || id <= 0) return;
    pocFindingId = id;
    const f = cache.find((x) => Number(x.id) === id);
    showPocModal();
    startPocSessionPoll();
    if (!f) {
      setPocStatus("Finding not in cache yet — loading Report data…", true);
      // Still open modal; snap refresh may fill later
      if (!opts || !opts.skipLoad) loadPocDraft(id);
      try {
        history.replaceState(null, "", `#poc/${id}`);
      } catch {
        /* ignore */
      }
      return;
    }
    fillPocWorkshopHeader(f, opts && opts.skipLoad ? pocLastLoad : null);
    if (!opts || !opts.skipLoad) {
      loadPocDraft(id);
    }
    try {
      history.replaceState(null, "", `#poc/${id}`);
    } catch {
      /* ignore */
    }
  }

  function refreshPocWorkshop() {
    setupPocChrome();
    if (pocFindingId == null || !isPocOpen()) return;
    openDevelopPoc(pocFindingId, { skipLoad: false });
  }

  async function loadPocDraft(fid) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const editor = $("#poc-editor");
    if (!tid || !rid || !editor) return;
    const api = typeof window.api === "function" ? window.api : null;
    if (!api) {
      setPocStatus("API unavailable", true);
      return;
    }
    setPocStatus("Loading pack…");
    try {
      const r = await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/poc`
      );
      pocLastLoad = r;
      editor.value = r.content || "";
      const f = cache.find((x) => Number(x.id) === Number(fid));
      if (f) fillPocWorkshopHeader(f, r);
      else renderPocArtifacts(r, null);
      const nCode = (r.poc_code_files || []).length;
      renderPocReadiness(r);
      if (r.exists) {
        setPocStatus(
          nCode
            ? `Loaded hub + ${nCode} script file${nCode === 1 ? "" : "s"}`
            : `Loaded hub ${r.poc_relpath || "poc_develop.md"} (no scripts yet)`
        );
      } else {
        setPocStatus(
          `Scaffold ready (not saved) — hub will be ${r.poc_relpath || "poc_develop.md"}`
        );
      }
    } catch (e) {
      setPocStatus(e.message || String(e), true);
    }
  }

  /**
   * @param {number|string} fid
   * @param {{ enqueue_agent?: boolean }} [opts]
   */
  async function savePocDraft(fid, opts) {
    const tid = meta.target_id;
    const rid = meta.run_id;
    const editor = $("#poc-editor");
    if (!tid || !rid) {
      toast("No run loaded", true);
      return;
    }
    const api = typeof window.api === "function" ? window.api : null;
    if (!api) {
      toast("API unavailable", true);
      return;
    }
    const content = editor ? editor.value : "";
    const enqueue_agent = !!(opts && opts.enqueue_agent);
    const operator_notes = buildPocOperatorNotes();
    setPocStatus(enqueue_agent ? "Saving hub and queuing agent…" : "Saving hub…");
    try {
      const r = await api(
        `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}/findings/${encodeURIComponent(fid)}/poc`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            content,
            enqueue_agent,
            operator_notes,
            operator: "operator",
          }),
        }
      );
      let msg = `Saved hub ${r.poc_relpath || "poc_develop.md"} in pack ${r.evidence_id || "?"}`;
      if (r.task_id) {
        msg += ` · queued develop_poc #${r.task_id} — watch Tasks, then Reload for scripts`;
      }
      toast(msg);
      setPocStatus(msg);
      pocFindingId = Number(fid);
      if (typeof window.loadRunFull === "function") {
        await window.loadRunFull();
        // Stay on POC tab; re-fill after snap refresh
        openDevelopPoc(fid, { skipLoad: true });
        if (editor) editor.value = content;
        setPocStatus(msg);
        // Refresh pack listing after save
        loadPocDraft(fid).catch(() => {});
      } else if (r && r.finding) {
        const idx = cache.findIndex((x) => Number(x.id) === Number(fid));
        if (idx >= 0) {
          cache[idx] = {
            ...cache[idx],
            evidence_id: r.evidence_id || cache[idx].evidence_id,
            body: r.finding.body || cache[idx].body,
          };
        }
        openDevelopPoc(fid, { skipLoad: true });
        if (editor) editor.value = content;
        setPocStatus(msg);
        loadPocDraft(fid).catch(() => {});
      }
    } catch (e) {
      toast(e.message || String(e), true);
      setPocStatus(e.message || String(e), true);
    }
  }

  async function doMerge(keepId, dropIds) {
    const base = apiBase();
    if (!base) {
      toast("No run loaded", true);
      return;
    }
    const drops = (dropIds || []).map(Number).filter((n) => n && n !== Number(keepId));
    if (!drops.length) {
      toast("Nothing to merge", true);
      return;
    }
    try {
      const r = await callApi(`${base}/findings/merge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          keep_id: Number(keepId),
          drop_ids: drops,
          operator: "operator",
        }),
      });
      toast(
        `Merged ${r.dropped_ids?.length || drops.length} finding(s) into #${keepId} (state unchanged: ${r.keep_state || "?"})`
      );
      if (typeof window.loadRunFull === "function") {
        await window.loadRunFull();
      }
      await loadClusters();
      openId = Number(keepId);
      openFinding(keepId);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function buildDedupComparePrompt(cluster) {
    if (!cluster) return "";
    const members = cluster.members || [];
    const lines = members.map((m) => {
      const isPrimary = Number(m.id) === Number(cluster.primary_id);
      const title = (m.title || "").trim() || "(no title)";
      const mark = isPrimary ? " (primary)" : "";
      return `- #${m.id} [${m.class || "-"}] ${m.state || "-"}${mark} — "${title}"`;
    });
    return [
      "Compare these near-duplicate / overlapping findings. Summarize similarities and differences (sink, class, title, state, evidence). Recommend keep-primary vs keep-separate and why. Do not merge unless I ask. Use get_finding for full bodies if needed.",
      "",
      `Cluster: ${cluster.cluster_id || "?"} · strength: ${cluster.strength || "overlap"} · primary: #${cluster.primary_id}${
        cluster.group_key ? ` · key: ${cluster.group_key}` : ""
      }`,
      "",
      "Findings:",
      ...lines,
    ].join("\n");
  }

  function askAiAboutCluster(cluster) {
    const text = buildDedupComparePrompt(cluster);
    if (!text) {
      toast("No cluster to compare", true);
      return;
    }
    window.VulnForgeModes?.setMode?.("ai");
    const ok = window.VulnForgeChat?.prefill?.(text);
    if (!ok) {
      toast("Ask is unavailable. Open the bubble and paste the compare prompt.", true);
    }
  }

  function bindDetailActions(root) {
    root.querySelectorAll(".report-promote-policy-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const fid = Number(btn.getAttribute("data-fid"));
        if (fid) openPolicyPromote(fid);
      });
    });
    root.querySelectorAll(".report-review-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (btn.disabled || btn.getAttribute("aria-disabled") === "true") return;
        const fid = Number(btn.getAttribute("data-fid"));
        const action = btn.getAttribute("data-action");
        if (!fid || !action) return;
        submitReview(fid, action, root);
      });
    });
    root.querySelectorAll(".report-open-related").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const fid = Number(btn.getAttribute("data-fid"));
        if (fid) openFinding(fid);
      });
    });
    root.querySelectorAll(".report-merge-into").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const keep = Number(btn.getAttribute("data-keep"));
        const drop = Number(btn.getAttribute("data-drop"));
        if (!keep || !drop) return;
        doMerge(keep, [drop]);
      });
    });
    root.querySelectorAll(".report-merge-all").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const keep = Number(btn.getAttribute("data-keep"));
        const drops = (btn.getAttribute("data-drops") || "")
          .split(",")
          .map((x) => Number(x.trim()))
          .filter(Boolean);
        if (!keep || !drops.length) return;
        doMerge(keep, drops);
      });
    });
    root.querySelectorAll(".report-ask-ai-cluster").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const cid = btn.getAttribute("data-cluster") || "";
        const cluster = clustersCache.find((c) => String(c.cluster_id) === String(cid));
        if (cluster) askAiAboutCluster(cluster);
      });
    });
    root.querySelectorAll(".report-open-ev").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const pack = btn.getAttribute("data-pack");
        const rel = btn.getAttribute("data-rel") || null;
        if (!pack) return;
        if (window.VulnForgeModes?.goEvidence) {
          window.VulnForgeModes.goEvidence(pack, rel || undefined);
        } else {
          window.VulnForgeModes?.setMode?.("evidence");
          if (typeof window.openEvidenceFile === "function" && rel) {
            window.openEvidenceFile(pack, rel);
          }
        }
      });
    });
    root.querySelectorAll(".report-cite").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const path = btn.getAttribute("data-path");
        const line = btn.getAttribute("data-line");
        if (!path) return;
        if (window.VulnForgeModes?.goExplorer) {
          window.VulnForgeModes.goExplorer(path, line ? Number(line) : undefined);
        } else {
          window.VulnForgeModes?.setMode("explorer");
          if (window.VulnForgeExplorer) {
            window.VulnForgeExplorer.ensureMounted();
            if (window.VulnForgeExplorer.reveal) {
              window.VulnForgeExplorer.reveal(path, line ? Number(line) : undefined);
            }
          }
        }
      });
    });
    root.querySelectorAll(".report-develop-poc").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const fid = Number(btn.getAttribute("data-fid"));
        if (!fid) return;
        if (window.VulnForgeModes?.goDevelopPoc) {
          window.VulnForgeModes.goDevelopPoc(fid);
        } else {
          window.VulnForgeModes?.setMode?.("report", "report");
          openDevelopPoc(fid);
        }
      });
    });
    root.querySelectorAll(".report-track-one").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const fid = Number(btn.getAttribute("data-fid"));
        if (fid) openTrackModal([fid]);
      });
    });
    root.querySelectorAll(".report-ctx-ev").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const pack = btn.getAttribute("data-pack");
        const rel = btn.getAttribute("data-rel");
        if (pack && rel) loadContextEvidence(pack, rel);
      });
    });
    root.querySelectorAll("[data-rv-go]").forEach((btn) => {
      btn.addEventListener("click", () => window.VulnForgeModes?.setMode?.(btn.getAttribute("data-rv-go")));
    });
  }

  /** Review queue (left column). Name kept: many callers refresh through renderTable(). */
  function renderTable() {
    const list = $("#report-queue");
    if (!list) return;
    const rows = sortedFindings();
    if (!cache.length) {
      list.innerHTML = `<li class="vf-empty">No findings yet.</li>`;
      const d = $("#report-detail");
      if (d && openId == null) {
        d.innerHTML = emptyDetailHtml();
        bindDetailActions(d);
      }
      updateSearchCount();
      updateSortHeaders();
      return;
    }
    if (!rows.length) {
      list.innerHTML = `<li class="vf-empty">${
        searchOrFilterActive() ? "No findings match this search / filter." : "No findings match this filter."
      }</li>`;
      updateSearchCount();
      updateSortHeaders();
      return;
    }
    const grouping = nearDupFilterActive();
    let prevGroup = "";
    const H = RH();
    list.innerHTML = rows
      .map((f) => {
        const b = bodyOf(f);
        const p = primaryPath(f);
        const open = Number(openId) === Number(f.id);
        const cm = clusterByFinding[f.id];
        const group = grouping ? nearDupGroupKey(f) : "";
        const groupStart = grouping && group !== prevGroup;
        prevGroup = group;
        const decided = H ? !H.isUndecided(f) : false;
        const cls = [
          "rv-queue-row",
          open ? "is-open" : "",
          decided ? "is-decided" : "",
          f.near_dup || cm ? "near-dup-row" : "",
          groupStart ? "near-dup-cluster-start" : "",
        ]
          .filter(Boolean)
          .join(" ");
        const groupAttr = grouping ? ` data-near-group="${esc(group)}"` : "";
        return `<li><button type="button" class="${cls}" data-fid="${f.id}"${groupAttr} aria-current="${open ? "true" : "false"}">
            <span class="rv-row rv-queue-top">
              ${sevTagHtml(f)}
              <span class="mono vf-faint">#${f.id}</span>
              ${tierPillHtml(f, { noSide: true })}
              <span class="rv-spacer"></span>
              <span class="report-state-cell">${statePill(f)}</span>
            </span>
            <span class="rv-queue-title-text">${esc(b.title || f.stable_key || "-")}</span>
            <span class="rv-queue-sub"><span class="mono">${esc(pathLabel(p))}</span> · ${esc(b.weakness_class || "-")}${
              f.near_dup || cm ? ` · <span class="rv-near">near-dup${cm && cm.label ? " " + esc(cm.label) : ""}</span>` : ""
            }</span>
          </button></li>`;
      })
      .join("");

    list.querySelectorAll(".rv-queue-row").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = Number(btn.getAttribute("data-fid"));
        const f = cache.find((x) => Number(x.id) === id);
        if (f) selectFinding(f);
        else renderTable();
      });
    });

    updateSearchCount();
    updateSortHeaders();
  }

  /** Open a finding in the desk and mark its queue row. */
  function selectFinding(f, opts) {
    if (!f) return;
    showFindingDetail(f, opts);
    $$(".rv-queue-row").forEach((el) => {
      const on = Number(el.getAttribute("data-fid")) === Number(f.id);
      el.classList.toggle("is-open", on);
      el.setAttribute("aria-current", on ? "true" : "false");
      if (on && !(opts && opts.noScroll)) el.scrollIntoView({ block: "nearest" });
    });
  }

  /** Select the first visible finding when nothing is open (triage desk default). */
  function ensureSelection() {
    if (openId != null && cache.some((x) => Number(x.id) === Number(openId))) return;
    const first = sortedFindings()[0];
    if (first) selectFinding(first, { noScroll: true });
    else clearFindingPanes();
  }

  function selectRelative(delta) {
    const H = RH();
    const rows = sortedFindings();
    const id = H ? H.stepSelection(rows, openId, delta) : rows[0] && rows[0].id;
    if (id == null) return;
    const f = cache.find((x) => Number(x.id) === Number(id));
    if (f) selectFinding(f);
  }

  /** Keyboard A / R: same path as the buttons (POST /findings/{id}/review). */
  function decide(action) {
    if (openId == null) return;
    const rail = $("#report-context");
    const btn = rail && rail.querySelector(`.report-review-btn[data-action="${action}"]`);
    if (!btn || btn.disabled || btn.getAttribute("aria-disabled") === "true") {
      if (action === "confirm") {
        const f = cache.find((x) => Number(x.id) === Number(openId));
        if (f && acceptBlockedByPending(f)) toast(acceptPendingCopy(), true);
      }
      return;
    }
    submitReview(openId, action, rail);
  }

  /** Keyboard E: open the current finding's evidence pack. */
  function openCurrentEvidence() {
    const f = cache.find((x) => Number(x.id) === Number(openId));
    if (!f) return false;
    const eid = f.evidence_id || bodyOf(f).evidence_id;
    if (!eid) {
      toast("No evidence pack linked to this finding", true);
      return true;
    }
    const rel = preferredEvidenceRel(f);
    if (window.VulnForgeModes?.goEvidence) window.VulnForgeModes.goEvidence(String(eid), rel || undefined);
    return true;
  }

  function downloadBlob(filename, text, mime) {
    const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  function exportBaseName() {
    const t = meta.target_id || "run";
    const r = meta.run_id || "export";
    return `vulnforge-${t}-${r}-findings`;
  }

  const EXPORT_DISCLAIMER =
    "needs_human = mechanical gates passed; confirmed = human accepted " +
    "(not exploit proven). Always re-check before production claims.";

  function humanReviewLatest(b) {
    if (b.human_review_latest && typeof b.human_review_latest === "object") {
      return b.human_review_latest;
    }
    const hist = Array.isArray(b.human_review) ? b.human_review : [];
    return hist.length ? hist[hist.length - 1] : null;
  }

  function validationReasonsFlat(b) {
    let reasons = b.validation_reasons;
    if (!Array.isArray(reasons) || !reasons.length) {
      reasons = b.validation_mech?.reasons;
    }
    if (!Array.isArray(reasons) || !reasons.length) return "";
    return reasons
      .map((r) => (typeof r === "string" ? r : JSON.stringify(r)))
      .join("; ");
  }

  function citationsFlat(b) {
    return (b.citations || [])
      .filter((c) => c && c.path)
      .map((c) => {
        let label = pathLabel(c);
        if (c.symbol) label += ` (${c.symbol})`;
        return label;
      })
      .join("; ");
  }

  function findingToRow(f) {
    const b = bodyOf(f);
    const tm = b.threat_model || {};
    const p = primaryPath(f) || {};
    const hr = humanReviewLatest(b) || {};
    return {
      id: f.id,
      state: f.state || "",
      severity: f.severity || b.severity_claim || "",
      evidence_tier: (f.evidence_tier && f.evidence_tier.tier) || "",
      weakness_class: b.weakness_class || "",
      title: b.title || f.stable_key || `Finding #${f.id}`,
      summary: b.summary || "",
      path: p.path || "",
      start_line: p.start_line ?? "",
      end_line: p.end_line ?? "",
      symbol: p.symbol || b.sink_symbol || "",
      attacker: tm.attacker || "",
      boundary: tm.boundary || "",
      impact: tm.impact || "",
      evidence_id: f.evidence_id || b.evidence_id || "",
      poc_relpath: b.poc_relpath || "",
      poc_files: "",
      stable_key: f.stable_key || "",
      citations: citationsFlat(b),
      human_review_action: hr.action || "",
      human_review_notes: hr.notes || "",
      validation_reasons: validationReasonsFlat(b),
    };
  }

  function partitionFindings(list) {
    const buckets = {
      needs_human: [],
      confirmed: [],
      candidate: [],
      rejected: [],
      other: [],
    };
    for (const f of list) {
      const st = (f.state || "").toLowerCase();
      if (st === "needs_human") buckets.needs_human.push(f);
      else if (st === "confirmed") buckets.confirmed.push(f);
      else if (st === "candidate") buckets.candidate.push(f);
      else if (st.startsWith("rejected") || st === "superseded") buckets.rejected.push(f);
      else buckets.other.push(f);
    }
    return buckets;
  }

  const EXPORT_SECTION_IDS = {
    findings: "export-sec-findings",
    architecture: "export-sec-architecture",
    hunts: "export-sec-hunts",
    summary: "export-sec-summary",
    codemap: "export-sec-codemap",
    poc: "export-sec-poc",
  };

  function ensureExportMeta() {
    if (meta.target_id && meta.run_id) return meta;
    // Fall back to /runs/{target_id}/{run_id} so export works before first snap.
    try {
      const m = (location.pathname || "").match(
        /\/runs\/([^/]+)\/([^/]+)/i
      );
      if (m) {
        meta = {
          target_id: decodeURIComponent(m[1]) || meta.target_id,
          run_id: decodeURIComponent(m[2]) || meta.run_id,
          target_path: meta.target_path || "",
        };
      }
    } catch {
      /* ignore */
    }
    return meta;
  }

  async function exportRawProjection(name) {
    if (!name) return;
    ensureExportMeta();
    if (!meta.target_id || !meta.run_id) {
      toast("No run loaded", true);
      return;
    }
    try {
      const data = await (typeof window.api === "function"
        ? window.api(
            `/api/runs/${encodeURIComponent(meta.target_id)}/${encodeURIComponent(meta.run_id)}/project/${encodeURIComponent(name)}`
          )
        : fetch(
            `/api/runs/${encodeURIComponent(meta.target_id)}/${encodeURIComponent(meta.run_id)}/project/${encodeURIComponent(name)}`
          ).then((r) => r.json()));
      downloadBlob(name, data.content ?? "", "text/plain;charset=utf-8");
      toast(`Downloaded ${name}`);
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function renderExportProjections() {
    const host = $("#report-export-projections");
    if (!host) return;
    const files = (Array.isArray(projectFiles) ? projectFiles : []).filter(
      (f) => f && f.name
    );
    if (!files.length) {
      host.innerHTML = `<span class="controls-hint">No project files on disk yet.</span>`;
      return;
    }
    host.innerHTML = files
      .map(
        (f) =>
          `<button type="button" class="btn btn-ghost btn-sm" data-export-proj="${esc(f.name)}" title="Download project/${esc(f.name)}">${esc(f.name)}</button>`
      )
      .join("");
    host.querySelectorAll("[data-export-proj]").forEach((btn) => {
      btn.addEventListener("click", () =>
        exportRawProjection(btn.getAttribute("data-export-proj"))
      );
    });
  }

  function openExportModal(ev) {
    if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
    if (ev && typeof ev.stopPropagation === "function") ev.stopPropagation();
    ensureExportMeta();
    const modal = document.getElementById("report-export-modal");
    if (!modal) {
      // Fallback if template not present — go straight to download
      exportReport({ formats: ["md", "html"], sections: defaultExportSections() });
      return false;
    }
    // Show modal: remove hidden *and* add .open (CSS uses .open { display:flex !important })
    modal.removeAttribute("hidden");
    modal.hidden = false;
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
    renderExportProjections();
    updateExportHint();
    // Defer focus so the modal is painted first
    setTimeout(() => {
      try {
        $("#report-export-download")?.focus();
      } catch {
        /* ignore */
      }
    }, 0);
    return false;
  }

  function closeExportModal() {
    const modal = document.getElementById("report-export-modal");
    if (!modal) return;
    modal.classList.remove("open");
    modal.hidden = true;
    modal.setAttribute("hidden", "");
    modal.setAttribute("aria-hidden", "true");
  }

  function defaultExportSections() {
    return {
      findings: true,
      architecture: true,
      hunts: true,
      summary: true,
      codemap: false,
      poc: false,
    };
  }

  function readExportSections() {
    const out = defaultExportSections();
    for (const [key, id] of Object.entries(EXPORT_SECTION_IDS)) {
      const el = document.getElementById(id);
      if (el) out[key] = !!el.checked;
    }
    return out;
  }

  function readExportFormats() {
    return Array.from(
      document.querySelectorAll(
        "#report-export-modal input[type=checkbox][data-fmt]"
      )
    )
      .filter((el) => el.checked)
      .map((el) => el.getAttribute("data-fmt"))
      .filter(Boolean);
  }

  function setExportSectionChecks(on) {
    for (const id of Object.values(EXPORT_SECTION_IDS)) {
      const el = document.getElementById(id);
      if (el) el.checked = !!on;
    }
    updateExportHint();
  }

  function setExportFormatChecks(on) {
    document
      .querySelectorAll("#report-export-modal input[type=checkbox][data-fmt]")
      .forEach((el) => {
        el.checked = !!on;
      });
    updateExportHint();
  }

  function readSarifFilters() {
    return {
      needsHuman: !!document.getElementById("export-sarif-needs-human")?.checked,
      rejected: !!document.getElementById("export-sarif-rejected")?.checked,
    };
  }

  function readSarifStatesLabel() {
    const f = readSarifFilters();
    const parts = ["confirmed"];
    if (f.needsHuman) parts.push("needs_human");
    if (f.rejected) parts.push("rejected");
    return parts.join(" + ");
  }

  function updateExportHint() {
    const hint = $("#report-export-hint");
    if (!hint) return;
    const secs = readExportSections();
    const fmts = readExportFormats();
    const secNames = Object.entries(secs)
      .filter(([, v]) => v)
      .map(([k]) => k);
    if (!secNames.length) {
      hint.textContent = "Select at least one section.";
      hint.style.color = "var(--bad, #f31260)";
      return;
    }
    if (!fmts.length) {
      hint.textContent = "Select at least one format.";
      hint.style.color = "var(--bad, #f31260)";
      return;
    }
    const multi = fmts.length > 1 ? " (zip bundle)" : "";
    const csvNote =
      fmts.includes("csv") &&
      (secs.architecture || secs.hunts || secs.summary || secs.codemap)
        ? " CSV is findings-only."
        : "";
    const sarifNote = fmts.includes("sarif")
      ? ` SARIF is findings-only (${readSarifStatesLabel()}).`
      : "";
    hint.style.color = "";
    hint.textContent = `Will download: ${fmts.join(", ")}${multi}. Sections: ${secNames.join(", ")}.${csvNote}${sarifNote}`;
  }

  function exportReport(opts) {
    ensureExportMeta();
    if (!meta.target_id || !meta.run_id) {
      toast("No run loaded", true);
      return;
    }
    const sections = opts?.sections || readExportSections();
    const formats = opts?.formats || readExportFormats();
    if (!formats.length) {
      toast("Select at least one format", true);
      return;
    }
    const anySection = Object.values(sections).some(Boolean);
    if (!anySection) {
      toast("Select at least one section", true);
      return;
    }
    // Findings required for CSV-only when other narrative sections alone
    if (
      formats.every((f) => f === "csv") &&
      !sections.findings &&
      !sections.poc
    ) {
      toast("CSV export needs Findings (or PoC) selected", true);
      return;
    }
    const params = new URLSearchParams();
    params.set("format", formats.join(","));
    params.set("include_findings", sections.findings ? "true" : "false");
    params.set("include_architecture", sections.architecture ? "true" : "false");
    params.set("include_hunts", sections.hunts ? "true" : "false");
    params.set("include_summary", sections.summary ? "true" : "false");
    params.set("include_codemap", sections.codemap ? "true" : "false");
    params.set("include_poc", sections.poc ? "true" : "false");
    if (formats.includes("sarif")) {
      const sarif = readSarifFilters();
      params.set("sarif_include_needs_human", sarif.needsHuman ? "true" : "false");
      params.set("sarif_include_rejected", sarif.rejected ? "true" : "false");
    }
    const url =
      `/api/runs/${encodeURIComponent(meta.target_id)}/${encodeURIComponent(meta.run_id)}/export?` +
      params.toString();
    // Prefer temporary <a download> so SPA hash state is not disrupted
    try {
      const a = document.createElement("a");
      a.href = url;
      a.rel = "noopener";
      a.style.display = "none";
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch {
      window.location.href = url;
    }
    const label =
      formats.length > 1
        ? `Exporting report zip (${formats.join(", ")})…`
        : `Exporting report (${formats[0]})…`;
    toast(label);
    closeExportModal();
  }

  /** @deprecated Prefer exportReport — kept for console/API compatibility */
  function exportJSON() {
    exportReport({
      formats: ["json"],
      sections: { ...defaultExportSections(), findings: true },
    });
  }

  function exportCSV() {
    exportReport({
      formats: ["csv"],
      sections: {
        findings: true,
        architecture: false,
        hunts: false,
        summary: false,
        codemap: false,
        poc: false,
      },
    });
  }

  function exportMarkdown() {
    exportReport({
      formats: ["md"],
      sections: defaultExportSections(),
    });
  }

  function exportServerFormat(fmt) {
    exportReport({
      formats: [fmt],
      sections: defaultExportSections(),
    });
  }

  let exportModalBound = false;

  function setupExportModal() {
    // Bind even if modal markup is late; retry once on next tick.
    const bindOnce = () => {
      if (exportModalBound) return true;
      const openBtn = document.getElementById("report-export-open");
      const modal = document.getElementById("report-export-modal");
      // Open button can bind without modal (fallback path in openExportModal)
      if (!openBtn) return false;

      openBtn.addEventListener("click", openExportModal);
      // Also set property handler as a belt-and-suspenders fallback
      openBtn.onclick = openExportModal;

      if (modal) {
        document
          .getElementById("report-export-close")
          ?.addEventListener("click", closeExportModal);
        document
          .getElementById("report-export-cancel")
          ?.addEventListener("click", closeExportModal);
        document
          .getElementById("report-export-download")
          ?.addEventListener("click", () => exportReport());
        document
          .getElementById("export-sec-all")
          ?.addEventListener("click", () => setExportSectionChecks(true));
        document
          .getElementById("export-sec-none")
          ?.addEventListener("click", () => setExportSectionChecks(false));
        document
          .getElementById("export-fmt-all")
          ?.addEventListener("click", () => setExportFormatChecks(true));
        document
          .getElementById("export-fmt-none")
          ?.addEventListener("click", () => setExportFormatChecks(false));
        modal
          .querySelectorAll("input[type=checkbox]")
          .forEach((el) => el.addEventListener("change", updateExportHint));
        // Keep closed on load
        if (!modal.classList.contains("open")) {
          modal.hidden = true;
          modal.setAttribute("aria-hidden", "true");
        }
      }

      document.addEventListener("keydown", (e) => {
        const m = document.getElementById("report-export-modal");
        if (e.key === "Escape" && m && m.classList.contains("open")) {
          closeExportModal();
        }
      });

      exportModalBound = true;
      return true;
    };

    if (!bindOnce()) {
      // Button not in DOM yet (should be rare) — try after paint
      setTimeout(bindOnce, 0);
      document.addEventListener("DOMContentLoaded", bindOnce, { once: true });
    }
  }

  // ---------------------------------------------------------------------------
  // Track in external issues (#189). Outward-facing: preview (no network) mints a
  // one-shot token; only the explicit Publish button sends it.
  // ---------------------------------------------------------------------------
  let trackIds = [];
  let trackToken = null;
  let trackGen = 0; // bumped on every invalidate; stale preview responses are dropped
  let trackBound = false;
  let trackMaxPerPublish = 25;

  function trackedLinksHtml(f) {
    const links = Array.isArray(f && f.tracking) ? f.tracking : [];
    if (!links.length) return "";
    return `<p class="controls-hint report-tracked">Tracked: ${links
      .map((t) => {
        const url = String(t.url || "");
        const safe = /^https:\/\//i.test(url) ? url : "";
        const label = `${esc(t.destination || t.sink || "")}#${esc(t.external_id || "")}`;
        return safe
          ? `<a href="${esc(safe)}" target="_blank" rel="noopener noreferrer">${label}</a>`
          : `<span class="mono">${label}</span>`;
      })
      .join(" · ")}</p>`;
  }

  function setTrackHint(msg, isErr) {
    const el = document.getElementById("report-track-hint");
    if (!el) return;
    el.textContent = msg || "";
    el.classList.toggle("bad", !!isErr);
  }

  function invalidateTrackPreview(msg) {
    trackGen += 1;
    trackToken = null;
    const pub = document.getElementById("report-track-publish");
    if (pub) pub.disabled = true;
    if (msg) setTrackHint(msg);
  }

  function trackRunBase() {
    const tid = meta.target_id;
    const rid = meta.run_id;
    if (!tid || !rid) return null;
    return `/api/runs/${encodeURIComponent(tid)}/${encodeURIComponent(rid)}`;
  }

  async function openTrackModal(ids) {
    const modal = document.getElementById("report-track-modal");
    const api = typeof window.api === "function" ? window.api : null;
    if (!modal || !api) {
      toast("Track dialog unavailable", true);
      return;
    }
    trackIds = (ids || []).map(Number).filter(Boolean);
    if (!trackIds.length) {
      toast("No findings to track", true);
      return;
    }
    if (trackIds.length > trackMaxPerPublish) {
      toast(`At most ${trackMaxPerPublish} findings per publish; narrow the filter`, true);
      return;
    }
    const idsEl = document.getElementById("report-track-ids");
    if (idsEl) idsEl.textContent = `Findings: ${trackIds.map((x) => "#" + x).join(", ")}`;
    const nh = document.getElementById("report-track-needs-human");
    if (nh) nh.checked = false;
    const prev = document.getElementById("report-track-preview");
    if (prev) prev.innerHTML = "";
    invalidateTrackPreview("Press Preview to see the exact issue text.");
    modal.removeAttribute("hidden");
    modal.hidden = false;
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
    const repoEl = document.getElementById("report-track-repo");
    try {
      const cfg = await api("/api/tracking/config");
      if (cfg && cfg.max_per_publish) trackMaxPerPublish = Number(cfg.max_per_publish) || 25;
      if (repoEl && !repoEl.value && cfg && cfg.destination) repoEl.value = cfg.destination;
    } catch {
      /* config is a prefill only */
    }
  }

  function closeTrackModal() {
    const modal = document.getElementById("report-track-modal");
    if (!modal) return;
    invalidateTrackPreview("");
    modal.classList.remove("open");
    modal.hidden = true;
    modal.setAttribute("hidden", "");
    modal.setAttribute("aria-hidden", "true");
  }

  function trackPreviewHtml(r) {
    const counts = Object.entries(r.state_counts || {})
      .map(([k, v]) => `${esc(v)} ${esc(k)}`)
      .join(", ");
    const head = `<p><strong>Destination:</strong> <span class="mono">${esc(r.sink)} ${esc(
      r.destination
    )}</span> · ${esc(r.eligible_count)} to publish${counts ? " (" + counts + ")" : ""}${
      r.include_needs_human ? ' · <strong class="bad">includes needs_human (NOT confirmed)</strong>' : ""
    }</p>`;
    const rows = (r.items || [])
      .map((it) => {
        if (!it.eligible) {
          return `<li>#${esc(it.finding_id)} — <em>skipped</em>: ${esc(it.reason || "")}</li>`;
        }
        const what = it.existing_url
          ? `replace title + body of <span class="mono">${esc(it.existing_url)}</span>`
          : "create (or replace the issue already carrying this stable_key)";
        const labels = (it.issue_labels || []).map((l) => esc(l)).join(", ");
        return `<li>#${esc(it.finding_id)} <span class="mono">${esc(it.state)}</span> — ${what}${
          labels && !it.existing_url ? ` · labels on create: <span class="mono">${labels}</span>` : ""
        }
          <details><summary>${esc(it.issue_title || "")}</summary><pre class="mono report-track-body">${esc(
            it.issue_body || ""
          )}</pre></details></li>`;
      })
      .join("");
    return head + `<ul class="report-reasons">${rows}</ul>`;
  }

  async function previewTrack() {
    const base = trackRunBase();
    const api = typeof window.api === "function" ? window.api : null;
    if (!base || !api) return toast("No run loaded", true);
    invalidateTrackPreview("Previewing…");
    const gen = trackGen;
    const ids = trackIds.slice();
    const repo = (document.getElementById("report-track-repo")?.value || "").trim();
    const include_needs_human = !!document.getElementById("report-track-needs-human")?.checked;
    try {
      const r = await api(`${base}/findings/track/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_ids: ids, repo: repo || null, include_needs_human }),
      });
      if (gen !== trackGen) return; // inputs or ids changed while previewing
      const prev = document.getElementById("report-track-preview");
      if (prev) prev.innerHTML = trackPreviewHtml(r);
      if (r.token) {
        trackToken = r.token;
        const pub = document.getElementById("report-track-publish");
        if (pub) {
          pub.disabled = false;
          pub.textContent = `Publish ${r.eligible_count} to ${r.destination}`;
        }
        setTrackHint("Review the issue text above. Publish sends exactly this.");
      } else {
        setTrackHint("Nothing eligible to publish.", true);
      }
    } catch (e) {
      if (gen === trackGen) setTrackHint(e.message || String(e), true);
    }
  }

  async function publishTrack() {
    const base = trackRunBase();
    const api = typeof window.api === "function" ? window.api : null;
    if (!base || !api || !trackToken) return;
    const token = trackToken;
    invalidateTrackPreview("Publishing…");
    const gen = trackGen;
    try {
      const r = await api(`${base}/findings/track`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, operator: "operator" }),
      });
      const res = r.results || [];
      if (typeof window.loadRunFull === "function") window.loadRunFull();
      if (gen !== trackGen) return; // dialog changed meanwhile; keep the newer view
      const prev = document.getElementById("report-track-preview");
      if (prev) {
        prev.innerHTML = `<ul class="report-reasons">${res
          .map((x) =>
            x.ok
              ? `<li>#${esc(x.finding_id)} ${esc(x.action)} — <a href="${esc(
                  /^https:\/\//i.test(String(x.url || "")) ? x.url : ""
                )}" target="_blank" rel="noopener noreferrer">${esc(x.url || "")}</a>${
                  x.remote_state ? ` (${esc(x.remote_state)})` : ""
                }</li>`
              : `<li>#${esc(x.finding_id)} ${esc(x.action || "error")}: ${esc(x.reason || "")}</li>`
          )
          .join("")}</ul>`;
      }
      setTrackHint(`Published ${r.published || 0} of ${res.length}.`, !r.ok);
    } catch (e) {
      if (gen === trackGen) setTrackHint(e.message || String(e), true);
    }
  }

  function setupTrackModal() {
    if (trackBound) return;
    const modal = document.getElementById("report-track-modal");
    const visibleBtn = document.getElementById("report-track-visible");
    if (!modal && !visibleBtn) return;
    trackBound = true;
    visibleBtn?.addEventListener("click", (e) => {
      e.preventDefault();
      const ids = sortedFindings()
        .filter((f) => f.state === "confirmed" || f.state === "needs_human")
        .map((f) => f.id);
      openTrackModal(ids);
    });
    document.getElementById("report-track-close")?.addEventListener("click", closeTrackModal);
    document.getElementById("report-track-cancel")?.addEventListener("click", closeTrackModal);
    document.getElementById("report-track-do-preview")?.addEventListener("click", previewTrack);
    document.getElementById("report-track-publish")?.addEventListener("click", publishTrack);
    ["report-track-repo", "report-track-needs-human"].forEach((id) => {
      const el = document.getElementById(id);
      el?.addEventListener("input", () => invalidateTrackPreview("Changed — preview again."));
      el?.addEventListener("change", () => invalidateTrackPreview("Changed — preview again."));
    });
    document.addEventListener("keydown", (e) => {
      const m = document.getElementById("report-track-modal");
      if (e.key === "Escape" && m && m.classList.contains("open")) closeTrackModal();
    });
  }

  setupTrackModal();
  document.addEventListener("DOMContentLoaded", setupTrackModal, { once: true });

  // --- Report → Reject → Promote to policy (#184) ---------------------------
  // Draft only. Save is an explicit click; provenance is stamped server-side.
  let promoteFid = null;
  let promoteBase = null;
  let promoteBound = false;

  function promoteEl(id) {
    return document.getElementById(id);
  }

  function setPromoteHint(msg, isErr) {
    const el = promoteEl("policy-promote-hint");
    if (!el) return;
    el.textContent = msg || "";
    el.style.color = isErr ? "var(--danger,#c44)" : "";
  }

  function promoteForm() {
    return {
      target_list: promoteEl("policy-promote-target")?.value || "exclusions",
      id: promoteEl("policy-promote-id")?.value || "",
      paths: promoteEl("policy-promote-paths")?.value || "",
      weakness_class: promoteEl("policy-promote-class")?.value || "",
      all_classes: !!promoteEl("policy-promote-all-classes")?.checked,
      reason: promoteEl("policy-promote-reason")?.value || "",
      base_revision: promoteBase,
    };
  }

  function syncPromoteClassRow() {
    const row = promoteEl("policy-promote-class-row");
    const target = promoteEl("policy-promote-target")?.value;
    if (row) row.hidden = target !== "exclusions";
    const cls = promoteEl("policy-promote-class");
    if (cls) cls.disabled = !!promoteEl("policy-promote-all-classes")?.checked;
  }

  function fillPromoteDraft(d) {
    const rule = d.rule || {};
    promoteBase = d.base_revision == null ? null : Number(d.base_revision);
    const set = (id, v) => {
      const el = promoteEl(id);
      if (el) el.value = v == null ? "" : String(v);
    };
    set("policy-promote-target", d.target_list || "exclusions");
    set("policy-promote-id", rule.id || "");
    set("policy-promote-paths", (rule.paths || []).join("\n"));
    set("policy-promote-class", rule.weakness_class || "");
    set("policy-promote-reason", rule.reason || "");
    const all = promoteEl("policy-promote-all-classes");
    if (all) all.checked = false;
    syncPromoteClassRow();
    const h = d.hitl || {};
    const prov = promoteEl("policy-promote-provenance");
    if (prov) {
      prov.textContent = `Provenance (stamped on save): finding #${d.finding_id} · HITL ${h.report_id || "?"}/${
        h.block_id || "?"
      } = ${h.value || "?"} @ ${h.at || "?"} · policy base rev ${promoteBase == null ? "none" : promoteBase}`;
    }
    const eff = promoteEl("policy-promote-effect");
    if (eff && d.effect) eff.textContent = d.effect;
    const warn = promoteEl("policy-promote-warnings");
    if (warn) {
      warn.innerHTML = (d.warnings || []).map((w) => `<div>⚠ ${esc(w)}</div>`).join("");
    }
    showPromoteMatches(d.would_match);
  }

  function showPromoteMatches(wm) {
    const box = promoteEl("policy-promote-matches");
    if (!box || !window.ReportPolicyPromote) return;
    box.innerHTML = window.ReportPolicyPromote.wouldMatchHtml(wm, esc);
    box.querySelectorAll(".policy-promote-open").forEach((b) =>
      b.addEventListener("click", () => {
        const fid = Number(b.getAttribute("data-fid"));
        closePolicyPromote();
        if (fid) openFinding(fid);
      })
    );
  }

  /** Re-draft. With keepEdits, only the base revision / provenance refresh; the operator's fields stay. */
  async function loadPromoteDraft(targetList, keepEdits) {
    const base = trackRunBase();
    if (!base || promoteFid == null) return;
    setPromoteHint("Drafting…");
    try {
      const r = await fetch(
        `${base}/findings/${encodeURIComponent(promoteFid)}/policy-draft?target_list=${encodeURIComponent(
          targetList || "exclusions"
        )}`
      );
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        setPromoteHint(window.ReportPolicyPromote.errorLines(data).join("; "), true);
        return;
      }
      if (keepEdits) {
        const kept = promoteForm();
        fillPromoteDraft(data);
        const put = (id, v) => {
          const el = promoteEl(id);
          if (el) el.value = v;
        };
        put("policy-promote-id", kept.id);
        put("policy-promote-paths", kept.paths);
        put("policy-promote-class", kept.weakness_class);
        put("policy-promote-reason", kept.reason);
        const all = promoteEl("policy-promote-all-classes");
        if (all) all.checked = kept.all_classes;
        syncPromoteClassRow();
        return true;
      }
      fillPromoteDraft(data);
      setPromoteHint("Draft only — edit it, Preview, then Save to policy.");
      return true;
    } catch (e) {
      setPromoteHint(e.message || String(e), true);
    }
  }

  async function sendPromote(dryRun) {
    const base = trackRunBase();
    if (!base || promoteFid == null || !window.ReportPolicyPromote) return;
    const body = window.ReportPolicyPromote.buildPromoteBody(promoteForm(), dryRun);
    setPromoteHint(dryRun ? "Checking…" : "Saving…");
    try {
      const r = await fetch(`${base}/findings/${encodeURIComponent(promoteFid)}/promote-to-policy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const lines = window.ReportPolicyPromote.errorLines(data);
        if (r.status === 409) await loadPromoteDraft(body.target_list, true);
        setPromoteHint(
          r.status === 409
            ? `${lines.join("; ")} — nothing was saved. Your edits are kept on the new base; Preview, then Save again.`
            : lines.join("; "),
          true
        );
        return;
      }
      showPromoteMatches(data.would_match);
      if (dryRun) {
        setPromoteHint(`Valid. Rule ${data.rule && data.rule.id} is not saved yet.`);
        return;
      }
      toast(`Saved rule ${data.rule && data.rule.id} to security policy (rev ${data.revision})`);
      closePolicyPromote();
      if (typeof window.loadRunFull === "function") window.loadRunFull();
    } catch (e) {
      setPromoteHint(e.message || String(e), true);
    }
  }

  async function openPolicyPromote(fid) {
    const modal = promoteEl("policy-promote-modal");
    if (!modal || !window.ReportPolicyPromote) {
      toast("Promote dialog unavailable", true);
      return;
    }
    setupPolicyPromote();
    promoteFid = Number(fid);
    promoteBase = null;
    const title = promoteEl("policy-promote-title");
    if (title) title.textContent = `Promote finding #${promoteFid} to policy`;
    modal.removeAttribute("hidden");
    modal.hidden = false;
    modal.classList.add("open");
    await loadPromoteDraft("exclusions");
  }

  function closePolicyPromote() {
    const modal = promoteEl("policy-promote-modal");
    if (!modal) return;
    modal.classList.remove("open");
    modal.hidden = true;
    promoteFid = null;
  }

  function setupPolicyPromote() {
    if (promoteBound || !promoteEl("policy-promote-modal")) return;
    promoteBound = true;
    promoteEl("policy-promote-close")?.addEventListener("click", closePolicyPromote);
    promoteEl("policy-promote-cancel")?.addEventListener("click", closePolicyPromote);
    promoteEl("policy-promote-preview")?.addEventListener("click", () => sendPromote(true));
    promoteEl("policy-promote-save")?.addEventListener("click", () => sendPromote(false));
    promoteEl("policy-promote-target")?.addEventListener("change", async (e) => {
      // New suggested id / class row for the other list; keep the operator's paths and reason.
      const paths = promoteEl("policy-promote-paths")?.value;
      const reason = promoteEl("policy-promote-reason")?.value;
      await loadPromoteDraft(e.target.value);
      if (paths != null && promoteEl("policy-promote-paths")) promoteEl("policy-promote-paths").value = paths;
      if (reason != null && promoteEl("policy-promote-reason")) promoteEl("policy-promote-reason").value = reason;
    });
    promoteEl("policy-promote-all-classes")?.addEventListener("change", syncPromoteClassRow);
    document.addEventListener("keydown", (e) => {
      const m = promoteEl("policy-promote-modal");
      if (e.key === "Escape" && m && m.classList.contains("open")) closePolicyPromote();
    });
  }

  setupPolicyPromote();
  document.addEventListener("DOMContentLoaded", setupPolicyPromote, { once: true });


  // Bind export UI immediately — do not wait for first snapshot / renderReport.
  // Previously handlers only attached inside renderReport → setupChrome, so the
  // button could appear with no listener (click did nothing).
  setupExportModal();
  ensureExportMeta();

  function rebuildClusterIndex() {
    clusterByFinding = {};
    for (const c of clustersCache) {
      for (const m of c.members || []) {
        clusterByFinding[m.id] = {
          cluster_id: c.cluster_id,
          label: m.label,
          primary_id: c.primary_id,
          strength: c.strength,
        };
      }
    }
  }

  async function loadClusters() {
    const base = apiBase();
    const el = $("#report-clusters");
    if (!base) {
      if (el) el.innerHTML = `<p class="controls-hint">No run loaded.</p>`;
      return;
    }
    try {
      const r = await callApi(`${base}/findings/clusters`);
      clustersCache = Array.isArray(r.clusters) ? r.clusters : [];
      rebuildClusterIndex();
      renderClusters();
      // Refresh table badges if filter depends on clusters
      renderSummary();
      renderTable();
      if (openId != null && reviewPage !== "findings") {
        const f = cache.find((x) => Number(x.id) === Number(openId));
        if (f) {
          fillFindingPanes(f);
          setReviewPage(reviewPage);
        }
      }
    } catch (e) {
      if (el) {
        el.innerHTML = `<p class="controls-hint err">${esc(e.message || String(e))}</p>`;
      }
    }
  }

  function renderClusters() {
    const el = $("#report-clusters");
    if (!el) return;
    if (!clustersCache.length) {
      el.innerHTML = `<p class="controls-hint">No multi-finding overlaps detected (same path+symbol or path-only weak groups).</p>`;
      return;
    }
    el.innerHTML = clustersCache
      .map((c) => {
        const members = (c.members || [])
          .map(
            (m) =>
              `<button type="button" class="path-chip report-cluster-member" data-fid="${m.id}" title="${esc(
                m.title || ""
              )}">
                <span class="badge info mono">${esc(m.label)}</span>
                #${m.id} ${badge(m.state, m)}
                <span class="mono">${esc(m.class || "-")}</span>
              </button>`
          )
          .join(" ");
        return `<div class="report-cluster-block" data-cluster="${esc(c.cluster_id)}">
          <div class="report-cluster-head">
            <strong class="mono">${esc(c.cluster_id)}</strong>
            <span class="badge ${c.strength === "merge_key" ? "near-dup" : "info"}">${esc(
              c.strength || "overlap"
            )}</span>
            <span class="controls-hint">primary #${c.primary_id} · ${c.size} members</span>
            <span class="mono controls-hint">${esc(c.group_key || "")}</span>
            <button type="button" class="btn btn-sm report-cluster-merge-all" data-keep="${
              c.primary_id
            }" data-drops="${(c.members || [])
              .filter((m) => Number(m.id) !== Number(c.primary_id))
              .map((m) => m.id)
              .join(",")}" title="Merge all into primary">Merge all → primary</button>
            <button type="button" class="btn btn-sm report-ask-ai-cluster" data-cluster="${esc(
              c.cluster_id || ""
            )}" title="Open AI chat with a compare prompt">Ask AI</button>
          </div>
          <div class="report-cluster-members">${members}</div>
        </div>`;
      })
      .join("");
    el.querySelectorAll(".report-cluster-member").forEach((btn) => {
      btn.addEventListener("click", () => {
        const fid = Number(btn.getAttribute("data-fid"));
        if (fid) openFinding(fid);
      });
    });
    el.querySelectorAll(".report-cluster-merge-all").forEach((btn) => {
      btn.addEventListener("click", () => {
        const keep = Number(btn.getAttribute("data-keep"));
        const drops = (btn.getAttribute("data-drops") || "")
          .split(",")
          .map((x) => Number(x.trim()))
          .filter(Boolean);
        if (keep && drops.length) doMerge(keep, drops);
      });
    });
    el.querySelectorAll(".report-ask-ai-cluster").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const cid = btn.getAttribute("data-cluster") || "";
        const cluster = clustersCache.find((c) => String(c.cluster_id) === String(cid));
        if (cluster) askAiAboutCluster(cluster);
      });
    });
  }

  function setupReportPanels() {
    if (reportPanelsBound) return;
    reportPanelsBound = true;
    $("#report-clusters-refresh")?.addEventListener("click", () => loadClusters());
  }

  function wireReportStateTips() {
    const root = $("#panel-report");
    if (!root || root.dataset.stateTipsWired === "1") return;
    if (typeof window.showInitFloatingTip !== "function") return;
    root.dataset.stateTipsWired = "1";
    if (typeof window.wireFloatingTipViewport === "function") {
      window.wireFloatingTipViewport();
    }
    const anchorOf = (target) => {
      const el = target && target.closest?.("[data-tip]");
      if (!el || !root.contains(el)) return null;
      if (!el.classList.contains("report-state-step") && !el.classList.contains("llm-verify") && !el.classList.contains("hunt-moa-agree")) {
        return null;
      }
      return el;
    };
    root.addEventListener("mouseover", (e) => {
      const el = anchorOf(e.target);
      if (el) window.showInitFloatingTip(el);
    });
    root.addEventListener("mouseout", (e) => {
      const el = anchorOf(e.target);
      if (!el) return;
      const next = e.relatedTarget;
      if (next && (next === el || el.contains(next))) return;
      window.hideInitFloatingTip?.(el);
    });
    root.addEventListener("focusin", (e) => {
      const el = anchorOf(e.target);
      if (el) window.showInitFloatingTip(el);
    });
    root.addEventListener("focusout", (e) => {
      const el = anchorOf(e.target);
      if (!el) return;
      const next = e.relatedTarget;
      if (next && (next === el || el.contains(next))) return;
      window.hideInitFloatingTip?.(el);
    });
  }

  function setupChrome() {
    // Idempotent — also called from renderReport after snap updates meta.
    wireReportStateTips();
    setupExportModal();
    ensureExportMeta();

    const search = $("#report-search");
    if (search && !search.dataset.bound) {
      search.dataset.bound = "1";
      if (search.value !== searchQuery) search.value = searchQuery;
      search.addEventListener("input", () => {
        const val = search.value || "";
        if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
        searchDebounceTimer = setTimeout(() => {
          searchDebounceTimer = null;
          setSearch(val);
        }, 150);
      });
    }

    const sortSel = $("#report-sort");
    if (sortSel && !sortSel.dataset.bound) {
      sortSel.dataset.bound = "1";
      sortSel.addEventListener("change", () => setSort(sortSel.value, { fromSelect: true }));
    }

    setupReportPanels();
    updateSortHeaders();
    updateSearchCount();
  }

  function setFilter(next) {
    filter = next || "all";
    renderSummary();
    refreshTablePreserveDetail();
    ensureSelection();
  }

  /** Open Report and expand a finding by id (Coverage deep-link). */
  function openFinding(id) {
    if (id == null) return;
    filter = "all";
    searchQuery = "";
    const search = $("#report-search");
    if (search) search.value = "";
    openId = Number(id);
    renderSummary();
    renderTable();
    updateSearchCount();
    updateSortHeaders();
    const f = cache.find((x) => Number(x.id) === Number(openId));
    if (f) selectFinding(f, { page: "detail" });
    else clearFindingPanes();
  }

  function renderReport(snap) {
    if (!$("#panel-report") && !$("#report-queue")) return;
    cache = Array.isArray(snap.findings) ? snap.findings : cache;
    meta = {
      target_id: snap.target_id || meta.target_id,
      run_id: snap.run_id || meta.run_id,
      target_path: snap.target_path || meta.target_path,
    };
    projectFiles = Array.isArray(snap.project_files) ? snap.project_files : [];
    renderExportProjections();
    window.__VF_report_findings = cache;
    // Default Needs review; fall back to All only until the operator picks a chip.
    if (!filterChosen && filter !== "all" && !cache.some(matchesFilter)) {
      filter = "all";
    }
    if (!filter) filter = "all";
    setupChrome();
    setupPocChrome();
    renderSummary();
    renderTable();
    updateSearchCount();
    updateSortHeaders();
    // Near-dup badges and row grouping depend on cluster membership.
    loadClusters().catch(() => {});
    // Restore open detail after refresh / human review (if still visible under filter/search)
    if (openId != null) {
      const stillVisible = sortedFindings().some(
        (x) => Number(x.id) === Number(openId)
      );
      const f = stillVisible
        ? cache.find((x) => Number(x.id) === Number(openId))
        : null;
      if (f) {
        fillFindingPanes(f);
        setReviewPage(reviewPage);
        renderTable();
      } else {
        clearFindingPanes();
        renderTable();
        ensureSelection();
      }
    } else {
      clearFindingPanes();
      ensureSelection();
    }

    // Keep open POC workshop headers in sync when snap refreshes
    if (pocFindingId != null && isPocOpen()) {
      const pf = cache.find((x) => Number(x.id) === Number(pocFindingId));
      if (pf) fillPocWorkshopHeader(pf, pocLastLoad);
    }
  }

  window.VulnForgeReport = {
    render: renderReport,
    setFilter,
    openFinding,
    selectRelative,
    decide,
    openCurrentEvidence,
    ensureSelection,
    openDevelopPoc,
    closeDevelopPoc,
    refreshPocWorkshop,
    isPocOpen,
    get pocFindingId() {
      return pocFindingId;
    },
    exportJSON,
    exportMarkdown,
    exportCSV,
    exportServerFormat,
    exportReport,
    openExportModal,
    closeExportModal,
  };
  window.renderReport = renderReport;
})();
