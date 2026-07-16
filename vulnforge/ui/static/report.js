/* VulnForge Report mode - findings table, expandable detail, export */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  let cache = [];
  let filter = "all";
  let openId = null;
  /** Finding id open in the Develop POC workshop modal (not a mode tab). */
  let pocFindingId = null;
  let pocChromeBound = false;
  let meta = { target_id: "", run_id: "", target_path: "" };
  /** Multi-member overlap clusters from GET /findings/clusters */
  let clustersCache = [];
  /** Map finding_id -> cluster member meta */
  let clusterByFinding = {};
  /** Selected finding ids for attack chain builder */
  let selectedIds = new Set();
  let chainsCache = [];
  let openChainId = null;
  let reportPanelsBound = false;

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badge(state) {
    if (typeof window.badge === "function") return window.badge(state);
    return `<span class="badge">${esc(state)}</span>`;
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

  function matchesFilter(f) {
    const st = (f.state || "").toLowerCase();
    const ftr = (filter || "all").toLowerCase();
    if (ftr === "all") return true;
    if (ftr === "rejected") return st.startsWith("rejected") || st === "superseded";
    if (ftr === "near_dup" || ftr === "overlaps") {
      return !!(f.near_dup || clusterByFinding[f.id]);
    }
    if (ftr === "needs_human") {
      const b = bodyOf(f);
      return st === "needs_human" || !!(b.needs_human || b.validation_mech?.pending_llm);
    }
    return st === ftr;
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

  function sortedFindings() {
    const order = {
      needs_human: 0,
      candidate: 1,
      confirmed: 2,
      rejected_mech: 3,
      rejected_llm: 4,
      rejected_human: 5,
      superseded: 6,
    };
    return [...cache]
      .filter(matchesFilter)
      .sort(
        (a, b) =>
          (order[a.state] ?? 9) - (order[b.state] ?? 9) || (b.id || 0) - (a.id || 0)
      );
  }

  function summaryCounts() {
    const c = {
      confirmed: 0,
      needs_human: 0,
      candidate: 0,
      rejected: 0,
      near_dup: 0,
      other: 0,
      total: cache.length,
    };
    for (const f of cache) {
      const st = (f.state || "").toLowerCase();
      if (st === "confirmed") c.confirmed++;
      else if (st === "needs_human") c.needs_human++;
      else if (st === "candidate") c.candidate++;
      else if (st.startsWith("rejected") || st === "superseded") c.rejected++;
      else c.other++;
      if (f.near_dup || clusterByFinding[f.id]) c.near_dup++;
    }
    return c;
  }

  function renderSummary() {
    const el = $("#report-summary");
    if (!el) return;
    const c = summaryCounts();
    const ftr = (filter || "all").toLowerCase();
    const active = (key) => (ftr === key ? " active" : "");
    el.innerHTML = `
      <div class="report-summary-grid report-summary-grid-wide">
        <button type="button" class="stat info stat-link${active("all")}" data-rfilter="all" title="Show all findings" aria-pressed="${ftr === "all"}">
          <div class="label">All</div><div class="value">${c.total}</div>
        </button>
        <button type="button" class="stat warn stat-link${active("needs_human")}" data-rfilter="needs_human" title="Filter: needs human review" aria-pressed="${ftr === "needs_human"}">
          <div class="label">Needs human</div><div class="value">${c.needs_human}</div>
        </button>
        <button type="button" class="stat good stat-link${active("confirmed")}" data-rfilter="confirmed" title="Filter: confirmed" aria-pressed="${ftr === "confirmed"}">
          <div class="label">Confirmed</div><div class="value">${c.confirmed}</div>
        </button>
        <button type="button" class="stat bad stat-link${active("rejected")}" data-rfilter="rejected" title="Filter: rejected" aria-pressed="${ftr === "rejected"}">
          <div class="label">Rejected</div><div class="value">${c.rejected}</div>
        </button>
        <button type="button" class="stat warn stat-link${active("near_dup")}" data-rfilter="near_dup" title="Filter: near-dup / overlaps" aria-pressed="${ftr === "near_dup"}">
          <div class="label">Near-dup</div><div class="value">${c.near_dup}</div>
        </button>
      </div>
      <p class="controls-hint report-disclaimer">
        Click a count to filter the table.
        <strong>needs_human</strong> = mechanical gates passed.
        <strong>confirmed</strong> = human accepted (not exploit proof). Expand a row to review.
        Use checkboxes to build <strong>attack chains</strong>.
      </p>`;
    el.querySelectorAll("[data-rfilter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        setFilter(btn.getAttribute("data-rfilter") || "all");
      });
    });
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

  function detailHtml(f) {
    const b = bodyOf(f);
    const tm = b.threat_model || {};
    const cites = (b.citations || [])
      .filter((c) => c && c.path)
      .map((c) => {
        const line = c.start_line != null ? c.start_line : "";
        return `<button type="button" class="path-chip report-cite" data-path="${esc(c.path)}" data-line="${esc(line)}">${esc(pathLabel(c))}${c.symbol ? " · " + esc(c.symbol) : ""}</button>`;
      })
      .join(" ");
    const rejectBox =
      typeof window.formatValidationReasonsHtml === "function"
        ? window.formatValidationReasonsHtml(f)
        : (b.validation_reasons || [])
            .map((r) => `<li>${esc(typeof r === "string" ? r : JSON.stringify(r))}</li>`)
            .join("")
          ? `<h4>Validation notes</h4><ul class="report-reasons">${(b.validation_reasons || [])
              .map((r) => `<li>${esc(typeof r === "string" ? r : JSON.stringify(r))}</li>`)
              .join("")}</ul>`
          : "";
    const eid = f.evidence_id || b.evidence_id;
    const evRel = preferredEvidenceRel(f);
    const reviews = Array.isArray(b.human_review) ? b.human_review : [];
    const reviewHist =
      reviews.length > 0
        ? `<details class="report-review-hist"><summary>Review history (${reviews.length})</summary><ul class="report-reasons">${reviews
            .slice()
            .reverse()
            .slice(0, 10)
            .map(
              (r) =>
                `<li class="mono">${esc(r.at || "")} · ${esc(r.from_state || "?")} → ${esc(
                  r.to_state || "?"
                )} · ${esc(r.action || "")}${
                  r.notes ? ` — ${esc(String(r.notes).slice(0, 160))}` : ""
                }</li>`
            )
            .join("")}</ul></details>`
        : "";
    const cm = clusterByFinding[f.id];
    const cluster = cm
      ? clustersCache.find((c) => c.cluster_id === cm.cluster_id)
      : null;
    const mergedClasses = b.merged_classes || [];
    const nearTitles = b.near_dup_titles || [];
    const supersededBy = b.superseded_by;
    const relatedHtml = cluster
      ? `<div class="report-related-panel">
          <h4>Related variants <span class="badge near-dup">${esc(cluster.strength || "overlap")}</span>
            <span class="controls-hint mono">cluster ${esc(cluster.cluster_id)} · primary #${cluster.primary_id}</span>
          </h4>
          <ul class="report-related-list">${(cluster.members || [])
            .map((m) => {
              const isSelf = Number(m.id) === Number(f.id);
              const isPrimary = Number(m.id) === Number(cluster.primary_id);
              return `<li class="report-related-item${isSelf ? " self" : ""}">
                <span class="badge info mono">${esc(m.label)}</span>
                <button type="button" class="btn btn-ghost btn-sm report-open-related" data-fid="${m.id}" ${
                  isSelf ? "disabled" : ""
                }>#${m.id}</button>
                <span class="mono">${esc(m.class || "-")}</span>
                ${badge(m.state)}
                <span class="report-related-title">${esc(m.title || "")}</span>
                ${
                  !isSelf && !isPrimary && f.state !== "superseded"
                    ? `<button type="button" class="btn btn-sm report-merge-into" data-keep="${cluster.primary_id}" data-drop="${m.id}" title="Supersede this variant into primary">Merge into primary</button>`
                    : ""
                }
                ${
                  isSelf && !isPrimary && f.state !== "superseded"
                    ? `<button type="button" class="btn btn-sm btn-primary report-merge-into" data-keep="${cluster.primary_id}" data-drop="${f.id}" title="Supersede this finding into cluster primary">Merge this into primary</button>`
                    : ""
                }
              </li>`;
            })
            .join("")}</ul>
          ${
            Number(f.id) === Number(cluster.primary_id) &&
            (cluster.members || []).some((m) => Number(m.id) !== Number(f.id) && m.state !== "superseded")
              ? `<button type="button" class="btn btn-sm report-merge-all" data-keep="${cluster.primary_id}" data-drops="${(cluster.members || [])
                  .filter((m) => Number(m.id) !== Number(cluster.primary_id))
                  .map((m) => m.id)
                  .join(",")}" title="Supersede all other variants into primary">Merge all variants into primary</button>`
              : ""
          }
          <p class="controls-hint">Merge marks drop as <span class="mono">superseded</span> and annotates keeper — does not change keeper state / never auto-confirms.</p>
        </div>`
      : "";
    const mergeMeta =
      mergedClasses.length || nearTitles.length || supersededBy != null
        ? `<div class="report-merge-meta">
            <h4>Merge metadata</h4>
            <div class="kv">
              ${
                supersededBy != null
                  ? `<div class="k">superseded_by</div><div class="v"><button type="button" class="btn btn-ghost btn-sm report-open-related" data-fid="${esc(
                      String(supersededBy)
                    )}">#${esc(String(supersededBy))}</button></div>`
                  : ""
              }
              ${
                mergedClasses.length
                  ? `<div class="k">merged_classes</div><div class="v mono">${esc(
                      mergedClasses.join(", ")
                    )}</div>`
                  : ""
              }
              ${
                nearTitles.length
                  ? `<div class="k">near_dup_titles</div><div class="v">${nearTitles
                      .map((t) => `<div class="controls-hint">${esc(t)}</div>`)
                      .join("")}</div>`
                  : ""
              }
            </div>
          </div>`
        : "";
    const nearBadge = f.near_dup || cluster
      ? `<span class="badge near-dup" title="Near-duplicate / overlap">near-dup${
          cm && cm.label ? " " + esc(cm.label) : ""
        }</span>`
      : "";
    return `
      <div class="report-detail-inner" data-fid="${f.id}">
        <div class="report-detail-head">
          <h3>${esc(b.title || f.stable_key || "Finding #" + f.id)}</h3>
          <div class="report-detail-badges">
            ${badge(f.state)}
            ${sevBadge(f.severity || b.severity_claim || "unknown")}
            <span class="badge info">${esc(b.weakness_class || "-")}</span>
            ${nearBadge}
          </div>
        </div>
        <p class="report-detail-summary">${esc(b.summary || "No summary.")}</p>
        ${rejectBox}
        ${relatedHtml}
        ${mergeMeta}
        <div class="report-detail-grid">
          <div>
            <h4>Threat model</h4>
            <div class="kv">
              <div class="k">Attacker</div><div class="v">${esc(tm.attacker || "-")}</div>
              <div class="k">Boundary</div><div class="v">${esc(tm.boundary || "-")}</div>
              <div class="k">Impact</div><div class="v">${esc(tm.impact || "-")}</div>
            </div>
          </div>
          <div>
            <h4>Identity</h4>
            <div class="kv">
              <div class="k">ID</div><div class="v mono">${f.id}</div>
              <div class="k">stable_key</div><div class="v mono">${esc(f.stable_key || "-")}</div>
              <div class="k">Evidence</div><div class="v mono">${eid ? esc(String(eid)) : b.no_poc ? "no_poc" : "-"}</div>
            </div>
          </div>
        </div>
        <h4>Citations</h4>
        <div class="finding-paths">${cites || '<span class="controls-hint">None</span>'}</div>
        <div class="report-review-panel">
          <h4>Human review</h4>
          <p class="controls-hint">Mech can auto-reject; otherwise findings wait here. Accept, reject, or reclassify confirmed/rejected items. Notes are saved on the finding and optionally under the evidence pack.</p>
          <label class="field-label" for="report-review-notes-${f.id}"><span class="label-text">Notes / supporting commentary</span></label>
          <textarea id="report-review-notes-${f.id}" class="op-notes report-review-notes" rows="3" placeholder="Why accept or reject? Links, residual risk, extra context…"></textarea>
          <label class="controls-hint report-review-ev-opt">
            <input type="checkbox" id="report-review-write-ev-${f.id}" checked />
            Write notes into evidence pack as human_review_*.md
          </label>
          <div class="report-review-actions">
            <button type="button" class="btn btn-good report-review-btn" data-action="confirm" data-fid="${f.id}">Accept (confirmed)</button>
            <button type="button" class="btn btn-bad report-review-btn" data-action="reject" data-fid="${f.id}">Reject</button>
            <button type="button" class="btn report-review-btn" data-action="needs_human" data-fid="${f.id}">Needs human review</button>
          </div>
          ${reviewHist}
        </div>
        <div class="report-detail-actions">
          ${
            eid
              ? `<button type="button" class="btn report-open-ev" data-pack="${esc(String(eid))}" data-rel="${esc(evRel || "")}">Open Evidence</button>`
              : b.no_poc
                ? `<span class="controls-hint">No evidence pack (no_poc)</span>`
                : `<span class="controls-hint">No evidence pack linked</span>`
          }
          <button type="button" class="btn report-close-detail">Close detail</button>
          <button type="button" class="btn btn-primary report-develop-poc" data-fid="${f.id}" title="Open working PoC workshop for this finding">Develop POC</button>
        </div>
      </div>`;
  }

  async function submitReview(fid, action, root) {
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
      // Refresh snapshot so table + evidence packs update
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
          };
        }
        renderSummary();
        renderTable();
        const f = cache.find((x) => Number(x.id) === Number(fid));
        const d = $("#report-detail");
        if (d && f) {
          d.hidden = false;
          d.innerHTML = detailHtml(f);
          bindDetailActions(d);
        }
      }
      openId = Number(fid);
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
      badges.innerHTML = `${badge(f.state)} ${sevBadge(
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

  function bindDetailActions(root) {
    root.querySelectorAll(".report-review-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
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
    root.querySelector(".report-close-detail")?.addEventListener("click", () => {
      openId = null;
      renderTable();
      const d = $("#report-detail");
      if (d) {
        d.hidden = true;
        d.innerHTML = "";
      }
    });
  }

  function renderTable() {
    const tbody = $("#report-tbody");
    if (!tbody) return;
    const rows = sortedFindings();
    if (!cache.length) {
      tbody.innerHTML = `<tr><td colspan="8"><div class="empty empty-cta">
        <p><strong>No findings yet</strong></p>
        <p class="controls-hint">Run recon and hunts, then return here. Use Explorer to steer work.</p>
        <div class="empty-cta-actions">
          <button type="button" class="btn btn-primary" id="report-go-explorer">Open Explorer</button>
          <button type="button" class="btn" id="report-go-mission">Mission</button>
        </div>
      </div></td></tr>`;
      $("#report-go-explorer")?.addEventListener("click", () =>
        window.VulnForgeModes?.setMode?.("explorer")
      );
      $("#report-go-mission")?.addEventListener("click", () =>
        window.VulnForgeModes?.setMode?.("mission", "overview")
      );
      return;
    }
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty">No findings match this filter.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows
      .map((f) => {
        const b = bodyOf(f);
        const p = primaryPath(f);
        const open = Number(openId) === Number(f.id);
        const cm = clusterByFinding[f.id];
        const near =
          f.near_dup || cm
            ? `<span class="badge near-dup" title="Near-duplicate / overlap">${
                cm && cm.label ? esc(cm.label) + " near-dup" : "near-dup"
              }</span>`
            : "";
        const checked = selectedIds.has(Number(f.id)) ? " checked" : "";
        return `<tr class="report-row${open ? " open" : ""}${f.near_dup || cm ? " near-dup-row" : ""}" data-fid="${f.id}" tabindex="0">
          <td class="report-check-cell" onclick="event.stopPropagation()">
            <input type="checkbox" class="report-select-cb" data-fid="${f.id}" aria-label="Select finding ${f.id}"${checked} />
          </td>
          <td class="mono">${f.id}</td>
          <td class="report-title-cell">${esc(b.title || f.stable_key || "-")} ${near}</td>
          <td><span class="mono">${esc(b.weakness_class || "-")}</span></td>
          <td>${sevBadge(f.severity || b.severity_claim || "unknown")}</td>
          <td>${badge(f.state)}</td>
          <td class="mono report-path-cell" title="${esc(pathLabel(p))}">${esc(pathLabel(p))}</td>
          <td class="report-row-action">${open ? "Hide" : "Details"}</td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll(".report-select-cb").forEach((cb) => {
      cb.addEventListener("change", (e) => {
        e.stopPropagation();
        const id = Number(cb.getAttribute("data-fid"));
        if (!id) return;
        if (cb.checked) selectedIds.add(id);
        else selectedIds.delete(id);
      });
    });

    tbody.querySelectorAll(".report-row").forEach((tr) => {
      const openDetail = () => {
        const id = Number(tr.getAttribute("data-fid"));
        if (Number(openId) === id) {
          openId = null;
          const d = $("#report-detail");
          if (d) {
            d.hidden = true;
            d.innerHTML = "";
          }
          renderTable();
          return;
        }
        openId = id;
        const f = cache.find((x) => Number(x.id) === id);
        const d = $("#report-detail");
        if (d && f) {
          d.hidden = false;
          d.innerHTML = detailHtml(f);
          bindDetailActions(d);
          d.scrollIntoView({ block: "nearest", behavior: "smooth" });
        }
        renderTable();
      };
      tr.addEventListener("click", openDetail);
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          openDetail();
        }
      });
    });
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

  function wantIncludePoc() {
    return !!$("#report-export-include-poc")?.checked;
  }

  function exportJSON() {
    // PoC packs live on disk — use server export when including them.
    if (wantIncludePoc()) {
      exportServerFormat("json");
      return;
    }
    const c = summaryCounts();
    const payload = {
      exported_at: new Date().toISOString(),
      disclaimer: EXPORT_DISCLAIMER,
      include_poc: false,
      target_id: meta.target_id,
      run_id: meta.run_id,
      target_path: meta.target_path,
      counts: c,
      rows: cache.map(findingToRow),
      findings: cache,
    };
    downloadBlob(
      `${exportBaseName()}.json`,
      JSON.stringify(payload, null, 2) + "\n",
      "application/json"
    );
    toast("Exported findings JSON");
  }

  function exportCSV() {
    if (wantIncludePoc()) {
      exportServerFormat("csv");
      return;
    }
    const cols = [
      "id",
      "state",
      "severity",
      "weakness_class",
      "title",
      "summary",
      "path",
      "start_line",
      "end_line",
      "symbol",
      "attacker",
      "boundary",
      "impact",
      "evidence_id",
      "poc_relpath",
      "poc_files",
      "stable_key",
      "citations",
      "human_review_action",
      "human_review_notes",
      "validation_reasons",
    ];
    const escapeCell = (v) => {
      const s = String(v ?? "");
      if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
      return s;
    };
    const lines = [`# ${EXPORT_DISCLAIMER}`, cols.join(",")];
    for (const f of cache) {
      const row = findingToRow(f);
      lines.push(cols.map((c) => escapeCell(row[c])).join(","));
    }
    downloadBlob(`${exportBaseName()}.csv`, lines.join("\n") + "\n", "text/csv");
    toast("Exported findings CSV");
  }

  function mdFindingBlock(f) {
    const b = bodyOf(f);
    const tm = b.threat_model || {};
    const hr = humanReviewLatest(b);
    const lines = [];
    lines.push(`### [${f.id}] ${b.title || f.stable_key || "Finding"}`, "");
    lines.push(`- **state:** ${f.state}`);
    lines.push(`- **class:** ${b.weakness_class || "-"}`);
    lines.push(`- **severity:** ${f.severity || b.severity_claim || "-"}`);
    lines.push(`- **stable_key:** \`${f.stable_key || "-"}\``);
    if (tm.attacker) lines.push(`- **attacker:** ${tm.attacker}`);
    if (tm.boundary) lines.push(`- **boundary:** ${tm.boundary}`);
    if (tm.impact) lines.push(`- **impact:** ${tm.impact}`);
    const p = primaryPath(f);
    if (p && p.path) lines.push(`- **location:** \`${pathLabel(p)}\``);
    const eid = f.evidence_id || b.evidence_id;
    if (eid) lines.push(`- **evidence:** \`${eid}\``);
    if (hr && hr.action) {
      lines.push(
        `- **human_review:** ${hr.action}${hr.notes ? " — " + hr.notes : ""}`
      );
    }
    const vr = validationReasonsFlat(b);
    if (vr) lines.push(`- **validation_reasons:** ${vr}`);
    lines.push("", b.summary || "", "", "**Citations:**", "");
    const cites = b.citations || [];
    if (cites.length) {
      for (const cit of cites) {
        if (!cit || !cit.path) continue;
        lines.push(
          `- \`${pathLabel(cit)}\`${cit.symbol ? " (" + cit.symbol + ")" : ""}`
        );
      }
    } else {
      lines.push("- _none_");
    }
    lines.push("");
    return lines;
  }

  function exportMarkdown() {
    if (wantIncludePoc()) {
      exportServerFormat("md");
      return;
    }
    const lines = [
      "# VulnForge findings export",
      "",
      `Target: \`${meta.target_path || meta.target_id || "-"}\``,
      `Run: \`${meta.target_id || "-"} / ${meta.run_id || "-"}\``,
      `Exported: ${new Date().toISOString()}`,
      "Include PoC: `no`",
      "",
      `> **Disclaimer:** ${EXPORT_DISCLAIMER}`,
      "",
    ];
    const c = summaryCounts();
    lines.push(
      `Needs human: ${c.needs_human} | Confirmed (human): ${c.confirmed} | ` +
        `Candidates: ${c.candidate} | Rejected: ${c.rejected} | Total: ${c.total}`,
      ""
    );
    if (!cache.length) {
      lines.push("_No findings._", "");
    } else {
      const buckets = partitionFindings(cache);
      const sections = [
        ["needs_human", "## Needs human review (mech-passed)"],
        ["confirmed", "## Confirmed findings (human-accepted)"],
        ["candidate", "## Candidates"],
        ["rejected", "## Rejected"],
        ["other", "## Other"],
      ];
      for (const [key, heading] of sections) {
        const group = buckets[key] || [];
        if (key === "other" && !group.length) continue;
        lines.push(heading, "");
        if (!group.length) {
          lines.push("_None._", "");
          continue;
        }
        for (const f of group) {
          lines.push(...mdFindingBlock(f));
        }
      }
    }
    downloadBlob(
      `${exportBaseName()}.md`,
      lines.join("\n"),
      "text/markdown;charset=utf-8"
    );
    toast("Exported findings Markdown");
  }


  function exportServerFormat(fmt) {
    if (!meta.target_id || !meta.run_id) {
      toast("No run loaded", true);
      return;
    }
    const poc = wantIncludePoc() ? "&include_poc=true" : "";
    const url =
      `/api/runs/${encodeURIComponent(meta.target_id)}/${encodeURIComponent(meta.run_id)}/export?format=${encodeURIComponent(fmt)}${poc}`;
    // Attachment response: navigate triggers download with Content-Disposition
    window.location.href = url;
    toast(
      wantIncludePoc()
        ? `Exporting findings (${fmt}) with PoC…`
        : `Exporting findings (${fmt})...`
    );
  }

  async function exportRawProjection(name) {
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
      if (openId != null) {
        const f = cache.find((x) => Number(x.id) === Number(openId));
        const d = $("#report-detail");
        if (d && f) {
          d.hidden = false;
          d.innerHTML = detailHtml(f);
          bindDetailActions(d);
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
                #${m.id} ${badge(m.state)}
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
  }

  function chainScopeStates() {
    const sel = $("#report-chain-scope");
    const raw = sel ? sel.value : "confirmed";
    return String(raw || "confirmed")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function loadChains() {
    const base = apiBase();
    const el = $("#report-chains-list");
    if (!base) {
      if (el) el.innerHTML = `<p class="controls-hint">No run loaded.</p>`;
      return;
    }
    try {
      const r = await callApi(`${base}/chains`);
      chainsCache = Array.isArray(r.chains) ? r.chains : [];
      renderChainsList();
      if (openChainId) {
        const ch = chainsCache.find((c) => c.id === openChainId);
        if (ch) renderChainDetail(ch);
        else {
          openChainId = null;
          const d = $("#report-chain-detail");
          if (d) {
            d.hidden = true;
            d.innerHTML = "";
          }
        }
      }
    } catch (e) {
      if (el) {
        el.innerHTML = `<p class="controls-hint err">${esc(e.message || String(e))}</p>`;
      }
    }
  }

  function renderChainsList() {
    const el = $("#report-chains-list");
    if (!el) return;
    if (!chainsCache.length) {
      el.innerHTML = `<p class="controls-hint">No attack chains yet. Select findings (checkboxes) or create from scope.</p>`;
      return;
    }
    el.innerHTML = chainsCache
      .map((c) => {
        const n = (c.steps || []).length;
        const open = openChainId === c.id;
        return `<div class="report-chain-row${open ? " open" : ""}" data-chain="${esc(c.id)}">
          <button type="button" class="btn btn-ghost report-chain-open" data-chain="${esc(c.id)}">
            <strong>${esc(c.title || "Chain")}</strong>
            <span class="controls-hint mono">${esc(String(c.id).slice(0, 8))}… · ${n} step${n === 1 ? "" : "s"}</span>
          </button>
          <button type="button" class="btn btn-sm report-chain-export" data-chain="${esc(c.id)}" title="Export markdown">MD</button>
          <button type="button" class="btn btn-sm btn-bad report-chain-delete" data-chain="${esc(c.id)}" title="Delete chain">Delete</button>
        </div>`;
      })
      .join("");
    el.querySelectorAll(".report-chain-open").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-chain");
        const ch = chainsCache.find((c) => c.id === id);
        if (ch) {
          openChainId = id;
          renderChainsList();
          renderChainDetail(ch);
        }
      });
    });
    el.querySelectorAll(".report-chain-export").forEach((btn) => {
      btn.addEventListener("click", () => exportChainMd(btn.getAttribute("data-chain")));
    });
    el.querySelectorAll(".report-chain-delete").forEach((btn) => {
      btn.addEventListener("click", () => deleteChain(btn.getAttribute("data-chain")));
    });
  }

  function renderChainDetail(chain) {
    const d = $("#report-chain-detail");
    if (!d || !chain) return;
    d.hidden = false;
    const steps = chain.steps || [];
    const stepsHtml = steps
      .map((s, i) => {
        const f = cache.find((x) => Number(x.id) === Number(s.finding_id));
        const title = f ? bodyOf(f).title || f.stable_key : "";
        const st = f ? f.state : "";
        return `<div class="report-chain-step" data-idx="${i}">
          <span class="mono">#${i + 1}</span>
          <button type="button" class="btn btn-ghost btn-sm report-open-related" data-fid="${s.finding_id}">finding #${s.finding_id}</button>
          ${st ? badge(st) : ""}
          <span class="report-related-title">${esc(title || "")}</span>
          <input type="text" class="report-chain-role" data-idx="${i}" placeholder="role" value="${esc(s.role || "")}" />
          <input type="text" class="report-chain-notes" data-idx="${i}" placeholder="notes" value="${esc(s.notes || "")}" />
          <span class="controls-hint mono">${esc(s.poc_path || "no poc")}</span>
          <button type="button" class="btn btn-sm report-chain-up" data-idx="${i}" title="Move up" ${i === 0 ? "disabled" : ""}>↑</button>
          <button type="button" class="btn btn-sm report-chain-down" data-idx="${i}" title="Move down" ${i >= steps.length - 1 ? "disabled" : ""}>↓</button>
        </div>`;
      })
      .join("");
    d.innerHTML = `
      <div class="report-chain-detail-inner" data-chain="${esc(chain.id)}">
        <div class="report-panel-head">
          <label class="field-label">Title
            <input type="text" id="report-chain-title" value="${esc(chain.title || "")}" />
          </label>
          <div>
            <button type="button" class="btn btn-sm btn-primary" id="report-chain-save">Save steps</button>
            <button type="button" class="btn btn-sm" id="report-chain-export-detail">Export MD</button>
            <button type="button" class="btn btn-sm" id="report-chain-close-detail">Close</button>
          </div>
        </div>
        <p class="controls-hint">Scope: <span class="mono">${esc((chain.include_states || []).join(", "))}</span>
          · stored under <span class="mono">evidence/chains/${esc(chain.id)}.json</span></p>
        <div class="report-chain-steps">${stepsHtml || '<p class="controls-hint">No steps.</p>'}</div>
      </div>`;
    d.querySelectorAll(".report-open-related").forEach((btn) => {
      btn.addEventListener("click", () => {
        const fid = Number(btn.getAttribute("data-fid"));
        if (fid) openFinding(fid);
      });
    });
    d.querySelectorAll(".report-chain-up").forEach((btn) => {
      btn.addEventListener("click", () => reorderChainStep(chain, Number(btn.getAttribute("data-idx")), -1));
    });
    d.querySelectorAll(".report-chain-down").forEach((btn) => {
      btn.addEventListener("click", () => reorderChainStep(chain, Number(btn.getAttribute("data-idx")), 1));
    });
    $("#report-chain-save")?.addEventListener("click", () => saveChainEdits(chain));
    $("#report-chain-export-detail")?.addEventListener("click", () => exportChainMd(chain.id));
    $("#report-chain-close-detail")?.addEventListener("click", () => {
      openChainId = null;
      d.hidden = true;
      d.innerHTML = "";
      renderChainsList();
    });
  }

  function collectChainStepsFromDom(chain) {
    const steps = (chain.steps || []).map((s) => ({ ...s }));
    const d = $("#report-chain-detail");
    if (!d) return steps;
    d.querySelectorAll(".report-chain-role").forEach((inp) => {
      const i = Number(inp.getAttribute("data-idx"));
      if (steps[i]) steps[i].role = inp.value || "";
    });
    d.querySelectorAll(".report-chain-notes").forEach((inp) => {
      const i = Number(inp.getAttribute("data-idx"));
      if (steps[i]) steps[i].notes = inp.value || "";
    });
    return steps;
  }

  async function reorderChainStep(chain, idx, delta) {
    const steps = collectChainStepsFromDom(chain);
    const j = idx + delta;
    if (j < 0 || j >= steps.length) return;
    const tmp = steps[idx];
    steps[idx] = steps[j];
    steps[j] = tmp;
    const titleEl = $("#report-chain-title");
    await putChain({
      ...chain,
      title: titleEl ? titleEl.value : chain.title,
      steps,
    });
  }

  async function saveChainEdits(chain) {
    const titleEl = $("#report-chain-title");
    await putChain({
      ...chain,
      title: titleEl ? titleEl.value : chain.title,
      steps: collectChainStepsFromDom(chain),
    });
  }

  async function putChain(chain) {
    const base = apiBase();
    if (!base || !chain?.id) return;
    try {
      const r = await callApi(`${base}/chains/${encodeURIComponent(chain.id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: chain.id,
          title: chain.title || "Attack chain",
          include_states: chain.include_states,
          steps: chain.steps || [],
        }),
      });
      toast("Chain saved");
      openChainId = r.chain?.id || chain.id;
      await loadChains();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function createChain(opts) {
    const base = apiBase();
    if (!base) {
      toast("No run loaded", true);
      return;
    }
    const include_states = chainScopeStates();
    const body = {
      include_states,
      title: "",
      enqueue_poc: false,
      operator: "operator",
    };
    if (opts && opts.fromSelection) {
      const ids = [...selectedIds];
      if (!ids.length) {
        toast("Select findings with checkboxes first", true);
        return;
      }
      body.finding_ids = ids;
    }
    try {
      const r = await callApi(`${base}/chains/from-findings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      toast(`Created chain ${r.chain?.id?.slice?.(0, 8) || ""}… (${(r.chain?.steps || []).length} steps)`);
      openChainId = r.chain?.id || null;
      selectedIds.clear();
      renderTable();
      await loadChains();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function deleteChain(chainId) {
    const base = apiBase();
    if (!base || !chainId) return;
    try {
      await callApi(`${base}/chains/${encodeURIComponent(chainId)}`, {
        method: "DELETE",
      });
      toast("Chain deleted");
      if (openChainId === chainId) {
        openChainId = null;
        const d = $("#report-chain-detail");
        if (d) {
          d.hidden = true;
          d.innerHTML = "";
        }
      }
      await loadChains();
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  async function exportChainMd(chainId) {
    const base = apiBase();
    if (!base || !chainId) return;
    try {
      const r = await callApi(`${base}/chains/${encodeURIComponent(chainId)}/export`);
      downloadBlob(
        r.filename || `chain-${chainId}.md`,
        r.markdown || "",
        "text/markdown;charset=utf-8"
      );
      toast("Exported chain markdown");
    } catch (e) {
      toast(e.message || String(e), true);
    }
  }

  function setupReportPanels() {
    if (reportPanelsBound) return;
    reportPanelsBound = true;
    $("#report-clusters-refresh")?.addEventListener("click", () => loadClusters());
    $("#report-chains-refresh")?.addEventListener("click", () => loadChains());
    $("#report-chain-create")?.addEventListener("click", () =>
      createChain({ fromSelection: true })
    );
    $("#report-chain-create-all")?.addEventListener("click", () =>
      createChain({ fromSelection: false })
    );
  }

  function setupChrome() {
    const bind = (id, fn) => {
      const el = $(id);
      if (el && !el.dataset.bound) {
        el.dataset.bound = "1";
        el.addEventListener("click", fn);
      }
    };
    bind("#report-export-json", exportJSON);
    bind("#report-export-md", exportMarkdown);
    bind("#report-export-csv", exportCSV);
    bind("#report-export-html", () => exportServerFormat("html"));
    bind("#report-export-xlsx", () => exportServerFormat("xlsx"));
    bind("#report-export-docx", () => exportServerFormat("docx"));
    $$("[data-export-proj]").forEach((btn) => {
      if (btn.dataset.bound) return;
      btn.dataset.bound = "1";
      btn.addEventListener("click", () =>
        exportRawProjection(btn.getAttribute("data-export-proj"))
      );
    });
    setupReportPanels();
  }

  function setFilter(next) {
    filter = next || "all";
    openId = null;
    const d = $("#report-detail");
    if (d) {
      d.hidden = true;
      d.innerHTML = "";
    }
    renderSummary();
    renderTable();
  }

  /** Open Report and expand a finding by id (Coverage deep-link). */
  function openFinding(id) {
    if (id == null) return;
    filter = "all";
    openId = Number(id);
    renderSummary();
    renderTable();
    const f = cache.find((x) => Number(x.id) === Number(openId));
    const d = $("#report-detail");
    if (d && f) {
      d.hidden = false;
      d.innerHTML = detailHtml(f);
      bindDetailActions(d);
      d.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
  }

  function renderReport(snap) {
    if (!$("#panel-report") && !$("#report-tbody")) return;
    cache = Array.isArray(snap.findings) ? snap.findings : cache;
    meta = {
      target_id: snap.target_id || meta.target_id,
      run_id: snap.run_id || meta.run_id,
      target_path: snap.target_path || meta.target_path,
    };
    window.__VF_report_findings = cache;
    // Keep filter if it still matches something; otherwise reset to all
    if (filter !== "all" && !cache.some(matchesFilter)) {
      filter = "all";
    }
    if (!filter) filter = "all";
    setupChrome();
    setupPocChrome();
    renderSummary();
    renderTable();
    // Load clusters + chains (async); badges update when clusters return
    loadClusters().catch(() => {});
    loadChains().catch(() => {});
    // Restore open detail after refresh / human review
    if (openId != null) {
      const f = cache.find((x) => Number(x.id) === Number(openId));
      const d = $("#report-detail");
      if (d && f) {
        d.hidden = false;
        d.innerHTML = detailHtml(f);
        bindDetailActions(d);
      } else if (d) {
        d.hidden = true;
        d.innerHTML = "";
        openId = null;
      }
    }

    // Keep open POC workshop headers in sync when snap refreshes
    if (pocFindingId != null && isPocOpen()) {
      const pf = cache.find((x) => Number(x.id) === Number(pocFindingId));
      if (pf) fillPocWorkshopHeader(pf, pocLastLoad);
    }

    // Optional: list available projection downloads
    const raw = $("#report-raw-exports");
    if (raw) {
      const files = snap.project_files || [];
      if (!files.length) {
        raw.innerHTML = `<span class="controls-hint">No raw projection files yet (generate on idle).</span>`;
      } else {
        raw.innerHTML = files
          .map(
            (f) =>
              `<button type="button" class="btn btn-ghost btn-sm" data-export-proj="${esc(f.name)}">${esc(f.name)}</button>`
          )
          .join(" ");
        raw.querySelectorAll("[data-export-proj]").forEach((btn) => {
          btn.addEventListener("click", () =>
            exportRawProjection(btn.getAttribute("data-export-proj"))
          );
        });
      }
    }
  }

  window.VulnForgeReport = {
    render: renderReport,
    setFilter,
    openFinding,
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
  };
  window.renderReport = renderReport;
})();
