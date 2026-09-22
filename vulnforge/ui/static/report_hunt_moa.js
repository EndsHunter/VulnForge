/**
 * Report / Mission provenance for multi-perspective hunt MoA (body.hunt_moa).
 * Agreement ≠ verification ≠ confirm. Absent field → no MoA chrome.
 *
 * UMD: browser global ReportHuntMoa and node require().
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.ReportHuntMoa = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const TIP =
    "Hunt MoA agreement across perspectives — not verification and not confirmed. " +
    "Confirmed is human-only. The harness never auto-confirms on agree.";

  const REQUEUE_LABELS = {
    all_perspectives_none:
      "All hunt perspectives returned none (all_perspectives_none). Not proof of safety.",
    partial_none:
      "Some hunt perspectives returned none (partial_none); a candidate still exists. Agreement ≠ confirm.",
  };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function trunc(s, n) {
    const t = String(s == null ? "" : s).trim();
    if (!t) return "";
    if (t.length <= n) return t;
    return t.slice(0, Math.max(0, n - 1)) + "…";
  }

  /** Normalize contract short token or spike long string → short key or "". */
  function normalizeRequeueNote(raw) {
    if (raw == null) return "";
    const s = String(raw).trim();
    if (!s) return "";
    if (s === "all_perspectives_none" || s.startsWith("all_perspectives_none")) {
      return "all_perspectives_none";
    }
    if (s === "partial_none" || s.startsWith("partial_none")) {
      return "partial_none";
    }
    return "";
  }

  function huntMoaOf(findingOrBody) {
    if (!findingOrBody || typeof findingOrBody !== "object") return null;
    const body =
      findingOrBody.body && typeof findingOrBody.body === "object"
        ? findingOrBody.body
        : findingOrBody;
    const moa = body.hunt_moa;
    if (!moa || typeof moa !== "object") return null;
    return moa;
  }

  function huntMoaMeta(findingOrBody) {
    const moa = huntMoaOf(findingOrBody);
    if (!moa) return null;
    const perspectives = Array.isArray(moa.perspectives) ? moa.perspectives : [];
    const agree =
      moa.agree_count != null ? Number(moa.agree_count) : NaN;
    const n =
      perspectives.length ||
      (Number.isFinite(agree) ? agree : 0);
    let label = moa.label != null ? String(moa.label).trim() : "";
    if (!label && Number.isFinite(agree) && n > 0) {
      label = `${agree}/${n} hunt agree`;
    }
    if (!label && !perspectives.length && moa.cell_outcome == null && !moa.requeue_note) {
      // Empty object → treat as absent chrome
      return null;
    }
    return {
      label: label || "hunt MoA",
      agree_count: Number.isFinite(agree) ? agree : null,
      perspectives,
      cell_outcome: moa.cell_outcome != null ? String(moa.cell_outcome) : "",
      requeue_note: normalizeRequeueNote(moa.requeue_note),
      requeue_raw: moa.requeue_note != null ? String(moa.requeue_note) : "",
      none_perspectives: Array.isArray(moa.none_perspectives)
        ? moa.none_perspectives.map(String)
        : [],
    };
  }

  function huntMoaBadgeHtml(findingOrBody) {
    const m = huntMoaMeta(findingOrBody);
    if (!m || !m.label) return "";
    return `<span class="badge hunt-moa-agree" title="${esc(TIP)}" data-tip="${esc(
      TIP
    )}" tabindex="0">${esc(m.label)}</span>`;
  }

  function perspectiveRowHtml(p) {
    if (!p || typeof p !== "object") return "";
    const id = esc(p.id || "?");
    const outcome = esc(p.outcome || "?");
    const title = trunc(p.title, 80);
    const reason = trunc(p.reason, 160);
    const extra = [title && `title: ${title}`, reason && `reason: ${reason}`]
      .filter(Boolean)
      .join(" · ");
    return `<li class="report-hunt-moa-slot">
      <span class="mono">${id}</span>
      · <span class="badge">${outcome}</span>
      ${extra ? `<span class="controls-hint">${esc(extra)}</span>` : ""}
    </li>`;
  }

  function huntMoaDetailHtml(findingOrBody) {
    const m = huntMoaMeta(findingOrBody);
    if (!m) return "";
    const rows = (m.perspectives || []).map(perspectiveRowHtml).filter(Boolean).join("");
    const none =
      m.none_perspectives && m.none_perspectives.length
        ? `<p class="controls-hint">None perspectives: <span class="mono">${esc(
            m.none_perspectives.join(", ")
          )}</span></p>`
        : "";
    const rq = m.requeue_note
      ? `<p class="controls-hint report-hunt-moa-requeue">${esc(
          REQUEUE_LABELS[m.requeue_note] || m.requeue_raw
        )}</p>`
      : "";
    const cell = m.cell_outcome
      ? `<span class="controls-hint mono">cell: ${esc(m.cell_outcome)}</span>`
      : "";
    return `<div class="report-hunt-moa" data-hunt-moa="1">
      <h4>Hunt MoA <span class="badge hunt-moa-agree">${esc(m.label)}</span> ${cell}</h4>
      <p class="controls-hint">${esc(TIP)}</p>
      ${rows ? `<ul class="report-hunt-moa-list">${rows}</ul>` : ""}
      ${none}
      ${rq}
    </div>`;
  }

  /** Pick a requeue note from cell findings (first match). */
  function cellRequeueNote(findings) {
    if (!Array.isArray(findings)) return "";
    for (const f of findings) {
      const m = huntMoaMeta(f);
      if (m && m.requeue_note) return m.requeue_note;
    }
    // Also accept task.result.hunt_moa / body on fixtures
    return "";
  }

  function cellRequeueNoteHtml(findings, taskResults) {
    let key = cellRequeueNote(findings);
    if (!key && Array.isArray(taskResults)) {
      for (const t of taskResults) {
        const res = (t && t.result) || {};
        const raw =
          res.requeue_note ||
          (res.hunt_moa && res.hunt_moa.requeue_note) ||
          "";
        key = normalizeRequeueNote(raw);
        if (key) break;
      }
    }
    if (!key) return "";
    const label = REQUEUE_LABELS[key] || key;
    return `<p class="cov-moa-requeue" data-requeue-note="${esc(key)}">
      <span class="cov-why-k">Hunt MoA</span> ${esc(label)}
    </p>`;
  }

  return {
    TIP,
    REQUEUE_LABELS,
    huntMoaOf,
    huntMoaMeta,
    huntMoaBadgeHtml,
    huntMoaDetailHtml,
    normalizeRequeueNote,
    cellRequeueNote,
    cellRequeueNoteHtml,
  };
});
