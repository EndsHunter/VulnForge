/**
 * Report → Reject → Promote to policy (#184): pure helpers.
 *
 * The draft is never saved by these helpers. Save is an explicit operator
 * click that POSTs to /promote-to-policy; provenance is stamped server-side
 * from the stored HITL reject, so the form never sends one.
 *
 * UMD: browser global ReportPolicyPromote and node require().
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.ReportPolicyPromote = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const TARGETS = ["exclusions", "out_of_scope"];

  const TARGET_LABELS = {
    exclusions: "Exclusion (this weakness class on these paths)",
    out_of_scope: "Out of scope (every class on these paths)",
  };

  function defaultEsc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /** Promote is offered only for an explicit human reject. */
  function canPromote(finding) {
    return !!finding && String(finding.state || "") === "rejected_human";
  }

  function parsePaths(text) {
    const out = [];
    String(text || "")
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((p) => {
        if (!out.includes(p)) out.push(p);
      });
    return out;
  }

  /**
   * Build the POST body from form values. Never includes provenance.
   * @param {{target_list:string,id:string,paths:string,weakness_class:string,reason:string,all_classes:boolean,base_revision:(number|null),note?:string}} f
   * @param {boolean} dryRun
   */
  function buildPromoteBody(f, dryRun) {
    const target = TARGETS.includes(f.target_list) ? f.target_list : "exclusions";
    const rule = { paths: parsePaths(f.paths), reason: String(f.reason || "").trim() };
    const id = String(f.id || "").trim();
    if (id) rule.id = id;
    if (target === "exclusions" && !f.all_classes) {
      rule.weakness_class = String(f.weakness_class || "").trim();
    }
    return {
      rule,
      target_list: target,
      base_revision: f.base_revision == null ? null : Number(f.base_revision),
      all_classes: target === "exclusions" && !!f.all_classes,
      note: String(f.note || ""),
      dry_run: !!dryRun,
    };
  }

  /** Error list from a FastAPI 4xx body ({detail:{error, errors, detail}}). */
  function errorLines(data) {
    const d = data && typeof data === "object" && data.detail != null ? data.detail : data;
    if (typeof d === "string") return [d];
    if (!d || typeof d !== "object") return ["request failed"];
    const out = [];
    if (Array.isArray(d.errors)) d.errors.forEach((e) => out.push(String(e)));
    if (!out.length && d.detail) out.push(String(d.detail));
    if (!out.length && d.error) out.push(String(d.error));
    return out.length ? out : ["request failed"];
  }

  function wouldMatchHtml(wm, esc) {
    const e = esc || defaultEsc;
    const hits = (wm && Array.isArray(wm.needs_human) && wm.needs_human) || [];
    const src =
      wm && wm.matches_source === false
        ? `<p class="controls-hint" style="color:var(--warn,#b80)">This rule would not match the rejected finding itself — check the paths.</p>`
        : "";
    if (!hits.length) {
      return `${src}<p class="controls-hint" style="margin:0">No findings awaiting review match this rule.</p>`;
    }
    return `${src}<p class="controls-hint" style="margin:0 0 0.35rem">These <span class="mono">needs_human</span> findings would match. They are <strong>not</strong> changed; review them yourself:</p>
      <ul class="report-reasons">${hits
        .map(
          (h) =>
            `<li><button type="button" class="btn btn-sm policy-promote-open" data-fid="${e(h.finding_id)}">#${e(
              h.finding_id
            )}</button> ${e(h.title || "")} <span class="muted mono">${e(
              (h.matched_paths || []).join(", ")
            )}</span></li>`
        )
        .join("")}</ul>${
      wm && wm.truncated
        ? `<p class="controls-hint" style="margin:0.35rem 0 0">Showing the first ${e(hits.length)} matches; more exist.</p>`
        : ""
    }`;
  }

  /** Policy history: rules first stamped from a human reject in this revision. */
  function historyProvenanceHtml(rows, esc) {
    const e = esc || defaultEsc;
    if (!Array.isArray(rows) || !rows.length) return "";
    return `<div class="controls-hint policy-provenance">${rows
      .map(
        (r) =>
          `<span>Rule <code>${e(r.rule_id)}</code> (${e(r.list)}) from human reject of finding <span class="mono">#${e(
            r.finding_id
          )}</span> · HITL <span class="mono">${e(r.hitl_report_id)}/${e(r.hitl_block_id)}</span> @ ${e(
            r.hitl_response_at
          )}${r.operator ? ` by ${e(r.operator)}` : ""}</span>`
      )
      .join("<br>")}</div>`;
  }

  return {
    TARGETS,
    TARGET_LABELS,
    canPromote,
    parsePaths,
    buildPromoteBody,
    errorLines,
    wouldMatchHtml,
    historyProvenanceHtml,
  };
});
