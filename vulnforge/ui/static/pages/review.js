/*
 * Review page (Triage Desk) — mode id "report". Spec: docs/ui/REDESIGN.md → Review.
 *
 * Two parts:
 *  1. ReviewHelpers — pure functions (UMD, node --test): queue order/filter/counts,
 *     next-undecided selection, data-flow trace, mech gate checklist, disprove judges,
 *     PoC status line. report.js renders with these.
 *  2. window.VFPages.review — page lifecycle + J/K/A/R/E keys (browser only). The
 *     rendering itself lives in report.js (window.VulnForgeReport).
 *
 * Honesty: nothing here changes finding state. Accept/Reject go through
 * VulnForgeReport.decide → POST /findings/{id}/review (explicit human review).
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.ReviewHelpers = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const SEVERITY_RANK = { critical: 5, crit: 5, high: 4, medium: 3, med: 3, low: 2, info: 1 };
  const STATE_RANK = {
    needs_human: 0,
    candidate: 1,
    confirmed: 2,
    rejected_mech: 3,
    rejected_llm: 4,
    rejected_human: 5,
    superseded: 6,
  };
  /** States a person still has to decide on. */
  const UNDECIDED = new Set(["needs_human", "candidate"]);

  const FILTERS = [
    { id: "needs_human", label: "Needs review" },
    { id: "candidate", label: "Candidate" },
    { id: "confirmed", label: "Confirmed" },
    { id: "rejected", label: "Rejected" },
    { id: "near_dup", label: "Near-dup" },
    { id: "all", label: "All" },
  ];

  function bodyOf(f) {
    return (f && f.body) || {};
  }

  function stateOf(f) {
    return String((f && f.state) || "").toLowerCase();
  }

  function severityOf(f) {
    const b = bodyOf(f);
    return String((f && f.severity) || b.severity_claim || "unknown").toLowerCase().trim();
  }

  /** Short severity key for .vf-sev--* (crit|high|med|low) or "" for unknown/info. */
  function sevKey(f) {
    const s = severityOf(f);
    if (s === "critical" || s === "crit") return "crit";
    if (s === "high") return "high";
    if (s === "medium" || s === "med") return "med";
    if (s === "low") return "low";
    return "";
  }

  function sevLabel(f) {
    const k = sevKey(f);
    return { crit: "Critical", high: "High", med: "Medium", low: "Low" }[k] ||
      (severityOf(f) === "info" ? "Info" : "Unknown");
  }

  function isRejected(f) {
    const st = stateOf(f);
    return st.startsWith("rejected") || st === "superseded";
  }

  function isUndecided(f) {
    return UNDECIDED.has(stateOf(f));
  }

  /** Pill tone + label for the current state (never a trail). */
  function statePill(f) {
    const st = stateOf(f);
    if (st === "needs_human") return { tone: "review", label: "Needs review" };
    if (st === "candidate") return { tone: "candidate", label: "Candidate" };
    if (st === "confirmed") return { tone: "confirmed", label: "Confirmed" };
    if (st === "rejected_mech") return { tone: "rejected", label: "Rejected · gates" };
    if (st === "rejected_llm") return { tone: "rejected", label: "Rejected · disprove" };
    if (st === "rejected_human") return { tone: "rejected", label: "Rejected · human" };
    if (st === "superseded") return { tone: "rejected", label: "Superseded" };
    return { tone: "candidate", label: st || "unknown" };
  }

  /** Queue order: severity desc, then state (needs review first), then newest id. */
  function compareQueue(a, b) {
    const sa = SEVERITY_RANK[severityOf(a)] || 0;
    const sb = SEVERITY_RANK[severityOf(b)] || 0;
    if (sa !== sb) return sb - sa;
    const ta = STATE_RANK[stateOf(a)] ?? 9;
    const tb = STATE_RANK[stateOf(b)] ?? 9;
    if (ta !== tb) return ta - tb;
    return (Number(b && b.id) || 0) - (Number(a && a.id) || 0);
  }

  /**
   * @param {object} f finding
   * @param {string} filter one of FILTERS ids
   * @param {(f: object) => boolean} [isNearDup]
   */
  function matchesQueueFilter(f, filter, isNearDup) {
    const ftr = String(filter || "all").toLowerCase();
    const st = stateOf(f);
    if (ftr === "all") return true;
    if (ftr === "needs_human") return st === "needs_human";
    if (ftr === "candidate") return st === "candidate";
    if (ftr === "confirmed") return st === "confirmed";
    if (ftr === "rejected") return isRejected(f);
    if (ftr === "near_dup" || ftr === "overlaps") {
      return !!((f && f.near_dup) || (isNearDup && isNearDup(f)));
    }
    return st === ftr;
  }

  function queueCounts(findings, isNearDup) {
    const c = { all: 0, needs_human: 0, candidate: 0, confirmed: 0, rejected: 0, near_dup: 0 };
    for (const f of findings || []) {
      c.all += 1;
      for (const k of ["needs_human", "candidate", "confirmed", "rejected", "near_dup"]) {
        if (matchesQueueFilter(f, k, isNearDup)) c[k] += 1;
      }
    }
    return c;
  }

  /**
   * Next finding to show after `currentId` is decided: the next undecided one after it
   * in queue order, else the nearest undecided before it, else null.
   * @param {object[]} ordered queue in display order (may still contain current)
   */
  function nextUndecided(ordered, currentId) {
    const list = Array.isArray(ordered) ? ordered : [];
    const idx = list.findIndex((f) => Number(f && f.id) === Number(currentId));
    const pick = (f) => f && Number(f.id) !== Number(currentId) && isUndecided(f);
    for (let i = idx + 1; i < list.length; i++) if (pick(list[i])) return Number(list[i].id);
    for (let i = (idx < 0 ? list.length : idx) - 1; i >= 0; i--) {
      if (pick(list[i])) return Number(list[i].id);
    }
    return null;
  }

  /** J/K: id of the neighbour `delta` steps away (clamped), or null when empty. */
  function stepSelection(ordered, currentId, delta) {
    const list = Array.isArray(ordered) ? ordered : [];
    if (!list.length) return null;
    const idx = list.findIndex((f) => Number(f && f.id) === Number(currentId));
    if (idx < 0) return Number(list[delta < 0 ? list.length - 1 : 0].id);
    const next = Math.max(0, Math.min(list.length - 1, idx + delta));
    return Number(list[next].id);
  }

  function locLabel(path, start, end) {
    if (!path) return "";
    let s = String(path);
    if (start != null && start !== "") s += `:${start}`;
    if (end != null && end !== "" && Number(end) !== Number(start)) s += `-${end}`;
    return s;
  }

  function normKind(raw) {
    const k = String(raw || "").toLowerCase();
    if (/source|input|entry/.test(k)) return "source";
    if (/sink/.test(k)) return "sink";
    if (/sanit|guard|check/.test(k)) return "guard";
    return "flow";
  }

  /**
   * Data-flow cards. Prefers an explicit trace (body.trace | data_flow | dataflow |
   * flow | taint_path: [{kind|role, path, line|start_line, symbol|what|expr}]).
   * Otherwise uses citations in order: first = source, last = sink (or the citation
   * matching body.sink_path), middle = flow. One citation → a single "cited" card,
   * or "sink" when it is the recorded sink.
   * @returns {{ kind: string, what: string, where: string, path: string, line: number|null, derived: boolean }[]}
   */
  function buildTrace(body) {
    const b = body || {};
    const explicit = [b.trace, b.data_flow, b.dataflow, b.flow, b.taint_path].find(
      (x) => Array.isArray(x) && x.length
    );
    if (explicit) {
      return explicit
        .filter((s) => s && typeof s === "object")
        .map((s) => {
          const line = s.line ?? s.start_line ?? null;
          return {
            kind: normKind(s.kind || s.role || s.type),
            what: String(s.symbol || s.what || s.expr || s.label || s.path || "").trim(),
            where: locLabel(s.path, line, s.end_line),
            path: s.path ? String(s.path) : "",
            line: line != null ? Number(line) : null,
            derived: false,
          };
        });
    }
    const cites = (Array.isArray(b.citations) ? b.citations : []).filter((c) => c && c.path);
    if (!cites.length) {
      if (b.sink_path) {
        return [{ kind: "sink", what: String(b.sink_symbol || b.sink_path), where: String(b.sink_path), path: String(b.sink_path), line: null, derived: true }];
      }
      return [];
    }
    const sinkPath = b.sink_path ? String(b.sink_path) : "";
    const sinkSym = b.sink_symbol ? String(b.sink_symbol) : "";
    let sinkIdx = -1;
    if (sinkPath) {
      sinkIdx = cites.findIndex(
        (c) => String(c.path) === sinkPath && (!sinkSym || !c.symbol || String(c.symbol) === sinkSym)
      );
    }
    return cites.map((c, i) => {
      let kind = "flow";
      if (cites.length === 1) kind = sinkIdx === 0 ? "sink" : "cited";
      else if (sinkIdx >= 0) kind = i === sinkIdx ? "sink" : i === 0 ? "source" : "flow";
      else kind = i === 0 ? "source" : i === cites.length - 1 ? "sink" : "flow";
      return {
        kind,
        what: String(c.symbol || c.path),
        where: locLabel(c.path, c.start_line, c.end_line),
        path: String(c.path),
        line: c.start_line != null ? Number(c.start_line) : null,
        derived: true,
      };
    });
  }

  /** validate_mech CHECKS → reason-code prefixes (vulnforge/stages/validate_mech.py). */
  const MECH_GATES = [
    { id: "schema", label: "Schema is complete", codes: ["schema"] },
    {
      id: "citations",
      label: "Citations resolve in the target",
      codes: ["missing_path", "citation_escape", "cited_missing", "line_oob", "bad_line_range", "citation_missing_line", "citation_not_object", "unreadable"],
    },
    { id: "content", label: "Cited lines match the claim", codes: ["citation_content_mismatch", "citation_empty_slice"] },
    {
      id: "evidence",
      label: "Evidence pack is present",
      codes: ["missing_evidence", "missing_evidence_id", "missing_manifest", "missing_poc", "poc_without_evidence_id", "weak_no_poc_justification", "hash_fail"],
    },
    { id: "target", label: "Target tree unmodified", codes: ["target_mutated", "binary_hash_fail", "binary_missing", "no_run"] },
    {
      id: "nonvacuous",
      label: "Threat model is specific",
      codes: ["vacuous_attacker", "vacuous_boundary", "vacuous_impact", "vacuous_impact_for_severity", "title_too_short", "summary_too_short"],
    },
    { id: "severity", label: "Severity claim is valid", codes: ["bad_severity"] },
  ];

  function reasonCode(r) {
    return String(r || "").split(/[:\s(]/)[0].trim().toLowerCase();
  }

  /**
   * Gate checklist. Per-check results are not stored, so: mech passed → every gate
   * passed; rejected_mech → gates owning a reason failed, the rest passed; otherwise
   * every gate is pending. Unmapped reasons come back in `other`.
   * @returns {{ status: "passed"|"failed"|"pending", gates: {id,label,status,reasons}[], other: string[], passed: number, total: number }}
   */
  function mechGates(finding) {
    const b = bodyOf(finding);
    const st = stateOf(finding);
    const mech = b.validation_mech && typeof b.validation_mech === "object" ? b.validation_mech : {};
    const rawReasons = Array.isArray(b.validation_reasons)
      ? b.validation_reasons
      : Array.isArray(mech.reasons) ? mech.reasons : [];
    const reasons = rawReasons.map((r) => (typeof r === "string" ? r : JSON.stringify(r)));
    let status = "pending";
    if (st === "rejected_mech" || String(mech.status || "").toLowerCase() === "failed") status = "failed";
    else if (String(mech.status || "").toLowerCase() === "passed" || ["needs_human", "confirmed", "rejected_llm", "rejected_human"].includes(st)) status = "passed";
    const used = new Set();
    const gates = MECH_GATES.map((g) => {
      const mine = status === "failed" ? reasons.filter((r) => g.codes.includes(reasonCode(r))) : [];
      mine.forEach((r) => used.add(r));
      return {
        id: g.id,
        label: g.label,
        status: status === "pending" ? "pending" : mine.length ? "failed" : "passed",
        reasons: mine,
      };
    });
    const other = status === "failed" ? reasons.filter((r) => !used.has(r)) : [];
    return {
      status,
      gates,
      other,
      passed: gates.filter((g) => g.status === "passed").length,
      total: gates.length,
    };
  }

  /**
   * Dual-disprove judges from body.validation_llm.verifiers. `stand` = could not
   * disprove; `reject` = argued it is not real. Demote-only; never confirms.
   */
  function disproveJudges(finding) {
    const v = bodyOf(finding).validation_llm;
    const verifiers = v && Array.isArray(v.verifiers) ? v.verifiers : [];
    return verifiers.map((vr, i) => {
      const verdict = String((vr && vr.verdict) || "").toLowerCase();
      const label =
        verdict === "stand" ? "could not disprove"
          : verdict === "reject" ? "rejected"
            : verdict || "pending";
      return {
        name: (vr && (vr.id || vr.perspective)) || `Judge ${String.fromCharCode(65 + i)}`,
        verdict,
        label,
        tone: verdict === "reject" ? "reject" : verdict === "stand" ? "stand" : "pending",
        note: String((vr && vr.reasoning) || "").trim(),
        model: (vr && vr.model_id) ? String(vr.model_id) : "",
      };
    });
  }

  /** One-line PoC status from finding body (no network). */
  function pocStatus(finding) {
    const b = bodyOf(finding);
    const run = b.poc_validation_latest;
    if (run && typeof run === "object") {
      const bits = [`Sandbox run: ${run.verdict || "unknown"}`];
      if (run.exit_code != null) bits.push(`exit ${run.exit_code}`);
      if (run.signal_matched === true) bits.push("signal matched");
      return { tone: "ran", text: bits.join(" · ") + ". Not proof; does not confirm." };
    }
    if (b.poc_development_latest) return { tone: "draft", text: "PoC drafted. Not run in the sandbox yet." };
    if (b.poc_relpath) return { tone: "draft", text: `PoC file ${b.poc_relpath}. Not run in the sandbox yet.` };
    if (b.no_poc) return { tone: "none", text: "No PoC (no_poc recorded)." };
    return { tone: "none", text: "No PoC yet." };
  }

  /** "6 min ago" style label; "" when unparseable. */
  function ageLabel(iso, nowMs) {
    const t = Date.parse(iso || "");
    if (!Number.isFinite(t)) return "";
    const s = Math.max(0, Math.round(((nowMs ?? Date.now()) - t) / 1000));
    if (s < 60) return "just now";
    const m = Math.round(s / 60);
    if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60);
    if (h < 48) return `${h} h ago`;
    return `${Math.round(h / 24)} d ago`;
  }

  /** Key → action for the page keyboard handler (null = not ours). */
  function keyAction(ev) {
    if (!ev || ev.metaKey || ev.ctrlKey || ev.altKey) return null;
    const k = String(ev.key || "").toLowerCase();
    return { j: "next", k: "prev", a: "accept", r: "reject", e: "evidence" }[k] || null;
  }

  return {
    FILTERS,
    MECH_GATES,
    sevKey,
    sevLabel,
    statePill,
    isUndecided,
    compareQueue,
    matchesQueueFilter,
    queueCounts,
    nextUndecided,
    stepSelection,
    buildTrace,
    mechGates,
    disproveJudges,
    pocStatus,
    ageLabel,
    keyAction,
  };
});

/* ---- Browser page registration (skipped under node) ---- */
(function () {
  "use strict";
  if (typeof window === "undefined" || typeof document === "undefined") return;

  const H = window.ReviewHelpers;

  function isActive() {
    return window.VulnForgeModes?.activeMode?.() === "report";
  }

  function inField(target) {
    if (!target) return false;
    if (target.isContentEditable) return true;
    return /^(INPUT|TEXTAREA|SELECT)$/i.test(target.tagName || "");
  }

  function onKey(ev) {
    if (!isActive() || inField(ev.target)) return;
    const R = window.VulnForgeReport;
    if (!R || R.isPocOpen?.()) return;
    if (document.querySelector(".modal-backdrop.open, .modal-backdrop[aria-hidden='false']")) return;
    const action = H && H.keyAction(ev);
    if (!action) return;
    let handled = true;
    if (action === "next") R.selectRelative?.(1);
    else if (action === "prev") R.selectRelative?.(-1);
    else if (action === "accept") R.decide?.("confirm");
    else if (action === "reject") R.decide?.("reject");
    else if (action === "evidence") handled = !!R.openCurrentEvidence?.();
    else handled = false;
    if (handled) {
      ev.preventDefault();
      // Capture phase: keep modes.js global "e → Explorer" from also firing.
      ev.stopPropagation();
    }
  }

  window.VFPages = window.VFPages || {};
  window.VFPages.review = {
    mount() {},
    // app.js already calls window.renderReport(snap) on every snapshot.
    render() {},
    isActive,
    onShow() {
      window.VulnForgeReport?.ensureSelection?.();
    },
    onHide() {},
  };

  document.addEventListener("keydown", onKey, true);
})();
