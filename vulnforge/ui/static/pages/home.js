/*
 * Home (run list) helpers. Spec: docs/ui/REDESIGN.md → Home.
 * Pure functions over /api/runs cards; UMD so node --test can load them.
 * app.js (renderRunCards / renderRunRow) calls these via window.HomeHelpers.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.HomeHelpers = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

  function runnerState(r) {
    const runner = (r && r.runner) || {};
    const st = String(runner.state || (r && r.active ? "busy" : "idle")).toLowerCase();
    return st || "idle";
  }

  function lastEventKind(r) {
    const ev = r && r.last_event && typeof r.last_event === "object" ? r.last_event : {};
    return String(ev.event || ev.kind || "").toLowerCase();
  }

  /**
   * Display status for a run card: running | pausing | paused | stalled | error | idle.
   * "stalled" = queued work but the task loop is not running.
   */
  function runStatus(r) {
    if (!r) return "idle";
    if (r.error) return "error";
    const st = runnerState(r);
    if (st === "failed" || st === "error" || st === "dead" || lastEventKind(r) === "failed_infra") {
      return "error";
    }
    if (st === "running" || st === "busy") return "running";
    if (st === "pausing") return "pausing";
    if (st === "paused" || (r.runner && r.runner.stop) || r.stop) return "paused";
    const queued = num((r.tasks || {}).queued);
    if (r.has_work && queued > 0) return "stalled";
    return "idle";
  }

  const STATUS_LABEL = {
    running: "Running",
    pausing: "Pausing",
    paused: "Paused",
    stalled: "Stalled",
    error: "Error",
    idle: "Idle",
  };

  /** CSS tone class on .vf-runner-pill (shell.css). */
  const STATUS_TONE = {
    running: "is-running",
    pausing: "is-pausing",
    paused: "is-paused",
    stalled: "is-paused",
    error: "is-error",
    idle: "",
  };

  const STATUS_RANK = { running: 0, pausing: 1, stalled: 2, paused: 3, error: 4, idle: 5 };

  /**
   * Pipeline mini-strip. Review counts needs_human only — a candidate has not
   * passed mechanical gates and is never "waiting for a person".
   */
  function runPipeline(r) {
    const f = (r && r.findings) || {};
    const total = num(r && r.total_tasks);
    const done = num(r && r.done_tasks);
    return {
      tasks: total ? `${done}/${total}` : "0",
      review: num(f.needs_human),
      confirmed: num(f.confirmed),
    };
  }

  function updatedTs(r) {
    const raw = (r && (r.updated_at || r.created_at)) || null;
    const t = raw ? Date.parse(raw) : NaN;
    if (Number.isFinite(t)) return t;
    return num(r && r.mtime) * 1000;
  }

  /** Running runs first, then by status rank, then most recently updated. */
  function sortRuns(runs) {
    return (runs || []).slice().sort((a, b) => {
      const ra = STATUS_RANK[runStatus(a)] ?? 9;
      const rb = STATUS_RANK[runStatus(b)] ?? 9;
      if (ra !== rb) return ra - rb;
      return updatedTs(b) - updatedTs(a);
    });
  }

  function runHref(r, hash) {
    const base = `/runs/${encodeURIComponent(r.target_id)}/${encodeURIComponent(r.run_id)}`;
    return hash ? `${base}#${hash}` : base;
  }

  /**
   * "Needs your attention" items, one per run, most urgent first:
   * review (needs_human > 0) → error → stalled/paused. A run with several
   * reasons keeps its most urgent kind and joins the reasons in `text`.
   * Card-level errors (r.error, no ids) are reported without a link.
   */
  function attentionItems(runs) {
    const out = [];
    for (const r of runs || []) {
      if (!r) continue;
      const label = r.target_id && r.run_id ? `${r.target_id} / ${r.run_id}` : String(r.key || "run");
      if (r.error) {
        out.push({ kind: "error", rank: 1, label, text: String(r.error), href: null });
        continue;
      }
      const reasons = [];
      const review = num((r.findings || {}).needs_human);
      if (review > 0) {
        reasons.push({
          kind: "review",
          rank: 0,
          text: review === 1 ? "1 finding needs review" : `${review} findings need review`,
          href: runHref(r, "report/report"),
        });
      }
      const st = runStatus(r);
      if (st === "error") {
        reasons.push({ kind: "error", rank: 1, text: "Task loop failed", href: runHref(r, "audit/tasks") });
      } else if (st === "stalled") {
        const q = num((r.tasks || {}).queued);
        reasons.push({
          kind: "stalled",
          rank: 2,
          text: `${q} task${q === 1 ? "" : "s"} queued, Ralph not running`,
          href: runHref(r),
        });
      } else if (st === "paused") {
        reasons.push({ kind: "paused", rank: 2, text: "Paused", href: runHref(r) });
      }
      if (!reasons.length) continue;
      const top = reasons[0];
      out.push({
        kind: top.kind,
        rank: top.rank,
        label,
        count: review > 0 ? review : undefined,
        text: reasons.map((x) => x.text).join(" · "),
        href: top.href,
      });
    }
    return out.sort((a, b) => a.rank - b.rank);
  }

  const KIND_LABEL = { review: "Review", error: "Error", stalled: "Stalled", paused: "Paused" };

  /** Attention band markup; "" when nothing needs attention (band stays hidden). */
  function renderAttentionHtml(items, esc) {
    const e = typeof esc === "function" ? esc : (s) => String(s);
    if (!items || !items.length) return "";
    const rows = items
      .map((it) => {
        const inner =
          `<span class="vf-attn-kind vf-attn-kind--${e(it.kind)}">${e(KIND_LABEL[it.kind] || it.kind)}</span>` +
          `<span class="vf-attn-run vf-mono">${e(it.label)}</span>` +
          `<span class="vf-attn-text">${e(it.text)}</span>`;
        return it.href
          ? `<li><a class="vf-attn-item" href="${e(it.href)}">${inner}<span class="vf-attn-go" aria-hidden="true">›</span></a></li>`
          : `<li><div class="vf-attn-item">${inner}</div></li>`;
      })
      .join("");
    return `<h2 class="vf-section-label">Needs your attention <span class="vf-attn-count">${items.length}</span></h2><ul class="vf-attn-list">${rows}</ul>`;
  }

  return {
    renderAttentionHtml,
    runStatus,
    runPipeline,
    sortRuns,
    attentionItems,
    runHref,
    STATUS_LABEL,
    STATUS_TONE,
  };
});
