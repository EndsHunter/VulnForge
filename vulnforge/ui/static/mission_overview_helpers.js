/**
 * Pure helpers for Mission Overview KPI strip + pipeline timeline.
 * UMD/CommonJS — usable from the browser (script tag) and node --test.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.MissionOverviewHelpers = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /** Classify a task kind into pipeline stage: recon | hunt | validate_mech | validate_llm | other. */
  function pipelineStageOfKind(kind) {
    const k = String(kind || "").toLowerCase();
    if (k === "recon" || k.startsWith("recon:") || k.startsWith("recon/")) return "recon";
    if (k === "hunt" || k.startsWith("hunt:") || k.startsWith("hunt/")) return "hunt";
    if (k === "validate_mech" || k.startsWith("validate_mech")) return "validate_mech";
    if (k === "validate_llm" || k.startsWith("validate_llm")) return "validate_llm";
    return "other";
  }

  const PIPELINE_DONE_STATES = new Set([
    "succeeded",
    "done",
    "failed_task",
    "failed_infra",
    "deadletter",
    "cancelled",
    "blocked",
  ]);
  const PIPELINE_ACTIVE_STATES = new Set(["leased", "running"]);
  const PIPELINE_QUEUED_STATES = new Set(["queued", "paused"]);

  /** Aggregate task list for one pipeline stage. */
  function summarizePipelineStage(tasks, stageId, extraDone) {
    const mine = (tasks || []).filter((t) => pipelineStageOfKind(t.kind) === stageId);
    let queued = 0;
    let active = 0;
    let done = 0;
    let failed = 0;
    for (const t of mine) {
      const st = String(t.state || "").toLowerCase();
      if (PIPELINE_ACTIVE_STATES.has(st)) active += 1;
      else if (PIPELINE_QUEUED_STATES.has(st)) queued += 1;
      else if (st === "failed_task" || st === "failed_infra" || st === "deadletter") {
        failed += 1;
        done += 1;
      } else if (PIPELINE_DONE_STATES.has(st) || st === "succeeded") {
        done += 1;
      }
    }
    const total = mine.length;
    let status = "idle"; // idle | pending | queued | running | done | partial | failed
    if (extraDone && total === 0) {
      status = "done";
    } else if (total === 0) {
      status = "pending";
    } else if (active > 0) {
      status = "running";
    } else if (queued > 0 && done === 0) {
      status = "queued";
    } else if (queued > 0 && done > 0) {
      status = "partial";
    } else if (failed > 0 && failed === total) {
      status = "failed";
    } else if (done === total) {
      status = failed > 0 ? "partial" : "done";
    } else {
      status = "partial";
    }
    return { id: stageId, total, queued, active, done, failed, status };
  }

  /**
   * Build recon → hunt → validate_mech → validate_llm stage summaries from snap.tasks
   * plus architecture/findings signals when task rows are sparse.
   */
  function buildPipelineStages(snap) {
    const tasks = Array.isArray(snap.tasks) ? snap.tasks : [];
    const hasArch = !!(
      snap.has_architecture ||
      snap.architecture_summary?.has_architecture ||
      (snap.architecture && (snap.architecture.summary || "").trim())
    );
    const recon = summarizePipelineStage(tasks, "recon", hasArch);
    // hasArch passed as extraDone: empty recon + architecture ⇒ done (no second pending→done patch).

    const hunt = summarizePipelineStage(tasks, "hunt", false);
    const mech = summarizePipelineStage(tasks, "validate_mech", false);
    const vllm = summarizePipelineStage(tasks, "validate_llm", false);

    return [
      {
        ...recon,
        label: "Recon",
        hint: "Architecture map (LLM)",
      },
      {
        ...hunt,
        label: "Hunt",
        hint: "Area × skill investigation (LLM)",
      },
      {
        ...mech,
        label: "Validate · mech",
        hint: "Mechanical gates (no LLM)",
      },
      {
        ...vllm,
        label: "Validate · LLM",
        hint: "Dual-disprove (never auto-confirms)",
      },
    ];
  }

  /**
   * KPI strip running/queued counts from a state→count map.
   * running = leased + running (sum, not OR); queued = queued + paused.
   */
  function countMissionTaskActivity(taskCounts) {
    const counts = taskCounts || {};
    const queued = (counts.queued || 0) + (counts.paused || 0);
    const running = (counts.leased || 0) + (counts.running || 0);
    return { queued, running };
  }

  /** True when task kind is a hunt (hunt / hunt:class / hunt/…). */
  function isHuntKind(kind) {
    const k = String(kind || "").toLowerCase();
    return k === "hunt" || k.startsWith("hunt:") || k.startsWith("hunt/");
  }

  /** Compact area × class label for a hunt task row. */
  function huntTaskLabel(task) {
    const p = (task && task.payload) || {};
    const area = String(p.area || "").trim();
    const cls = String(p.class || p.weakness_class || "").trim();
    if (area && cls) return area + " × " + cls;
    if (cls) return cls;
    if (area) return area;
    const k = String((task && task.kind) || "");
    if (k.toLowerCase().startsWith("hunt:")) return k.slice(5) || "hunt";
    if (k.toLowerCase().startsWith("hunt/")) return k.slice(5) || "hunt";
    return "hunt";
  }

  const FEED_ACTIVE = new Set(["leased", "running"]);
  const FEED_QUEUED = new Set(["queued", "paused"]);
  const FEED_DONE = new Set([
    "succeeded",
    "done",
    "failed_task",
    "failed_infra",
    "deadletter",
    "cancelled",
    "blocked",
  ]);

  function huntFeedRank(state) {
    const st = String(state || "").toLowerCase();
    if (FEED_ACTIVE.has(st)) return 0;
    if (FEED_QUEUED.has(st)) return 1;
    if (FEED_DONE.has(st)) return 2;
    return 3;
  }

  /**
   * Hunt queue counts + compact live feed from snap.tasks.
   * Feed prefers active → queued → recent done (by id desc within rank).
   */
  function summarizeHuntQueue(tasks, opts) {
    const limit = (opts && opts.limit) || 8;
    const all = Array.isArray(tasks) ? tasks : [];
    const hunts = all.filter((t) => isHuntKind(t.kind));
    const counts = summarizePipelineStage(hunts, "hunt", false);
    const feed = hunts
      .slice()
      .sort((a, b) => {
        const ra = huntFeedRank(a.state);
        const rb = huntFeedRank(b.state);
        if (ra !== rb) return ra - rb;
        return (Number(b.id) || 0) - (Number(a.id) || 0);
      })
      .slice(0, limit)
      .map((t) => ({
        id: t.id,
        state: String(t.state || "").toLowerCase(),
        kind: t.kind,
        label: huntTaskLabel(t),
        has_transcript: !!t.has_transcript,
        area: (t.payload && t.payload.area) || "",
        class: (t.payload && (t.payload.class || t.payload.weakness_class)) || "",
      }));
    return {
      total: counts.total,
      queued: counts.queued,
      active: counts.active,
      done: counts.done,
      failed: counts.failed,
      status: counts.status,
      feed,
    };
  }

  /**
   * needs_human + candidate findings for the strip.
   * findings may be a list (full snap) or a state→count map (SSE card).
   */
  function listNeedsHumanFindings(findings, opts) {
    const limit = (opts && opts.limit) || 6;
    if (Array.isArray(findings)) {
      const items = findings.filter((f) => {
        const st = String((f && f.state) || "").toLowerCase();
        return st === "needs_human" || st === "candidate";
      });
      const sliced = items.slice(0, limit).map((f) => ({
        id: f.id,
        state: String(f.state || "").toLowerCase(),
        title: f.title || f.stable_key || ("Finding #" + f.id),
        severity: f.severity || "",
        class: f.weakness_class || f.class || f.hunt_class || "",
      }));
      return { count: items.length, items: sliced };
    }
    const counts = findings && typeof findings === "object" ? findings : {};
    const count = (counts.needs_human || 0) + (counts.candidate || 0);
    return { count, items: [] };
  }

  /**
   * Lightweight residual / finding cell counts from snap.coverage
   * (missing area×class cells count as residual empty).
   */
  function summarizeCoverageResidual(cov) {
    const areas = (cov && cov.areas) || [];
    const classes = (cov && cov.classes) || [];
    const cells = (cov && cov.cells) || [];
    const map = Object.create(null);
    for (const c of cells) {
      map[String(c.area || "") + "\0" + String(c.class || "")] = c;
    }
    const residualDepths = new Set(["", "planned", "shallow", "none", "aborted"]);
    const findingDepths = new Set(["candidate", "confirmed", "needs_human"]);
    let residual = 0;
    let hasFinding = 0;
    let empty = 0;
    if (areas.length && classes.length) {
      for (const a of areas) {
        for (const cl of classes) {
          const cell = map[String(a) + "\0" + String(cl)];
          const d = String((cell && (cell.last_depth || cell.depth)) || "").toLowerCase();
          if (!cell || residualDepths.has(d)) {
            residual += 1;
            if (!cell || d === "" || d === "planned") empty += 1;
          } else if (findingDepths.has(d)) {
            hasFinding += 1;
          }
        }
      }
    } else {
      for (const c of cells) {
        const d = String(c.last_depth || c.depth || "").toLowerCase();
        if (findingDepths.has(d)) hasFinding += 1;
        else {
          residual += 1;
          if (!d || d === "planned") empty += 1;
        }
      }
    }
    return {
      residual,
      hasFinding,
      empty,
      areas: areas.length,
      classes: classes.length,
      cells: cells.length,
    };
  }

  return {
    pipelineStageOfKind,
    summarizePipelineStage,
    buildPipelineStages,
    countMissionTaskActivity,
    isHuntKind,
    huntTaskLabel,
    summarizeHuntQueue,
    listNeedsHumanFindings,
    summarizeCoverageResidual,
    PIPELINE_DONE_STATES,
    PIPELINE_ACTIVE_STATES,
    PIPELINE_QUEUED_STATES,
  };
});
