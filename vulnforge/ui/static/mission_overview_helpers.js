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

  return {
    pipelineStageOfKind,
    summarizePipelineStage,
    buildPipelineStages,
    countMissionTaskActivity,
    PIPELINE_DONE_STATES,
    PIPELINE_ACTIVE_STATES,
    PIPELINE_QUEUED_STATES,
  };
});
