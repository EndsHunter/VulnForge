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

  /**
   * Display fold of validate_mech + validate_llm. Does not change task kinds.
   * Empty side (total 0, not running/queued) is ignored so validate_llm-off
   * does not leave Validate pending after mech finishes.
   */
  function foldValidateStatus(mech, llm) {
    const a = mech || {};
    const b = llm || {};
    if (a.status === "running" || b.status === "running") return "running";
    if (a.status === "queued" || b.status === "queued") {
      return (a.done || 0) > 0 || (b.done || 0) > 0 ? "partial" : "queued";
    }
    const aEmpty = (a.total || 0) === 0;
    const bEmpty = (b.total || 0) === 0;
    const aDone = a.status === "done" || ((a.total || 0) > 0 && a.done === a.total);
    const bDone = b.status === "done" || ((b.total || 0) > 0 && b.done === b.total);
    if ((aDone || aEmpty) && (bDone || bEmpty) && (aDone || bDone)) {
      const total = (a.total || 0) + (b.total || 0);
      const failed = (a.failed || 0) + (b.failed || 0);
      if (failed > 0 && failed === total) return "failed";
      if (failed > 0) return "partial";
      return "done";
    }
    if (a.status === "partial" || b.status === "partial") return "partial";
    if (a.status === "failed" || b.status === "failed") return "partial";
    if (a.status === "idle" && b.status === "idle") return "idle";
    return "pending";
  }

  function buildVisualPipeline(snap) {
    const stages = buildPipelineStages(snap);
    const recon = stages[0];
    const hunt = stages[1];
    const mech = stages[2];
    const llm = stages[3];
    return [
      {
        id: "recon",
        label: recon.label,
        hint: recon.hint,
        status: recon.status,
        done: recon.done,
        total: recon.total,
      },
      {
        id: "hunt",
        label: hunt.label,
        hint: hunt.hint,
        status: hunt.status,
        done: hunt.done,
        total: hunt.total,
      },
      {
        id: "validate",
        label: "Validate",
        hint: "Mechanical gates, then LLM disprove (never auto-confirms)",
        status: foldValidateStatus(mech, llm),
        done: (mech.done || 0) + (llm.done || 0),
        total: (mech.total || 0) + (llm.total || 0),
        mech,
        llm,
      },
    ];
  }

  function countFindingState(snap, state) {
    const findings = snap && snap.findings;
    if (Array.isArray(findings)) {
      return findings.filter(
        (f) => String((f && f.state) || "").toLowerCase() === state
      ).length;
    }
    const counts = findings && typeof findings === "object" ? findings : {};
    return Number(counts[state] || 0) || 0;
  }

  function buildMissionKpis(snap) {
    const s = snap || {};
    const done = Number(s.done_tasks || 0);
    const total = Number(s.total_tasks || 0);
    const barTasks = Math.round((Number(s.progress) || 0) * 100);
    const needs = countFindingState(s, "needs_human");
    const cov = summarizeCoverageResidual(s.coverage);
    const denom =
      cov.areas && cov.classes ? cov.areas * cov.classes : cov.cells;
    const covPct = denom > 0 ? Math.round((100 * (denom - cov.residual)) / denom) : null;
    return [
      {
        id: "tasks",
        label: "Tasks",
        value: done + "/" + total,
        hint: "Done / total tasks",
        barPct: barTasks,
        nav: { mode: "audit", tab: "tasks" },
      },
      {
        id: "needs_human",
        label: "Needs human",
        value: String(needs),
        hint: "Mechanical gates passed. Not confirmed.",
        barPct: null,
        nav: { mode: "report", tab: "report", filter: "needs_human" },
      },
      {
        id: "coverage",
        label: "Coverage",
        value: covPct == null ? "—" : covPct + "%",
        hint: "Share of area × class cells that are not residual. Not proof.",
        barPct: covPct,
        nav: { mode: "hunts", tab: "hunts" },
      },
    ];
  }

  function buildArchitectureBrief(snap) {
    const s = snap || {};
    const sum = s.architecture_summary || {};
    const arch = s.architecture || {};
    const inv = s.target_inventory || {};
    const text = String(sum.summary || arch.summary || "").trim();
    const comps = Array.isArray(sum.components) ? sum.components : [];
    const rels = Array.isArray(sum.relations) ? sum.relations : [];
    const focus = Array.isArray(sum.hunt_focus) ? sum.hunt_focus : [];
    const hasArchitecture = !!(
      sum.has_architecture ||
      s.has_architecture ||
      text ||
      comps.length
    );
    const fileCount =
      inv.file_count == null || inv.file_count === ""
        ? null
        : Number(inv.file_count);
    const eps = Array.isArray(inv.entrypoints) ? inv.entrypoints : [];
    const lr = inv.last_recon;
    const lastReconError =
      lr && lr.state && lr.state !== "succeeded"
        ? String(lr.error || lr.state)
        : null;
    const diagramSource = hasArchitecture
      ? {
          components: sum.components || [],
          trust_boundaries: sum.trust_boundaries || [],
          modules: sum.modules || [],
          relations: sum.relations || [],
        }
      : null;
    const snippet =
      text.length > 420 ? text.slice(0, 420) + "…" : text;
    return {
      title: sum.title || "Architecture",
      hasArchitecture,
      snippet,
      componentCount: comps.length,
      relationCount: rels.length,
      huntFocusCount: focus.length,
      fileCount: Number.isFinite(fileCount) ? fileCount : null,
      entrypointCount: eps.length,
      lastReconError,
      diagramSource,
    };
  }

  function buildMissionCockpit(snap, opts) {
    const s = snap || {};
    const events = opts && Array.isArray(opts.recentEvents) ? opts.recentEvents.slice() : [];
    return {
      kpis: buildMissionKpis(s),
      pipeline: buildVisualPipeline(s),
      events,
      architecture: buildArchitectureBrief(s),
      validateLlmOn: !!s.validate_llm_on,
    };
  }

  return {
    pipelineStageOfKind,
    summarizePipelineStage,
    buildPipelineStages,
    buildVisualPipeline,
    buildMissionKpis,
    buildArchitectureBrief,
    buildMissionCockpit,
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
