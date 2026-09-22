/**
 * Pure helpers for Mission Overview KPI strip, finding funnel,
 * who/why-paused, and concurrent work lanes.
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

  /**
   * Map a helper stage onto a concurrent lane light.
   * idle | running | idle-with-results | failed.
   * Ralph is not a lane — the runner strip owns that state.
   *
   * running / queued / partial-with-active (and any queued remainder) → running
   * done, or idle/pending/partial with done>0 and nothing in flight → idle-with-results
   * idle/pending with no results → idle
   * failed stays failed
   */
  function laneStatusOf(stage) {
    const s = stage || {};
    const status = String(s.status || "idle");
    const active = Number(s.active || s.running) || 0;
    const queued = Number(s.queued) || 0;
    const done = Number(s.done) || 0;
    const total = Number(s.total) || 0;

    if (status === "failed") return "failed";

    if (
      status === "running" ||
      status === "queued" ||
      (status === "partial" && active > 0) ||
      active > 0 ||
      queued > 0
    ) {
      return "running";
    }

    if (status === "done" && total > 0) return "idle-with-results";
    if ((status === "idle" || status === "pending") && done > 0) return "idle-with-results";
    // Architecture-only recon: extraDone sets status done with no task rows.
    if (status === "done") return "idle-with-results";
    // Mixed finish (some failures, queue empty) still has results.
    if (status === "partial" && done > 0) return "idle-with-results";

    return "idle";
  }

  /** Visible lane counts, e.g. "3 running · 12 done". Empty when nothing to show. */
  function formatLaneCounts(stage) {
    const s = stage || {};
    const active = Number(s.active || s.running) || 0;
    const queued = Number(s.queued) || 0;
    const done = Number(s.done) || 0;
    const failed = Number(s.failed) || 0;
    const parts = [];
    if (active > 0) parts.push(active + " running");
    if (queued > 0) parts.push(queued + " queued");
    if (done > 0) {
      if (failed > 0 && failed === done && active === 0 && queued === 0) {
        parts.push(failed + " failed");
      } else {
        parts.push(done + " done");
      }
    }
    return parts.join(" · ");
  }

  function decorateVisualLane(stage) {
    const active = Number(stage && stage.active) || 0;
    const base = {
      ...(stage || {}),
      active,
      queued: Number(stage && stage.queued) || 0,
      done: Number(stage && stage.done) || 0,
      total: Number(stage && stage.total) || 0,
      failed: Number(stage && stage.failed) || 0,
      running: active,
    };
    return {
      ...base,
      status: laneStatusOf(base),
      counts: formatLaneCounts(base),
    };
  }

  function buildVisualPipeline(snap) {
    const stages = buildPipelineStages(snap);
    const recon = stages[0];
    const hunt = stages[1];
    const mech = stages[2];
    const llm = stages[3];
    const validate = {
      id: "validate",
      label: "Validate",
      hint: "Mechanical gates, then LLM disprove (never auto-confirms)",
      status: foldValidateStatus(mech, llm),
      done: (mech.done || 0) + (llm.done || 0),
      total: (mech.total || 0) + (llm.total || 0),
      active: (mech.active || 0) + (llm.active || 0),
      queued: (mech.queued || 0) + (llm.queued || 0),
      failed: (mech.failed || 0) + (llm.failed || 0),
      mech,
      llm,
    };
    return [recon, hunt, validate].map(decorateVisualLane);
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

  /**
   * State counts from snap.findings — either a finding list or the
   * count_findings_by_state map. No new lifecycle states.
   */
  function findingStateCounts(snap) {
    const findings = snap && snap.findings;
    const counts = {};
    if (Array.isArray(findings)) {
      for (const f of findings) {
        const st = String((f && f.state) || "").toLowerCase() || "unknown";
        counts[st] = (counts[st] || 0) + 1;
      }
      return counts;
    }
    if (findings && typeof findings === "object") {
      for (const [k, v] of Object.entries(findings)) {
        const n = Number(v) || 0;
        if (n > 0) counts[String(k).toLowerCase()] = n;
      }
    }
    return counts;
  }

  /**
   * Finding funnel counts. Ingested is every recorded finding.
   * Screened is everything that has left `candidate` (mech, disprove, or
   * review wrote a later state). needs_human and confirmed are those states.
   * Not a work-lane pipeline.
   */
  function buildFindingFunnel(snap) {
    const counts = findingStateCounts(snap);
    let ingested = 0;
    for (const n of Object.values(counts)) ingested += n;
    const candidate = counts.candidate || 0;
    const screened = Math.max(0, ingested - candidate);
    const needs = counts.needs_human || 0;
    const confirmed = counts.confirmed || 0;
    return [
      {
        id: "ingested",
        label: "Ingested",
        value: ingested,
        hint: "Findings written into this run. Includes every status: new, waiting, accepted, and rejected.",
        nav: { mode: "report", tab: "report", filter: "all" },
      },
      {
        id: "screened",
        label: "Screened",
        value: screened,
        hint: "Findings that are no longer just a fresh candidate. A later check or a person already updated them. Not a separate status of its own.",
        nav: { mode: "report", tab: "report", filter: "all" },
      },
      {
        id: "needs_human",
        label: "Needs human",
        value: needs,
        hint: "Waiting for a person. Automatic checks passed. Not confirmed until someone accepts it.",
        nav: { mode: "report", tab: "report", filter: "needs_human" },
      },
      {
        id: "confirmed",
        label: "Confirmed",
        value: confirmed,
        hint: "A person accepted this finding. Confirmation is never automatic.",
        nav: { mode: "report", tab: "report", filter: "confirmed" },
      },
    ];
  }

  function taskRows(snap) {
    const tasks = snap && snap.tasks;
    return Array.isArray(tasks) ? tasks : null;
  }

  function taskCountMap(snap) {
    const tasks = snap && snap.tasks;
    if (tasks && typeof tasks === "object" && !Array.isArray(tasks)) return tasks;
    const summary = snap && snap.tasks_summary;
    if (
      !Array.isArray(tasks) &&
      summary &&
      typeof summary === "object" &&
      !Array.isArray(summary)
    ) {
      return summary;
    }
    return null;
  }

  function pauseReasonOf(task) {
    const result = task && task.result;
    let raw = "";
    if (result && typeof result === "object") {
      if (result.error) raw = String(result.error);
      else if (result.reason) raw = String(result.reason);
      else if (result.operator_paused) raw = "operator_pause";
    } else if (typeof result === "string") {
      raw = result;
    }
    raw = String(raw || "").trim();
    return raw || "paused";
  }

  function displayPauseReason(reason) {
    const key = String(reason || "").trim();
    if (key === "operator_pause" || key === "ui_pause") return "operator pause";
    if (!key) return "paused";
    return key.replace(/_/g, " ");
  }

  function runnerPauseWhy(runner, state) {
    const custom = runner && (runner.reason || runner.pause_reason);
    if (custom) return String(custom).trim();
    if (state === "pausing") return "STOP set; workers still finishing";
    if (state === "paused") return "STOP set";
    if (runner && runner.stop && state !== "running") return "STOP set";
    return "";
  }

  const PRESENCE_CAP = 3;

  function formatWorkerBit(w) {
    const who = w.leaseOwner ? w.leaseOwner : "leased worker";
    const kind = w.kind ? String(w.kind) : "task";
    const id =
      w.taskId != null && w.taskId !== "" && Number.isFinite(Number(w.taskId))
        ? " #" + Number(w.taskId)
        : "";
    return who + " on " + kind + id;
  }

  function formatPauseBit(p) {
    const kind = p.kind ? String(p.kind) + " " : "";
    const id =
      p.taskId != null && p.taskId !== "" && Number.isFinite(Number(p.taskId))
        ? "#" + Number(p.taskId)
        : "task";
    const reason = displayPauseReason(p.reason);
    const shown = reason.length > 80 ? reason.slice(0, 77) + "..." : reason;
    return kind + id + " — " + shown;
  }

  function joinCapped(prefix, bits) {
    const shown = bits.slice(0, PRESENCE_CAP);
    const extra = bits.length - shown.length;
    let text = prefix + shown.join(", ");
    if (extra > 0) text += " +" + extra;
    return text;
  }

  function ralphClause(state, why) {
    if (state === "running") return "Ralph running";
    if (state === "pausing") {
      return "Ralph pausing — " + (why || "STOP set; workers still finishing");
    }
    if (state === "paused") return "Ralph paused — " + (why || "STOP set");
    if (state === "busy") return "Ralph busy — run lock held";
    if (state === "idle") return "Ralph idle";
    return "";
  }

  function ralphTip(state) {
    if (state === "running") {
      return "Ralph is the task loop. Running means it is picking up queued work.";
    }
    if (state === "pausing") {
      return "Ralph is the task loop. Stop was requested: it will not start new tasks, and workers already going are still finishing.";
    }
    if (state === "paused") {
      return "Ralph is the task loop. Paused means it will not pick up work until someone resumes it.";
    }
    if (state === "busy") {
      return "Ralph is the task loop. The run lock is held, so a second loop cannot start.";
    }
    if (state === "idle") {
      return "Ralph is the task loop. It is not running. Start or resume it from the top bar to pick up queued tasks.";
    }
    return "Ralph is the task loop that picks up queued work.";
  }

  const TIP_WORKING_WHO =
    "Who is on a task right now. The id is the worker holding the lease, then the task kind and number.";
  const TIP_WORKING_COUNT =
    "How many tasks are leased to a worker. This view only has the count, not which worker.";
  const TIP_WORKING_NONE = "No task is checked out to a worker right now.";
  const TIP_PAUSED_WHY =
    "Tasks that stopped before they finished, and why. Operator pause means a person paused that task.";
  const TIP_PAUSED_COUNT =
    "How many tasks are paused. This view only has the count, not each reason.";

  /**
   * Who is leased, and why Ralph or a task is paused.
   * Reads runner state plus task lease_owner / pause result already on the snap.
   */
  function buildMissionPresence(snap) {
    const s = snap || {};
    const runner = s.runner && typeof s.runner === "object" ? s.runner : {};
    const runnerState = String(runner.state || "").toLowerCase();
    const runnerWhy = runnerPauseWhy(runner, runnerState);
    const rows = taskRows(s);
    const workers = [];
    const pauses = [];
    if (rows) {
      for (const t of rows) {
        const st = String((t && t.state) || "").toLowerCase();
        if (st === "leased" || st === "running") {
          const owner = String((t && (t.lease_owner || t.leaseOwner)) || "").trim();
          workers.push({
            taskId: t.id,
            kind: (t && t.kind) || "",
            leaseOwner: owner,
          });
        } else if (st === "paused") {
          pauses.push({
            taskId: t.id,
            kind: (t && t.kind) || "",
            reason: pauseReasonOf(t),
          });
        }
      }
    }
    let leasedCount = workers.length;
    let pausedCount = pauses.length;
    if (!rows) {
      const summary = taskCountMap(s) || {};
      leasedCount = (Number(summary.leased) || 0) + (Number(summary.running) || 0);
      pausedCount = Number(summary.paused) || 0;
    }
    const segments = [];
    const ralph = ralphClause(runnerState, runnerWhy);
    if (ralph) {
      segments.push({ id: "ralph", text: ralph, tip: ralphTip(runnerState) });
    }
    if (workers.length) {
      segments.push({
        id: "working",
        text: joinCapped("Working: ", workers.map(formatWorkerBit)),
        tip: TIP_WORKING_WHO,
      });
    } else if (leasedCount > 0) {
      segments.push({
        id: "working",
        text: "Working: " + leasedCount + " leased",
        tip: TIP_WORKING_COUNT,
      });
    } else {
      segments.push({
        id: "working",
        text: "No worker leased",
        tip: TIP_WORKING_NONE,
      });
    }
    if (pauses.length) {
      segments.push({
        id: "paused",
        text: joinCapped("Paused: ", pauses.map(formatPauseBit)),
        tip: TIP_PAUSED_WHY,
      });
    } else if (pausedCount > 0) {
      segments.push({
        id: "paused",
        text: "Paused: " + pausedCount + (pausedCount === 1 ? " task" : " tasks"),
        tip: TIP_PAUSED_COUNT,
      });
    }
    return {
      runnerState,
      runnerWhy,
      workers,
      pauses,
      leasedCount,
      pausedCount,
      segments,
      line: segments.map((s) => s.text).join(" · "),
    };
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
    };
  }

  function buildMissionCockpit(snap, opts) {
    const s = snap || {};
    const events = opts && Array.isArray(opts.recentEvents) ? opts.recentEvents.slice() : [];
    return {
      kpis: buildMissionKpis(s),
      funnel: buildFindingFunnel(s),
      presence: buildMissionPresence(s),
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
    laneStatusOf,
    formatLaneCounts,
    buildVisualPipeline,
    buildFindingFunnel,
    buildMissionPresence,
    buildMissionKpis,
    buildArchitectureBrief,
    buildMissionCockpit,
    countMissionTaskActivity,
    isHuntKind,
    huntTaskLabel,
    summarizeHuntQueue,
    listNeedsHumanFindings,
    countFindingState,
    summarizeCoverageResidual,
    PIPELINE_DONE_STATES,
    PIPELINE_ACTIVE_STATES,
    PIPELINE_QUEUED_STATES,
  };
});
