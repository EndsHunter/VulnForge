"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const helpers = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "mission_overview_helpers.js")
);

const {
  pipelineStageOfKind,
  summarizePipelineStage,
  buildPipelineStages,
  laneStatusOf,
  formatLaneCounts,
  buildVisualPipeline,
  buildMissionKpis,
  buildFindingFunnel,
  buildMissionPresence,
  buildArchitectureBrief,
  buildMissionCockpit,
  countMissionTaskActivity,
  isHuntKind,
  huntTaskLabel,
  summarizeHuntQueue,
  listNeedsHumanFindings,
  summarizeCoverageResidual,
} = helpers;

describe("pipelineStageOfKind", () => {
  it("maps recon / hunt / validate kinds", () => {
    assert.equal(pipelineStageOfKind("recon"), "recon");
    assert.equal(pipelineStageOfKind("recon:arch"), "recon");
    assert.equal(pipelineStageOfKind("recon/map"), "recon");
    assert.equal(pipelineStageOfKind("hunt"), "hunt");
    assert.equal(pipelineStageOfKind("hunt:area"), "hunt");
    assert.equal(pipelineStageOfKind("validate_mech"), "validate_mech");
    assert.equal(pipelineStageOfKind("validate_mech:gate"), "validate_mech");
    assert.equal(pipelineStageOfKind("validate_llm"), "validate_llm");
    assert.equal(pipelineStageOfKind("validate_llm:dual"), "validate_llm");
  });

  it("returns other for unknown or empty", () => {
    assert.equal(pipelineStageOfKind("poc"), "other");
    assert.equal(pipelineStageOfKind(""), "other");
    assert.equal(pipelineStageOfKind(null), "other");
  });
});

describe("countMissionTaskActivity", () => {
  it("sums leased + running (not OR)", () => {
    const { running, queued } = countMissionTaskActivity({
      leased: 2,
      running: 3,
      queued: 1,
      paused: 4,
    });
    assert.equal(running, 5);
    assert.equal(queued, 5);
  });

  it("treats missing states as zero", () => {
    assert.deepEqual(countMissionTaskActivity({ leased: 2 }), { queued: 0, running: 2 });
    assert.deepEqual(countMissionTaskActivity({ running: 1 }), { queued: 0, running: 1 });
    assert.deepEqual(countMissionTaskActivity({}), { queued: 0, running: 0 });
    assert.deepEqual(countMissionTaskActivity(null), { queued: 0, running: 0 });
  });

  it("does not undercount when both leased and running are set", () => {
    // Regression: previously `leased || running` dropped one side.
    const both = countMissionTaskActivity({ leased: 1, running: 1 });
    assert.equal(both.running, 2);
  });
});

describe("summarizePipelineStage", () => {
  it("counts active / queued / done / failed", () => {
    const tasks = [
      { kind: "hunt", state: "leased" },
      { kind: "hunt", state: "running" },
      { kind: "hunt", state: "queued" },
      { kind: "hunt", state: "paused" },
      { kind: "hunt", state: "succeeded" },
      { kind: "hunt", state: "failed_task" },
      { kind: "recon", state: "running" },
    ];
    const s = summarizePipelineStage(tasks, "hunt", false);
    assert.equal(s.total, 6);
    assert.equal(s.active, 2);
    assert.equal(s.queued, 2);
    assert.equal(s.done, 2);
    assert.equal(s.failed, 1);
    assert.equal(s.status, "running");
  });

  it("marks pending when empty without extraDone", () => {
    assert.equal(summarizePipelineStage([], "recon", false).status, "pending");
  });

  it("marks done when empty with extraDone", () => {
    assert.equal(summarizePipelineStage([], "recon", true).status, "done");
  });

  it("marks failed when all tasks failed", () => {
    const tasks = [
      { kind: "validate_mech", state: "failed_task" },
      { kind: "validate_mech", state: "deadletter" },
    ];
    const s = summarizePipelineStage(tasks, "validate_mech", false);
    assert.equal(s.status, "failed");
    assert.equal(s.failed, 2);
    assert.equal(s.done, 2);
  });
});

describe("buildPipelineStages", () => {
  it("returns four labeled stages", () => {
    const stages = buildPipelineStages({ tasks: [] });
    assert.equal(stages.length, 4);
    assert.deepEqual(
      stages.map((s) => s.id),
      ["recon", "hunt", "validate_mech", "validate_llm"]
    );
    assert.equal(stages[0].label, "Recon");
    assert.equal(stages[1].status, "pending");
  });

  it("marks recon done when architecture exists and no recon tasks", () => {
    const stages = buildPipelineStages({
      tasks: [],
      has_architecture: true,
    });
    assert.equal(stages[0].status, "done");
  });

  it("aggregates hunt tasks into running stage", () => {
    const stages = buildPipelineStages({
      tasks: [
        { kind: "hunt:auth", state: "leased" },
        { kind: "hunt:sqli", state: "queued" },
      ],
      has_architecture: true,
    });
    assert.equal(stages[0].status, "done");
    assert.equal(stages[1].status, "running");
    assert.equal(stages[1].active, 1);
    assert.equal(stages[1].queued, 1);
  });

  it("has no dead priorTouched cascade stub side effects", () => {
    // Hunt stays pending when empty regardless of recon pending — no no-op cascade.
    const stages = buildPipelineStages({ tasks: [] });
    assert.equal(stages[0].status, "pending");
    assert.equal(stages[1].status, "pending");
  });
});


describe("isHuntKind / huntTaskLabel", () => {
  it("detects hunt kinds", () => {
    assert.equal(isHuntKind("hunt"), true);
    assert.equal(isHuntKind("hunt:injection"), true);
    assert.equal(isHuntKind("hunt/area"), true);
    assert.equal(isHuntKind("recon"), false);
  });

  it("labels area × class from payload", () => {
    assert.equal(
      huntTaskLabel({ kind: "hunt", payload: { area: "app", class: "injection" } }),
      "app × injection"
    );
    assert.equal(huntTaskLabel({ kind: "hunt:injection", payload: {} }), "injection");
  });
});

describe("summarizeHuntQueue", () => {
  it("counts and orders feed active → queued → done", () => {
    const q = summarizeHuntQueue([
      { id: 1, kind: "hunt", state: "succeeded", payload: { area: "a", class: "x" } },
      { id: 2, kind: "hunt", state: "queued", payload: { area: "b", class: "y" } },
      { id: 3, kind: "hunt", state: "leased", payload: { area: "c", class: "z" } },
      { id: 4, kind: "recon", state: "queued", payload: {} },
    ]);
    assert.equal(q.total, 3);
    assert.equal(q.active, 1);
    assert.equal(q.queued, 1);
    assert.equal(q.done, 1);
    assert.deepEqual(
      q.feed.map((f) => f.id),
      [3, 2, 1]
    );
  });

  it("empty when no hunts", () => {
    const q = summarizeHuntQueue([{ id: 1, kind: "recon", state: "queued" }]);
    assert.equal(q.total, 0);
    assert.equal(q.feed.length, 0);
  });
});

describe("listNeedsHumanFindings", () => {
  it("filters list and counts map", () => {
    const fromList = listNeedsHumanFindings([
      { id: 1, state: "needs_human", title: "A" },
      { id: 2, state: "confirmed", title: "B" },
      { id: 3, state: "candidate", title: "C" },
    ]);
    assert.equal(fromList.count, 2);
    assert.equal(fromList.items.length, 2);
    const fromMap = listNeedsHumanFindings({ needs_human: 4, candidate: 1, confirmed: 2 });
    assert.equal(fromMap.count, 5);
    assert.equal(fromMap.items.length, 0);
  });
});

describe("summarizeCoverageResidual", () => {
  it("counts residual empty cells in full matrix", () => {
    const s = summarizeCoverageResidual({
      areas: ["a", "b"],
      classes: ["injection"],
      cells: [{ area: "a", class: "injection", last_depth: "shallow" }],
    });
    assert.equal(s.residual, 2); // a shallow + b empty
    assert.equal(s.hasFinding, 0);
  });
});

describe("laneStatusOf / formatLaneCounts", () => {
  it("maps helper statuses onto concurrent lane lights", () => {
    assert.equal(laneStatusOf({ status: "running", active: 1, done: 2, total: 3 }), "running");
    assert.equal(laneStatusOf({ status: "queued", queued: 2, total: 2 }), "running");
    assert.equal(
      laneStatusOf({ status: "partial", active: 2, done: 3, total: 5 }),
      "running"
    );
    assert.equal(
      laneStatusOf({ status: "partial", active: 0, queued: 1, done: 4, total: 5 }),
      "running"
    );
    assert.equal(laneStatusOf({ status: "done", done: 4, total: 4 }), "idle-with-results");
    assert.equal(laneStatusOf({ status: "done", done: 0, total: 0 }), "idle-with-results");
    assert.equal(laneStatusOf({ status: "idle", done: 2, total: 2 }), "idle-with-results");
    assert.equal(laneStatusOf({ status: "pending", done: 1, total: 1 }), "idle-with-results");
    assert.equal(laneStatusOf({ status: "idle", done: 0, total: 0 }), "idle");
    assert.equal(laneStatusOf({ status: "pending", done: 0, total: 0 }), "idle");
    assert.equal(
      laneStatusOf({ status: "partial", active: 0, queued: 0, done: 3, failed: 1, total: 3 }),
      "idle-with-results"
    );
    assert.equal(
      laneStatusOf({ status: "failed", failed: 2, done: 2, total: 2 }),
      "failed"
    );
  });

  it("formats live counts from active, queued, and done", () => {
    assert.equal(formatLaneCounts({ active: 3, done: 12, total: 15 }), "3 running · 12 done");
    assert.equal(formatLaneCounts({ running: 3, done: 12 }), "3 running · 12 done");
    assert.equal(
      formatLaneCounts({ active: 1, queued: 2, done: 4 }),
      "1 running · 2 queued · 4 done"
    );
    assert.equal(formatLaneCounts({ queued: 2, total: 2 }), "2 queued");
    assert.equal(formatLaneCounts({ done: 0, total: 0 }), "");
    assert.equal(
      formatLaneCounts({ failed: 2, done: 2, total: 2 }),
      "2 failed"
    );
  });
});

describe("buildVisualPipeline", () => {
  it("returns three lanes and leaves mechanical pipeline at four", () => {
    const snap = { tasks: [] };
    const visual = buildVisualPipeline(snap);
    assert.equal(visual.length, 3);
    assert.deepEqual(
      visual.map((s) => s.id),
      ["recon", "hunt", "validate"]
    );
    assert.deepEqual(
      visual.map((s) => s.status),
      ["idle", "idle", "idle"]
    );
    assert.equal(buildPipelineStages(snap).length, 4);
  });

  it("folds running from either validate kind and keeps done counts", () => {
    const visual = buildVisualPipeline({
      tasks: [
        { kind: "validate_mech", state: "succeeded" },
        { kind: "validate_llm", state: "leased" },
      ],
    });
    assert.equal(visual[2].status, "running");
    assert.equal(visual[2].running, 1);
    assert.equal(visual[2].active, 1);
    assert.equal(visual[2].done, 1);
    assert.equal(visual[2].total, 2);
    assert.equal(visual[2].counts, "1 running · 1 done");
    assert.equal(visual[2].mech.status, "done");
    assert.equal(visual[2].llm.status, "running");
  });

  it("treats empty llm as vacuous so mech-done is idle with results", () => {
    const visual = buildVisualPipeline({
      tasks: [{ kind: "validate_mech", state: "succeeded" }],
    });
    assert.equal(visual[2].status, "idle-with-results");
    assert.equal(visual[2].counts, "1 done");
    assert.equal(visual[2].running, 0);
    assert.equal(visual[2].llm.total, 0);
    assert.equal(visual[2].mech.status, "done");
  });

  it("shows Validate results while Hunt is still running", () => {
    const hunts = [
      { kind: "hunt:a", state: "leased" },
      { kind: "hunt:b", state: "running" },
      { kind: "hunt:c", state: "running" },
    ];
    for (let i = 0; i < 12; i += 1) {
      hunts.push({ kind: "hunt:done-" + i, state: "succeeded" });
    }
    const visual = buildVisualPipeline({
      has_architecture: true,
      tasks: hunts.concat([
        { kind: "recon", state: "succeeded" },
        { kind: "validate_mech", state: "succeeded" },
        { kind: "validate_mech", state: "succeeded" },
        { kind: "validate_llm", state: "succeeded" },
        { kind: "validate_llm", state: "succeeded" },
      ]),
    });
    assert.equal(visual[0].status, "idle-with-results");
    assert.equal(visual[0].counts, "1 done");
    assert.equal(visual[1].status, "running");
    assert.equal(visual[1].running, 3);
    assert.equal(visual[1].done, 12);
    assert.equal(visual[1].counts, "3 running · 12 done");
    assert.equal(visual[2].status, "idle-with-results");
    assert.equal(visual[2].counts, "4 done");
    assert.equal(visual[2].running, 0);
  });

  it("keeps an all-failed lane failed", () => {
    const visual = buildVisualPipeline({
      tasks: [
        { kind: "validate_mech", state: "failed_task" },
        { kind: "validate_mech", state: "deadletter" },
      ],
    });
    assert.equal(visual[2].status, "failed");
    assert.equal(visual[2].counts, "2 failed");
    assert.equal(visual[1].status, "idle");
  });

  it("marks architecture-only recon as idle with results and no fake counts", () => {
    const visual = buildVisualPipeline({
      tasks: [],
      has_architecture: true,
    });
    assert.equal(visual[0].status, "idle-with-results");
    assert.equal(visual[0].total, 0);
    assert.equal(visual[0].counts, "");
    assert.equal(visual[1].status, "idle");
    assert.equal(visual[2].status, "idle");
  });
});

describe("buildMissionKpis", () => {
  it("returns tasks, needs_human, coverage", () => {
    const kpis = buildMissionKpis({
      done_tasks: 3,
      total_tasks: 10,
      progress: 0.3,
      findings: [
        { state: "needs_human" },
        { state: "candidate" },
        { state: "confirmed" },
      ],
      coverage: {
        areas: ["a", "b"],
        classes: ["injection"],
        cells: [{ area: "a", class: "injection", last_depth: "needs_human" }],
      },
    });
    assert.equal(kpis.length, 3);
    assert.deepEqual(
      kpis.map((k) => k.id),
      ["tasks", "needs_human", "coverage"]
    );
    assert.equal(kpis[0].value, "3/10");
    assert.equal(kpis[0].barPct, 30);
    assert.equal(kpis[1].value, "1");
    assert.equal(kpis[1].barPct, null);
    assert.equal(kpis[2].value, "50%");
    assert.equal(kpis[2].barPct, 50);
  });

  it("counts needs_human only from a state map", () => {
    const kpis = buildMissionKpis({
      findings: { needs_human: 4, candidate: 2, confirmed: 9 },
    });
    assert.equal(kpis[1].value, "4");
  });

  it("leaves coverage bar null when there are no cells", () => {
    const kpis = buildMissionKpis({ coverage: { areas: [], classes: [], cells: [] } });
    assert.equal(kpis[2].barPct, null);
    assert.equal(kpis[2].value, "—");
  });
});

describe("buildFindingFunnel", () => {
  it("maps existing states onto ingested → screened → needs_human → confirmed", () => {
    const funnel = buildFindingFunnel({
      findings: [
        { state: "candidate" },
        { state: "candidate" },
        { state: "rejected_mech" },
        { state: "rejected_llm" },
        { state: "needs_human" },
        { state: "needs_human" },
        { state: "confirmed" },
        { state: "superseded" },
      ],
    });
    assert.deepEqual(
      funnel.map((s) => s.id),
      ["ingested", "screened", "needs_human", "confirmed"]
    );
    assert.deepEqual(
      funnel.map((s) => s.value),
      [8, 6, 2, 1]
    );
    assert.equal(funnel[2].nav.filter, "needs_human");
    assert.equal(funnel[3].nav.filter, "confirmed");
    assert.equal(funnel[3].hint.includes("Never automatic"), true);
  });

  it("counts a state map the same way as a finding list", () => {
    const funnel = buildFindingFunnel({
      findings: { candidate: 3, needs_human: 2, confirmed: 1, rejected_mech: 1 },
    });
    assert.deepEqual(
      funnel.map((s) => s.value),
      [7, 4, 2, 1]
    );
  });

  it("is zero when nothing has been recorded", () => {
    const funnel = buildFindingFunnel({});
    assert.deepEqual(
      funnel.map((s) => s.value),
      [0, 0, 0, 0]
    );
  });

  it("does not treat candidate as screened", () => {
    const funnel = buildFindingFunnel({
      findings: [{ state: "candidate" }, { state: "Candidate" }],
    });
    assert.equal(funnel[0].value, 2);
    assert.equal(funnel[1].value, 0);
    assert.equal(funnel[2].value, 0);
  });
});

describe("buildMissionPresence", () => {
  it("names the leased worker and the operator pause reason", () => {
    const presence = buildMissionPresence({
      runner: { state: "running", pid: 4242, alive: true },
      tasks: [
        { id: 7, kind: "hunt", state: "leased", lease_owner: "vf-4242-ab12cd34" },
        {
          id: 8,
          kind: "hunt",
          state: "paused",
          result: { error: "operator_pause", operator_paused: true },
        },
        { id: 3, kind: "recon", state: "succeeded" },
      ],
    });
    assert.equal(presence.runnerState, "running");
    assert.equal(presence.workers.length, 1);
    assert.equal(presence.workers[0].leaseOwner, "vf-4242-ab12cd34");
    assert.equal(presence.pauses[0].reason, "operator_pause");
    assert.equal(
      presence.line,
      "Ralph running · Working: vf-4242-ab12cd34 on hunt #7 · Paused: hunt #8 — operator pause"
    );
  });

  it("says why Ralph is paused when STOP is set", () => {
    const presence = buildMissionPresence({
      runner: { state: "paused", stop: true, alive: false },
      tasks: [],
    });
    assert.equal(presence.runnerWhy, "STOP set");
    assert.equal(presence.line, "Ralph paused — STOP set · No worker leased");
  });

  it("explains pausing while workers are still finishing", () => {
    const presence = buildMissionPresence({
      runner: { state: "pausing", stop: true, alive: true },
      tasks: [{ id: 2, kind: "recon", state: "leased", lease_owner: "vf-9-aa" }],
    });
    assert.equal(
      presence.line,
      "Ralph pausing — STOP set; workers still finishing · Working: vf-9-aa on recon #2"
    );
  });

  it("falls back to leased and paused counts when the snap has no task rows", () => {
    const presence = buildMissionPresence({
      runner: { state: "idle" },
      tasks: { leased: 2, paused: 1, queued: 4 },
    });
    assert.equal(presence.workers.length, 0);
    assert.equal(presence.leasedCount, 2);
    assert.equal(presence.pausedCount, 1);
    assert.equal(
      presence.line,
      "Ralph idle · Working: 2 leased · Paused: 1 task"
    );
  });

  it("uses a leased-worker label when the lease owner is missing", () => {
    const presence = buildMissionPresence({
      tasks: [{ id: 4, kind: "validate_mech", state: "leased" }],
    });
    assert.equal(presence.line, "Working: leased worker on validate_mech #4");
  });

  it("reads result.reason when error is absent", () => {
    const presence = buildMissionPresence({
      runner: { state: "running" },
      tasks: [
        {
          id: 1,
          kind: "hunt",
          state: "paused",
          result: { reason: "waiting_on_operator" },
        },
      ],
    });
    assert.equal(presence.pauses[0].reason, "waiting_on_operator");
    assert.match(presence.line, /Paused: hunt #1 — waiting on operator/);
  });
});

describe("buildMissionCockpit", () => {
  it("assembles kpis, 3 work lanes, events, architecture from snap", () => {
    const snap = {
      done_tasks: 1,
      total_tasks: 2,
      progress: 0.5,
      findings: [{ state: "needs_human" }, { state: "candidate" }],
      validate_llm_on: true,
      architecture_summary: {
        title: "App",
        has_architecture: true,
        summary: "HTTP API over SQLite",
        components: [{ name: "API" }],
        relations: [{ from: "API", to: "DB" }],
        hunt_focus: [{ area: "auth" }],
      },
      target_inventory: {
        file_count: 12,
        entrypoints: ["app.py", "cli.py"],
      },
    };
    const events = [
      { event: "task_done", ts: "1" },
      { event: "hunt_split", ts: "2" },
    ];
    const vm = buildMissionCockpit(snap, { recentEvents: events });
    assert.equal(vm.kpis.length, 3);
    assert.deepEqual(
      vm.kpis.map((k) => k.id),
      ["tasks", "needs_human", "coverage"]
    );
    assert.equal(vm.kpis[1].value, "1");
    assert.equal(vm.pipeline.length, 3);
    assert.deepEqual(
      vm.pipeline.map((s) => s.id),
      ["recon", "hunt", "validate"]
    );
    assert.equal(vm.funnel.length, 4);
    assert.deepEqual(
      vm.funnel.map((s) => s.id),
      ["ingested", "screened", "needs_human", "confirmed"]
    );
    assert.equal(vm.funnel[0].value, 2);
    assert.equal(vm.funnel[1].value, 1);
    assert.equal(vm.funnel[2].value, 1);
    assert.equal(vm.presence.line.includes("No worker leased"), true);
    assert.equal(
      vm.pipeline.some((s) => s.id === "ralph"),
      false
    );
    assert.equal(buildPipelineStages(snap).length, 4);
    assert.equal(vm.events.length, 2);
    assert.equal(vm.events[0].event, "task_done");
    assert.equal(vm.validateLlmOn, true);
    assert.equal(vm.architecture.title, "App");
    assert.equal(vm.architecture.componentCount, 1);
    assert.equal(vm.architecture.fileCount, 12);
    assert.equal(vm.architecture.entrypointCount, 2);
    assert.equal(vm.architecture.huntFocusCount, 1);
  });

  it("does not invent architecture inventory", () => {
    const brief = buildArchitectureBrief({
      architecture_summary: { has_architecture: false },
      target_inventory: {},
    });
    assert.equal(brief.hasArchitecture, false);
    assert.equal(brief.fileCount, null);
    assert.equal(brief.componentCount, 0);
    assert.equal(brief.snippet.includes("Cloudflare"), false);
    assert.equal(brief.snippet.includes("PHP"), false);
  });
});
