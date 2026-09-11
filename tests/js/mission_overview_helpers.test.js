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

describe("buildVisualPipeline", () => {
  it("returns three stages and leaves mechanical pipeline at four", () => {
    const snap = { tasks: [] };
    const visual = buildVisualPipeline(snap);
    assert.equal(visual.length, 3);
    assert.deepEqual(
      visual.map((s) => s.id),
      ["recon", "hunt", "validate"]
    );
    assert.equal(buildPipelineStages(snap).length, 4);
  });

  it("folds running from either validate kind", () => {
    const visual = buildVisualPipeline({
      tasks: [
        { kind: "validate_mech", state: "succeeded" },
        { kind: "validate_llm", state: "leased" },
      ],
    });
    assert.equal(visual[2].status, "running");
    assert.equal(visual[2].done, 1);
    assert.equal(visual[2].total, 2);
    assert.equal(visual[2].mech.status, "done");
    assert.equal(visual[2].llm.status, "running");
  });

  it("treats empty llm as vacuous so mech-done is validate done", () => {
    const visual = buildVisualPipeline({
      tasks: [{ kind: "validate_mech", state: "succeeded" }],
    });
    assert.equal(visual[2].status, "done");
    assert.equal(visual[2].llm.total, 0);
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

describe("buildMissionCockpit", () => {
  it("assembles kpis, 3-stage pipeline, events, architecture from snap", () => {
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
    assert.equal(buildPipelineStages(snap).length, 4);
    assert.equal(vm.events.length, 2);
    assert.equal(vm.events[0].event, "task_done");
    assert.equal(vm.validateLlmOn, true);
    assert.equal(vm.architecture.title, "App");
    assert.equal(vm.architecture.componentCount, 1);
    assert.equal(vm.architecture.fileCount, 12);
    assert.equal(vm.architecture.entrypointCount, 2);
    assert.equal(vm.architecture.huntFocusCount, 1);
    assert.ok(vm.architecture.diagramSource);
    assert.equal(vm.architecture.diagramSource.components.length, 1);
  });

  it("does not invent architecture inventory", () => {
    const brief = buildArchitectureBrief({
      architecture_summary: { has_architecture: false },
      target_inventory: {},
    });
    assert.equal(brief.hasArchitecture, false);
    assert.equal(brief.diagramSource, null);
    assert.equal(brief.fileCount, null);
    assert.equal(brief.componentCount, 0);
    assert.equal(brief.snippet.includes("Cloudflare"), false);
    assert.equal(brief.snippet.includes("PHP"), false);
  });
});
