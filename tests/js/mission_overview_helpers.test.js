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
  countMissionTaskActivity,
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
