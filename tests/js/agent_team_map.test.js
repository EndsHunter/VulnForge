"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const helpers = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "agent_team_map.js")
);

const {
  leaseCap,
  parseLeaseOwner,
  workLabel,
  steerFor,
  buildAgentTeamMap,
  renderAgentTeamHtml,
} = helpers;

function snap(extra) {
  return {
    run: { max_leases_parallel: 2, max_tasks: 50 },
    tasks: [
      {
        id: 7,
        kind: "hunt",
        state: "leased",
        priority: 40,
        lease_owner: "vf-4242-a1b2c3d4",
        payload: { area: "api", class: "injection", path_hints: ["app.py"] },
      },
      {
        id: 2,
        kind: "recon",
        state: "queued",
        priority: 10,
        payload: { agent: "default-map" },
      },
      {
        id: 8,
        kind: "hunt",
        state: "paused",
        priority: 50,
        payload: { area: "auth", class: "access-control", path_hints: ["app.py"] },
      },
    ],
    ...extra,
  };
}

describe("parseLeaseOwner", () => {
  it("reads vf-{pid}-{token}", () => {
    const owner = parseLeaseOwner("vf-4242-a1b2c3d4");
    assert.equal(owner.pid, 4242);
    assert.equal(owner.label, "worker 4242");
    assert.equal(owner.token, "a1b2c3d4");
    assert.equal(owner.raw, "vf-4242-a1b2c3d4");
  });

  it("keeps a non-standard owner visible", () => {
    const owner = parseLeaseOwner("operator-test");
    assert.equal(owner.pid, null);
    assert.equal(owner.label, "operator-test");
  });

  it("names an empty holder", () => {
    assert.equal(parseLeaseOwner("").label, "Unnamed holder");
    assert.equal(parseLeaseOwner(null).label, "Unnamed holder");
  });
});

describe("leaseCap", () => {
  it("prefers run.max_leases_parallel", () => {
    assert.equal(leaseCap({ run: { max_leases_parallel: 3 }, config: { run: { max_leases_parallel: 9 } } }), 3);
  });

  it("falls back through config then 1", () => {
    assert.equal(leaseCap({ config: { run: { max_leases_parallel: 4 } } }), 4);
    assert.equal(leaseCap({ config: { max_leases_parallel: 5 } }), 5);
    assert.equal(leaseCap({}), 1);
    assert.equal(leaseCap({ run: { max_leases_parallel: 0 } }), 1);
  });
});

describe("workLabel", () => {
  it("joins area, class, and path without making a lane", () => {
    assert.equal(
      workLabel({ kind: "hunt", payload: { area: "api", class: "injection", path_hints: ["app.py"] } }),
      "api × injection · app.py"
    );
    assert.equal(workLabel({ kind: "recon", payload: { agent: "default-map" } }), "default-map");
  });
});

describe("steerFor", () => {
  it("offers pause, halt, and note on a lease, and resume on paused", () => {
    assert.deepEqual(steerFor("leased"), ["live", "pause", "halt", "note"]);
    assert.deepEqual(steerFor("running"), ["live", "pause", "halt", "note"]);
    assert.deepEqual(steerFor("queued"), ["pause", "halt"]);
    assert.deepEqual(steerFor("paused"), ["resume", "halt"]);
    assert.deepEqual(steerFor("succeeded"), []);
  });
});

describe("buildAgentTeamMap", () => {
  it("fills lease slots and keeps queued and paused beside them", () => {
    const map = buildAgentTeamMap(snap());
    assert.equal(map.cap, 2);
    assert.equal(map.held, 1);
    assert.equal(map.leasedCount, 1);
    assert.equal(map.slots[0].status, "held");
    assert.equal(map.slots[0].task.owner.label, "worker 4242");
    assert.equal(map.slots[0].task.label, "api × injection · app.py");
    assert.equal(map.slots[1].status, "open");
    assert.equal(map.slots[1].task, null);
    assert.equal(map.queued.total, 1);
    assert.equal(map.queued.shown[0].kind, "recon");
    assert.equal(map.paused.total, 1);
    assert.equal(map.paused.shown[0].id, 8);
    assert.equal(map.overflow.length, 0);
    assert.equal(map.pipeline, undefined);
    assert.equal(map.lanes, undefined);
  });

  it("marks the holder alive only when that pid is in the runner", () => {
    const alive = buildAgentTeamMap(snap({ runner: { alive: true, pids: [4242], state: "running" } }));
    assert.equal(alive.slots[0].task.presence, "alive");
    const missing = buildAgentTeamMap(snap({ runner: { alive: true, pids: [99], state: "running" } }));
    assert.equal(missing.slots[0].task.presence, "not in runner");
    const idle = buildAgentTeamMap(snap({ runner: { alive: false, pids: [], state: "idle" } }));
    assert.equal(idle.slots[0].task.presence, "");
  });

  it("treats running like leased and parks extras beyond the cap", () => {
    const map = buildAgentTeamMap({
      run: { max_leases_parallel: 1 },
      tasks: [
        { id: 3, kind: "hunt", state: "running", lease_owner: "vf-9-aa", payload: {} },
        { id: 4, kind: "validate_poc", state: "leased", lease_owner: "vf-10-bb", payload: {} },
        { id: 1, kind: "recon", state: "succeeded", payload: {} },
      ],
    });
    assert.equal(map.cap, 1);
    assert.equal(map.slots[0].task.id, 3);
    assert.equal(map.overflow.length, 1);
    assert.equal(map.overflow[0].id, 4);
    assert.equal(map.queued.total, 0);
    assert.equal(map.paused.total, 0);
  });

  it("clips long queues and still reports the hidden count", () => {
    const tasks = [];
    for (let i = 1; i <= 10; i++) {
      tasks.push({ id: i, kind: "hunt", state: "queued", priority: i, payload: { class: "c" + i } });
    }
    const map = buildAgentTeamMap({ run: { max_leases_parallel: 2 }, tasks });
    assert.equal(map.queued.shown.length, helpers.LIST_LIMIT);
    assert.equal(map.queued.hidden, 2);
    assert.equal(map.queued.total, 10);
    assert.equal(map.queued.shown[0].id, 1);
  });
});

describe("renderAgentTeamHtml", () => {
  it("shows the holder, an open slot, and confirm on pause halt and note", () => {
    const html = renderAgentTeamHtml(buildAgentTeamMap(snap()));
    assert.match(html, /worker 4242/);
    assert.match(html, /vf-4242-a1b2c3d4/);
    assert.match(html, /No task holds this lease/);
    assert.match(html, /data-lease-status="open"/);
    assert.match(html, /aria-label="Queued work"/);
    assert.match(html, /aria-label="Paused work"/);
    assert.match(html, /default-map/);
    assert.match(html, /access-control/);
    assert.match(html, /data-agent-team-action="pause"[^>]*data-confirm="1"/);
    assert.match(html, /data-agent-team-action="halt"[^>]*data-confirm="1"/);
    assert.match(html, /data-agent-team-action="note"[^>]*data-confirm="1"/);
    assert.match(html, /data-agent-team-action="live"[^>]*data-confirm="0"/);
    assert.match(html, /data-agent-team-action="resume"[^>]*data-confirm="0"/);
    assert.match(html, /data-agent-team-live="7"/);
    assert.doesNotMatch(html, /arch-campaign/);
    assert.doesNotMatch(html, /btn-start/);
    assert.doesNotMatch(html, /Ralph/);
    assert.doesNotMatch(html, /data-stage=/);
  });

  it("escapes payload text", () => {
    const html = renderAgentTeamHtml(
      buildAgentTeamMap({
        run: { max_leases_parallel: 1 },
        tasks: [
          {
            id: 1,
            kind: "hunt",
            state: "leased",
            lease_owner: "vf-1-aa",
            payload: { area: `<script>`, class: `a"b` },
          },
        ],
      })
    );
    assert.doesNotMatch(html, /<script>/);
    assert.match(html, /&lt;script&gt;/);
  });
});
