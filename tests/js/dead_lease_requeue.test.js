"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_JS = path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "app.js");

function formatTaskResultBody(source) {
  const start = source.indexOf("const DEAD_LEASE_REQUEUE_COPY");
  const end = source.indexOf("function renderTasks");
  if (start < 0 || end < start) {
    throw new Error("formatTaskResult span missing");
  }
  return source.slice(start, end);
}

function loadFormatTaskResult() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(
    `${formatTaskResultBody(fs.readFileSync(APP_JS, "utf8"))}\nthis.formatTaskResult = formatTaskResult;\nthis.isDeadLeaseRequeueResult = isDeadLeaseRequeueResult;`,
    sandbox
  );
  return sandbox;
}

const { formatTaskResult, isDeadLeaseRequeueResult } = loadFormatTaskResult();

describe("dead lease reclaim row", () => {
  it("shows worker died / requeued and not an error", () => {
    const fresh = formatTaskResult({
      state: "queued",
      result: {
        status: "requeued",
        message: "Worker died; task requeued",
        worker_died: true,
      },
    });
    assert.equal(fresh.text, "Worker died; task requeued");
    assert.equal(fresh.text.includes("error"), false);
    assert.equal(fresh.title.includes("error"), false);
    assert.equal(isDeadLeaseRequeueResult({ worker_died: true }), true);

    const legacy = formatTaskResult({
      state: "queued",
      result: {
        status: "requeued",
        error: "dead_lease_owner",
        orphaned_lease_reclaim: true,
      },
    });
    assert.equal(legacy.text, "Worker died; task requeued");
    assert.equal(legacy.text.includes("dead_lease_owner"), false);
    assert.equal(legacy.text.includes("orphaned_lease"), false);
  });

  it("leaves real task errors as the result payload", () => {
    const failed = {
      status: "failed_task",
      error: "no_submit",
    };
    const row = formatTaskResult({ state: "failed_task", result: failed });
    assert.equal(row.text, JSON.stringify(failed));
    assert.match(row.text, /no_submit/);
    assert.equal(isDeadLeaseRequeueResult(failed), false);

    const infra = formatTaskResult({
      state: "queued",
      result: { error: "context_overflow" },
    });
    assert.match(infra.text, /context_overflow/);
    assert.equal(isDeadLeaseRequeueResult({ error: "context_overflow" }), false);

    const pauseBody = {
      status: "requeued",
      error: "pause_kill_orphan",
      orphaned_lease_reclaim: true,
    };
    const pause = formatTaskResult({ state: "queued", result: pauseBody });
    assert.equal(pause.text, JSON.stringify(pauseBody));
    assert.match(pause.text, /pause_kill_orphan/);
  });
});
