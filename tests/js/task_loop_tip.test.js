"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_JS = path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "app.js");

function formatTaskLoopBody(source) {
  const start = source.indexOf("function formatTaskLoop");
  const end = source.indexOf("function priorityTierLabel");
  if (start < 0 || end < start) {
    throw new Error("formatTaskLoop span missing");
  }
  return source.slice(start, end);
}

const body = formatTaskLoopBody(fs.readFileSync(APP_JS, "utf8"));

function loadFormatTaskLoop() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(`${body}\nthis.formatTaskLoop = formatTaskLoop;`, sandbox);
  return sandbox.formatTaskLoop;
}

const formatTaskLoop = loadFormatTaskLoop();

describe("formatTaskLoop lease tip", () => {
  it("keeps Lease n/m and explains the budget", () => {
    const row = formatTaskLoop({ attempt: 1, payload: {} }, 3);
    assert.equal(row.label, "Lease 1/3");
    assert.match(row.title, /attempt budget/);
    assert.match(row.title, /A new lease increments the count/);
    assert.match(row.title, /not leased again/);
    assert.match(row.title, /deadletter/);
  });

  it("keeps a zero lease and a generation marker", () => {
    assert.equal(formatTaskLoop({ attempt: 0, payload: {} }, 3).label, "Lease 0/3");
    const gen = formatTaskLoop({ attempt: 1, payload: { recon_generation: 2 } }, 3);
    assert.match(gen.label, /Gen 2/);
    assert.match(gen.label, /Lease 1\/3/);
  });
});
