"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  RUN_NAV,
  primaryNav,
  footerNav,
  isRunMode,
  defaultTabFor,
} = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "run_nav.js"));

describe("RUN_NAV", () => {
  it("has unique ids", () => {
    const ids = RUN_NAV.map((item) => item.id);
    assert.equal(ids.length, new Set(ids).size);
  });

  it("splits modes and hrefs", () => {
    assert.deepEqual(
      primaryNav(RUN_NAV).map((item) => item.mode),
      ["mission", "hunts", "explorer", "report", "evidence", "audit", "ai"]
    );
    assert.deepEqual(
      footerNav(RUN_NAV).map((item) => item.href),
      ["/dev", "/settings"]
    );
    for (const item of primaryNav(RUN_NAV)) {
      assert.equal(item.kind, "mode");
      assert.equal("href" in item, false);
    }
    for (const item of footerNav(RUN_NAV)) {
      assert.equal(item.kind, "href");
      assert.equal("mode" in item, false);
      assert.equal("defaultTab" in item, false);
    }
  });

  it("covers today's hash mode keys including audit (Tasks)", () => {
    assert.deepEqual(
      primaryNav().map((item) => [item.mode, item.defaultTab]),
      [
        ["mission", "overview"],
        ["hunts", "hunts"],
        ["explorer", "explorer"],
        ["report", "report"],
        ["evidence", "evidence"],
        ["audit", "tasks"],
        ["ai", "ai"],
      ]
    );
    assert.equal(primaryNav().find((item) => item.mode === "audit").label, "Tasks");
  });
});

describe("isRunMode / defaultTabFor", () => {
  it("accepts workspace modes only", () => {
    assert.equal(isRunMode("mission"), true);
    assert.equal(isRunMode("audit"), true);
    assert.equal(isRunMode("settings"), false);
    assert.equal(isRunMode("dev"), false);
    assert.equal(isRunMode("tasks"), false);
    assert.equal(isRunMode("coverage"), false);
  });

  it("returns default tabs or null", () => {
    assert.equal(defaultTabFor("mission"), "overview");
    assert.equal(defaultTabFor("audit"), "tasks");
    assert.equal(defaultTabFor("settings"), null);
    assert.equal(defaultTabFor("poc"), null);
  });
});
