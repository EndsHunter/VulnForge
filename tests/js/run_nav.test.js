"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  RUN_NAV,
  primaryNav,
  workspaceModes,
  headNav,
  footerNav,
  isRunMode,
  defaultTabFor,
  isOverlayMode,
} = require(path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "run_nav.js"));

describe("RUN_NAV", () => {
  it("has unique ids", () => {
    const ids = RUN_NAV.map((item) => item.id);
    assert.equal(ids.length, new Set(ids).size);
  });

  it("uses one rail slot per item and no inRail twin", () => {
    const rails = new Set(["head", "primary", "footer", null]);
    for (const item of RUN_NAV) {
      assert.equal("inRail" in item, false);
      assert.equal(rails.has(item.rail), true, `${item.id} rail=${item.rail}`);
    }
  });

  it("splits head, primary rail, workspace modes, and footer", () => {
    assert.deepEqual(
      headNav(RUN_NAV).map((item) => item.href),
      ["/"]
    );
    assert.deepEqual(
      primaryNav(RUN_NAV).map((item) => item.mode),
      ["mission", "hunts", "explorer", "report"]
    );
    assert.deepEqual(
      workspaceModes(RUN_NAV).map((item) => item.mode),
      ["mission", "hunts", "explorer", "report", "evidence", "audit", "ai"]
    );
    assert.deepEqual(
      footerNav(RUN_NAV).map((item) => item.href),
      ["/settings", "/dev", "/tool-gaps"]
    );
    for (const item of primaryNav(RUN_NAV)) {
      assert.equal(item.kind, "mode");
      assert.equal(item.rail, "primary");
      assert.equal("href" in item, false);
    }
    for (const item of workspaceModes(RUN_NAV)) {
      assert.equal(item.kind, "mode");
    }
    for (const item of footerNav(RUN_NAV)) {
      assert.equal(item.kind, "href");
      assert.equal(item.rail, "footer");
      assert.equal("mode" in item, false);
      assert.equal("defaultTab" in item, false);
    }
  });

  it("keeps hash mode keys including audit (Tasks) on workspaceModes", () => {
    assert.deepEqual(
      workspaceModes().map((item) => [item.mode, item.defaultTab]),
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
    assert.equal(workspaceModes().find((item) => item.mode === "audit").label, "Tasks");
    assert.equal(workspaceModes().find((item) => item.mode === "ai").overlay, true);
    assert.equal(primaryNav().some((item) => item.mode === "audit"), false);
    assert.equal(primaryNav().some((item) => item.mode === "ai"), false);
    assert.equal(primaryNav().some((item) => item.mode === "evidence"), false);
  });
});

describe("isRunMode / defaultTabFor / isOverlayMode", () => {
  it("accepts workspace modes only", () => {
    assert.equal(isRunMode("mission"), true);
    assert.equal(isRunMode("audit"), true);
    assert.equal(isRunMode("ai"), true);
    assert.equal(isRunMode("evidence"), true);
    assert.equal(isRunMode("settings"), false);
    assert.equal(isRunMode("dev"), false);
    assert.equal(isRunMode("tasks"), false);
    assert.equal(isRunMode("coverage"), false);
  });

  it("returns default tabs or null", () => {
    assert.equal(defaultTabFor("mission"), "overview");
    assert.equal(defaultTabFor("audit"), "tasks");
    assert.equal(defaultTabFor("evidence"), "evidence");
    assert.equal(defaultTabFor("ai"), "ai");
    assert.equal(defaultTabFor("settings"), null);
    assert.equal(defaultTabFor("poc"), null);
  });

  it("treats only AI as overlay", () => {
    assert.equal(isOverlayMode("ai"), true);
    assert.equal(isOverlayMode("mission"), false);
    assert.equal(isOverlayMode("evidence"), false);
    assert.equal(isOverlayMode("audit"), false);
    assert.equal(isOverlayMode("settings"), false);
  });
});
