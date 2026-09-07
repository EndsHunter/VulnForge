"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const helpers = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "monaco_loader.js")
);

describe("languageFromPath", () => {
  it("maps common source extensions", () => {
    assert.equal(helpers.languageFromPath("app.py"), "python");
    assert.equal(helpers.languageFromPath("src/main.go"), "go");
    assert.equal(helpers.languageFromPath("pkg/Foo.java"), "java");
    assert.equal(helpers.languageFromPath("a/b/c.ts"), "typescript");
    assert.equal(helpers.languageFromPath("x.JS"), "javascript");
  });

  it("handles dockerfile / makefile / unknown", () => {
    assert.equal(helpers.languageFromPath("Dockerfile"), "dockerfile");
    assert.equal(helpers.languageFromPath("dockerfile.dev"), "dockerfile");
    assert.equal(helpers.languageFromPath("Makefile"), "plaintext");
    assert.equal(helpers.languageFromPath("README"), "plaintext");
    assert.equal(helpers.languageFromPath("weird.xyz"), "plaintext");
  });
});
