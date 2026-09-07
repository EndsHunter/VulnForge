"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const helpers = require(
  path.join(__dirname, "..", "..", "vulnforge", "ui", "static", "architecture_diagram_helpers.js")
);

const {
  DISCLAIMER,
  extractComponents,
  splitBoundaryTokens,
  buildArchitectureGraph,
  renderDiagramCardHtml,
  renderArchitectureSvg,
} = helpers;

describe("extractComponents", () => {
  it("dedupes by name and keeps path_hints", () => {
    const comps = extractComponents({
      components: [
        { name: "API", role: "http", path_hints: ["api/"] },
        { name: "api", path_hints: ["api/routes.py"] },
        { name: "", path_hints: ["x"] },
        "DB",
      ],
    });
    assert.equal(comps.length, 2);
    assert.equal(comps[0].name, "API");
    assert.deepEqual(comps[0].path_hints, ["api/"]);
    assert.equal(comps[1].name, "DB");
  });
});

describe("splitBoundaryTokens", () => {
  it("splits arrows and slash", () => {
    assert.deepEqual(splitBoundaryTokens("API → Auth"), ["API", "Auth"]);
    assert.deepEqual(splitBoundaryTokens("public/private"), ["public", "private"]);
    assert.deepEqual(splitBoundaryTokens("edge to core"), ["edge", "core"]);
  });
});

describe("buildArchitectureGraph", () => {
  it("infers boundary edges from trust_boundaries naming components", () => {
    const g = buildArchitectureGraph({
      components: [
        { name: "API", path_hints: ["api/"] },
        { name: "Auth", path_hints: ["auth/"] },
        { name: "DB", path_hints: ["db/"] },
      ],
      trust_boundaries: ["API → Auth", "Auth/DB"],
    });
    assert.equal(g.nodes.length, 3);
    assert.equal(g.disclaimer, DISCLAIMER);
    const kinds = g.edges.map((e) => e.kind);
    assert.ok(kinds.includes("boundary"));
    const pairs = g.edges
      .filter((e) => e.kind === "boundary")
      .map((e) => [e.from, e.to].sort().join("~"));
    assert.ok(pairs.some((p) => p.includes("api") && p.includes("auth")));
  });

  it("infers path edges from shared path_hints", () => {
    const g = buildArchitectureGraph({
      components: [
        { name: "Routes", path_hints: ["api/"] },
        { name: "Handlers", path_hints: ["api/handlers.py"] },
        { name: "Other", path_hints: ["lib/"] },
      ],
      trust_boundaries: [],
    });
    const pathEdges = g.edges.filter((e) => e.kind === "path");
    assert.equal(pathEdges.length, 1);
    const ids = [pathEdges[0].from, pathEdges[0].to].join(" ");
    assert.ok(ids.includes("routes") && ids.includes("handlers"));
  });

  it("returns empty nodes when no components", () => {
    const g = buildArchitectureGraph({ summary: "x", trust_boundaries: ["a/b"] });
    assert.equal(g.nodes.length, 0);
    assert.equal(g.edges.length, 0);
  });
});

describe("renderDiagramCardHtml", () => {
  it("includes disclaimer and SVG when components exist", () => {
    const html = renderDiagramCardHtml({
      components: [{ name: "API", path_hints: ["app.py"] }],
      trust_boundaries: [],
    });
    assert.ok(html.includes(DISCLAIMER));
    assert.ok(html.includes("arch-diag-svg"));
    assert.ok(html.includes('data-path="app.py"'));
  });

  it("empty components still shows disclaimer", () => {
    const html = renderDiagramCardHtml({ components: [], trust_boundaries: [] });
    assert.ok(html.includes(DISCLAIMER));
    assert.ok(html.includes("No components"));
  });
});

describe("renderArchitectureSvg", () => {
  it("marks clickable nodes that have path_hints", () => {
    const g = buildArchitectureGraph({
      components: [{ name: "API", path_hints: ["app.py"] }],
    });
    const svg = renderArchitectureSvg(g);
    assert.ok(svg.includes("arch-diag-node-clickable"));
  });
});
