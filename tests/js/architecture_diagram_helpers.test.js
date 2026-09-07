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
  it("marks clickable nodes that have path_hints with tabindex/role=button", () => {
    const g = buildArchitectureGraph({
      components: [{ name: "API", path_hints: ["app.py"] }],
    });
    const svg = renderArchitectureSvg(g);
    assert.ok(svg.includes("arch-diag-node-clickable"));
    assert.ok(svg.includes('tabindex="0"'));
    assert.ok(svg.includes('role="button"'));
    assert.ok(svg.includes('role="group"'));
  });

  it("omits tabindex/role=button on nodes without path_hints", () => {
    const g = buildArchitectureGraph({
      components: [
        { name: "API", path_hints: ["app.py"] },
        { name: "Docs", role: "docs only" },
      ],
    });
    const svg = renderArchitectureSvg(g);
    assert.ok(svg.includes("arch-diag-node-clickable"));
    // Exactly one interactive button (the API node)
    const buttons = svg.match(/role="button"/g) || [];
    assert.equal(buttons.length, 1);
    const tabindexes = svg.match(/tabindex="0"/g) || [];
    assert.equal(tabindexes.length, 1);
    // Docs node present but not clickable
    assert.ok(svg.includes("Docs") || svg.includes("docs"));
    assert.ok(svg.includes('data-path=""'));
  });

  it("uses role=img when no nodes are clickable", () => {
    const g = buildArchitectureGraph({
      components: [{ name: "Abstract", role: "no paths" }],
    });
    const svg = renderArchitectureSvg(g);
    assert.ok(svg.includes('role="img"'));
    assert.equal((svg.match(/role="button"/g) || []).length, 0);
    assert.equal((svg.match(/tabindex=/g) || []).length, 0);
  });
});

describe("path edge shared-root cap", () => {
  it("still links specific shared path prefixes", () => {
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
  });

  it("does not explode on an overly common shared root", () => {
    const components = [
      { name: "Root", path_hints: ["src/"] },
      { name: "A", path_hints: ["src/a.py"] },
      { name: "B", path_hints: ["src/b.py"] },
      { name: "C", path_hints: ["src/c.py"] },
      { name: "D", path_hints: ["src/d.py"] },
      { name: "E", path_hints: ["src/e.py"] },
    ];
    const g = buildArchitectureGraph({ components, trust_boundaries: [] });
    const pathEdges = g.edges.filter((e) => e.kind === "path");
    // Without a cap, Root↔each file = 5 star edges (src/ touches 6 nodes).
    assert.equal(pathEdges.length, 0);
  });

  it("keeps edges when a shared root touches few nodes", () => {
    const g = buildArchitectureGraph({
      components: [
        { name: "Auth", path_hints: ["auth/"] },
        { name: "Login", path_hints: ["auth/login.py"] },
        { name: "Session", path_hints: ["auth/session.py"] },
        { name: "Unrelated", path_hints: ["payments/"] },
      ],
      trust_boundaries: [],
    });
    const pathEdges = g.edges.filter((e) => e.kind === "path");
    // auth/ touches 3 nodes (<=4) → Auth-Login, Auth-Session
    assert.equal(pathEdges.length, 2);
  });
});
