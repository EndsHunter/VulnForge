/**
 * Pure helpers for Architecture Diagram v0 (inferred graph + SVG).
 * UMD/CommonJS — browser script tag and node --test.
 *
 * Edges are heuristic only (trust_boundaries text + shared path_hints).
 * Not a formal architecture model.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.ArchitectureDiagramHelpers = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var DISCLAIMER = "Inferred from architecture map — not a formal model.";

  /** Normalize a component-like object into {id,name,role,path_hints}. */
  function normalizeComponent(c, index) {
    if (c == null) return null;
    if (typeof c === "string") {
      var s = String(c).trim();
      if (!s) return null;
      return {
        id: "c" + index + ":" + s.toLowerCase(),
        name: s.slice(0, 120),
        role: "",
        path_hints: [],
      };
    }
    if (typeof c !== "object") return null;
    var name = String(c.name || c.id || "").trim();
    if (!name) return null;
    var role = String(c.role || c.description || c.summary || "").trim();
    var hintsRaw = Array.isArray(c.path_hints)
      ? c.path_hints
      : Array.isArray(c.paths)
        ? c.paths
        : [];
    var path_hints = [];
    for (var i = 0; i < hintsRaw.length && path_hints.length < 12; i++) {
      if (hintsRaw[i] == null) continue;
      var h = String(hintsRaw[i]).trim();
      if (h) path_hints.push(h.slice(0, 80));
    }
    return {
      id: "c" + index + ":" + name.toLowerCase(),
      name: name.slice(0, 120),
      role: role.slice(0, 400),
      path_hints: path_hints,
    };
  }

  /** Extract component list from architecture or architecture_summary. */
  function extractComponents(archOrSummary) {
    var src = archOrSummary && typeof archOrSummary === "object" ? archOrSummary : {};
    var raw = Array.isArray(src.components)
      ? src.components
      : Array.isArray(src.modules)
        ? src.modules
        : [];
    var out = [];
    var seen = Object.create(null);
    for (var i = 0; i < raw.length; i++) {
      var n = normalizeComponent(raw[i], i);
      if (!n) continue;
      var key = n.name.toLowerCase();
      if (seen[key]) continue;
      seen[key] = true;
      out.push(n);
    }
    return out;
  }

  function extractTrustBoundaries(archOrSummary) {
    var src = archOrSummary && typeof archOrSummary === "object" ? archOrSummary : {};
    var raw = Array.isArray(src.trust_boundaries) ? src.trust_boundaries : [];
    var out = [];
    for (var i = 0; i < raw.length && out.length < 40; i++) {
      var x = raw[i];
      if (typeof x === "string") {
        var t = x.trim();
        if (t) out.push(t);
        continue;
      }
      if (x && typeof x === "object") {
        var parts = [
          x.name,
          x.id,
          x.description,
          x.role,
          x.from,
          x.to,
          x.between,
          x.boundary,
        ]
          .filter(Boolean)
          .map(function (p) {
            return String(p).trim();
          })
          .filter(Boolean);
        if (parts.length) out.push(parts.join(" "));
      }
    }
    return out;
  }

  /**
   * Split a trust-boundary phrase into candidate tokens that may name components.
   * Separators: arrows, slash, " to ", " vs ", " and ", "↔".
   */
  function splitBoundaryTokens(text) {
    var s = String(text || "").trim();
    if (!s) return [];
    var parts = s.split(/\s*(?:→|->|←|↔|\/|\bto\b|\bvs\.?\b|\band\b|\bversus\b)\s*/i);
    var tokens = [];
    for (var i = 0; i < parts.length; i++) {
      var p = String(parts[i] || "")
        .replace(/^[\s:;,\-–—]+|[\s:;,\-–—]+$/g, "")
        .trim();
      if (p) tokens.push(p);
    }
    return tokens;
  }

  /** Find best component match for a token (exact name, then substring). */
  function matchComponent(token, components) {
    var t = String(token || "")
      .trim()
      .toLowerCase();
    if (!t) return null;
    var i;
    for (i = 0; i < components.length; i++) {
      if (components[i].name.toLowerCase() === t) return components[i];
    }
    for (i = 0; i < components.length; i++) {
      var n = components[i].name.toLowerCase();
      if (n.length >= 2 && (t.indexOf(n) !== -1 || n.indexOf(t) !== -1)) {
        return components[i];
      }
    }
    return null;
  }

  function edgeKey(a, b) {
    return a < b ? a + "|" + b : b + "|" + a;
  }

  /**
   * Infer undirected edges from trust_boundaries strings and shared path_hints.
   * @returns {{nodes: object[], edges: {from,to,kind,label}[]}}
   */
  function buildArchitectureGraph(archOrSummary) {
    var nodes = extractComponents(archOrSummary);
    var edges = [];
    var seen = Object.create(null);

    function addEdge(a, b, kind, label) {
      if (!a || !b || a.id === b.id) return;
      var k = edgeKey(a.id, b.id) + "::" + kind;
      if (seen[k]) return;
      seen[k] = true;
      edges.push({
        from: a.id,
        to: b.id,
        kind: kind,
        label: label || kind,
      });
    }

    var bounds = extractTrustBoundaries(archOrSummary);
    for (var bi = 0; bi < bounds.length; bi++) {
      var tokens = splitBoundaryTokens(bounds[bi]);
      var matched = [];
      var mi;
      for (mi = 0; mi < tokens.length; mi++) {
        var m = matchComponent(tokens[mi], nodes);
        if (m && matched.indexOf(m) === -1) matched.push(m);
      }
      // Pair consecutive matched components in the phrase
      for (mi = 0; mi + 1 < matched.length; mi++) {
        addEdge(matched[mi], matched[mi + 1], "boundary", "trust boundary");
      }
    }

    // Shared path_hints: same hint, or one is a prefix of another.
    // Cap edges from overly common shared roots (avoids dense graphs when
    // many components share e.g. "src/" or "packages/").
    var MAX_NODES_PER_SHARED_ROOT = 4;
    var MAX_PATH_EDGES = 24;

    function normalizeHint(h) {
      return String(h || "")
        .replace(/\\/g, "/")
        .replace(/^\.\//, "")
        .replace(/\/+$/, "")
        .toLowerCase();
    }
    /** Longest related root: exact match, or the shorter prefix path. */
    function sharedRootOf(a, b) {
      if (!a || !b) return null;
      if (a === b) return a;
      if (a.indexOf(b + "/") === 0) return b;
      if (b.indexOf(a + "/") === 0) return a;
      return null;
    }

    var nodeHints = [];
    var ni, nj, hi, hj;
    for (ni = 0; ni < nodes.length; ni++) {
      nodeHints[ni] = nodes[ni].path_hints.map(normalizeHint).filter(Boolean);
    }

    var rootCountCache = Object.create(null);
    function rootNodeCount(root) {
      if (rootCountCache[root] != null) return rootCountCache[root];
      var count = 0;
      for (var ri = 0; ri < nodeHints.length; ri++) {
        var hs = nodeHints[ri];
        for (var rj = 0; rj < hs.length; rj++) {
          if (hs[rj] === root || hs[rj].indexOf(root + "/") === 0) {
            count++;
            break;
          }
        }
      }
      rootCountCache[root] = count;
      return count;
    }

    var pathEdgeCount = 0;
    for (ni = 0; ni < nodes.length && pathEdgeCount < MAX_PATH_EDGES; ni++) {
      for (nj = ni + 1; nj < nodes.length && pathEdgeCount < MAX_PATH_EDGES; nj++) {
        var ha = nodeHints[ni];
        var hb = nodeHints[nj];
        var bestRoot = null;
        for (hi = 0; hi < ha.length; hi++) {
          for (hj = 0; hj < hb.length; hj++) {
            var root = sharedRootOf(ha[hi], hb[hj]);
            if (!root) continue;
            if (!bestRoot || root.length > bestRoot.length) bestRoot = root;
          }
        }
        if (!bestRoot) continue;
        if (rootNodeCount(bestRoot) > MAX_NODES_PER_SHARED_ROOT) continue;
        addEdge(nodes[ni], nodes[nj], "path", "shared path");
        pathEdgeCount++;
      }
    }

    return { nodes: nodes, edges: edges, disclaimer: DISCLAIMER };
  }

  /** Escape XML/SVG text. */
  function escXml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /**
   * Simple circle layout for nodes; returns SVG markup string.
   * Each node is a <g class="arch-diag-node"> with data-node-id and data-path.
   */
  function renderArchitectureSvg(graph, opts) {
    opts = opts || {};
    var nodes = (graph && graph.nodes) || [];
    var edges = (graph && graph.edges) || [];
    var width = opts.width || 640;
    var height = opts.height || 360;
    var pad = 56;

    if (!nodes.length) {
      return (
        '<svg class="arch-diag-svg arch-diag-empty" viewBox="0 0 ' +
        width +
        " " +
        height +
        '" role="img" aria-label="No components to diagram">' +
        '<text x="' +
        width / 2 +
        '" y="' +
        height / 2 +
        '" text-anchor="middle" class="arch-diag-empty-text">No components to diagram</text>' +
        "</svg>"
      );
    }

    var cx = width / 2;
    var cy = height / 2;
    var n = nodes.length;
    var radius = Math.min(width, height) / 2 - pad;
    if (n === 1) radius = 0;
    var positions = Object.create(null);
    var i;
    for (i = 0; i < n; i++) {
      var angle = -Math.PI / 2 + (2 * Math.PI * i) / n;
      positions[nodes[i].id] = {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    }

    var byId = Object.create(null);
    for (i = 0; i < n; i++) byId[nodes[i].id] = nodes[i];

    var edgeLines = [];
    for (i = 0; i < edges.length; i++) {
      var e = edges[i];
      var a = positions[e.from];
      var b = positions[e.to];
      if (!a || !b) continue;
      var midX = (a.x + b.x) / 2;
      var midY = (a.y + b.y) / 2;
      var kindClass =
        e.kind === "boundary" ? "arch-diag-edge-boundary" : "arch-diag-edge-path";
      edgeLines.push(
        '<line class="arch-diag-edge ' +
          kindClass +
          '" x1="' +
          a.x.toFixed(1) +
          '" y1="' +
          a.y.toFixed(1) +
          '" x2="' +
          b.x.toFixed(1) +
          '" y2="' +
          b.y.toFixed(1) +
          '" />'
      );
      if (e.label) {
        edgeLines.push(
          '<text class="arch-diag-edge-label" x="' +
            midX.toFixed(1) +
            '" y="' +
            (midY - 4).toFixed(1) +
            '" text-anchor="middle">' +
            escXml(e.label) +
            "</text>"
        );
      }
    }

    var nodeEls = [];
    var anyClickable = false;
    for (i = 0; i < n; i++) {
      var node = nodes[i];
      var p = positions[node.id];
      var path0 = node.path_hints && node.path_hints[0] ? node.path_hints[0] : "";
      var title = node.name + (node.role ? " — " + node.role : "");
      if (path0) title += " → " + path0;
      var label = node.name.length > 22 ? node.name.slice(0, 20) + "…" : node.name;
      var clickable = "";
      var interactiveAttrs = "";
      if (path0) {
        anyClickable = true;
        clickable = " arch-diag-node-clickable";
        interactiveAttrs = ' tabindex="0" role="button"';
      }
      nodeEls.push(
        '<g class="arch-diag-node' +
          clickable +
          '" data-node-id="' +
          escXml(node.id) +
          '" data-path="' +
          escXml(path0) +
          '"' +
          interactiveAttrs +
          ' aria-label="' +
          escXml(title) +
          '">' +
          "<title>" +
          escXml(title) +
          "</title>" +
          '<circle class="arch-diag-node-circle" cx="' +
          p.x.toFixed(1) +
          '" cy="' +
          p.y.toFixed(1) +
          '" r="28" />' +
          '<text class="arch-diag-node-label" x="' +
          p.x.toFixed(1) +
          '" y="' +
          (p.y + 4).toFixed(1) +
          '" text-anchor="middle">' +
          escXml(label) +
          "</text>" +
          "</g>"
      );
    }

    var svgRole = anyClickable ? "group" : "img";
    return (
      '<svg class="arch-diag-svg" viewBox="0 0 ' +
      width +
      " " +
      height +
      '" role="' +
      svgRole +
      '" aria-label="Inferred architecture diagram">' +
      "<defs>" +
      '<marker id="arch-diag-arrow" viewBox="0 0 10 10" refX="10" refY="5" ' +
      'markerWidth="6" markerHeight="6" orient="auto-start-reverse">' +
      '<path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />' +
      "</marker>" +
      "</defs>" +
      edgeLines.join("") +
      nodeEls.join("") +
      "</svg>"
    );
  }

  /**
   * Full diagram card HTML (disclaimer + svg or empty). Pure string builder;
   * click wiring is done by the host UI.
   */
  function renderDiagramCardHtml(archOrSummary, opts) {
    opts = opts || {};
    var graph = buildArchitectureGraph(archOrSummary);
    var emptyMsg =
      opts.emptyMessage ||
      "No components recorded — diagram appears after recon maps components.";
    if (!graph.nodes.length) {
      return (
        '<section class="card arch-diagram-card" id="arch-diagram-card">' +
        '<header class="arch-section-head"><h3>Diagram</h3></header>' +
        '<p class="arch-diagram-disclaimer controls-hint">' +
        escXml(DISCLAIMER) +
        "</p>" +
        '<div class="empty arch-diagram-empty"><p class="controls-hint">' +
        escXml(emptyMsg) +
        "</p></div>" +
        "</section>"
      );
    }
    var svg = renderArchitectureSvg(graph, opts);
    var edgeNote =
      graph.edges.length === 0
        ? '<p class="controls-hint arch-diagram-edge-note">No edges inferred yet (need trust_boundaries naming components, or shared path_hints).</p>'
        : '<p class="controls-hint arch-diagram-edge-note">' +
          graph.edges.length +
          " inferred edge" +
          (graph.edges.length === 1 ? "" : "s") +
          " (boundaries + shared paths). Click a node with path_hints to open Explorer.</p>";
    return (
      '<section class="card arch-diagram-card" id="arch-diagram-card">' +
      '<header class="arch-section-head"><h3>Diagram</h3>' +
      '<span class="arch-section-count">' +
      graph.nodes.length +
      "</span></header>" +
      '<p class="arch-diagram-disclaimer">' +
      escXml(DISCLAIMER) +
      "</p>" +
      '<div class="arch-diagram-viewport">' +
      svg +
      "</div>" +
      edgeNote +
      "</section>"
    );
  }

  return {
    DISCLAIMER: DISCLAIMER,
    normalizeComponent: normalizeComponent,
    extractComponents: extractComponents,
    extractTrustBoundaries: extractTrustBoundaries,
    splitBoundaryTokens: splitBoundaryTokens,
    matchComponent: matchComponent,
    buildArchitectureGraph: buildArchitectureGraph,
    renderArchitectureSvg: renderArchitectureSvg,
    renderDiagramCardHtml: renderDiagramCardHtml,
    escXml: escXml,
  };
});
