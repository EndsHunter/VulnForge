/*
 * Cases (/benchmarks/cases): the library grouped by suite. Read-only here;
 * edits go through /api/benchmarks (versioned, oracle-hashed).
 */
(function () {
  "use strict";

  var B = window.VFBench;
  var H = window.VFBenchHelpers;
  var h = B.h;

  function mount(root) {
    var head = h("div.bench-row");
    var reseed = h("button.vf-btn", { type: "button", onclick: function () {
      reseed.disabled = true;
      B.api("/api/benchmarks/seed", { method: "POST" })
        .then(function (j) {
          B.toast("Reseed: " + (j.seeded || []).length + " added, " + (j.skipped || []).length + " kept as-is");
          load();
        })
        .catch(function (e) { B.toast("Reseed failed: " + e.message, "bad"); })
        .finally(function () { reseed.disabled = false; });
    } }, "Reseed missing cases");
    head.appendChild(h("p.bench-purpose", "Each case is a versioned target plus oracle. Editing a case bumps its version, and runs across different oracle versions refuse to compare."));
    head.appendChild(h("span.vf-spacer"));
    head.appendChild(reseed);
    root.appendChild(head);
    var list = root.appendChild(h("div.bench-case-groups"));

    function load() {
      Promise.all([B.api("/api/benchmarks"), B.api("/api/benchmarks/suites")])
        .then(function (res) {
          var labels = {};
          var blurbs = {};
          (res[1].suites || []).forEach(function (s) { labels[s.id] = s.label; blurbs[s.id] = s.blurb; });
          list.textContent = "";
          H.groupBySuite(res[0].benchmarks || []).forEach(function (g) {
            list.appendChild(group(g, labels[g.suite] || g.suite, blurbs[g.suite] || ""));
          });
        })
        .catch(function (e) {
          list.textContent = "";
          list.appendChild(h("div.vf-empty", "Failed to load cases: " + e.message));
        });
    }
    load();
  }

  function group(g, label, blurb) {
    var body = h("tbody");
    g.defs.forEach(function (d) {
      var tags = (d.tags || []).filter(function (t) { return t !== "seed"; });
      body.appendChild(h("tr", { "data-case": d.id },
        h("td.vf-mono", d.id),
        h("td", d.name || ""),
        h("td.vf-mono", (d.types || []).join(", ")),
        h("td.vf-mono.bench-col-target", d.target_ref || ""),
        h("td.vf-mono", "v" + (d.head_version || 1)),
        h("td", tags.slice(0, 4).map(function (t) { return h("span.vf-chip.bench-tag", t); }))));
    });
    return h("section.vf-card.bench-case-group", { "data-suite": g.suite },
      h("header.bench-suite-head",
        h("h2.bench-suite-title", label),
        g.suite === "realworld" ? B.pill("real OSS", "vf-pill--confirmed") : null,
        h("span.vf-faint", g.defs.length + " cases")),
      blurb ? h("p.vf-faint.bench-suite-blurb", blurb) : null,
      h("div.bench-table-wrap", h("table.bench-table",
        h("thead", h("tr", ["Id", "Name", "Types", "Target", "Version", "Tags"].map(function (t) { return h("th", t); }))),
        body)));
  }

  B.views.cases = { mount: mount };
})();
