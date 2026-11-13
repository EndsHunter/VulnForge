/*
 * Run (/benchmarks/runs/<id>) and Compare (/benchmarks/compare?a=&b=) views.
 */
(function () {
  "use strict";

  var B = window.VFBench;
  var H = window.VFBenchHelpers;
  var h = B.h;

  var SUITE_LABELS = { realworld: "Real-world OSS", synthetic: "Synthetic apps", fixtures: "Fixture checks" };

  function titleOf(run) {
    if (run.suite_id) return SUITE_LABELS[run.suite_id] || run.suite_id;
    return run.def_id || run.id;
  }

  function backLink() {
    return h("a.bench-back", { href: "/benchmarks" }, "← Scoreboard");
  }

  function fingerprintCard(fp) {
    var rows = H.fingerprintRows(fp);
    return h("section.vf-card.bench-fp", { "aria-label": "Fingerprint" },
      h("h2.vf-section-label", "Fingerprint"),
      Object.keys(fp || {}).length
        ? h("dl.bench-fp-list", rows.map(function (r) {
            return [h("dt", r.label), h("dd.vf-mono", r.value)];
          }))
        : h("div.vf-empty", "No fingerprint (L0 runs and runs recorded before fingerprints)."));
  }

  // ---------------------------------------------------------------- Run view

  function mountRun(root, ctx) {
    var st = { root: root, id: ctx.runId, timer: null };
    function load() {
      B.api("/api/benchmarks/runs/" + encodeURIComponent(st.id))
        .then(function (j) {
          renderRun(st, j);
          clearTimeout(st.timer);
          var s = j.run && j.run.status;
          if (s === "running" || s === "queued") st.timer = setTimeout(load, 2500);
        })
        .catch(function (e) {
          root.textContent = "";
          root.appendChild(backLink());
          root.appendChild(h("div.vf-empty", "Failed to load run " + st.id + ": " + e.message));
        });
    }
    st.reload = load;
    load();
  }

  function renderRun(st, payload) {
    var run = payload.run;
    var m = run.metrics || {};
    var root = st.root;
    root.textContent = "";
    var isSuite = !!(m.suite || run.suite_id);
    var active = run.status === "running" || run.status === "queued";
    var baseId = payload.baseline_id;
    var isBase = baseId && baseId === run.id;

    root.appendChild(backLink());
    var actions = h("div.bench-row");
    if (active && run.mode === "live") {
      actions.appendChild(h("button.vf-btn.vf-btn--danger", { type: "button", onclick: function () { B.stopRun(run.id).then(st.reload); } }, "Stop"));
    }
    if (isSuite && run.suite_id && !active && run.status !== "cancelled" && !isBase) {
      actions.appendChild(h("button.vf-btn", { type: "button", onclick: function () {
        B.pinBaseline(run.id).then(st.reload);
      } }, "Pin as baseline"));
    }
    if (isSuite && baseId && !isBase && run.tier !== "l0") {
      actions.appendChild(h("a.vf-btn.vf-btn--primary", { href: B.compareHref(baseId, run.id) }, "Compare with baseline"));
    }
    root.appendChild(h("header.bench-run-head",
      h("h2.bench-run-title", titleOf(run)),
      B.tierPill(run.tier),
      B.statusPill(run.status, { suite: isSuite, tier: run.tier }),
      isBase ? B.pill("baseline", "vf-pill--confirmed") : null,
      h("span.vf-mono.vf-faint", run.id),
      h("span.vf-spacer"),
      actions));
    if (run.note) root.appendChild(h("p.bench-note", run.note));
    if (run.parent_id) {
      root.appendChild(h("p.vf-faint", "Part of suite run ", h("a.vf-mono", { href: B.runHref(run.parent_id) }, run.parent_id)));
    }
    root.appendChild(B.caveat(run.tier));
    if (run.error) root.appendChild(h("p.bench-error", run.error));
    if (active) root.appendChild(h("p.bench-progress", h("span.bench-live-dot"), " ", H.progressText(run)));

    if (isSuite && run.tier === "l0") {
      root.appendChild(l0Members(m.members || []));
      return;
    }
    if (isSuite) {
      var summary = m.summary || payload.summary || {};
      root.appendChild(headlineTiles(summary));
      var grid = h("div.bench-run-grid");
      grid.appendChild(caseTable(m.members || []));
      var side = h("div.bench-run-side");
      side.appendChild(fingerprintCard(run.fingerprint));
      side.appendChild(compareTo(run, baseId));
      grid.appendChild(side);
      root.appendChild(grid);
      return;
    }
    // Single case
    var grid1 = h("div.bench-run-grid");
    grid1.appendChild(caseDetail(run));
    grid1.appendChild(h("div.bench-run-side", fingerprintCard(run.fingerprint)));
    root.appendChild(grid1);
  }

  function headlineTiles(summary) {
    var head = summary.headline || {};
    var spread = summary.spread || {};
    var n = summary.n_repeats || 1;
    var totals = summary.totals || {};
    return h("section.vf-card",
      h("div.bench-metrics", H.METRICS.map(function (spec) {
        return B.metricTile(spec, head[spec.key], n > 1 ? { range: H.fmtRange(spec.key, spread[spec.key], n) } : {});
      })),
      h("p.vf-faint.bench-totals",
        [
          (totals.hit_count || 0) + " / " + (totals.oracle_count || 0) + " oracle hits (gated)",
          (totals.raw_hit_count || 0) + " raw",
          (totals.cases || 0) + " case runs scored",
          totals.errors ? totals.errors + " errors" : null,
          n > 1 ? n + " repeats: values are means, ranges are min–max" : "1 run: LLM variance not measured"
        ].filter(Boolean).join(" · ")));
  }

  function caseTable(members) {
    var rows = H.sortCaseRows(H.caseRows(members));
    var body = h("tbody");
    rows.forEach(function (r) {
      var single = r.run_ids.length === 1 ? r.run_ids[0] : null;
      body.appendChild(h("tr", { "data-case": r.def_id },
        h("td.vf-mono", single ? h("a", { href: B.runHref(single) }, r.def_id) : r.def_id),
        h("td", (function (v) { return B.pill(v.text, v.cls); })(H.caseVerdict(r))),
        h("td.vf-mono", { "data-tone": r.hit_rate === 1 ? "good" : r.hit_rate === 0 ? "bad" : "" },
          r.oracles ? r.hits + "/" + r.oracles : "–"),
        h("td.vf-mono", r.scored ? String(r.unmatched) : "–"),
        h("td.vf-mono", H.fmtTokens(r.tokens)),
        h("td.vf-mono", H.fmtDuration(r.wall_s)),
        h("td.bench-col-runs", r.run_ids.length > 1
          ? r.run_ids.map(function (id, i) { return h("a.vf-mono", { href: B.runHref(id), title: id }, "#" + (i + 1)); })
          : (r.errors[0] ? h("span.bench-error-inline", r.errors[0]) : null))
      ));
    });
    return h("section.vf-card.bench-cases",
      h("h2.vf-section-label", "Cases"),
      rows.length
        ? h("div.bench-table-wrap", h("table.bench-table",
            h("thead", h("tr", ["Case", "Status", "Hits", "Unmatched", "Tokens", "Wall", "Runs"].map(function (t) { return h("th", t); }))),
            body))
        : h("div.vf-empty", "No cases yet."));
  }

  function l0Members(members) {
    var body = h("tbody");
    members.slice().sort(function (a, b) {
      var pa = a.status === "passed" ? 1 : 0;
      var pb = b.status === "passed" ? 1 : 0;
      return pa - pb || String(a.def_id).localeCompare(String(b.def_id));
    }).forEach(function (r) {
      body.appendChild(h("tr",
        h("td.vf-mono", h("a", { href: B.runHref(r.run_id) }, r.def_id)),
        h("td.vf-mono", (r.types_run || []).join(", ")),
        h("td", B.statusPill(r.status)),
        h("td.vf-mono", r.score == null ? "–" : String(Math.round(r.score * 1000) / 1000)),
        h("td", r.error ? h("span.bench-error-inline", r.error) : null)));
    });
    return h("section.vf-card.bench-cases",
      h("h2.vf-section-label", "Fixture checks"),
      h("div.bench-table-wrap", h("table.bench-table",
        h("thead", h("tr", ["Case", "Types", "Status", "Score", "Error"].map(function (t) { return h("th", t); }))),
        body)));
  }

  function compareTo(run, baseId) {
    var sec = h("section.vf-card.bench-compare-to", h("h2.vf-section-label", "Compare"));
    var sel = h("select.bench-input", { "aria-label": "Compare against run" }, h("option", { value: "" }, "Loading…"));
    var go = h("button.vf-btn", { type: "button", onclick: function () {
      if (sel.value) window.location.href = B.compareHref(sel.value, run.id);
    } }, "Compare");
    sec.appendChild(h("div.bench-row", sel, go));
    sec.appendChild(h("p.vf-faint", "Pick an earlier run of the same suite and tier as the A side."));
    B.api("/api/benchmarks/runs?suite=true&suite_id=" + encodeURIComponent(run.suite_id || "") +
      "&tier=" + encodeURIComponent(run.tier || "") + "&limit=50")
      .then(function (j) {
        sel.textContent = "";
        var rows = (j.runs || []).filter(function (r) { return r.id !== run.id && r.status !== "running" && r.status !== "queued"; });
        if (!rows.length) {
          sel.appendChild(h("option", { value: "" }, "No other runs"));
          go.disabled = true;
          return;
        }
        rows.forEach(function (r) {
          var fp = r.fingerprint || {};
          var label = (r.id === baseId ? "★ baseline · " : "") + r.id + " · " + (fp.model || "?") + " · " + H.shortAge(r.started_at);
          sel.appendChild(h("option", { value: r.id, selected: r.id === baseId ? true : null }, label));
        });
      })
      .catch(function () { sel.textContent = ""; sel.appendChild(h("option", { value: "" }, "Failed to load")); });
    return sec;
  }

  function caseDetail(run) {
    var m = run.metrics || {};
    var tok = m.tokens || {};
    var sec = h("section.vf-card.bench-case-detail");
    if (run.tier === "l0") {
      sec.appendChild(h("h2.vf-section-label", "L0 result"));
      var by = m.by_type || {};
      Object.keys(by).forEach(function (t) {
        var x = by[t] || {};
        sec.appendChild(h("div.bench-kv", h("span", t), h("span.vf-mono",
          x.recall != null ? "recall " + H.fmtPct(x.recall) + " (" + (x.hit_count || 0) + "/" + (x.oracle_count || 0) + ")"
            : "score " + (x.score != null ? x.score : "–") + (x.passed ? " · passed" : " · failed"))));
      });
      return sec;
    }
    sec.appendChild(h("h2.vf-section-label", "Result"));
    sec.appendChild(h("div.bench-metrics", [
      B.metricTile(H.metricSpec("recall"), m.recall),
      B.metricTile(H.metricSpec("recall_raw"), m.recall_raw),
      B.metricTile({ key: "unmatched", label: "Unmatched", sub: "gated", kind: "num", note: H.metricSpec("unmatched_per_target").note }, m.unmatched, { text: m.unmatched == null ? "–" : String(m.unmatched) }),
      B.metricTile({ key: "tokens", label: "Tokens", sub: (tok.llm_calls || 0) + " calls", kind: "tokens", note: "All LLM tokens for this case." }, tok.total_tokens, { text: H.fmtTokens(tok.total_tokens) })
    ]));
    var list = h("ul.bench-oracle-list");
    var matches = {};
    (m.matches || []).forEach(function (x) { matches[x.oracle_id] = x; });
    function item(oid, kind) {
      var mt = matches[oid];
      return h("li", { "data-kind": kind },
        h("span.bench-oracle-kind", kind === "hit" ? "hit" : kind === "raw" ? "gate loss" : "miss"),
        h("span.vf-mono", oid),
        mt ? h("span.vf-faint", " finding #" + mt.finding_id + " (" + mt.state + ")") : null);
    }
    (m.hits || []).forEach(function (o) { list.appendChild(item(o, "hit")); });
    (m.raw_only || []).forEach(function (o) { list.appendChild(item(o, "raw")); });
    (m.misses || []).forEach(function (o) { list.appendChild(item(o, "miss")); });
    sec.appendChild(h("h3.bench-sub", "Oracles"));
    sec.appendChild(list.childNodes.length ? list : h("div.vf-empty", "Not scored yet."));
    var bs = m.by_state || {};
    if (Object.keys(bs).length) {
      sec.appendChild(h("h3.bench-sub", "Findings by state"));
      sec.appendChild(h("div.bench-row", Object.keys(bs).sort().map(function (k) {
        return B.pill(k + " " + bs[k], k === "needs_human" ? "vf-pill--review" : k.indexOf("rejected") === 0 ? "vf-pill--rejected" : "vf-pill--candidate");
      })));
      if (m.ungated_count) sec.appendChild(h("p.vf-faint", m.ungated_count + " finding(s) never reached the gates (task cap hit)."));
    }
    if (run.harness_run_dir) {
      sec.appendChild(h("h3.bench-sub", "Eval harness"));
      sec.appendChild(h("p.vf-mono.bench-path", run.harness_run_dir));
    }
    return sec;
  }

  // ------------------------------------------------------------ Compare view

  function mountCompare(root, ctx) {
    root.appendChild(backLink());
    if (!ctx.a || !ctx.b) {
      root.appendChild(h("div.vf-empty", "Pick two runs: open a run and use Compare."));
      return;
    }
    B.api("/api/benchmarks/compare?a=" + encodeURIComponent(ctx.a) + "&b=" + encodeURIComponent(ctx.b))
      .then(function (j) { renderCompare(root, j); })
      .catch(function (e) { root.appendChild(h("div.vf-empty", "Compare failed: " + e.message)); });
  }

  function sideRef(label, side) {
    var fp = side.fingerprint || {};
    return h("div.bench-cmp-side",
      h("span.vf-section-label", label),
      h("a.vf-mono", { href: B.runHref(side.id) }, side.id),
      h("span.vf-faint", [fp.model || "?", H.shortSha(fp.git_sha)].filter(Boolean).join(" · ")),
      h("span.vf-faint", (side.summary && side.summary.n_repeats || 1) + " repeat(s)"));
  }

  function renderCompare(root, cmp) {
    root.appendChild(h("header.bench-run-head",
      h("h2.bench-run-title", "Compare"),
      sideRef("A · baseline", cmp.a),
      h("span.bench-cmp-arrow", "→"),
      sideRef("B", cmp.b)));
    if (!cmp.comparable) {
      root.appendChild(h("section.vf-card.bench-refusal", h("strong", "Not comparable. "), cmp.refusal));
      return;
    }
    (cmp.warnings || []).forEach(function (w) { root.appendChild(h("p.bench-warning", w)); });

    var diff = H.fingerprintDiffRows(cmp.fingerprint_diff);
    root.appendChild(h("section.vf-card",
      h("h2.vf-section-label", "What changed"),
      diff.length
        ? h("table.bench-table.bench-fp-diff",
            h("thead", h("tr", h("th", ""), h("th", "A"), h("th", "B"))),
            h("tbody", diff.map(function (d) {
              return h("tr", h("td", d.label), h("td.vf-mono", d.a), h("td.vf-mono", d.b));
            })))
        : h("div.vf-empty", "Same fingerprint: any difference is run-to-run noise.")));

    var ha = (cmp.a.summary || {}).headline || {};
    var hb = (cmp.b.summary || {}).headline || {};
    root.appendChild(h("section.vf-card",
      h("h2.vf-section-label", "Headline"),
      h("table.bench-table.bench-cmp-metrics",
        h("thead", h("tr", h("th", "Metric"), h("th", "A"), h("th", "B"), h("th", "Δ"))),
        h("tbody", H.METRICS.map(function (spec) {
          var d = H.fmtDelta(spec.key, (cmp.deltas || {})[spec.key]);
          return h("tr", { title: spec.note },
            h("td", spec.label, h("span.vf-faint", " " + spec.sub)),
            h("td.vf-mono", H.fmtMetric(spec.key, ha[spec.key])),
            h("td.vf-mono", H.fmtMetric(spec.key, hb[spec.key])),
            h("td.vf-mono.bench-delta", { "data-tone": d.tone }, d.text));
        }))),
      B.caveat("directed")));

    var g = H.flipGroups(cmp.flips);
    function flipList(title, rows, kind) {
      return h("section.vf-card.bench-flips", { "data-kind": kind },
        h("h2.vf-section-label", title + " (" + rows.length + ")"),
        rows.length
          ? h("ul.bench-flip-list", rows.map(function (f) {
              return h("li",
                h("span.vf-mono", f.def_id),
                f.oracle_id !== f.def_id ? [" ", h("span.vf-mono.vf-faint", f.oracle_id)] : null,
                h("span.vf-spacer"),
                h("span.vf-mono", H.fmtPct(f.a_rate) + " → " + H.fmtPct(f.b_rate)));
            }))
          : h("div.vf-empty", kind === "regression" ? "No oracle went from hit to miss." : "No oracle went from miss to hit."));
    }
    root.appendChild(h("div.bench-flip-grid",
      flipList("Regressions", g.regression, "regression"),
      flipList("Gains", g.gain, "gain")));
    var hits = g.unchanged.filter(function (f) { return f.change === "hit"; }).length;
    root.appendChild(h("p.vf-faint", g.unchanged.length + " oracles unchanged: " + hits + " hit at the same rate in A and B, " +
      (g.unchanged.length - hits) + " missed in every run of both."));
  }

  B.views.run = { mount: mountRun };
  B.views.compare = { mount: mountCompare };
})();
