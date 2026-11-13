/*
 * Scoreboard (/benchmarks): one card per suite × tier (latest vs baseline),
 * active runs, the run composer, fixture checks, and recent runs.
 */
(function () {
  "use strict";

  var B = window.VFBench;
  var H = window.VFBenchHelpers;
  var h = B.h;

  var PURPOSE =
    "Compared to a baseline, did a change (prompt, tool, hunt profile, model or commit) " +
    "find more real bugs, with fewer unmatched findings, for fewer tokens and less time?";

  var state = { root: null, data: null, active: [], recent: [], timer: null, suiteLabels: {} };

  function mount(root) {
    state.root = root;
    root.appendChild(h("p.bench-purpose", PURPOSE));
    state.activeEl = root.appendChild(h("section.vf-card.bench-active", { hidden: true, "aria-label": "Active runs" }));
    state.cardsEl = root.appendChild(h("section.bench-suites", { "aria-label": "Suites" }));
    state.fixturesEl = root.appendChild(h("section.vf-card.bench-fixtures", { "aria-label": "Fixture checks" }));
    state.recentEl = root.appendChild(h("section.vf-card.bench-recent", { "aria-label": "Recent runs" }));
    state.dialog = buildComposer();
    root.appendChild(state.dialog);
    refresh();
  }

  function refresh() {
    return Promise.all([
      B.api("/api/benchmarks/suites"),
      B.api("/api/benchmarks/runs/active"),
      B.api("/api/benchmarks/runs?suite=true&limit=25")
    ]).then(function (res) {
      state.data = res[0];
      state.active = res[1].runs || [];
      state.recent = res[2].runs || [];
      (state.data.suites || []).forEach(function (s) { state.suiteLabels[s.id] = s.label; });
      render();
      schedulePoll();
    }).catch(function (e) {
      state.cardsEl.textContent = "";
      state.cardsEl.appendChild(h("div.vf-empty", "Failed to load benchmarks: " + e.message));
    });
  }

  function schedulePoll() {
    clearTimeout(state.timer);
    if (state.active.length) state.timer = setTimeout(refresh, 3000);
  }

  function render() {
    renderActive();
    renderSuites();
    renderFixtures();
    renderRecent();
  }

  function suiteLabel(id, run) {
    if (id) return state.suiteLabels[id] || id;
    return (run && run.def_id) || "?";
  }

  function renderActive() {
    var el = state.activeEl;
    el.textContent = "";
    var rows = state.active.filter(function (r) { return !r.parent_id; });
    el.hidden = !rows.length;
    if (!rows.length) return;
    el.appendChild(h("h2.vf-section-label", "Running now"));
    el.appendChild(
      h("ul.bench-active-list", rows.map(function (r) {
        return h("li.bench-active-row",
          h("span.bench-live-dot", { "aria-hidden": "true" }),
          h("a.bench-active-name", { href: B.runHref(r.id) }, suiteLabel(r.suite_id, r)),
          B.tierPill(r.tier),
          h("span.vf-mono.vf-faint", H.progressText(r)),
          h("span.vf-faint", H.shortAge(r.started_at)),
          h("span.vf-spacer"),
          r.mode === "live"
            ? h("button.vf-btn.vf-btn--danger", { type: "button", onclick: function () { B.stopRun(r.id).then(refresh); } }, "Stop")
            : null
        );
      }))
    );
  }

  function liveBusy() {
    return state.active.some(function (r) { return r.mode === "live"; });
  }

  function renderSuites() {
    var el = state.cardsEl;
    el.textContent = "";
    (state.data.suites || []).forEach(function (s) {
      s.tiers.forEach(function (tier) {
        if (tier === "l0") return; // fixture checks have their own card
        el.appendChild(suiteCard(s, tier, (s.runs || {})[tier] || {}));
      });
    });
  }

  function suiteCard(s, tier, info) {
    var latest = info.latest;
    var base = info.baseline;
    var head = (latest && latest.headline) || {};
    var baseHead = (base && base.headline) || {};
    var sameAsBase = latest && base && latest.id === base.id;
    var tiles = H.METRICS.map(function (spec) {
      var v = head[spec.key];
      var opts = {};
      if (latest && base && !sameAsBase) {
        var bv = baseHead[spec.key];
        opts.delta = typeof v === "number" && typeof bv === "number" ? v - bv : null;
        opts.deltaLabel = "vs base";
      }
      if (latest && latest.n_repeats > 1) opts.range = H.fmtRange(spec.key, (latest.spread || {})[spec.key], latest.n_repeats);
      return B.metricTile(spec, v, opts);
    });
    var fp = (latest && latest.fingerprint) || {};
    return h("article.vf-card.bench-suite", { "data-suite": s.id, "data-tier": tier },
      h("header.bench-suite-head",
        h("h2.bench-suite-title", s.label),
        B.tierPill(tier),
        h("span.vf-faint", s.case_count + " cases"),
        h("span.vf-spacer"),
        h("button.vf-btn.vf-btn--primary", {
          type: "button",
          disabled: liveBusy() || !s.case_count ? true : null,
          title: liveBusy() ? "A live run is already going" : "Start a live run of this suite",
          onclick: function () { openComposer(s, tier); }
        }, "Run suite")
      ),
      h("p.bench-suite-blurb.vf-faint", s.blurb),
      B.caveat(tier),
      latest
        ? h("div.bench-metrics", tiles)
        : h("div.vf-empty", "No finished run yet. Run the suite, then pin a baseline."),
      h("footer.bench-suite-foot",
        latest
          ? h("span.bench-run-ref",
              h("a.vf-mono", { href: B.runHref(latest.id) }, latest.id), " ",
              B.statusPill(latest.status, { suite: true, tier: tier }),
              latest.totals && latest.totals.errors ? B.pill(latest.totals.errors + " errors", "bench-pill--fail") : null, " ",
              h("span.vf-faint", [fp.model || "?", H.shortSha(fp.git_sha), H.shortAge(latest.started_at)].filter(Boolean).join(" · ")))
          : null,
        h("span.bench-base-ref",
          base
            ? [h("span.vf-faint", "baseline "), h("a.vf-mono", { href: B.runHref(base.id) }, base.id)]
            : h("span.vf-faint", "No baseline pinned")),
        h("span.vf-spacer"),
        (info.trend || []).length ? B.sparkline(info.trend) : null,
        latest && base && !sameAsBase
          ? h("a.vf-btn", { href: B.compareHref(base.id, latest.id) }, "Compare")
          : null
      )
    );
  }

  function renderFixtures() {
    var el = state.fixturesEl;
    el.textContent = "";
    var s = (state.data.suites || []).filter(function (x) { return x.id === "fixtures"; })[0];
    var info = s && s.runs && s.runs.l0 ? s.runs.l0 : {};
    var latest = info.latest;
    var details = h("details.bench-fixtures-details");
    var summary = h("summary.bench-fixtures-summary",
      h("span.vf-section-label", "Fixture checks"),
      B.tierPill("l0"),
      latest
        ? h("span.vf-mono", (latest.passed_count || 0) + " / " + (latest.count || 0) + " passed")
        : h("span.vf-faint", "never run"),
      latest ? h("span.vf-faint", H.shortAge(latest.started_at)) : null
    );
    details.appendChild(summary);
    details.appendChild(B.caveat("l0"));
    var btn = h("button.vf-btn", { type: "button", onclick: function () { runFixtures(btn); } }, "Run fixture checks");
    details.appendChild(h("div.bench-row", btn, latest ? h("a", { href: B.runHref(latest.id) }, "Open last check") : null));
    el.appendChild(details);
  }

  function runFixtures(btn) {
    btn.disabled = true;
    btn.textContent = "Running…";
    B.api("/api/benchmarks/runs", { method: "POST", body: { suite: "fixtures", tier: "l0" } })
      .then(function (j) {
        var r = j.run || {};
        var m = r.metrics || {};
        B.toast("Fixture checks: " + (m.passed_count || 0) + " / " + (m.count || 0) + " passed", m.passed ? "" : "warn");
        refresh();
      })
      .catch(function (e) { B.toast("Fixture checks failed: " + e.message, "bad"); })
      .finally(function () { btn.disabled = false; btn.textContent = "Run fixture checks"; });
  }

  function baselineIds() {
    var ids = {};
    (state.data.suites || []).forEach(function (s) {
      Object.keys(s.runs || {}).forEach(function (t) {
        var b = s.runs[t].baseline_id;
        if (b) ids[b] = true;
      });
    });
    return ids;
  }

  function renderRecent() {
    var el = state.recentEl;
    el.textContent = "";
    el.appendChild(h("h2.vf-section-label", "Recent runs"));
    var rows = state.recent;
    if (!rows.length) {
      el.appendChild(h("div.vf-empty", "No suite runs yet."));
      return;
    }
    var base = baselineIds();
    var body = h("tbody");
    rows.forEach(function (r) {
      var m = r.metrics || {};
      var head = (m.summary && m.summary.headline) || {};
      var fp = r.fingerprint || {};
      var isL0 = r.tier === "l0";
      body.appendChild(h("tr", { "data-run": r.id, onclick: function (ev) {
          if (ev.target.closest("a,button")) return;
          window.location.href = B.runHref(r.id);
        } },
        h("td", h("a", { href: B.runHref(r.id) }, suiteLabel(r.suite_id, r)), base[r.id] ? [" ", B.pill("baseline", "vf-pill--confirmed")] : null),
        h("td", B.tierPill(r.tier)),
        h("td", B.statusPill(r.status, { suite: true, tier: r.tier })),
        h("td.vf-mono", isL0 ? (m.passed_count || 0) + "/" + (m.count || 0) : H.fmtPct(head.recall)),
        h("td.vf-mono", isL0 ? "" : H.fmtTokens(head.tokens_per_hit)),
        h("td.vf-mono.bench-col-model", fp.model || ""),
        h("td.vf-mono", H.shortSha(fp.git_sha) + (fp.git_dirty ? "*" : "")),
        h("td.bench-col-note", r.note || ""),
        h("td.vf-faint", H.shortAge(r.started_at))
      ));
    });
    el.appendChild(h("div.bench-table-wrap",
      h("table.bench-table",
        h("thead", h("tr", ["Suite", "Tier", "Status", "Recall / pass", "Tokens / hit", "Model", "Commit", "Note", "Started"].map(function (t) { return h("th", t); }))),
        body)));
  }

  // ---- Run composer -------------------------------------------------------

  function buildComposer() {
    var d = h("dialog.bench-dialog", { "aria-labelledby": "bench-compose-title" });
    d.addEventListener("close", function () { state.composing = null; });
    return d;
  }

  function openComposer(s, tier) {
    var d = state.dialog;
    d.textContent = "";
    state.composing = { suite: s.id, tier: tier };
    var max = (state.data && state.data.max_repeat) || 5;
    var repeat = h("input.bench-input", { id: "bench-repeat", type: "number", min: 1, max: max, value: 1 });
    var disprove = h("input", { id: "bench-validate", type: "checkbox", checked: true });
    var note = h("input.bench-input", { id: "bench-note", type: "text", maxlength: 500, placeholder: "What changed? e.g. new hunt prompt" });
    var cost = h("p.bench-cost.vf-faint");
    function syncCost() {
      var n = Math.max(1, Math.min(max, Number(repeat.value) || 1));
      cost.textContent = s.case_count * n + " case runs on the Settings LLM. This spends tokens and can take a while. Findings stay in throwaway eval runs and are never confirmed.";
    }
    repeat.addEventListener("input", syncCost);
    syncCost();
    var start = h("button.vf-btn.vf-btn--primary", { type: "submit" }, "Start live run");
    var form = h("form.bench-form", { method: "dialog", onsubmit: function (ev) {
        ev.preventDefault();
        start.disabled = true;
        B.api("/api/benchmarks/runs", {
          method: "POST",
          body: {
            suite: s.id,
            tier: tier,
            repeat: Math.max(1, Math.min(max, Number(repeat.value) || 1)),
            validate_llm: !!disprove.checked,
            note: note.value || ""
          }
        }).then(function (j) {
          d.close();
          var r = j.run || {};
          if (r.status === "error") B.toast("Run refused: " + (r.error || "error"), "bad");
          else B.toast("Started " + r.id);
          refresh();
        }).catch(function (e) {
          B.toast("Start failed: " + e.message, "bad");
          start.disabled = false;
        });
      } },
      h("h2.bench-dialog-title", { id: "bench-compose-title" }, "Run " + s.label),
      B.caveat(tier),
      h("label.bench-field", h("span", "Repeat each case"), repeat,
        h("span.vf-faint", "More repeats measure LLM variance. One run can't tell a change from noise.")),
      h("label.bench-field.bench-field--check", disprove, h("span", "Run adversarial disprove (validate_llm), as in production")),
      h("label.bench-field", h("span", "Note"), note),
      cost,
      h("div.bench-row.bench-row--end",
        h("button.vf-btn.vf-btn--ghost", { type: "button", onclick: function () { d.close(); } }, "Cancel"),
        start)
    );
    d.appendChild(form);
    if (typeof d.showModal === "function") d.showModal();
    else d.setAttribute("open", "");
    note.focus();
  }

  B.views.scoreboard = { mount: mount };
})();
