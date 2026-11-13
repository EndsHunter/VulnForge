/*
 * Benchmarks desk: pure helpers (formatting, metric deltas, flip groups,
 * per-case rows, trend geometry). No DOM. UMD so `node --test` can load them.
 * Spec: issue #204 design comment. Honesty: L0 and directed numbers are
 * labelled; unmatched ≠ false positive; nothing here is "confirmed".
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.VFBenchHelpers = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /** Headline metrics in display order. `better` drives delta tone. */
  var METRICS = [
    { key: "recall", label: "Recall", sub: "gated", kind: "pct", better: "up",
      note: "Oracle hits from findings that passed the gates (needs_human)." },
    { key: "recall_raw", label: "Raw recall", sub: "any state", kind: "pct", better: "up",
      note: "Hits from findings in any state, including gate rejects." },
    { key: "unmatched_per_target", label: "Unmatched", sub: "per target", kind: "num", better: "down",
      note: "Gated findings matching no oracle. Not proven false positives: real-OSS oracles are incomplete." },
    { key: "tokens_per_hit", label: "Tokens", sub: "per oracle hit", kind: "tokens", better: "down",
      note: "All LLM tokens divided by gated oracle hits. Oracle-matched, never human-confirmed." },
    { key: "wall_s", label: "Wall time", sub: "sum of cases", kind: "dur", better: "down",
      note: "Sum of per-case wall time." }
  ];

  var TIER_LABELS = { l0: "L0 fixture check", directed: "Directed" };
  var TIER_CAVEATS = {
    l0: "Mechanical. No LLM ran. Fixtures and scorers line up; says nothing about model quality.",
    directed: "Hunts were pointed at the oracle file and class: recall when told where to look."
  };

  var FP_LABELS = {
    git_sha: "Commit",
    git_dirty: "Uncommitted changes",
    model: "Model",
    endpoint_host: "Endpoint",
    api_mode: "API mode",
    prompts_hash: "System prompts",
    hunt_profiles_hash: "Hunt profiles",
    tools_hash: "Agent tools",
    validate_llm: "Disprove (validate_llm)"
  };

  function isNum(v) {
    return typeof v === "number" && Number.isFinite(v);
  }

  function metricSpec(key) {
    for (var i = 0; i < METRICS.length; i++) if (METRICS[i].key === key) return METRICS[i];
    return null;
  }

  function fmtPct(v) {
    return isNum(v) ? (Math.round(v * 1000) / 10).toFixed(1) + "%" : "–";
  }

  function fmtTokens(v) {
    if (!isNum(v)) return "–";
    var a = Math.abs(v);
    if (a >= 1e6) return (v / 1e6).toFixed(a >= 1e7 ? 0 : 1) + "M";
    if (a >= 1e3) return (v / 1e3).toFixed(a >= 1e4 ? 0 : 1) + "k";
    return String(Math.round(v));
  }

  function fmtDuration(s) {
    if (!isNum(s)) return "–";
    var t = Math.round(Math.abs(s));
    var sign = s < 0 ? "-" : "";
    if (t < 60) return sign + t + "s";
    var m = Math.floor(t / 60);
    if (m < 60) return sign + m + "m " + (t % 60) + "s";
    return sign + Math.floor(m / 60) + "h " + (m % 60) + "m";
  }

  function fmtNum(v, digits) {
    if (!isNum(v)) return "–";
    var d = digits == null ? 2 : digits;
    return Number(v.toFixed(d)).toString();
  }

  /** Format a metric value by its kind. */
  function fmtMetric(key, v) {
    var spec = metricSpec(key);
    var kind = spec ? spec.kind : "num";
    if (kind === "pct") return fmtPct(v);
    if (kind === "tokens") return fmtTokens(v);
    if (kind === "dur") return fmtDuration(v);
    return fmtNum(v);
  }

  /** Delta for a metric: text with sign + tone good/bad/flat/none. */
  function fmtDelta(key, d) {
    if (!isNum(d)) return { text: "–", tone: "none" };
    var spec = metricSpec(key) || { kind: "num", better: "up" };
    var eps = spec.kind === "pct" ? 0.0005 : 0.005;
    if (Math.abs(d) < eps) return { text: "±0", tone: "flat" };
    var sign = d > 0 ? "+" : "−";
    var abs = Math.abs(d);
    var body;
    if (spec.kind === "pct") body = (Math.round(abs * 1000) / 10).toFixed(1) + " pt";
    else if (spec.kind === "tokens") body = fmtTokens(abs);
    else if (spec.kind === "dur") body = fmtDuration(abs);
    else body = fmtNum(abs);
    var improved = spec.better === "down" ? d < 0 : d > 0;
    return { text: sign + body, tone: improved ? "good" : "bad" };
  }

  /** "62.5% (50.0–75.0%)" when there is a spread over >1 repeat. */
  function fmtSpread(key, spread, nRepeats) {
    if (!spread || !isNum(spread.mean)) return fmtMetric(key, null);
    var main = fmtMetric(key, spread.mean);
    if (!(nRepeats > 1) || spread.min === spread.max) return main;
    return main + " (" + fmtMetric(key, spread.min) + "–" + fmtMetric(key, spread.max) + ")";
  }

  /** "62.5%–68.8%" when repeats disagree, else "". */
  function fmtRange(key, spread, nRepeats) {
    if (!spread || !(nRepeats > 1) || !isNum(spread.min) || spread.min === spread.max) return "";
    return fmtMetric(key, spread.min) + "–" + fmtMetric(key, spread.max);
  }

  /**
   * Pill text + class for a run. Directed suite runs and cases are not
   * pass/fail ("recall > 0" is not a quality bar): suites read "finished",
   * cases read "hit" / "miss". L0 keeps passed / failed.
   */
  function statusView(status, ctx) {
    var c = ctx || {};
    var s = String(status || "");
    if (c.tier === "directed" && (s === "passed" || s === "failed")) {
      if (c.suite) return { text: "finished", cls: "vf-pill--candidate" };
      return s === "passed" ? { text: "hit", cls: "vf-pill--confirmed" } : { text: "miss", cls: "vf-pill--rejected" };
    }
    return { text: s || "?", cls: statusPill(s) };
  }

  function tierLabel(t) {
    return TIER_LABELS[t] || String(t || "?");
  }

  function tierCaveat(t) {
    return TIER_CAVEATS[t] || "";
  }

  /** shell.css pill modifier for a run status. */
  function statusPill(status) {
    var s = String(status || "");
    if (s === "passed") return "vf-pill--confirmed";
    if (s === "running" || s === "queued") return "vf-pill--review";
    if (s === "failed" || s === "error") return "bench-pill--fail";
    return "vf-pill--rejected";
  }

  function shortSha(s) {
    return s ? String(s).slice(0, 8) : "";
  }

  function fpValue(key, v) {
    if (v === undefined || v === null || v === "") return "–";
    if (typeof v === "boolean") {
      if (key === "git_dirty") return v ? "yes" : "no";
      return v ? "on" : "off";
    }
    if (key === "git_sha") return shortSha(v);
    return String(v);
  }

  /** Fingerprint as [{key,label,value}] in a fixed order. */
  function fingerprintRows(fp) {
    var f = fp || {};
    return Object.keys(FP_LABELS).map(function (k) {
      return { key: k, label: FP_LABELS[k], value: fpValue(k, f[k]) };
    });
  }

  /** Server fingerprint_diff rows → labelled text rows. */
  function fingerprintDiffRows(diff) {
    return (diff || []).map(function (d) {
      return { key: d.key, label: FP_LABELS[d.key] || d.key, a: fpValue(d.key, d.a), b: fpValue(d.key, d.b) };
    });
  }

  /** Split server flips into regression / gain / unchanged. */
  function flipGroups(flips) {
    var out = { regression: [], gain: [], unchanged: [] };
    (flips || []).forEach(function (f) {
      if (f.change === "regression") out.regression.push(f);
      else if (f.change === "gain") out.gain.push(f);
      else out.unchanged.push(f);
    });
    return out;
  }

  /**
   * Suite members (one row per case × repeat) → one row per case.
   * hit_rate = gated hits / (oracles × scored repeats).
   */
  function caseRows(members) {
    var by = {};
    var order = [];
    (members || []).forEach(function (m) {
      var id = String(m.def_id || "?");
      if (!by[id]) {
        by[id] = { def_id: id, repeats: 0, scored: 0, hits: 0, oracles: 0, unmatched: 0,
          tokens: null, wall_s: null, statuses: [], run_ids: [], errors: [] };
        order.push(id);
      }
      var r = by[id];
      r.repeats += 1;
      r.statuses.push(m.status);
      if (m.run_id) r.run_ids.push(m.run_id);
      if (m.error) r.errors.push(m.error);
      if (m.status === "passed" || m.status === "failed") {
        r.scored += 1;
        r.hits += Number(m.hit_count) || 0;
        r.oracles += Number(m.oracle_count) || 0;
        r.unmatched += Number(m.unmatched) || 0;
        if (isNum(m.tokens_total)) r.tokens = (r.tokens || 0) + m.tokens_total;
        if (isNum(m.wall_s)) r.wall_s = (r.wall_s || 0) + m.wall_s;
      }
    });
    return order.map(function (id) {
      var r = by[id];
      r.hit_rate = r.oracles ? r.hits / r.oracles : null;
      r.status = worstStatus(r.statuses);
      return r;
    });
  }

  var STATUS_RANK = { error: 0, cancelled: 1, running: 2, queued: 3, failed: 4, passed: 5 };

  function worstStatus(list) {
    var best = null;
    (list || []).forEach(function (s) {
      if (best === null || (STATUS_RANK[s] != null ? STATUS_RANK[s] : 9) < (STATUS_RANK[best] != null ? STATUS_RANK[best] : 9)) best = s;
    });
    return best || "queued";
  }

  /**
   * Pill for a directed case row (folded repeats): hit / partial / miss from
   * the gated hits; error, running and cancelled pass through.
   */
  function caseVerdict(row) {
    var r = row || {};
    var settled = (r.statuses || []).every(function (s) { return s === "passed" || s === "failed"; });
    if (!settled || !r.scored) return statusView(r.status, {});
    if (!r.oracles) return { text: "no oracle", cls: "vf-pill--rejected" };
    if (r.hits >= r.oracles) return { text: "hit", cls: "vf-pill--confirmed" };
    if (r.hits > 0) return { text: "partial", cls: "vf-pill--review" };
    return { text: "miss", cls: "vf-pill--rejected" };
  }

  /** Sort case rows: errors, then misses, then by id. */
  function sortCaseRows(rows) {
    return (rows || []).slice().sort(function (a, b) {
      var ea = a.status === "error" ? 0 : 1;
      var eb = b.status === "error" ? 0 : 1;
      if (ea !== eb) return ea - eb;
      var ha = isNum(a.hit_rate) ? a.hit_rate : 2;
      var hb = isNum(b.hit_rate) ? b.hit_rate : 2;
      if (ha !== hb) return ha - hb;
      return a.def_id < b.def_id ? -1 : a.def_id > b.def_id ? 1 : 0;
    });
  }

  /**
   * Trend polyline for recall over runs (oldest → newest).
   * Returns {points:"x,y …", dots:[{x,y,id,value}], empty}.
   */
  function trendGeometry(points, opts) {
    var o = opts || {};
    var w = o.width || 160;
    var h = o.height || 36;
    var pad = o.pad == null ? 3 : o.pad;
    var key = o.key || "recall";
    var rows = (points || []).filter(function (p) { return p && isNum(p[key]); });
    if (!rows.length) return { points: "", dots: [], empty: true };
    var max = o.max != null ? o.max : 1;
    var min = o.min != null ? o.min : 0;
    var span = max - min || 1;
    var step = rows.length > 1 ? (w - 2 * pad) / (rows.length - 1) : 0;
    var dots = rows.map(function (p, i) {
      var v = Math.max(min, Math.min(max, p[key]));
      var x = rows.length > 1 ? pad + i * step : w / 2;
      var y = h - pad - ((v - min) / span) * (h - 2 * pad);
      return { x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10, id: p.id, value: p[key] };
    });
    return {
      points: dots.map(function (d) { return d.x + "," + d.y; }).join(" "),
      dots: dots,
      empty: false
    };
  }

  /** Live progress line for an active run. */
  function progressText(run) {
    var m = (run && run.metrics) || {};
    var live = m.live || {};
    if (m.suite) {
      var done = live.done != null ? live.done : (m.passed_count || 0) + (m.failed_count || 0) + (m.error_count || 0);
      var total = live.total != null ? live.total : m.count || (m.member_run_ids || []).length;
      return done + " / " + total + " case runs";
    }
    return live.phase ? "phase: " + live.phase : String((run && run.status) || "");
  }

  /** Group library defs by suite, in suite order. */
  function groupBySuite(defs, suiteOrder) {
    var order = suiteOrder || ["realworld", "synthetic", "fixtures"];
    var groups = {};
    (defs || []).forEach(function (d) {
      var s = d.suite || "fixtures";
      (groups[s] = groups[s] || []).push(d);
    });
    var keys = order.filter(function (k) { return groups[k]; });
    Object.keys(groups).forEach(function (k) { if (keys.indexOf(k) < 0) keys.push(k); });
    return keys.map(function (k) {
      return { suite: k, defs: groups[k].slice().sort(function (a, b) { return a.id < b.id ? -1 : 1; }) };
    });
  }

  /** Short relative age: "3m ago", "2h ago", "4d ago". */
  function shortAge(iso, nowMs) {
    var t = Date.parse(iso || "");
    if (!Number.isFinite(t)) return "";
    var s = Math.max(0, Math.round(((nowMs == null ? Date.now() : nowMs) - t) / 1000));
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  return {
    METRICS: METRICS,
    caseRows: caseRows,
    caseVerdict: caseVerdict,
    fingerprintDiffRows: fingerprintDiffRows,
    fingerprintRows: fingerprintRows,
    flipGroups: flipGroups,
    fmtDelta: fmtDelta,
    fmtDuration: fmtDuration,
    fmtMetric: fmtMetric,
    fmtPct: fmtPct,
    fmtRange: fmtRange,
    fmtSpread: fmtSpread,
    fmtTokens: fmtTokens,
    groupBySuite: groupBySuite,
    metricSpec: metricSpec,
    progressText: progressText,
    shortAge: shortAge,
    shortSha: shortSha,
    sortCaseRows: sortCaseRows,
    statusPill: statusPill,
    statusView: statusView,
    tierCaveat: tierCaveat,
    tierLabel: tierLabel,
    trendGeometry: trendGeometry,
    worstStatus: worstStatus
  };
});
