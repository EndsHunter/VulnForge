/**
 * Pure helpers for bench Results charts + version compare.
 * UMD/CommonJS — browser script tag and node --test.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.BenchResultsHelpers = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var DEFAULT_WIDTH = 640;
  var DEFAULT_HEIGHT = 180;
  var DEFAULT_PAD = 28;

  function asNumber(val, fallback) {
    var n = Number(val);
    return isFinite(n) ? n : fallback;
  }

  function formatScore(n, digits) {
    digits = digits == null ? 3 : digits;
    var v = Number(n);
    if (!isFinite(v)) return "—";
    return v.toFixed(digits);
  }

  function formatDelta(n, digits) {
    digits = digits == null ? 3 : digits;
    var v = Number(n);
    if (!isFinite(v)) return "—";
    var sign = v > 0 ? "+" : "";
    return sign + v.toFixed(digits);
  }

  function deltaTone(n) {
    var v = Number(n);
    if (!isFinite(v) || v === 0) return "zero";
    return v > 0 ? "pos" : "neg";
  }

  /**
   * Scatter: x = duration_s (speed), y = score (accuracy).
   * X domain [0, max(1, max duration)]. Y domain [0, max(1, max score)].
   */
  function scatterToDots(points, opts) {
    opts = opts || {};
    var width = asNumber(opts.width, 640);
    var height = asNumber(opts.height, 280);
    var padL = asNumber(opts.padLeft, 48);
    var padR = asNumber(opts.padRight, 16);
    var padT = asNumber(opts.padTop, 16);
    var padB = asNumber(opts.padBottom, 36);
    var rows = Array.isArray(points) ? points : [];
    var innerW = Math.max(1, width - padL - padR);
    var innerH = Math.max(1, height - padT - padB);
    if (!rows.length) {
      return {
        dots: [],
        empty: true,
        width: width,
        height: height,
        padL: padL,
        padR: padR,
        padT: padT,
        padB: padB,
        maxDuration: 1,
        maxScore: 1,
      };
    }
    var maxDuration = 1;
    var maxScore = 1;
    rows.forEach(function (p) {
      var dur = asNumber(p && p.duration_s, 0);
      var score = asNumber(p && (p.accuracy != null ? p.accuracy : p.score), 0);
      if (dur > maxDuration) maxDuration = dur;
      if (score > maxScore) maxScore = score;
    });
    var dots = rows.map(function (p) {
      var dur = asNumber(p && p.duration_s, 0);
      var score = asNumber(p && (p.accuracy != null ? p.accuracy : p.score), 0);
      var x = padL + (dur / maxDuration) * innerW;
      var y = padT + (1 - score / maxScore) * innerH;
      return {
        x: Math.round(x * 100) / 100,
        y: Math.round(y * 100) / 100,
        duration_s: dur,
        score: score,
        started_at: p && p.started_at ? String(p.started_at) : "",
        run_id: p && p.run_id ? String(p.run_id) : "",
        def_id: p && p.def_id ? String(p.def_id) : "",
        version: p && p.version != null ? p.version : null,
      };
    });
    var seen = {};
    dots.forEach(function (d) {
      var key = String(d.x) + "," + String(d.y);
      var n = seen[key] || 0;
      seen[key] = n + 1;
      if (n === 0) return;
      var ang = n * 0.85;
      var rad = Math.min(12, 3 + n * 1.5);
      d.x = Math.round((d.x + Math.cos(ang) * rad) * 100) / 100;
      d.y = Math.round((d.y + Math.sin(ang) * rad) * 100) / 100;
    });
    var xTicks = [];
    var yTicks = [];
    var steps = 2;
    for (var i = 0; i <= steps; i++) {
      var t = i / steps;
      xTicks.push({
        x: padL + t * innerW,
        label: formatScore(t * maxDuration, t * maxDuration >= 10 ? 0 : 1),
      });
      yTicks.push({
        y: padT + t * innerH,
        label: formatScore((1 - t) * maxScore, 1),
      });
    }
    return {
      dots: dots,
      empty: false,
      width: width,
      height: height,
      padL: padL,
      padR: padR,
      padT: padT,
      padB: padB,
      maxDuration: maxDuration,
      maxScore: maxScore,
      xTicks: xTicks,
      yTicks: yTicks,
    };
  }

  function gridXs(width, padL, padR, maxDuration, steps) {
    steps = steps || 2;
    var innerW = Math.max(1, width - padL - padR);
    var out = [];
    for (var i = 0; i <= steps; i++) {
      var t = i / steps;
      out.push({
        x: padL + t * innerW,
        label: formatScore(t * maxDuration, t * maxDuration >= 10 ? 0 : 1),
      });
    }
    return out;
  }

  /**
   * Map series points to an SVG polyline + dots (legacy time series).
   * Y domain is [0, max(1, max score)] so recall stays in the unit interval
   * unless a type score exceeds 1.
   */
  function seriesToPolyline(points, opts) {
    opts = opts || {};
    var width = asNumber(opts.width, DEFAULT_WIDTH);
    var height = asNumber(opts.height, DEFAULT_HEIGHT);
    var pad = asNumber(opts.pad, DEFAULT_PAD);
    var rows = Array.isArray(points) ? points : [];
    var innerW = Math.max(1, width - pad * 2);
    var innerH = Math.max(1, height - pad * 2);
    if (!rows.length) {
      return {
        points: "",
        dots: [],
        empty: true,
        width: width,
        height: height,
        pad: pad,
        maxScore: 1,
      };
    }
    var scores = rows.map(function (p) { return asNumber(p && p.score, 0); });
    var maxScore = 1;
    for (var i = 0; i < scores.length; i++) {
      if (scores[i] > maxScore) maxScore = scores[i];
    }
    var dots = rows.map(function (p, idx) {
      var score = asNumber(p && p.score, 0);
      var x = rows.length === 1
        ? pad + innerW / 2
        : pad + (idx / (rows.length - 1)) * innerW;
      var y = pad + (1 - score / maxScore) * innerH;
      return {
        x: Math.round(x * 100) / 100,
        y: Math.round(y * 100) / 100,
        score: score,
        started_at: p && p.started_at ? String(p.started_at) : "",
        run_id: p && p.run_id ? String(p.run_id) : "",
        version: p && p.version != null ? p.version : null,
      };
    });
    return {
      points: dots.map(function (d) { return d.x + "," + d.y; }).join(" "),
      dots: dots,
      empty: false,
      width: width,
      height: height,
      pad: pad,
      maxScore: maxScore,
    };
  }

  function gridYs(height, pad, steps, maxScore) {
    steps = steps || 2;
    maxScore = asNumber(maxScore, 1);
    var innerH = Math.max(1, height - pad * 2);
    var out = [];
    for (var i = 0; i <= steps; i++) {
      var t = i / steps;
      out.push({
        y: pad + t * innerH,
        label: formatScore((1 - t) * maxScore, 1),
      });
    }
    return out;
  }

  return {
    DEFAULT_WIDTH: DEFAULT_WIDTH,
    DEFAULT_HEIGHT: DEFAULT_HEIGHT,
    DEFAULT_PAD: DEFAULT_PAD,
    formatScore: formatScore,
    formatDelta: formatDelta,
    deltaTone: deltaTone,
    scatterToDots: scatterToDots,
    seriesToPolyline: seriesToPolyline,
    gridXs: gridXs,
    gridYs: gridYs,
  };
});
