/*
 * Benchmarks desk: boot, tiny API client, DOM builder, shared widgets.
 * Views register on window.VFBench.views.<name> = { mount(root, ctx) }.
 * body[data-bench-view] picks the view (server route decides).
 */
(function () {
  "use strict";

  var H = window.VFBenchHelpers;

  function api(path, opts) {
    var o = opts || {};
    var init = { method: o.method || "GET", headers: {} };
    if (o.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(o.body);
    }
    return fetch(path, init).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) {
          var d = j && j.detail;
          var msg = (d && (d.error || d)) || (j && j.error) || ("HTTP " + r.status);
          var err = new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
          err.status = r.status;
          err.body = j;
          throw err;
        }
        return j;
      });
    });
  }

  /** h("div.cls", {attrs}, children…). Strings become text nodes. */
  function h(sel, attrs) {
    var parts = String(sel).split(".");
    var el = document.createElement(parts[0] || "div");
    if (parts.length > 1) el.className = parts.slice(1).join(" ");
    var kids = Array.prototype.slice.call(arguments, 2);
    if (attrs && (typeof attrs !== "object" || attrs.nodeType || Array.isArray(attrs))) {
      kids.unshift(attrs);
      attrs = null;
    }
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "class") el.className = (el.className ? el.className + " " : "") + v;
        else if (k.slice(0, 2) === "on" && typeof v === "function") el.addEventListener(k.slice(2), v);
        else if (k === "text") el.textContent = v;
        else el.setAttribute(k, v === true ? "" : String(v));
      });
    }
    (function add(list) {
      list.forEach(function (c) {
        if (c === null || c === undefined || c === false) return;
        if (Array.isArray(c)) add(c);
        else el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
      });
    })(kids);
    return el;
  }

  function toast(msg, tone) {
    var t = document.getElementById("toast");
    if (!t) return;
    t.textContent = msg;
    t.setAttribute("role", "status");
    t.className = "toast show" + (tone === "bad" ? " err" : "");
    t.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.className = "toast"; t.hidden = true; }, 4200);
  }

  function pill(text, cls) {
    return h("span.vf-pill", { class: cls || "" }, text);
  }

  /** Status pill; pass {suite, tier} so directed runs read finished / hit / miss. */
  function statusPill(status, ctx) {
    var v = H.statusView(status, ctx);
    return pill(v.text, v.cls);
  }

  function tierPill(tier) {
    return h("span.vf-pill.bench-tier", { "data-tier": tier, title: H.tierCaveat(tier) }, H.tierLabel(tier));
  }

  /** Caveat line printed next to every set of numbers. */
  function caveat(tier) {
    var text = H.tierCaveat(tier);
    return text ? h("p.bench-caveat", { "data-tier": tier }, text) : null;
  }

  /** One metric tile: label, value, optional delta and spread. */
  function metricTile(spec, value, opts) {
    var o = opts || {};
    var delta = o.delta !== undefined ? H.fmtDelta(spec.key, o.delta) : null;
    return h(
      "div.bench-metric",
      { title: spec.note, "data-metric": spec.key },
      h("div.bench-metric-label", spec.label, h("span.vf-faint", " " + spec.sub)),
      h("div.bench-metric-value.vf-mono", o.text || H.fmtMetric(spec.key, value)),
      o.range ? h("div.bench-metric-range.vf-mono", { title: "min–max across repeats" }, o.range) : null,
      delta ? h("div.bench-delta.vf-mono", { "data-tone": delta.tone }, delta.text + (o.deltaLabel ? " " + o.deltaLabel : "")) : null
    );
  }

  function svgEl(name, attrs) {
    var el = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    return el;
  }

  /** Recall trend sparkline (oldest → newest). */
  function sparkline(points, opts) {
    var o = opts || {};
    var w = o.width || 160;
    var hgt = o.height || 36;
    var g = H.trendGeometry(points, { width: w, height: hgt, key: o.key || "recall" });
    var svg = svgEl("svg", { viewBox: "0 0 " + w + " " + hgt, class: "bench-spark", role: "img",
      "aria-label": g.empty ? "No runs yet" : "Recall over the last " + g.dots.length + " runs" });
    svg.appendChild(svgEl("line", { x1: 0, x2: w, y1: hgt - 3, y2: hgt - 3, class: "bench-spark-base" }));
    if (!g.empty) {
      if (g.dots.length > 1) svg.appendChild(svgEl("polyline", { points: g.points, class: "bench-spark-line" }));
      g.dots.forEach(function (d, i) {
        var c = svgEl("circle", { cx: d.x, cy: d.y, r: i === g.dots.length - 1 ? 3 : 2, class: "bench-spark-dot" });
        var t = svgEl("title", {});
        var p = (points || []).filter(function (x) { return x.id === d.id; })[0] || {};
        t.textContent = H.fmtPct(d.value) + " · " + (p.model || "?") + " · " + (p.git_sha || "");
        c.appendChild(t);
        svg.appendChild(c);
      });
    }
    return svg;
  }

  function runHref(id) {
    return "/benchmarks/runs/" + encodeURIComponent(id);
  }

  function compareHref(a, b) {
    return "/benchmarks/compare?a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b);
  }

  function stopRun(id) {
    if (!window.confirm("Stop this live run? Ralph is stopped and the run is marked cancelled.")) {
      return Promise.resolve(null);
    }
    return api("/api/benchmarks/runs/" + encodeURIComponent(id) + "/stop", { method: "POST" })
      .then(function (j) { toast("Stopped " + id); return j; })
      .catch(function (e) { toast("Stop failed: " + e.message, "bad"); });
  }

  function pinBaseline(id) {
    return api("/api/benchmarks/runs/" + encodeURIComponent(id) + "/baseline", { method: "POST" })
      .then(function (j) { toast("Pinned " + id + " as baseline for " + j.key); return j; })
      .catch(function (e) { toast("Pin failed: " + e.message, "bad"); throw e; });
  }

  window.VFBench = {
    views: {},
    api: api,
    h: h,
    toast: toast,
    pill: pill,
    statusPill: statusPill,
    tierPill: tierPill,
    caveat: caveat,
    metricTile: metricTile,
    sparkline: sparkline,
    runHref: runHref,
    compareHref: compareHref,
    stopRun: stopRun,
    pinBaseline: pinBaseline
  };

  function boot() {
    var root = document.getElementById("bench-root");
    var name = document.body.getAttribute("data-bench-view") || "scoreboard";
    var view = window.VFBench.views[name];
    if (!root || !view) return;
    root.textContent = "";
    view.mount(root, {
      runId: root.getAttribute("data-run-id") || "",
      a: root.getAttribute("data-compare-a") || "",
      b: root.getAttribute("data-compare-b") || ""
    });
  }

  // View modules load after this file; boot once everything is parsed.
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else setTimeout(boot, 0);
})();
