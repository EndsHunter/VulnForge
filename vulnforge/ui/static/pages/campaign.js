/*
 * Campaign page (Campaign Flow) — mode id "hunts". Spec: docs/ui/REDESIGN.md → Campaign.
 * Contract: window.VFPages.campaign = { mount(el), render(snap), onShow(snap), onHide() }.
 *
 * This module owns the pipeline row, "Now running / Up next" and Activity.
 * The residual matrix, legend, bulk actions, cell inspector and the planner
 * drawer are painted by coverage.js (window.VulnForgeCoverage) into the same
 * page block, so existing re-queue / planner code is reused, not rewritten.
 */
(function () {
  "use strict";

  const ACTIVITY_LIMIT = 12;
  const LIVE_POLL_MS = 5000;
  /** Re-read the yield curve at most this often when nothing visible changed. */
  const YIELD_MAX_AGE_MS = 60000;

  let root = null;
  let activity = [];
  let activityLoadedFor = null;
  let livePoll = null;
  /** task id → /tasks/{id}/live payload */
  const liveInfo = new Map();
  /** campaign/status → yield (vulnforge.yield@1); advisory, never stops Ralph. */
  let yieldData = null;
  let yieldFor = null;
  let yieldAt = 0;
  let yieldBusy = false;

  const H = () => window.MissionOverviewHelpers || {};
  const $ = (sel, el) => (el || document).querySelector(sel);

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function apiBase() {
    const [t, r] = String(window.currentKey || "").split("/");
    return `/api/runs/${encodeURIComponent(t || "")}/${encodeURIComponent(r || "")}`;
  }

  function api(path) {
    if (typeof window.api === "function") return window.api(path);
    return fetch(path).then((res) => {
      if (!res.ok) throw new Error(res.statusText);
      return res.json();
    });
  }

  function isActive() {
    return window.VulnForgeModes?.activeMode?.() === "hunts";
  }

  // ---------- Pipeline row ----------

  const STATUS_TONE = {
    running: "run",
    queued: "wait",
    partial: "wait",
    waiting: "wait",
    done: "done",
    failed: "bad",
    off: "muted",
    optional: "muted",
    idle: "muted",
  };

  function renderPipeline(snap) {
    const el = $("#campaign-pipeline", root);
    if (!el || !H().buildCampaignPipeline) return;
    const stages = H().buildCampaignPipeline(snap);
    el.innerHTML = stages
      .map((s) => {
        const tone = STATUS_TONE[s.status] || "muted";
        const exit = s.exit
          ? `<span class="cmp-stage-exit"${s.exitLabel ? ` title="${esc(s.exitLabel)}"` : ""}>${esc(s.exit)}</span>`
          : "";
        return `<li>
          <button type="button" class="cmp-stage${s.status === "running" || s.status === "waiting" ? " is-live" : ""}" data-stage="${esc(s.id)}">
            <span class="cmp-stage-top">
              <span class="cmp-stage-name">${esc(s.label)}</span>
              <span class="cmp-stage-badge cmp-tone-${tone}">${esc(s.status)}</span>
            </span>
            <span class="cmp-stage-big"><b class="vf-mono">${esc(s.big)}</b> <span>${esc(s.bigLabel)}</span></span>
            <span class="cmp-stage-bar" aria-hidden="true"><span class="done" style="width:${s.donePct}%"></span><span class="wait" style="width:${s.waitPct}%"></span></span>
            <span class="cmp-stage-foot"><span>${esc(s.sub)}</span>${exit}</span>
          </button>
        </li>`;
      })
      .join("");
    el.querySelectorAll("[data-stage]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const s = stages.find((x) => x.id === btn.dataset.stage);
        const modes = window.VulnForgeModes;
        if (!s || !s.nav || !modes) return;
        if (s.nav.mode === "report") modes.goReport?.(s.nav.filter);
        else if (s.nav.mode !== "hunts") modes.setMode?.(s.nav.mode);
      });
    });
  }

  // ---------- Yield curve (advisory) ----------

  const UNFINISHED = new Set(["queued", "leased", "paused", "cancelled", "running"]);

  /** Changes when a task finishes or a finding moves, so the curve refetches then. */
  function yieldFingerprint(snap) {
    let done = 0;
    for (const t of snap.tasks || []) {
      const st = String(t.state || "").toLowerCase();
      if (st && !UNFINISHED.has(st)) done += 1;
    }
    const f = snap.findings_summary || {};
    return `${window.currentKey || ""}|${done}|${JSON.stringify(f)}`;
  }

  function openCellCount(snap) {
    const sum = window.VulnForgeCoverage?.summary?.();
    if (sum && Number.isFinite(Number(sum.open))) return { open: Number(sum.open), total: Number(sum.total) || 0 };
    if (snap?.coverage && H().summarizeResidualMatrix) {
      const m = H().summarizeResidualMatrix(snap.coverage, []);
      return { open: m.open, total: m.total };
    }
    return null;
  }

  function renderYield(snap) {
    const el = $("#campaign-yield", root);
    if (!el || !H().buildYieldView) return;
    if (yieldFor === null || !yieldData) {
      // Not read yet for this run, or an older server without the field:
      // say nothing rather than a wrong "no hunts".
      el.innerHTML = "";
      return;
    }
    const v = H().buildYieldView(yieldData, openCellCount(snap), { width: 120, height: 28 });
    let spark = "";
    if (v.state === "ok") {
      const n = v.hits.length;
      const slot = n > 1 ? (v.width - 8) / (n - 1) : v.width;
      const hits = v.hits
        .map(
          (h) =>
            `<rect class="cmp-yield-hit" x="${(h.x - slot / 2).toFixed(1)}" y="0" width="${slot.toFixed(1)}" height="${v.height}"><title>${esc(h.title)}</title></rect>`
        )
        .join("");
      const end = v.last ? `<circle class="cmp-yield-end" cx="${v.last.x.toFixed(1)}" cy="${v.last.y.toFixed(1)}" r="4"></circle>` : "";
      spark = `<svg class="cmp-yield-spark" viewBox="0 0 ${v.width} ${v.height}" width="${v.width}" height="${v.height}" role="img" aria-label="${esc(`Yield per window. ${v.sentence}`)}">
        <line class="cmp-yield-base" x1="4" y1="${v.height - 4}" x2="${v.width - 4}" y2="${v.height - 4}"></line>
        <path class="cmp-yield-line" d="${esc(v.path)}"></path>${end}${hits}
      </svg>`;
    }
    const rate = v.rateText ? ` <span class="cmp-yield-rate vf-mono">${esc(v.rateText)}</span>` : "";
    const open = v.openText
      ? `<button type="button" class="vf-chip cmp-yield-open" title="${esc(v.openTitle)}">${esc(v.openText)}</button>`
      : "";
    el.dataset.state = v.state;
    el.innerHTML = `<span class="cmp-yield-label" title="${esc(v.title)}">Yield</span>${spark}
      <span class="cmp-yield-text" title="${esc(v.title)}">${esc(v.sentence)}${rate}</span>${open}`;
    el.querySelector(".cmp-yield-open")?.addEventListener("click", () => {
      window.VulnForgeCoverage?.setFilter?.("residual");
      $("#cmp-matrix-title", root)?.scrollIntoView?.({ block: "start", behavior: "smooth" });
    });
  }

  async function loadYield(snap) {
    const key = yieldFingerprint(snap);
    const runKey = String(window.currentKey || "");
    if (yieldFor && !yieldFor.startsWith(runKey + "|")) {
      yieldData = null; // run switched
      yieldFor = null;
      renderYield(snap);
    }
    if (yieldBusy || (key === yieldFor && Date.now() - yieldAt < YIELD_MAX_AGE_MS)) return;
    yieldBusy = true;
    try {
      const status = await api(`${apiBase()}/campaign/status`);
      if (String(window.currentKey || "") !== runKey) return;
      yieldData = status && status.yield ? status.yield : null;
      yieldFor = key;
      yieldAt = Date.now();
      renderYield(window.__VF_last_snap || snap);
    } catch {
      /* advisory read; keep the last value */
    } finally {
      yieldBusy = false;
    }
  }

  // ---------- Now running / Up next ----------

  function renderWork(snap) {
    const el = $("#campaign-now", root);
    if (!el || !H().buildCampaignWork) return;
    const w = H().buildCampaignWork(snap.tasks || [], { limit: 5 });
    const runner = String(snap.runner?.state || "idle").toLowerCase();
    const running = w.running.length
      ? w.running
          .map((t) => {
            const live = liveInfo.get(String(t.id));
            const bits = [];
            if (live && Number(live.max_rounds)) bits.push(`turn ${live.round || 0} of ${live.max_rounds}`);
            if (live && live.tool) bits.push(`last tool <span class="vf-mono">${esc(live.tool)}</span>`);
            if (live && live.phase && live.phase !== "idle") bits.push(esc(live.phase));
            return `<li class="cmp-run-row">
              <span class="cmp-run-dot" aria-hidden="true"></span>
              <span class="cmp-run-main">
                <span><b>${esc(t.hunt ? "hunt" : t.kind)} #${esc(String(t.id))}</b> <span class="vf-mono">${esc(t.hunt ? t.label : "")}</span></span>
                ${bits.length ? `<span class="cmp-run-meta">${bits.join(" · ")}</span>` : ""}
              </span>
              <button type="button" class="vf-btn vf-btn--ghost cmp-run-open" data-tid="${esc(String(t.id))}">Watch</button>
            </li>`;
          })
          .join("")
      : `<li class="vf-empty">${
          runner === "running" ? "Ralph is running; nothing leased this second." : `Nothing running. Ralph is ${esc(runner)}.`
        }</li>`;
    const next = w.next.length
      ? w.next
          .map(
            (t) =>
              `<li><span class="vf-mono">${esc(t.hunt ? t.label : t.kind)}</span> <span class="vf-faint">#${esc(String(t.id))}${t.state === "paused" ? " · paused" : ""}</span></li>`
          )
          .join("")
      : `<li class="vf-empty">Queue is empty.</li>`;
    const more = w.queuedTotal > w.next.length ? `<p class="vf-faint cmp-more">+${w.queuedTotal - w.next.length} more in Tasks</p>` : "";
    el.innerHTML = `<ul class="cmp-run-list">${running}</ul>
      <h3 class="cmp-subhead">Up next <span class="vf-faint">${w.queuedTotal}</span></h3>
      <ol class="cmp-next-list">${next}</ol>${more}`;
    el.querySelectorAll(".cmp-run-open").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tid = Number(btn.dataset.tid);
        if (typeof window.openLiveTask === "function") window.openLiveTask(tid);
      });
    });
    syncLivePoll(w.running);
  }

  function syncLivePoll(running) {
    const ids = running.filter((t) => t.hunt).map((t) => String(t.id));
    for (const k of [...liveInfo.keys()]) if (!ids.includes(k)) liveInfo.delete(k);
    if (!ids.length || !isActive()) {
      stopLivePoll();
      return;
    }
    if (livePoll) return;
    const tick = async () => {
      const snap = window.__VF_last_snap;
      const w = snap && H().buildCampaignWork ? H().buildCampaignWork(snap.tasks || []) : { running: [] };
      const want = w.running.filter((t) => t.hunt).slice(0, 3);
      if (!want.length || !isActive()) {
        stopLivePoll();
        return;
      }
      let changed = false;
      for (const t of want) {
        try {
          const live = await api(`${apiBase()}/tasks/${encodeURIComponent(t.id)}/live`);
          const prev = liveInfo.get(String(t.id));
          if (!prev || prev.round !== live.round || prev.tool !== live.tool || prev.phase !== live.phase) changed = true;
          liveInfo.set(String(t.id), live);
        } catch {
          /* live endpoint is best-effort; keep the last value */
        }
      }
      if (changed && snap) renderWork(snap);
    };
    livePoll = setInterval(tick, LIVE_POLL_MS);
    tick();
  }

  function stopLivePoll() {
    if (livePoll) clearInterval(livePoll);
    livePoll = null;
  }

  // ---------- Activity ----------

  function relTime(ts) {
    const t = Date.parse(ts || "");
    if (!Number.isFinite(t)) return "";
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.round(s / 60)}m`;
    if (s < 86400) return `${Math.round(s / 3600)}h`;
    return `${Math.round(s / 86400)}d`;
  }

  const QUIET_EVENTS = new Set(["task_step", "heartbeat", "message", "session", "idle", "task_leased"]);

  const seenEvents = new Set();

  function eventKey(ev) {
    if (ev && ev._line != null) return `l${ev._line}`;
    return [ev?.ts, ev?.event, ev?.task_id, ev?.finding_id].join("|");
  }

  function pushEvents(list) {
    const describe = H().describeEvent;
    if (!describe) return;
    for (const ev of list || []) {
      const name = String(ev?.event || ev?.type || "");
      if (QUIET_EVENTS.has(name)) continue;
      const key = eventKey(ev);
      if (seenEvents.has(key)) continue;
      seenEvents.add(key);
      activity.unshift(describe(ev));
    }
    // Batches can arrive out of order (initial load vs live stream): newest first.
    activity.sort((a, b) => String(b.ts || "").localeCompare(String(a.ts || "")));
    activity = activity.slice(0, ACTIVITY_LIMIT);
  }

  function renderActivity() {
    const el = $("#campaign-activity", root);
    if (!el) return;
    el.innerHTML = activity.length
      ? activity
          .map(
            (a) =>
              `<li><span class="vf-mono cmp-act-ts" title="${esc(a.ts)}">${esc(relTime(a.ts))}</span><span class="cmp-act-text${a.tone ? ` cmp-tone-${esc(a.tone)}` : ""}">${esc(a.text)}</span></li>`
          )
          .join("")
      : `<li class="vf-empty">No activity yet.</li>`;
  }

  async function loadActivity(snap) {
    const key = String(window.currentKey || "");
    if (!key || activityLoadedFor === key) return;
    activityLoadedFor = key;
    const total = Number(snap?.event_count) || 0;
    const after = Math.max(0, total - 40);
    try {
      const data = await api(`${apiBase()}/events?after=${after}&limit=40`);
      pushEvents(data.events || []);
      renderActivity();
    } catch {
      activityLoadedFor = null;
    }
  }

  // ---------- Page lifecycle ----------

  function mount(el) {
    root = el;
  }

  function render(snap) {
    if (!root || !snap) return;
    renderPipeline(snap);
    renderYield(snap);
    loadYield(snap);
    renderWork(snap);
    renderActivity();
    loadActivity(snap);
  }

  window.VFPages = window.VFPages || {};
  window.VFPages.campaign = {
    mount,
    render,
    isActive,
    onShow(snap) {
      if (snap) render(snap);
    },
    onHide() {
      stopLivePoll();
      window.VulnForgeCoverage?.closePlanner?.();
    },
  };

  function boot() {
    const el = document.getElementById("page-campaign");
    if (el) mount(el);
    window.addEventListener("vf:snapshot", (ev) => render(ev.detail));
    window.addEventListener("vf:events", (ev) => {
      pushEvents(ev.detail || []);
      renderActivity();
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
