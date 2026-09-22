/**
 * Live agent-team map: who holds each harness lease, plus queued and paused work.
 * UMD — browser script tag and node --test.
 *
 * This is a worker/lease map. It does not classify Recon / Hunt / Validate
 * and it does not describe Ralph start/pause.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.AgentTeamMap = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const LIST_LIMIT = 8;

  const STATE_WORD = {
    leased: "Running",
    running: "Running",
    queued: "Queued",
    paused: "Paused",
  };

  const ACTIONS = {
    live: {
      label: "Live",
      confirm: false,
      cls: "btn btn-sm btn-primary",
      title: "Open the live tool-round pane",
    },
    pause: {
      label: "Pause",
      confirm: true,
      cls: "btn btn-sm",
      title: "Park this task. A running agent stops so the next queued task can start.",
    },
    halt: {
      label: "Halt",
      confirm: true,
      cls: "btn btn-sm btn-bad",
      title: "Permanently cancel this task. A running agent stops and the task does not resume.",
    },
    resume: {
      label: "Resume",
      confirm: false,
      cls: "btn btn-sm btn-primary",
      title: "Return this paused task to the queue (run next).",
    },
    note: {
      label: "Send note",
      confirm: true,
      cls: "btn btn-sm",
      title: "Queue an operator note for the next tool round. Does not confirm findings.",
    },
  };

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function positiveInt(value) {
    const n = Number(value);
    if (!Number.isFinite(n) || n < 1) return null;
    return Math.floor(n);
  }

  /** Lease cap from run.max_leases_parallel, then the flat config, then 1. */
  function leaseCap(snap) {
    const run = (snap && snap.run) || {};
    const cfg = (snap && snap.config) || {};
    const nested = (cfg.run && cfg.run.max_leases_parallel) || null;
    return (
      positiveInt(run.max_leases_parallel) ||
      positiveInt(nested) ||
      positiveInt(cfg.max_leases_parallel) ||
      1
    );
  }

  /**
   * Parse harness lease owner ``vf-{pid}-{token}``.
   * Other owners stay visible as their raw string.
   */
  function parseLeaseOwner(owner) {
    const raw = String(owner || "").trim();
    if (!raw) {
      return { raw: "", pid: null, token: "", label: "Unnamed holder" };
    }
    const match = /^vf-(\d+)-([0-9a-fA-F]+)$/.exec(raw);
    if (!match) {
      return { raw, pid: null, token: "", label: raw };
    }
    const pid = Number(match[1]);
    return {
      raw,
      pid: pid > 0 ? pid : null,
      token: match[2],
      label: pid > 0 ? "worker " + pid : raw,
    };
  }

  function firstPath(payload) {
    const p = payload || {};
    if (typeof p.path === "string" && p.path.trim()) return p.path.trim();
    const sel = p.selection;
    if (sel && typeof sel.path === "string" && sel.path.trim()) return sel.path.trim();
    if (Array.isArray(p.path_hints) && p.path_hints.length) {
      const hint = String(p.path_hints[0] || "").trim();
      if (hint) return hint;
    }
    return "";
  }

  /** Short work label from the task payload. Not a pipeline lane. */
  function workLabel(task) {
    const p = (task && task.payload) || {};
    const area = String(p.area || "").trim();
    const cls = String(p.class || p.weakness_class || p.attack_class || "").trim();
    const agent = String(p.agent || "").trim();
    const path = firstPath(p);
    const bits = [];
    if (area && cls) bits.push(area + " × " + cls);
    else if (cls) bits.push(cls);
    else if (area) bits.push(area);
    else if (agent) bits.push(agent);
    if (path) bits.push(path);
    if (bits.length) return bits.join(" · ");
    return String((task && task.kind) || "task");
  }

  function steerFor(state) {
    const s = String(state || "").toLowerCase();
    if (s === "leased" || s === "running") return ["live", "pause", "halt", "note"];
    if (s === "queued") return ["pause", "halt"];
    if (s === "paused") return ["resume", "halt"];
    return [];
  }

  function stateWord(state) {
    const s = String(state || "").toLowerCase();
    return STATE_WORD[s] || s || "unknown";
  }

  function badgeClass(state) {
    const s = String(state || "").toLowerCase();
    if (s === "running") return "leased";
    return s || "idle";
  }

  function livePidSet(snap) {
    const pids = (snap && snap.runner && snap.runner.pids) || [];
    const out = new Set();
    for (const pid of pids) {
      const n = Number(pid);
      if (Number.isFinite(n) && n > 0) out.add(n);
    }
    return out;
  }

  function runnerHasWorkers(snap, livePids) {
    const runner = (snap && snap.runner) || {};
    if (runner.alive) return true;
    if (livePids.size) return true;
    const state = String(runner.state || "").toLowerCase();
    return state === "running" || state === "pausing";
  }

  function presenceFor(owner, livePids, workersKnown) {
    if (!owner || owner.pid == null || !workersKnown) return "";
    return livePids.has(owner.pid) ? "alive" : "not in runner";
  }

  function asRow(task, livePids, workersKnown) {
    const state = String((task && task.state) || "").toLowerCase();
    const owner = parseLeaseOwner(task && task.lease_owner);
    return {
      id: task && task.id,
      kind: String((task && task.kind) || ""),
      state,
      label: workLabel(task),
      owner,
      presence: presenceFor(owner, livePids, workersKnown),
      actions: steerFor(state),
    };
  }

  function clip(rows) {
    const list = rows || [];
    return {
      shown: list.slice(0, LIST_LIMIT),
      hidden: Math.max(0, list.length - LIST_LIMIT),
      total: list.length,
    };
  }

  /**
   * View model for the agent-team map.
   * Slots are the lease cap. Leased tasks fill slots in id order.
   * Extra leased rows (beyond the cap) stay visible as overflow.
   */
  function buildAgentTeamMap(snap) {
    const tasks = Array.isArray(snap && snap.tasks) ? snap.tasks : [];
    const cap = leaseCap(snap);
    const livePids = livePidSet(snap);
    const workersKnown = runnerHasWorkers(snap, livePids);
    const leased = [];
    const queued = [];
    const paused = [];
    for (const task of tasks) {
      const state = String((task && task.state) || "").toLowerCase();
      if (state === "leased" || state === "running") leased.push(task);
      else if (state === "queued") queued.push(task);
      else if (state === "paused") paused.push(task);
    }
    leased.sort((a, b) => (Number(a.id) || 0) - (Number(b.id) || 0));
    queued.sort(
      (a, b) =>
        (Number(a.priority) || 100) - (Number(b.priority) || 100) ||
        (Number(a.id) || 0) - (Number(b.id) || 0)
    );
    paused.sort((a, b) => (Number(a.id) || 0) - (Number(b.id) || 0));

    const leasedRows = leased.map((task) => asRow(task, livePids, workersKnown));
    const slots = [];
    for (let i = 0; i < cap; i++) {
      const held = leasedRows[i] || null;
      slots.push({
        index: i + 1,
        status: held ? "held" : "open",
        task: held,
      });
    }
    return {
      cap,
      held: Math.min(leasedRows.length, cap),
      leasedCount: leasedRows.length,
      slots,
      overflow: leasedRows.slice(cap),
      queued: clip(queued.map((task) => asRow(task, livePids, workersKnown))),
      paused: clip(paused.map((task) => asRow(task, livePids, workersKnown))),
    };
  }

  function actionButtons(actions, taskId) {
    return (actions || [])
      .filter((name) => name !== "note" && ACTIONS[name])
      .map((name) => {
        const meta = ACTIONS[name];
        return `<button type="button" class="${meta.cls}" data-agent-team-action="${esc(
          name
        )}" data-tid="${esc(taskId)}" data-confirm="${meta.confirm ? "1" : "0"}" title="${esc(
          meta.title
        )}">${esc(meta.label)}</button>`;
      })
      .join("");
  }

  function noteRow(task) {
    if (!task || task.actions.indexOf("note") < 0) return "";
    const meta = ACTIONS.note;
    return `<label class="agent-team-note">
      <span class="visually-hidden">Operator note for task #${esc(task.id)}</span>
      <textarea data-agent-team-note="${esc(task.id)}" rows="2" maxlength="2000" placeholder="Note for the next round. Does not confirm findings."></textarea>
      <button type="button" class="${meta.cls}" data-agent-team-action="note" data-tid="${esc(
        task.id
      )}" data-confirm="1" title="${esc(meta.title)}">${esc(meta.label)}</button>
    </label>`;
  }

  function workLine(task) {
    return `<span class="mono">#${esc(task.id)}</span>
      <strong>${esc(task.kind || "task")}</strong>
      <span class="badge ${esc(badgeClass(task.state))}">${esc(stateWord(task.state))}</span>
      <span class="agent-team-label">${esc(task.label)}</span>`;
  }

  function slotHtml(slot) {
    if (!slot.task) {
      return `<article class="agent-team-slot is-open" data-lease-slot="${esc(
        slot.index
      )}" data-lease-status="open" role="listitem">
        <header class="agent-team-slot-head">
          <span class="agent-team-slot-index">Lease ${esc(slot.index)}</span>
          <span class="agent-team-holder">Open</span>
        </header>
        <p class="agent-team-open">No task holds this lease.</p>
      </article>`;
    }
    const task = slot.task;
    const owner = task.owner || {};
    const presence = task.presence
      ? `<span class="agent-team-presence">${esc(task.presence)}</span>`
      : "";
    const ownerLine = owner.raw
      ? `<p class="agent-team-owner mono" title="${esc(owner.raw)}">${esc(owner.raw)}</p>`
      : "";
    return `<article class="agent-team-slot is-held" data-lease-slot="${esc(
      slot.index
    )}" data-lease-status="held" data-task-id="${esc(task.id)}" role="listitem">
      <header class="agent-team-slot-head">
        <span class="agent-team-slot-index">Lease ${esc(slot.index)}</span>
        <span class="agent-team-holder">${esc(owner.label || "Unnamed holder")}</span>
        ${presence}
      </header>
      ${ownerLine}
      <p class="agent-team-work">${workLine(task)}</p>
      <p class="agent-team-now" data-agent-team-live="${esc(task.id)}">Waiting for the tool round.</p>
      <div class="task-prio-actions">${actionButtons(task.actions, task.id)}</div>
      ${noteRow(task)}
    </article>`;
  }

  function listSection(title, aria, block) {
    const rows = (block && block.shown) || [];
    const body = rows.length
      ? rows
          .map(
            (task) => `<div class="agent-team-row" data-task-id="${esc(task.id)}">
          <div class="agent-team-row-main">${workLine(task)}</div>
          <div class="task-prio-actions">${actionButtons(task.actions, task.id)}</div>
        </div>`
          )
          .join("")
      : `<p class="agent-team-empty controls-hint">None.</p>`;
    const more =
      block && block.hidden
        ? `<p class="controls-hint">${esc(block.hidden)} more in the task table.</p>`
        : "";
    const count = block ? block.total : 0;
    return `<section class="agent-team-list" aria-label="${esc(aria)}">
      <h3 class="agent-team-list-title">${esc(title)} <span class="mono">${esc(count)}</span></h3>
      ${body}
      ${more}
    </section>`;
  }

  function overflowSection(rows) {
    if (!rows || !rows.length) return "";
    const body = rows
      .map(
        (task) => `<div class="agent-team-row" data-task-id="${esc(task.id)}">
        <div class="agent-team-row-main">${workLine(task)}</div>
        <p class="agent-team-owner mono">${esc((task.owner && task.owner.label) || "")}</p>
        <div class="task-prio-actions">${actionButtons(task.actions, task.id)}</div>
        ${noteRow(task)}
      </div>`
      )
      .join("");
    return `<section class="agent-team-overflow" aria-label="Leased beyond the cap">
      <h3 class="agent-team-list-title">Leased beyond the cap <span class="mono">${esc(
        rows.length
      )}</span></h3>
      ${body}
    </section>`;
  }

  function renderAgentTeamHtml(model) {
    const map = model || { slots: [], queued: { shown: [], total: 0 }, paused: { shown: [], total: 0 } };
    const slots = (map.slots || []).map(slotHtml).join("");
    return `<div class="agent-team-slots" role="list" aria-label="Lease slots">${
      slots || `<p class="agent-team-empty">No lease slots.</p>`
    }</div>
    ${overflowSection(map.overflow)}
    <div class="agent-team-lists">
      ${listSection("Queued", "Queued work", map.queued)}
      ${listSection("Paused", "Paused work", map.paused)}
    </div>`;
  }

  return {
    LIST_LIMIT,
    leaseCap,
    parseLeaseOwner,
    workLabel,
    steerFor,
    buildAgentTeamMap,
    renderAgentTeamHtml,
  };
});
