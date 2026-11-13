/*
 * Dev workbench pure helpers (issue #203). UMD so node --test can load them.
 * No DOM access here: routing, filters, provenance labels, line diff, tool
 * chip models, payload builders and the Tool lab apply gate.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.DevHelpers = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /* ---------- Routing ---------- */

  const SECTIONS = ["skills", "recon", "tools", "lab"];

  function safeDecode(s) {
    try {
      return decodeURIComponent(s);
    } catch (_) {
      return s;
    }
  }

  /**
   * Parse a /dev hash. Legacy aliases stay working:
   *  #hunt[/id]       → skills  (Campaign matrix links)
   *  #tools/<draftId> → lab     (/tool-gaps "Create tool…")
   *  #skillgen        → skills  (author prompt now lives in Generate)
   */
  function parseDevHash(hash) {
    const raw = String(hash || "").replace(/^#/, "");
    const slash = raw.indexOf("/");
    const head = (slash < 0 ? raw : raw.slice(0, slash)).toLowerCase();
    const rest = slash < 0 ? "" : raw.slice(slash + 1);
    const id = rest ? safeDecode(rest) : "";
    if (head === "hunt" || head === "skillgen") return { section: "skills", id };
    if (head === "tools") return id ? { section: "lab", id } : { section: "tools", id: "" };
    if (SECTIONS.includes(head)) return { section: head, id };
    return { section: "skills", id: "" };
  }

  function devHash(section, id) {
    const s = SECTIONS.includes(section) ? section : "skills";
    return id ? `#${s}/${encodeURIComponent(id)}` : `#${s}`;
  }

  /* ---------- Skills list ---------- */

  const SKILL_FILTERS = [
    { id: "all", label: "All" },
    { id: "active", label: "Active" },
    { id: "seed", label: "Seed" },
    { id: "modified", label: "Modified" },
    { id: "custom", label: "Custom & generated" },
  ];

  function isCustomSource(source) {
    const s = String(source || "").toLowerCase();
    return s === "custom" || s === "generated";
  }

  function seedStatusOf(p) {
    return String((p && (p.seed_status || p.source)) || "custom").toLowerCase();
  }

  function matchesSkillFilter(p, filter) {
    const st = seedStatusOf(p);
    switch (filter) {
      case "active":
        return !!(p && p.active);
      case "seed":
        return st === "seed";
      case "modified":
        return st === "modified_seed";
      case "custom":
        return isCustomSource(p && p.source) || st === "custom" || st === "generated";
      default:
        return true;
    }
  }

  function matchesQuery(p, q) {
    const s = String(q || "").trim().toLowerCase();
    if (!s) return true;
    return [p.id, p.title, p.description]
      .map((x) => String(x || "").toLowerCase())
      .some((x) => x.includes(s));
  }

  function filterSkills(profiles, filter, query) {
    return (profiles || []).filter((p) => matchesSkillFilter(p, filter) && matchesQuery(p, query));
  }

  function skillFilterCounts(profiles) {
    const out = {};
    for (const f of SKILL_FILTERS) {
      out[f.id] = (profiles || []).filter((p) => matchesSkillFilter(p, f.id)).length;
    }
    return out;
  }

  /** Provenance pill: label + vf-pill modifier. */
  function provenance(p) {
    const st = seedStatusOf(p);
    if (st === "seed") return { label: "seed", tone: "" };
    if (st === "modified_seed") return { label: "modified seed", tone: "review" };
    if (st === "generated") return { label: "generated", tone: "confirmed" };
    return { label: st || "custom", tone: "candidate" };
  }

  function sortAgents(agents) {
    return (agents || []).slice().sort((a, b) => {
      const oa = Number.isFinite(Number(a.order)) ? Number(a.order) : 1e9;
      const ob = Number.isFinite(Number(b.order)) ? Number(b.order) : 1e9;
      return oa - ob || String(a.id).localeCompare(String(b.id));
    });
  }

  /* ---------- Line diff (seed vs current) ---------- */

  /**
   * Line diff via LCS. Returns [{op: " "|"-"|"+", text}] where "-" is only in
   * `a` (seed) and "+" only in `b` (current). Falls back to whole replace when
   * the table would be too large.
   */
  function lineDiff(a, b, maxCells) {
    const A = String(a ?? "").split("\n");
    const B = String(b ?? "").split("\n");
    const limit = maxCells || 4e6;
    // Trim common prefix/suffix first (cheap, shrinks the table).
    let pre = 0;
    while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
    let suf = 0;
    while (
      suf < A.length - pre &&
      suf < B.length - pre &&
      A[A.length - 1 - suf] === B[B.length - 1 - suf]
    )
      suf++;
    const a2 = A.slice(pre, A.length - suf);
    const b2 = B.slice(pre, B.length - suf);
    const out = A.slice(0, pre).map((text) => ({ op: " ", text }));
    const n = a2.length;
    const m = b2.length;
    if ((n + 1) * (m + 1) > limit) {
      a2.forEach((text) => out.push({ op: "-", text }));
      b2.forEach((text) => out.push({ op: "+", text }));
    } else {
      const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
      for (let i = n - 1; i >= 0; i--) {
        for (let j = m - 1; j >= 0; j--) {
          dp[i][j] = a2[i] === b2[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
        }
      }
      let i = 0;
      let j = 0;
      while (i < n && j < m) {
        if (a2[i] === b2[j]) {
          out.push({ op: " ", text: a2[i] });
          i++;
          j++;
        } else if (dp[i + 1][j] >= dp[i][j + 1]) {
          out.push({ op: "-", text: a2[i++] });
        } else {
          out.push({ op: "+", text: b2[j++] });
        }
      }
      while (i < n) out.push({ op: "-", text: a2[i++] });
      while (j < m) out.push({ op: "+", text: b2[j++] });
    }
    A.slice(A.length - suf).forEach((text) => out.push({ op: " ", text }));
    return out;
  }

  function diffStats(lines) {
    let added = 0;
    let removed = 0;
    for (const l of lines || []) {
      if (l.op === "+") added++;
      else if (l.op === "-") removed++;
    }
    return { added, removed, same: added === 0 && removed === 0 };
  }

  /** Classify unified-diff text lines for rendering. */
  function parseUnifiedDiff(text) {
    const s = String(text || "");
    if (!s) return [];
    return s.replace(/\n$/, "").split("\n").map((line) => {
      let kind = "ctx";
      if (line.startsWith("+++") || line.startsWith("---")) kind = "file";
      else if (line.startsWith("@@")) kind = "hunk";
      else if (line.startsWith("+")) kind = "add";
      else if (line.startsWith("-")) kind = "del";
      return { kind, text: line };
    });
  }

  /* ---------- Tool chips / allowlists ---------- */

  const STAGES = ["recon", "hunt", "develop_poc"];

  /**
   * Names offered as chips for a stage. `submit_*` stay out: the runtime always
   * keeps the critical submit tools, so offering them would only mislead.
   */
  function toolChoices(catalog, stage, builtinForStage) {
    const fromBuiltin = Array.isArray(builtinForStage) ? builtinForStage : [];
    const names = fromBuiltin.length
      ? fromBuiltin
      : (catalog || [])
          .filter((t) => !stage || (t.stages || []).includes(stage))
          .map((t) => t.name);
    const seen = new Set();
    const out = [];
    for (const n of names) {
      const s = String(n || "");
      if (!s || s.startsWith("submit_") || seen.has(s)) continue;
      seen.add(s);
      out.push(s);
    }
    return out;
  }

  /** null/empty list = full default set; else narrowed list. */
  function allowlistState(tools) {
    const list = Array.isArray(tools) ? tools.filter(Boolean).map(String) : [];
    return { all: list.length === 0, selected: list };
  }

  function huntToolsPayload(all, selected) {
    if (all) return { clear_tools: true, tools: null };
    return { clear_tools: false, tools: (selected || []).slice() };
  }

  function stageDefaultsPayload(state) {
    const out = {};
    for (const s of STAGES) {
      const v = state ? state[s] : null;
      out[s] = Array.isArray(v) ? v.slice() : null;
    }
    return out;
  }

  function numOrUndef(raw, parse) {
    const s = String(raw ?? "").trim();
    if (s === "") return undefined;
    const n = parse(s);
    return Number.isFinite(n) ? n : undefined;
  }

  /** Recon agent save payload from editor form values. */
  function reconPayload(form) {
    const f = form || {};
    const out = {
      title: String(f.title || "").trim(),
      description: String(f.description || "").trim(),
      active: !!f.active,
      body_md: String(f.body_md || ""),
      // Empty list clears the allowlist (server: [] → full recon set).
      tools: f.allTools ? [] : (f.tools || []).slice(),
    };
    const order = numOrUndef(f.order, (s) => parseInt(s, 10));
    const temp = numOrUndef(f.temperature, parseFloat);
    const rounds = numOrUndef(f.max_tool_rounds, (s) => parseInt(s, 10));
    if (order !== undefined) out.order = order;
    if (temp !== undefined) out.temperature = temp;
    if (rounds !== undefined) out.max_tool_rounds = rounds;
    return out;
  }

  /* ---------- Tool lab ---------- */

  const LAB_STEPS = [
    { id: "brief", label: "Brief" },
    { id: "spec", label: "Spec" },
    { id: "impl", label: "Impl" },
    { id: "validate", label: "Validate" },
    { id: "integrate", label: "Integrate" },
  ];

  /** Per-step done flags from a draft payload (GET /api/tool-drafts/{id}). */
  function labProgress(draft) {
    const d = draft || {};
    const meta = d.meta || {};
    const rep = d.validation_report;
    const hasSchema = !!(d.schema && Array.isArray(d.schema.tools) && d.schema.tools.length);
    return {
      brief: !!(meta.id || d.id),
      spec: !!String(d.spec_md || "").trim(),
      impl: !!String(d.impl_py || "").trim() && hasSchema,
      validate: !!(rep && rep.ok),
      integrate: meta.status === "integrated",
    };
  }

  /**
   * Can the operator press Apply? Mirrors the server gate so the button tells
   * the truth; the server still enforces plan_hash + allow_overwrite.
   */
  function applyGate(s) {
    const st = s || {};
    if (st.status === "integrated") return { enabled: false, reason: "Already integrated." };
    if (st.status === "rejected") return { enabled: false, reason: "Draft is rejected." };
    if (!st.dry || !st.dry.plan_hash) return { enabled: false, reason: "Run a dry-run first." };
    if (st.stale) return { enabled: false, reason: "Draft changed since the dry-run. Run it again." };
    const ow = (st.dry.overwrites || []).length;
    if (ow && !st.overwriteAck) {
      return { enabled: false, reason: `Confirm the overwrite of ${ow} existing file${ow > 1 ? "s" : ""}.` };
    }
    return { enabled: true, reason: "" };
  }

  /** Pill for a planned integrate op. */
  function opBadge(op) {
    const o = op || {};
    if (o.op === "skip") return { label: "skipped (exists)", tone: "rejected" };
    if (o.overwrite) return { label: "overwrites existing file", tone: "danger" };
    if (o.exists) return { label: "updates", tone: "review" };
    return { label: "new file", tone: "confirmed" };
  }

  function draftStatusTone(status) {
    switch (String(status || "").toLowerCase()) {
      case "validated":
        return "confirmed";
      case "integrated":
        return "confirmed";
      case "generated":
        return "review";
      case "rejected":
        return "rejected";
      default:
        return "candidate";
    }
  }

  /* ---------- Setup pack ---------- */

  function summarizeSetupImport(r) {
    const secs = (r && r.sections) || {};
    const bits = [];
    if (secs.hunt_profiles) bits.push(`${secs.hunt_profiles.count ?? "?"} hunt skills`);
    if (secs.recon_agents) bits.push(`${secs.recon_agents.count ?? "?"} recon agents`);
    if (secs.tool_drafts) bits.push(`${secs.tool_drafts.count ?? "?"} drafts`);
    if (secs.skill_generator) bits.push(`author prompt ${secs.skill_generator.action || "ok"}`);
    if (secs.ui_settings) bits.push("settings");
    return bits.join(" · ") || "nothing imported";
  }

  return {
    SECTIONS,
    SKILL_FILTERS,
    STAGES,
    LAB_STEPS,
    parseDevHash,
    devHash,
    isCustomSource,
    matchesSkillFilter,
    filterSkills,
    skillFilterCounts,
    provenance,
    sortAgents,
    lineDiff,
    diffStats,
    parseUnifiedDiff,
    toolChoices,
    allowlistState,
    huntToolsPayload,
    stageDefaultsPayload,
    reconPayload,
    labProgress,
    applyGate,
    opBadge,
    draftStatusTone,
    summarizeSetupImport,
  };
});
