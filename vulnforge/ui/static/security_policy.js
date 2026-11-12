/* Mission → Security policy panel (operator-owned; vulnforge/security-policy@1).
 *
 * The policy only narrows scope and demotes findings (exclusion gate →
 * rejected_mech with the rule cited; severity cap). It never confirms anything.
 * "Draft from SECURITY.md" only fills the editor — nothing is saved until Save.
 *
 * Uses app.js globals at call time: api, toast, esc, runApiBase.
 */
(function () {
  const TEMPLATE = {
    schema: "vulnforge/security-policy@1",
    notes: "",
    trust_boundaries: [],
    attacker_controlled: [],
    trusted_inputs: [],
    in_scope: [],
    out_of_scope: [],
    exclusions: [],
    severity_rubric: [],
  };

  const EXAMPLE = {
    schema: "vulnforge/security-policy@1",
    notes: "Internal admin tool; only the public /api surface faces the internet.",
    trust_boundaries: [
      { id: "tb-1", name: "internet → api", description: "Public HTTP API", paths: ["src/api/**"] },
    ],
    attacker_controlled: [
      { id: "src-1", description: "HTTP query params, JSON bodies, headers", paths: ["src/api/**"] },
    ],
    trusted_inputs: [{ id: "trust-1", description: "Env vars set by the deployer", paths: [] }],
    in_scope: [{ id: "scope-1", paths: ["src/**"], note: "focus guidance only" }],
    out_of_scope: [{ id: "oos-1", paths: ["tests/**", "examples/**"], reason: "test fixtures" }],
    exclusions: [
      { id: "ex-1", paths: ["vendor/**"], weakness_class: "*", reason: "vendored; tracked upstream" },
    ],
    severity_rubric: [
      { id: "sev-1", max_severity: "MEDIUM", paths: ["src/admin/**"], criteria: "admin-only surface" },
    ],
  };

  function panelHtml() {
    return `
      <div id="policy-panel" class="card arch-edit-panel policy-panel" style="display:none">
        <header class="arch-section-head">
          <h3>Security policy <span id="policy-rev" class="controls-hint"></span></h3>
        </header>
        <p class="controls-hint">Operator-owned trust boundaries, exclusions and severity rubric for this run (stored in harness.db; the target stays read-only).
        Exclusions / out-of-scope rules reject a finding mechanically only when <strong>every</strong> cited path matches; the matched rule is shown in the Report.
        The rubric only lowers <span class="mono">severity_claim</span>. Nothing here confirms a finding. Applies to findings validated after you save.</p>
        <div class="field">
          <label for="policy-json">Policy JSON</label>
          <textarea id="policy-json" class="op-notes mono" rows="16" spellcheck="false"></textarea>
        </div>
        <div id="policy-errors" class="controls-hint" style="display:none;color:var(--danger,#c44)"></div>
        <div class="field">
          <label for="policy-note">Note (optional)</label>
          <input type="text" id="policy-note" class="op-notes" placeholder="Why this change?" />
        </div>
        <div class="toolbar arch-toolbar-actions">
          <button type="button" class="btn btn-primary" id="policy-save">Save</button>
          <button type="button" class="btn" id="policy-draft-md" title="Fill the editor from the target's SECURITY.md (not saved)">Draft from SECURITY.md</button>
          <button type="button" class="btn" id="policy-example">Insert example</button>
          <button type="button" class="btn" id="policy-history-btn">History</button>
          <button type="button" class="btn" id="policy-close">Close</button>
        </div>
        <div id="policy-history" class="arch-history-list controls-hint" style="display:none"></div>
      </div>`;
  }

  function setErrors(list) {
    const el = document.getElementById("policy-errors");
    if (!el) return;
    if (!list || !list.length) {
      el.style.display = "none";
      el.innerHTML = "";
      return;
    }
    el.style.display = "block";
    el.innerHTML = `<ul>${list.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`;
  }

  function setEditor(policy) {
    const ta = document.getElementById("policy-json");
    if (ta) ta.value = JSON.stringify(policy || TEMPLATE, null, 2);
  }

  async function load() {
    setErrors([]);
    const revEl = document.getElementById("policy-rev");
    try {
      const r = await api(`${runApiBase()}/security-policy`);
      setEditor(r.policy || TEMPLATE);
      if (revEl) {
        revEl.textContent = r.revision != null ? `rev ${r.revision} · ${r.source || ""}` : "(none saved)";
      }
    } catch (e) {
      toast(e.message, true);
    }
  }

  async function save() {
    const ta = document.getElementById("policy-json");
    const note = (document.getElementById("policy-note")?.value || "").trim();
    let policy;
    try {
      policy = JSON.parse((ta?.value || "{}").trim() || "{}");
    } catch (e) {
      setErrors(["Invalid JSON: " + e.message]);
      return;
    }
    try {
      const r = await fetch(`${runApiBase()}/security-policy`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policy, note }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const errs = (data.detail && data.detail.errors) || [data.detail || r.statusText];
        setErrors(errs.map(String));
        return;
      }
      setErrors([]);
      toast(`Security policy saved (rev ${data.revision})`);
      await load();
    } catch (e) {
      toast(e.message, true);
    }
  }

  async function draftFromSecurityMd() {
    try {
      const r = await api(`${runApiBase()}/security-policy/draft/security-md`);
      if (!r.found) {
        toast("No SECURITY.md found in the target", true);
        return;
      }
      setEditor(r.policy);
      toast(`Drafted from ${r.source_path} — review, then Save`);
    } catch (e) {
      toast(e.message, true);
    }
  }

  async function history() {
    const box = document.getElementById("policy-history");
    if (!box) return;
    const show = box.style.display === "none";
    box.style.display = show ? "block" : "none";
    if (!show) return;
    box.innerHTML = "Loading…";
    try {
      const r = await api(`${runApiBase()}/security-policy/history?limit=50`);
      const revs = Array.isArray(r.revisions) ? r.revisions : [];
      if (!revs.length) {
        box.innerHTML = "<p class='controls-hint' style='margin:0'>No revisions yet.</p>";
        return;
      }
      box.innerHTML = `<ul class="arch-rev-list">${revs
        .map(
          (rev) => `<li class="arch-rev-row">
            <div class="arch-rev-meta">
              <span class="mono">#${esc(String(rev.revision))}</span>
              <span class="badge">${esc(rev.source || "—")}</span>
              <span class="controls-hint">${esc(rev.created_at || "")}</span>
              ${rev.note ? `<span class="controls-hint arch-rev-note">${esc(String(rev.note).slice(0, 120))}</span>` : ""}
            </div>
            ${
              window.ReportPolicyPromote
                ? window.ReportPolicyPromote.historyProvenanceHtml(rev.promoted_rules, esc)
                : ""
            }
            <div class="arch-rev-actions">
              <button type="button" class="btn btn-sm policy-view-btn" data-rev="${esc(String(rev.revision))}">Load into editor</button>
              <button type="button" class="btn btn-sm policy-restore-btn" data-rev="${esc(String(rev.revision))}">Restore</button>
            </div>
          </li>`
        )
        .join("")}</ul>`;
      box.querySelectorAll(".policy-view-btn").forEach((b) =>
        b.addEventListener("click", async () => {
          try {
            const rev = await api(`${runApiBase()}/security-policy/history/${encodeURIComponent(b.dataset.rev)}`);
            setEditor(rev.policy);
            toast(`Loaded revision #${rev.revision} into the editor (not saved)`);
          } catch (e) {
            toast(e.message, true);
          }
        })
      );
      box.querySelectorAll(".policy-restore-btn").forEach((b) =>
        b.addEventListener("click", async () => {
          if (!confirm(`Restore security policy revision #${b.dataset.rev} as the current policy?`)) return;
          try {
            const r2 = await api(`${runApiBase()}/security-policy/restore/${encodeURIComponent(b.dataset.rev)}`, {
              method: "POST",
              body: JSON.stringify({ note: `restored from #${b.dataset.rev}` }),
            });
            toast(`Restored as revision #${r2.revision}`);
            box.style.display = "none";
            await load();
          } catch (e) {
            toast(e.message, true);
          }
        })
      );
    } catch (e) {
      box.innerHTML = `<p class="controls-hint" style="color:var(--danger,#c44)">${esc(e.message)}</p>`;
    }
  }

  async function toggle() {
    const panel = document.getElementById("policy-panel");
    if (!panel) return;
    const show = panel.style.display === "none";
    panel.style.display = show ? "block" : "none";
    if (!show) return;
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    await load();
  }

  function bind() {
    document.getElementById("arch-policy-toggle")?.addEventListener("click", toggle);
    document.getElementById("policy-save")?.addEventListener("click", save);
    document.getElementById("policy-draft-md")?.addEventListener("click", draftFromSecurityMd);
    document.getElementById("policy-example")?.addEventListener("click", () => setEditor(EXAMPLE));
    document.getElementById("policy-history-btn")?.addEventListener("click", history);
    document.getElementById("policy-close")?.addEventListener("click", () => {
      const p = document.getElementById("policy-panel");
      if (p) p.style.display = "none";
    });
  }

  /** Keep an open editor (and unsaved text) across Mission re-renders. */
  function capture() {
    const panel = document.getElementById("policy-panel");
    if (!panel || panel.style.display === "none") return null;
    return {
      json: document.getElementById("policy-json")?.value || "",
      note: document.getElementById("policy-note")?.value || "",
      rev: document.getElementById("policy-rev")?.textContent || "",
    };
  }

  function restore(state) {
    if (!state) return;
    const panel = document.getElementById("policy-panel");
    if (!panel) return;
    panel.style.display = "block";
    const ta = document.getElementById("policy-json");
    if (ta) ta.value = state.json;
    const note = document.getElementById("policy-note");
    if (note) note.value = state.note;
    const rev = document.getElementById("policy-rev");
    if (rev) rev.textContent = state.rev;
  }

  window.VFSecurityPolicy = { panelHtml, bind, toggle, capture, restore };
})();
