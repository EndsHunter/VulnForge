/*
 * Dev → setup pack export / import (header ⋯ menu). One JSON for a fresh
 * install: hunt skills, recon agents, author prompt, tool drafts, UI settings
 * (API keys redacted on export). Backed by /api/dev-setup/*.
 */
(function () {
  "use strict";
  if (document.body?.dataset?.page !== "dev") return;

  const H = window.DevHelpers;
  const U = window.DevUI;

  async function exportSetup() {
    const data = await U.api("/api/dev-setup/export");
    U.downloadJson("vulnforge_dev_setup.json", data);
    const s = data.summary || {};
    U.toast(`Exported ${s.hunt_profiles ?? "?"} hunt skills · ${s.recon_agents ?? "?"} recon agents · ${s.tool_drafts ?? "?"} drafts`);
  }

  function openImport() {
    const m = document.getElementById("dev-import-modal");
    m.querySelector("#imp-json").value = "";
    m.querySelector("#imp-file").value = "";
    m.querySelectorAll(".imp-section").forEach((c) => (c.checked = true));
    const llm = m.querySelector("#imp-llm-review");
    if (llm) llm.checked = false;
    U.openModal("dev-import-modal");
  }

  async function submitImport() {
    const m = document.getElementById("dev-import-modal");
    let text = m.querySelector("#imp-json").value.trim();
    const file = m.querySelector("#imp-file").files[0];
    if (!text && file) text = await file.text();
    if (!text) {
      U.toast("Paste JSON or choose a file", true);
      return;
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      U.toast("Invalid JSON", true);
      return;
    }
    const mode = m.querySelector('input[name="imp-mode"]:checked')?.value || "merge";
    const include = [...m.querySelectorAll(".imp-section:checked")].map((c) => c.value);
    if (!include.length) {
      U.toast("Pick at least one section", true);
      return;
    }
    if (mode === "replace" && !confirm(`Replace mode wipes each selected collection before loading:\n\n${include.join(", ")}\n\nContinue?`)) return;
    const r = await U.busy(m.querySelector("#imp-submit"), "Importing…", () =>
      U.api("/api/dev-setup/import", {
        method: "POST",
        body: JSON.stringify({ data, mode, include, llm_review: !!m.querySelector("#imp-llm-review")?.checked }),
      })
    );
    U.closeModal("dev-import-modal");
    U.toast(`Imported (${mode}): ${H.summarizeSetupImport(r)}`);
    U.catalog(true).catch(() => {});
    window.DevRouter?.reloadMounted();
  }

  function wire() {
    document.getElementById("dev-export")?.addEventListener("click", () => {
      document.getElementById("dev-menu")?.removeAttribute("open");
      exportSetup().catch(U.fail);
    });
    document.getElementById("dev-import")?.addEventListener("click", () => {
      document.getElementById("dev-menu")?.removeAttribute("open");
      openImport();
    });
    const m = document.getElementById("dev-import-modal");
    if (!m) return;
    m.querySelector("#imp-cancel").addEventListener("click", () => U.closeModal("dev-import-modal"));
    m.querySelector("#imp-submit").addEventListener("click", () => submitImport().catch(U.fail));
    m.querySelector("#imp-file").addEventListener("change", async (e) => {
      const f = e.target.files[0];
      if (f) m.querySelector("#imp-json").value = await f.text();
    });
  }

  wire();
})();
