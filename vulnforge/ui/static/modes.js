/* VulnForge mode navigation — Mission / Coverage / Explorer / Report / Evidence / Tasks / AI / Harness.
 * Develop POC is an on-demand modal (Report → Develop POC), not a top-level mode tab.
 */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  const MODE_DEFAULT_TAB = {
    mission: "overview",
    coverage: "coverage",
    explorer: "explorer",
    report: "report",
    evidence: "evidence",
    audit: "tasks", // UI label: Tasks
    ai: "ai",
    harness: "harness",
  };

  /**
   * Parse hash segment. `#poc/<id>` is the current PoC workshop deep link
   * (opens Report + modal), not a workspace mode.
   */
  function resolveModeHash(mode, tab) {
    if (mode === "poc") {
      return { mode: "report", tab: "report", pocFindingId: tab || null };
    }
    return { mode, tab };
  }

  function activateTab(tabId) {
    // Only toggle tabs/panels inside the active mode panel (and global if any)
    $$(".mode-panel.active .tab").forEach((t) => {
      t.classList.toggle("active", t.getAttribute("data-tab") === tabId);
    });
    $$(".mode-panel.active .tab-panel").forEach((p) => {
      const id = p.id.replace(/^panel-/, "");
      p.classList.toggle("active", id === tabId);
    });
    if (tabId === "explorer") {
      if (window.VulnForgeExplorer?.ensureMounted) {
        window.VulnForgeExplorer.ensureMounted();
      } else if (typeof window.mountExplorer === "function") {
        if (!window.explorerMounted) window.mountExplorer();
        else if (!window.explorerTreeLoaded) window.loadExplorerTree?.();
      }
    }
  }

  function setMode(mode, preferredTab) {
    // Close Develop POC modal when leaving Report for another workspace mode.
    if (mode !== "report" && window.VulnForgeReport?.isPocOpen?.()) {
      window.VulnForgeReport.closeDevelopPoc({ stayOnReport: false, skipHash: true });
    }

    $$(".mode-tab").forEach((t) => {
      const on = t.getAttribute("data-mode") === mode;
      t.classList.toggle("active", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
    });
    $$(".mode-panel").forEach((p) => {
      p.classList.toggle("active", p.getAttribute("data-mode-panel") === mode);
    });
    const tab = preferredTab || MODE_DEFAULT_TAB[mode] || "overview";
    activateTab(tab);
    if (mode === "report" && typeof window.renderReport === "function") {
      const snap = window.__VF_last_snap;
      if (snap) window.renderReport(snap);
    }
    if (mode === "evidence" && typeof window.renderEvidence === "function") {
      const packs = window.__VF_last_snap?.evidence;
      if (packs) window.renderEvidence(packs);
    }
    if (mode === "ai" && window.VulnForgeChat?.ensureMounted) {
      window.VulnForgeChat.ensureMounted();
    }
    if (mode === "coverage" && window.VulnForgeCoverage?.render) {
      const snap = window.__VF_last_snap;
      if (snap) window.VulnForgeCoverage.render(snap);
    }
    if (mode === "harness" && window.VulnForgeHarness?.activate) {
      window.VulnForgeHarness.activate();
    }
    try {
      // Preserve #poc/<id> hash while POC modal is open on report
      if (
        mode === "report" &&
        window.VulnForgeReport?.isPocOpen?.() &&
        window.VulnForgeReport?.pocFindingId != null
      ) {
        history.replaceState(
          null,
          "",
          `#poc/${window.VulnForgeReport.pocFindingId}`
        );
      } else {
        history.replaceState(null, "", `#${mode}/${tab}`);
      }
    } catch {
      /* ignore */
    }
  }

  function parseHash() {
    const h = (location.hash || "").replace(/^#/, "");
    if (!h) return null;
    const [rawMode, rawTab] = h.split("/");
    const resolved = resolveModeHash(rawMode, rawTab || "");
    const mode = resolved.mode;
    if (!MODE_DEFAULT_TAB[mode]) return null;
    return {
      mode,
      tab: resolved.tab || MODE_DEFAULT_TAB[mode],
      pocFindingId: resolved.pocFindingId || null,
    };
  }

  function setupModes() {
    if (!document.body || document.body.dataset.page !== "run") return;
    if (!$(".mode-nav")) return;

    $$(".mode-tab").forEach((btn) => {
      btn.addEventListener("click", () => setMode(btn.getAttribute("data-mode")));
    });

    // Sub-tabs within modes
    $$(".mode-panel .tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        const tabId = tab.getAttribute("data-tab");
        const mode = tab.closest(".mode-panel")?.getAttribute("data-mode-panel");
        activateTab(tabId);
        if (mode) {
          try {
            history.replaceState(null, "", `#${mode}/${tabId}`);
          } catch {
            /* ignore */
          }
        }
      });
    });

    // Deep-link helpers for the rest of the app
    function goExplorer(path, line) {
      setMode("explorer");
      if (path && window.VulnForgeExplorer?.reveal) {
        window.VulnForgeExplorer.reveal(path, line);
      } else if (path && typeof window.loadExplorerFile === "function") {
        window.loadExplorerFile(path);
      }
    }

    /**
     * Open Evidence mode; optionally focus a pack/file.
     * @param {string} [packId]
     * @param {string} [relpath]
     */
    function goEvidence(packId, relpath) {
      if (window.VulnForgeReport?.closeDevelopPoc) {
        window.VulnForgeReport.closeDevelopPoc({ stayOnReport: false, skipHash: true });
      }
      if (packId && typeof window.selectEvidencePack === "function") {
        window.selectEvidencePack(packId, relpath || null);
      }
      setMode("evidence", "evidence");
      if (packId && typeof window.openEvidenceFile === "function") {
        const packs = window.__VF_last_snap?.evidence || [];
        const pack = packs.find((p) => String(p.id) === String(packId));
        let rel = relpath;
        if (!rel && pack) {
          const files = (pack.files || []).map((f) => f.relpath || f);
          const md = files.find((n) => /\.md$/i.test(n));
          rel = md || files[0] || null;
        }
        if (rel) window.openEvidenceFile(packId, rel);
      }
    }

    window.VulnForgeModes = {
      setMode,
      goExplorer,
      goEvidence,
      goCoverage() {
        setMode("coverage");
      },
      goReport(fileOrFilter) {
        setMode("report", "report");
        if (fileOrFilter && window.VulnForgeReport?.setFilter) {
          const f = String(fileOrFilter);
          if (
            ["all", "confirmed", "candidate", "rejected", "needs_human"].includes(f)
          ) {
            window.VulnForgeReport.setFilter(f);
          }
        }
      },
      /**
       * Open Develop POC workshop modal for a finding (Report → Develop POC).
       * @param {number|string} findingId
       */
      goDevelopPoc(findingId) {
        // Stay on Report underneath; open modal only
        setMode("report", "report");
        if (findingId != null && window.VulnForgeReport?.openDevelopPoc) {
          window.VulnForgeReport.openDevelopPoc(findingId);
        }
      },
    };

    const fromHash = parseHash();
    if (fromHash) {
      setMode(fromHash.mode, fromHash.tab);
      const fid = fromHash.pocFindingId;
      if (fid && fid !== "poc" && window.VulnForgeReport?.openDevelopPoc) {
        const n = Number(fid);
        if (Number.isFinite(n) && n > 0) {
          // Defer until report cache may load
          setTimeout(() => window.VulnForgeReport.openDevelopPoc(n), 0);
        }
      }
    } else setMode("mission", "overview");

    // Keyboard: e -> Explorer (now a top-level mode)
    document.addEventListener("keydown", (ev) => {
      if (ev.target && /^(INPUT|TEXTAREA|SELECT)$/i.test(ev.target.tagName)) return;
      if (ev.key === "Escape" && window.VulnForgeReport?.isPocOpen?.()) {
        window.VulnForgeReport.closeDevelopPoc();
        ev.preventDefault();
        return;
      }
      if (ev.key === "e" && !ev.metaKey && !ev.ctrlKey && !ev.altKey) {
        setMode("explorer");
        ev.preventDefault();
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupModes);
  } else {
    setupModes();
  }
})();
