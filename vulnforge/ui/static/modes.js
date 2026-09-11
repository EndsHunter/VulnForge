/* VulnForge mode navigation. Develop POC is a Report modal, not a rail item. */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  const table = window.RunNav;
  const RUN_NAV = table?.RUN_NAV || [];
  const primaryNav = table?.primaryNav || ((nav) => (nav || []).filter((i) => i.kind === "mode" && i.rail === "primary"));
  const headNav = table?.headNav || ((nav) => (nav || []).filter((i) => i.rail === "head"));
  const footerNav = table?.footerNav || ((nav) => (nav || []).filter((i) => i.rail === "footer"));
  const isRunMode = table?.isRunMode || (() => false);
  const defaultTabFor = table?.defaultTabFor || (() => null);
  const isOverlayMode = table?.isOverlayMode || ((mode) => mode === "ai");

  const I = {
    home: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M2.5 8 L8 3.2 L13.5 8"/><path d="M4.2 7.2V13h7.6V7.2"/></svg>`,
    mission: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="8" cy="8" r="5.2"/><circle cx="8" cy="8" r="1.6"/><path d="M8 2.8v1.6M8 11.6v1.6M2.8 8h1.6M11.6 8h1.6"/></svg>`,
    hunts: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="8" cy="8" r="3.2"/><path d="M8 1.6v2.4M8 12v2.4M1.6 8h2.4M12 8h2.4"/></svg>`,
    explorer: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M2.5 4.5h4l1.2 1.5H13.5v6.5h-11z"/></svg>`,
    report: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M3.5 2.5h9v11h-9z"/><path d="M5.5 6h5M5.5 8.5h5M5.5 11h3"/></svg>`,
    settings: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="8" cy="8" r="2.2"/><path d="M8 2.5v1.5M8 12v1.5M2.5 8h1.5M12 8h1.5M4.2 4.2l1.1 1.1M10.7 10.7l1.1 1.1M11.8 4.2l-1.1 1.1M5.3 10.7l-1.1 1.1"/></svg>`,
    dev: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M5 5 L2.5 8 L5 11M11 5 L13.5 8 L11 11M9.2 3.6 L6.8 12.4"/></svg>`,
    "tool-gaps": `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="3" y="3" width="10" height="10" rx="1.5"/><path d="M6 8h4M8 6v4"/></svg>`,
  };

  let exclusive = { mode: "mission", tab: "overview" };

  /**
   * Parse hash segment. `#poc/<id>` is the current PoC workshop deep link
   * (opens Report + modal), not a workspace mode.
   * Legacy aliases: #coverage → hunts, #harness → mission, #tasks → audit/tasks.
   */
  function resolveModeHash(mode, tab) {
    if (mode === "poc") {
      return { mode: "report", tab: "report", pocFindingId: tab || null };
    }
    if (mode === "coverage") {
      return { mode: "hunts", tab: tab === "coverage" || !tab ? "hunts" : tab };
    }
    if (mode === "harness") {
      return { mode: "mission", tab: "overview" };
    }
    if (mode === "tasks") {
      return { mode: "audit", tab: tab || "tasks" };
    }
    if (mode === "evidence") {
      return { mode: "report", tab: "report" };
    }
    return { mode, tab };
  }

  function activateTab(tabId) {
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

  function railInner(item) {
    const icon = I[item.id] || "";
    return `${icon}<span class="lab">${item.label}</span>`;
  }

  function renderRunRail(root, nav) {
    if (!root) return;
    const items = nav || RUN_NAV;
    const head = headNav(items)
      .map(
        (item) =>
          `<a class="run-rail-item run-rail-href" data-nav-id="${item.id}" href="${item.href}" title="${item.label}">${railInner(item)}</a>`
      )
      .join("");
    const primary = primaryNav(items);
    const footer = footerNav(items);
    const primaryHtml = primary
      .map(
        (item) =>
          `<button type="button" class="run-rail-item" role="tab" data-nav-id="${item.id}" data-mode="${item.mode}" aria-selected="false" title="${item.label}">${railInner(item)}</button>`
      )
      .join("");
    const footerHtml = footer
      .map(
        (item) =>
          `<a class="run-rail-item run-rail-href" data-nav-id="${item.id}" href="${item.href}" title="${item.label}">${railInner(item)}</a>`
      )
      .join("");
    root.innerHTML = `${head}<nav class="run-rail-primary" role="tablist" aria-label="Workspace mode">${primaryHtml}</nav><div class="run-rail-footer">${footerHtml}</div>`;
  }

  function bindRunRail(root, nav) {
    if (!root) return;
    const items = nav || RUN_NAV;
    root.querySelectorAll("[data-nav-id]").forEach((el) => {
      const id = el.getAttribute("data-nav-id");
      const item = items.find((row) => row.id === id);
      if (!item || item.kind !== "mode") return;
      el.addEventListener("click", () => setMode(item.mode));
    });
  }

  function setMode(mode, preferredTab) {
    if (mode !== "report" && window.VulnForgeReport?.isPocOpen?.()) {
      window.VulnForgeReport.closeDevelopPoc({ stayOnReport: false, skipHash: true });
    }

    const tab = preferredTab || defaultTabFor(mode) || "overview";

    if (isOverlayMode(mode)) {
      if (window.VulnForgeChat?.openSheet) window.VulnForgeChat.openSheet();
      else if (window.VulnForgeChat?.ensureMounted) window.VulnForgeChat.ensureMounted();
      try {
        history.replaceState(null, "", `#${mode}/${tab}`);
      } catch {
        /* ignore */
      }
      return;
    }

    exclusive = { mode, tab };

    $$("[data-nav-id]").forEach((t) => {
      const id = t.getAttribute("data-nav-id");
      const item = RUN_NAV.find((row) => row.id === id);
      if (!item || item.kind !== "mode" || item.rail !== "primary") {
        t.removeAttribute("aria-selected");
        t.classList.remove("active", "on");
        return;
      }
      const on = item.mode === mode;
      t.classList.toggle("active", on);
      t.classList.toggle("on", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
    });
    $$(".mode-panel").forEach((p) => {
      p.classList.toggle("active", p.getAttribute("data-mode-panel") === mode);
    });
    activateTab(tab);
    if (mode === "report" && typeof window.renderReport === "function") {
      const snap = window.__VF_last_snap;
      if (snap) window.renderReport(snap);
    }
    if (mode === "evidence" && typeof window.renderEvidence === "function") {
      const packs = window.__VF_last_snap?.evidence;
      if (packs) window.renderEvidence(packs);
    }
    if (mode === "hunts" && window.VulnForgeCoverage?.render) {
      const snap = window.__VF_last_snap;
      if (snap) window.VulnForgeCoverage.render(snap);
    }
    try {
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
    if (!isRunMode(mode)) return null;
    return {
      mode,
      tab: resolved.tab || defaultTabFor(mode),
      pocFindingId: resolved.pocFindingId || null,
    };
  }

  function setupModes() {
    if (!document.body || document.body.dataset.page !== "run") return;
    const rail = $("[data-run-rail]");
    if (!rail) return;

    renderRunRail(rail, RUN_NAV);
    bindRunRail(rail, RUN_NAV);

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
        setMode("hunts");
      },
      goHunts() {
        setMode("hunts");
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
        setMode("report", "report");
        if (findingId != null && window.VulnForgeReport?.openDevelopPoc) {
          window.VulnForgeReport.openDevelopPoc(findingId);
        }
      },
    };

    const fromHash = parseHash();
    if (fromHash && isOverlayMode(fromHash.mode)) {
      setMode("mission", "overview");
      setMode(fromHash.mode, fromHash.tab);
    } else if (fromHash) {
      setMode(fromHash.mode, fromHash.tab);
      const fid = fromHash.pocFindingId;
      if (fid && fid !== "poc" && window.VulnForgeReport?.openDevelopPoc) {
        const n = Number(fid);
        if (Number.isFinite(n) && n > 0) {
          setTimeout(() => window.VulnForgeReport.openDevelopPoc(n), 0);
        }
      }
    } else setMode("mission", "overview");

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
