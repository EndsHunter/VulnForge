/* VulnForge mode navigation: header tabs + page lifecycle (docs/ui/REDESIGN.md).
 * Develop POC is a Review modal, not a tab. */

(function () {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  const table = window.RunNav;
  const RUN_NAV = table?.RUN_NAV || [];
  const primaryNav = table?.primaryNav || ((nav) => (nav || []).filter((i) => i.kind === "mode" && i.rail === "primary"));
  const isRunMode = table?.isRunMode || (() => false);
  const defaultTabFor = table?.defaultTabFor || (() => null);
  const isOverlayMode = table?.isOverlayMode || ((mode) => mode === "ai");

  const DEFAULT_MODE = table?.DEFAULT_MODE || "hunts";
  /** mode id → window.VFPages key */
  const PAGE_OF_MODE = { report: "review", hunts: "campaign", explorer: "atlas" };

  let exclusive = { mode: DEFAULT_MODE, tab: defaultTabFor(DEFAULT_MODE) || DEFAULT_MODE };

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
    if (mode === "harness" || mode === "mission") {
      // Mission was split: campaign stats → Campaign, architecture → Atlas.
      // (Legacy: tab === "overview" also lands here.)
      return { mode: "hunts", tab: "hunts" };
    }
    if (mode === "tasks") {
      return { mode: "audit", tab: tab || "tasks" };
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

  /** Header tab bar: primary non-overlay modes; AI overlay is the ⌘K button. */
  function renderRunTabs(root, nav) {
    if (!root) return;
    const items = primaryNav(nav || RUN_NAV).filter((item) => !item.overlay);
    root.innerHTML = items
      .map((item) => {
        const badge =
          item.id === "review"
            ? ` <span class="vf-tab-badge" id="tab-badge-review" hidden></span>`
            : "";
        return `<button type="button" class="vf-tab" role="tab" data-nav-id="${item.id}" data-mode="${item.mode}" aria-selected="false">${item.label}${badge}</button>`;
      })
      .join("");
  }

  /** Review tab badge = needs_human count (set by app.js after each snapshot). */
  function setReviewBadge(n) {
    const el = document.getElementById("tab-badge-review");
    if (!el) return;
    const count = Number(n) || 0;
    el.textContent = String(count);
    el.hidden = count <= 0;
    el.setAttribute("aria-label", `${count} need review`);
  }

  function pageFor(mode) {
    const key = PAGE_OF_MODE[mode];
    return key ? window.VFPages?.[key] || null : null;
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

    const tab = preferredTab || defaultTabFor(mode) || mode;

    if (isOverlayMode(mode)) {
      const chat = window.VulnForgeChat;
      if (chat?.isSheetOpen?.()) {
        chat.closeSheet();
        try {
          history.replaceState(null, "", `#${exclusive.mode}/${exclusive.tab}`);
        } catch {
          /* ignore */
        }
      } else if (chat?.openSheet) {
        chat.openSheet();
        try {
          history.replaceState(null, "", `#${mode}/${tab}`);
        } catch {
          /* ignore */
        }
      } else if (chat?.ensureMounted) {
        chat.ensureMounted();
      }
      return;
    }

    const prevMode = exclusive.mode;
    exclusive = { mode, tab };

    $$("[data-nav-id]").forEach((t) => {
      const id = t.getAttribute("data-nav-id");
      const item = RUN_NAV.find((row) => row.id === id);
      if (!item || item.kind !== "mode" || item.rail !== "primary") {
        t.removeAttribute("aria-selected");
        t.classList.remove("active", "on");
        return;
      }
      if (item.overlay) {
        t.classList.remove("active");
        t.removeAttribute("aria-selected");
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
    if (prevMode !== mode) {
      try {
        pageFor(prevMode)?.onHide?.();
      } catch (err) {
        console.error("page onHide failed", err);
      }
    }
    try {
      pageFor(mode)?.onShow?.(window.__VF_last_snap || null);
    } catch (err) {
      console.error("page onShow failed", err);
    }
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
    if (window.VulnForgeChat?.syncChrome) window.VulnForgeChat.syncChrome();
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
    const tabs = $("[data-run-tabs]");
    if (!tabs) return;

    renderRunTabs(tabs, RUN_NAV);
    bindRunRail(tabs, RUN_NAV);
    $("#btn-command")?.addEventListener("click", () => setMode("ai"));

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
      if (path && window.VFPages?.atlas?.reveal) {
        window.VFPages.atlas.reveal(path, line);
      } else if (path && window.VulnForgeExplorer?.reveal) {
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
      setReviewBadge,
      activeMode() {
        return exclusive.mode;
      },
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
      setMode(DEFAULT_MODE);
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
    } else setMode(DEFAULT_MODE);

    document.addEventListener("keydown", (ev) => {
      if ((ev.metaKey || ev.ctrlKey) && !ev.altKey && (ev.key === "k" || ev.key === "K")) {
        setMode("ai");
        ev.preventDefault();
        return;
      }
      if (ev.target && /^(INPUT|TEXTAREA|SELECT)$/i.test(ev.target.tagName)) return;
      if (ev.key === "Escape" && window.VulnForgeReport?.isPocOpen?.()) {
        window.VulnForgeReport.closeDevelopPoc();
        ev.preventDefault();
        return;
      }
      // Review owns E (open evidence); elsewhere E jumps to Atlas.
      if (ev.key === "e" && exclusive.mode !== "report" && !ev.metaKey && !ev.ctrlKey && !ev.altKey) {
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
