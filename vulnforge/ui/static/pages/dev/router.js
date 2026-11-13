/*
 * Dev workbench router (issue #203). /dev is a standalone page, so this plays
 * the role modes.js plays on the run cockpit: section tabs + hash routing,
 * lazily mounting each VFPages.dev* module and calling onShow/onHide.
 *
 * Hashes: #skills[/id] #recon[/id] #tools #lab[/draftId]
 * Legacy: #hunt[/id] → skills, #tools/<draftId> → lab (see DevHelpers.parseDevHash).
 */
(function () {
  "use strict";
  if (document.body?.dataset?.page !== "dev") return;

  const H = window.DevHelpers;
  const MODULES = { skills: "devSkills", recon: "devRecon", tools: "devTools", lab: "devLab" };
  const mounted = new Set();
  let active = null;

  function page(section) {
    return window.VFPages && window.VFPages[MODULES[section]];
  }

  function show(route) {
    const { section, id } = route;
    const mod = page(section);
    if (!mod) return;
    document.querySelectorAll("[data-dev-tab]").forEach((b) => {
      b.setAttribute("aria-selected", String(b.getAttribute("data-dev-tab") === section));
    });
    document.querySelectorAll("[data-dev-panel]").forEach((p) => {
      p.hidden = p.getAttribute("data-dev-panel") !== section;
    });
    if (active && active !== section) page(active)?.onHide?.();
    if (!mounted.has(section)) {
      mod.mount(document.querySelector(`[data-dev-panel="${section}"]`));
      mounted.add(section);
    }
    active = section;
    document.title = `${document.querySelector(`[data-dev-tab="${section}"]`)?.textContent.trim() || "Dev"} · Dev | VulnForge`;
    mod.onShow?.(id);
  }

  function fromHash() {
    const r = H.parseDevHash(location.hash);
    // Normalise legacy aliases in the address bar.
    const want = H.devHash(r.section, r.id);
    if (location.hash && location.hash !== want) history.replaceState(null, "", want);
    show(r);
  }

  document.querySelectorAll("[data-dev-tab]").forEach((b) => {
    b.addEventListener("click", () => {
      const s = b.getAttribute("data-dev-tab");
      if (s === active) return;
      location.hash = H.devHash(s, "");
    });
  });
  window.addEventListener("hashchange", fromHash);

  window.DevRouter = {
    reloadMounted() {
      mounted.forEach((s) => page(s)?.reload?.().catch?.(window.DevUI.fail));
    },
  };

  fromHash();
})();
