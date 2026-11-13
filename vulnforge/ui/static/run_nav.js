/**
 * Run-page nav table. UMD for node --test and the browser (modes.js).
 *
 * One frozen table. `rail` is the only slot field (`"head"|"primary"|"footer"|null`).
 * `primaryNav` is the header tab bar (Review, Campaign, Atlas, Evidence, Tasks) plus
 * the AI overlay, which renders as the ⌘K button rather than a tab. Mode ids are the
 * legacy hash keys (report, hunts, explorer, audit) so deep links keep working; labels
 * follow docs/ui/REDESIGN.md. Legacy `#mission/*` hashes resolve to Campaign in
 * modes.js. `footer` items live in the header ⋯ menu.
 *
 * @typedef {{
 *   kind: "mode",
 *   id: string,
 *   mode: "hunts"|"explorer"|"report"|"evidence"|"audit"|"ai",
 *   label: string,
 *   defaultTab: string,
 *   rail: "primary"|null,
 *   overlay?: true
 * }} ModeNavItem
 *
 * @typedef {{
 *   kind: "href",
 *   id: string,
 *   href: string,
 *   label: string,
 *   rail: "head"|"footer"
 * }} HrefNavItem
 *
 * @typedef {ModeNavItem | HrefNavItem} RunNavItem
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.RunNav = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /** @type {readonly RunNavItem[]} */
  const RUN_NAV = Object.freeze([
    { kind: "href", id: "home", href: "/", label: "Home", rail: "head" },
    { kind: "mode", id: "review", mode: "report", label: "Review", defaultTab: "report", rail: "primary" },
    { kind: "mode", id: "campaign", mode: "hunts", label: "Campaign", defaultTab: "hunts", rail: "primary" },
    { kind: "mode", id: "atlas", mode: "explorer", label: "Atlas", defaultTab: "explorer", rail: "primary" },
    { kind: "mode", id: "evidence", mode: "evidence", label: "Evidence", defaultTab: "evidence", rail: "primary" },
    { kind: "mode", id: "audit", mode: "audit", label: "Tasks", defaultTab: "tasks", rail: "primary" },
    { kind: "mode", id: "ai", mode: "ai", label: "AI", defaultTab: "ai", rail: "primary", overlay: true },
    { kind: "href", id: "settings", href: "/settings", label: "Settings", rail: "footer" },
    { kind: "href", id: "dev", href: "/dev", label: "Dev", rail: "footer" },
    { kind: "href", id: "tool-gaps", href: "/tool-gaps", label: "Tool gaps", rail: "footer" },
  ]);

  /** Landing mode when the URL has no hash (docs/ui/REDESIGN.md). */
  const DEFAULT_MODE = "hunts";

  function primaryNav(nav) {
    return (nav || RUN_NAV).filter((item) => item.kind === "mode" && item.rail === "primary");
  }

  function workspaceModes(nav) {
    return (nav || RUN_NAV).filter((item) => item.kind === "mode");
  }

  function headNav(nav) {
    return (nav || RUN_NAV).filter((item) => item.rail === "head");
  }

  function footerNav(nav) {
    return (nav || RUN_NAV).filter((item) => item.rail === "footer");
  }

  function isRunMode(mode) {
    return workspaceModes(RUN_NAV).some((item) => item.mode === mode);
  }

  function defaultTabFor(mode) {
    const item = workspaceModes(RUN_NAV).find((row) => row.mode === mode);
    return item ? item.defaultTab : null;
  }

  function isOverlayMode(mode) {
    const item = workspaceModes(RUN_NAV).find((row) => row.mode === mode);
    return !!(item && item.overlay);
  }

  return {
    RUN_NAV,
    primaryNav,
    workspaceModes,
    headNav,
    footerNav,
    isRunMode,
    defaultTabFor,
    isOverlayMode,
    DEFAULT_MODE,
  };
});
