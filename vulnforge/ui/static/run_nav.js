/**
 * Run-page nav table. UMD for node --test and the browser (modes.js).
 *
 * One frozen table. `rail` is the only slot field (`"head"|"primary"|"footer"|null`).
 * `primaryNav` is the four rail modes. `workspaceModes` is all seven `kind === "mode"`
 * items. `isRunMode` / `defaultTabFor` read `workspaceModes`, never `primaryNav`.
 * AI is overlay (`overlay: true`), not a rail mode.
 *
 * @typedef {{
 *   kind: "mode",
 *   id: string,
 *   mode: "mission"|"hunts"|"explorer"|"report"|"evidence"|"audit"|"ai",
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
    { kind: "mode", id: "mission", mode: "mission", label: "Mission", defaultTab: "overview", rail: "primary" },
    { kind: "mode", id: "hunts", mode: "hunts", label: "Hunts", defaultTab: "hunts", rail: "primary" },
    { kind: "mode", id: "explorer", mode: "explorer", label: "Explorer", defaultTab: "explorer", rail: "primary" },
    { kind: "mode", id: "report", mode: "report", label: "Report", defaultTab: "report", rail: "primary" },
    { kind: "mode", id: "evidence", mode: "evidence", label: "Evidence", defaultTab: "evidence", rail: null },
    { kind: "mode", id: "audit", mode: "audit", label: "Tasks", defaultTab: "tasks", rail: null },
    { kind: "mode", id: "ai", mode: "ai", label: "AI", defaultTab: "ai", rail: null, overlay: true },
    { kind: "href", id: "settings", href: "/settings", label: "Settings", rail: "footer" },
    { kind: "href", id: "dev", href: "/dev", label: "Dev", rail: "footer" },
    { kind: "href", id: "tool-gaps", href: "/tool-gaps", label: "Tool gaps", rail: "footer" },
  ]);

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
  };
});
