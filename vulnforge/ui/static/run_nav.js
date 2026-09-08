/**
 * Run-page rail table. UMD for node --test and the browser (modes.js).
 *
 * @typedef {{
 *   kind: "mode",
 *   id: string,
 *   mode: "mission"|"hunts"|"explorer"|"report"|"evidence"|"audit"|"ai",
 *   label: string,
 *   defaultTab: string
 * }} ModeNavItem
 *
 * @typedef {{
 *   kind: "href",
 *   id: string,
 *   href: string,
 *   label: string
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
    { kind: "mode", id: "mission", mode: "mission", label: "Mission", defaultTab: "overview" },
    { kind: "mode", id: "hunts", mode: "hunts", label: "Hunts", defaultTab: "hunts" },
    { kind: "mode", id: "explorer", mode: "explorer", label: "Explorer", defaultTab: "explorer" },
    { kind: "mode", id: "report", mode: "report", label: "Report", defaultTab: "report" },
    { kind: "mode", id: "evidence", mode: "evidence", label: "Evidence", defaultTab: "evidence" },
    { kind: "mode", id: "audit", mode: "audit", label: "Tasks", defaultTab: "tasks" },
    { kind: "mode", id: "ai", mode: "ai", label: "AI", defaultTab: "ai" },
    { kind: "href", id: "dev", href: "/dev", label: "Dev" },
    { kind: "href", id: "settings", href: "/settings", label: "Settings" },
  ]);

  function primaryNav(nav) {
    return (nav || RUN_NAV).filter((item) => item.kind === "mode");
  }

  function footerNav(nav) {
    return (nav || RUN_NAV).filter((item) => item.kind === "href");
  }

  function isRunMode(mode) {
    return primaryNav(RUN_NAV).some((item) => item.mode === mode);
  }

  function defaultTabFor(mode) {
    const item = primaryNav(RUN_NAV).find((row) => row.mode === mode);
    return item ? item.defaultTab : null;
  }

  return {
    RUN_NAV,
    primaryNav,
    footerNav,
    isRunMode,
    defaultTabFor,
  };
});
