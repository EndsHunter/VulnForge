/* VulnForge Monaco boot — local AMD loader (Ticket 5). */
(function () {
  "use strict";
  if (window.__vfMonacoBootStarted) return;
  window.__vfMonacoBootStarted = true;

  var vs = "/static/vendor/monaco/vs";
  window.require = window.require || {};
  window.require.paths = window.require.paths || {};
  window.require.paths.vs = vs;

  function onReady() {
    var req = window.require;
    if (typeof req !== "function") return;
    req(["vs/editor/editor.main"], function () {
      window.__vfMonacoReady = true;
      if (window.VulnForgeMonaco && window.VulnForgeMonaco.defineCockpitTheme && window.monaco) {
        window.VulnForgeMonaco.defineCockpitTheme(window.monaco);
      }
    });
  }

  // Prefer a pre-placed loader script tag; otherwise inject local vendor loader.
  var existing = document.querySelector("script[data-vf-monaco-vendor]");
  if (existing) {
    if (typeof window.require === "function") onReady();
    else existing.addEventListener("load", onReady);
    return;
  }

  var s = document.createElement("script");
  s.src = vs + "/loader.js";
  s.async = true;
  s.setAttribute("data-vf-monaco-vendor", "1");
  s.onload = onReady;
  s.onerror = function () {
    console.warn("[VulnForge] Monaco vendor loader failed");
  };
  document.head.appendChild(s);
})();
