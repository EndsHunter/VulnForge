/* VulnForge Monaco helpers (Ticket 5). Loader script tags live in run.html. */
(function (root) {
  "use strict";

  var EXT_LANG = {
    js: "javascript",
    mjs: "javascript",
    cjs: "javascript",
    jsx: "javascript",
    ts: "typescript",
    tsx: "typescript",
    py: "python",
    rb: "ruby",
    go: "go",
    rs: "rust",
    java: "java",
    kt: "kotlin",
    c: "c",
    h: "c",
    cpp: "cpp",
    cc: "cpp",
    cxx: "cpp",
    hpp: "cpp",
    cs: "csharp",
    php: "php",
    md: "markdown",
    markdown: "markdown",
    json: "json",
    yaml: "yaml",
    yml: "yaml",
    toml: "ini",
    ini: "ini",
    html: "html",
    htm: "html",
    css: "css",
    scss: "scss",
    less: "less",
    sh: "shell",
    bash: "shell",
    zsh: "shell",
    sql: "sql",
    xml: "xml",
    svg: "xml",
    dockerfile: "dockerfile",
    makefile: "plaintext",
    mk: "plaintext",
    txt: "plaintext",
    log: "plaintext"
  };

  function languageFromPath(path) {
    var base = String(path || "").split(/[/\\]/).pop() || "";
    var lower = base.toLowerCase();
    if (lower === "dockerfile" || lower.indexOf("dockerfile.") === 0) return "dockerfile";
    if (lower === "makefile" || lower === "gnumakefile") return "plaintext";
    var dot = lower.lastIndexOf(".");
    if (dot < 0) return "plaintext";
    return EXT_LANG[lower.slice(dot + 1)] || "plaintext";
  }

  function defineCockpitTheme(monaco) {
    if (!monaco || monaco.__vfCockpitTheme) return;
    // Hex only: monaco.editor.defineTheme does not accept CSS variables.
    // Pairing: bg-inset #121317, text #ece7dc, muted #9a9488, accent #6aa8a2,
    // accent-bright #8bc0bb, bg-card #26272e, bg-card-hover #2c2d35,
    // border #2d2e32, border-strong #3a3b40.
    monaco.editor.defineTheme("vulnforge-cockpit", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment", foreground: "9a9488", fontStyle: "italic" },
        { token: "string", foreground: "e3a01a" },
        { token: "keyword", foreground: "8bc0bb" },
        { token: "number", foreground: "8bb8b3" },
        { token: "type", foreground: "c3a6ff" }
      ],
      colors: {
        "editor.background": "#121317",
        "editor.foreground": "#ece7dc",
        "editorLineNumber.foreground": "#9a9488",
        "editorLineNumber.activeForeground": "#8bc0bb",
        "editor.selectionBackground": "#6aa8a255",
        "editor.inactiveSelectionBackground": "#6aa8a233",
        "editor.lineHighlightBackground": "#2c2d3588",
        "editorCursor.foreground": "#6aa8a2",
        "editorWidget.background": "#26272e",
        "editorWidget.border": "#2d2e32",
        "editorIndentGuide.background": "#2d2e3288",
        "editorGutter.background": "#121317",
        "scrollbarSlider.background": "#2d2e3288",
        "scrollbarSlider.hoverBackground": "#3a3b40aa"
      }
    });
    monaco.__vfCockpitTheme = true;
  }

  function whenMonacoReady(cb, attempts) {
    attempts = attempts == null ? 80 : attempts;
    if (root.monaco && root.monaco.editor) {
      defineCockpitTheme(root.monaco);
      cb(null, root.monaco);
      return;
    }
    if (attempts <= 0) {
      cb(new Error("Monaco not available"));
      return;
    }
    setTimeout(function () {
      whenMonacoReady(cb, attempts - 1);
    }, 50);
  }

  function loadMonaco() {
    return new Promise(function (resolve, reject) {
      whenMonacoReady(function (err, monaco) {
        if (err) reject(err);
        else resolve(monaco);
      });
    });
  }

  var api = {
    MONACO_VERSION: "0.52.2",
    languageFromPath: languageFromPath,
    loadMonaco: loadMonaco,
    defineCockpitTheme: defineCockpitTheme,
    whenMonacoReady: whenMonacoReady
  };

  root.VulnForgeMonaco = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
