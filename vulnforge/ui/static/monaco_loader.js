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
    monaco.editor.defineTheme("vulnforge-cockpit", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment", foreground: "9a8a9c", fontStyle: "italic" },
        { token: "string", foreground: "f0b429" },
        { token: "keyword", foreground: "ff7a9a" },
        { token: "number", foreground: "7eb8e8" },
        { token: "type", foreground: "c78bff" }
      ],
      colors: {
        "editor.background": "#08060c",
        "editor.foreground": "#f2e8ef",
        "editorLineNumber.foreground": "#9a8a9c",
        "editorLineNumber.activeForeground": "#ff7a9a",
        "editor.selectionBackground": "#ff3d6e55",
        "editor.inactiveSelectionBackground": "#ff3d6e33",
        "editor.lineHighlightBackground": "#1a152288",
        "editorCursor.foreground": "#ff3d6e",
        "editorWidget.background": "#121018",
        "editorWidget.border": "#3a2e44",
        "editorIndentGuide.background": "#3a2e4488",
        "editorGutter.background": "#08060c",
        "scrollbarSlider.background": "#3a2e4488",
        "scrollbarSlider.hoverBackground": "#564458aa"
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
