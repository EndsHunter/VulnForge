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
    // Pairing: bg-inset #0a0e13, text #e8eef6, muted #8b9bb0, accent #f97316,
    // accent-bright #fb923c, bg-card #141b24, bg-card-hover #1a232e,
    // border #243044, border-strong #33465c.
    monaco.editor.defineTheme("vulnforge-cockpit", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment", foreground: "8b9bb0", fontStyle: "italic" },
        { token: "string", foreground: "f0b429" },
        { token: "keyword", foreground: "fb923c" },
        { token: "number", foreground: "7eb8e8" },
        { token: "type", foreground: "c78bff" }
      ],
      colors: {
        "editor.background": "#0a0e13",
        "editor.foreground": "#e8eef6",
        "editorLineNumber.foreground": "#8b9bb0",
        "editorLineNumber.activeForeground": "#fb923c",
        "editor.selectionBackground": "#f9731655",
        "editor.inactiveSelectionBackground": "#f9731633",
        "editor.lineHighlightBackground": "#1a232e88",
        "editorCursor.foreground": "#f97316",
        "editorWidget.background": "#141b24",
        "editorWidget.border": "#243044",
        "editorIndentGuide.background": "#24304488",
        "editorGutter.background": "#0a0e13",
        "scrollbarSlider.background": "#24304488",
        "scrollbarSlider.hoverBackground": "#33465caa"
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
