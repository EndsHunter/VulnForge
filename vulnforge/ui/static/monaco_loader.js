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
    // Pairing: bg-inset #0b0d10, text #e7e9ee, muted #a2aab6, accent #5cc8b8,
    // accent-bright #8fe0d4, bg-card #1d2129, bg-card-hover #232833,
    // border #2a2f39, border-strong #3a414c.
    monaco.editor.defineTheme("vulnforge-cockpit", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment", foreground: "a2aab6", fontStyle: "italic" },
        { token: "string", foreground: "e3a01a" },
        { token: "keyword", foreground: "8fe0d4" },
        { token: "number", foreground: "8bb8b3" },
        { token: "type", foreground: "c3a6ff" }
      ],
      colors: {
        "editor.background": "#0b0d10",
        "editor.foreground": "#e7e9ee",
        "editorLineNumber.foreground": "#a2aab6",
        "editorLineNumber.activeForeground": "#8fe0d4",
        "editor.selectionBackground": "#5cc8b855",
        "editor.inactiveSelectionBackground": "#5cc8b833",
        "editor.lineHighlightBackground": "#23283388",
        "editorCursor.foreground": "#5cc8b8",
        "editorWidget.background": "#1d2129",
        "editorWidget.border": "#2a2f39",
        "editorIndentGuide.background": "#2a2f3988",
        "editorGutter.background": "#0b0d10",
        "scrollbarSlider.background": "#2a2f3988",
        "scrollbarSlider.hoverBackground": "#3a414caa"
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
