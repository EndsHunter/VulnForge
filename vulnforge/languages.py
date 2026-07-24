"""Central language / extension / entrypoint catalog for code_static audits.

Single source of truth for:
  - extension → language name
  - source-worthy extensions (file_by_file, binary-vs-source heuristics)
  - entrypoint basenames + project-file suffixes (inventory + codemap)
  - package / workspace markers (codemap package roots)
  - code extensions scanned for sinks and import edges

Web/script stacks (Python, JS/TS, Go, Rust) remain first-class; this module
also covers systems and legacy stacks that are easy to miss: C, C++, Ada,
Java, Perl, Fortran, COBOL, Pascal/Delphi, assembly, CUDA, etc.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

# ---------------------------------------------------------------------------
# Extension → language id (short, stable, lowercase)
# ---------------------------------------------------------------------------

EXT_TO_LANGUAGE: dict[str, str] = {
    # Python
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    # JavaScript / TypeScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".vue": "vue",
    ".svelte": "svelte",
    # JVM
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".sc": "scala",
    ".groovy": "groovy",
    ".gradle": "gradle",
    # .NET
    ".cs": "csharp",
    ".fs": "fsharp",
    ".fsi": "fsharp",
    ".fsx": "fsharp",
    ".vb": "vbnet",
    ".vbs": "vbscript",
    ".bas": "basic",
    # C / C++ / ObjC
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".c++": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".h++": "cpp",
    ".inl": "cpp",
    ".ipp": "cpp",
    ".ixx": "cpp",  # C++ modules
    ".m": "objc",
    ".mm": "objcpp",
    # Ada
    ".ads": "ada",
    ".adb": "ada",
    ".ada": "ada",
    ".gpr": "ada",  # GNAT project
    # Fortran
    ".f": "fortran",
    ".for": "fortran",
    ".f77": "fortran",
    ".f90": "fortran",
    ".f95": "fortran",
    ".f03": "fortran",
    ".f08": "fortran",
    # COBOL
    ".cob": "cobol",
    ".cbl": "cobol",
    ".cpy": "cobol",
    # Pascal / Delphi
    ".pas": "pascal",
    ".pp": "pascal",
    ".dpr": "delphi",
    ".dpk": "delphi",
    ".lpr": "pascal",
    # Perl / Raku
    ".pl": "perl",
    ".pm": "perl",
    ".t": "perl",
    ".psgi": "perl",
    ".pod": "perl",
    ".p6": "raku",
    ".raku": "raku",
    ".rakumod": "raku",
    # Ruby / PHP / shell
    ".rb": "ruby",
    ".rake": "ruby",
    ".php": "php",
    ".phtml": "php",
    ".inc": "php",  # ambiguous; treated as php for inventory counts
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".fish": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".bat": "batch",
    ".cmd": "batch",
    # Go / Rust / systems
    ".go": "go",
    ".rs": "rust",
    ".zig": "zig",
    ".nim": "nim",
    ".d": "d",
    ".cr": "crystal",
    ".v": "verilog",  # hardware HDL; V-lang is rare in enterprise trees
    # Swift
    ".swift": "swift",
    # Functional / Lisp family
    ".hs": "haskell",
    ".lhs": "haskell",
    ".ml": "ocaml",
    ".mli": "ocaml",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".cljc": "clojure",
    ".lisp": "lisp",
    ".cl": "common-lisp",  # also used by OpenCL; path/content disambiguates later
    ".scm": "scheme",
    ".rkt": "racket",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
    # Scripting / data
    ".lua": "lua",
    ".r": "r",
    ".jl": "julia",
    ".tcl": "tcl",
    ".dart": "dart",
    ".sol": "solidity",
    # Assembly
    ".s": "assembly",
    ".asm": "assembly",
    ".nasm": "assembly",
    # GPU
    ".cu": "cuda",
    ".cuh": "cuda",
    ".clkernel": "opencl",
    # IDL / RPC / schema often security-relevant
    ".proto": "protobuf",
    ".thrift": "thrift",
    ".avdl": "avro",
    ".graphql": "graphql",
    ".gql": "graphql",
    # SQL / data access
    ".sql": "sql",
    ".pls": "plsql",
    ".pkb": "plsql",
    ".pks": "plsql",
    # Build / native project files (counted as language-adjacent)
    ".cmake": "cmake",
    ".mk": "make",
    # VHDL / hardware (memory/side-channel adjacent audits)
    ".vhd": "vhdl",
    ".vhdl": "vhdl",
    ".sv": "systemverilog",
    # Web markup that carries sinks
    ".html": "html",
    ".htm": "html",
    ".xhtml": "html",
}

# Extensions worth hunting as source (file_by_file / source candidate).
SOURCE_EXTS: frozenset[str] = frozenset(
    {
        # Python
        ".py",
        ".pyi",
        ".pyw",
        # JS/TS
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".vue",
        ".svelte",
        # JVM
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".sc",
        ".groovy",
        # .NET
        ".cs",
        ".fs",
        ".fsi",
        ".fsx",
        ".vb",
        # C/C++/ObjC
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".hh",
        ".hxx",
        ".inl",
        ".ipp",
        ".ixx",
        ".m",
        ".mm",
        # Ada
        ".ads",
        ".adb",
        ".ada",
        # Fortran / COBOL / Pascal
        ".f",
        ".for",
        ".f90",
        ".f95",
        ".f03",
        ".f08",
        ".cob",
        ".cbl",
        ".pas",
        ".pp",
        ".dpr",
        # Perl / Raku
        ".pl",
        ".pm",
        ".t",
        ".psgi",
        ".p6",
        ".raku",
        ".rakumod",
        # Ruby / PHP
        ".rb",
        ".php",
        ".phtml",
        # Go / Rust / systems
        ".go",
        ".rs",
        ".zig",
        ".nim",
        ".d",
        ".cr",
        ".swift",
        # Functional
        ".hs",
        ".ml",
        ".mli",
        ".clj",
        ".cljs",
        ".ex",
        ".exs",
        ".erl",
        # Scripting
        ".lua",
        ".r",
        ".jl",
        ".tcl",
        ".dart",
        ".sol",
        # Shell / automation
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        # Assembly / GPU
        ".s",
        ".S",
        ".asm",
        ".cu",
        ".cuh",
        # Schema / SQL often carries injectable queries
        ".sql",
        ".pls",
        ".graphql",
        ".gql",
        ".proto",
        ".thrift",
        # Hardware description (when present in product trees)
        ".vhd",
        ".vhdl",
        ".sv",
    }
)

# Extensions scanned for mechanical sinks and import-edge scrape.
CODE_EXTS: frozenset[str] = SOURCE_EXTS | frozenset(
    {
        ".gpr",  # Ada project (text)
        ".cmake",
        ".html",
        ".htm",
        ".xhtml",
    }
)

# Languages where memory-safety / unsafe native interfaces apply.
MEMORY_SAFETY_LANGUAGES: frozenset[str] = frozenset(
    {
        "c",
        "cpp",
        "objc",
        "objcpp",
        "rust",  # only unsafe/FFI in practice; skill still applies
        "ada",  # Unchecked_Conversion, address overlays, interfaces.C
        "fortran",
        "assembly",
        "cuda",
        "zig",
        "d",
        "nim",  # when using ptr / emit
        "cobol",  # less common; buffer handling in legacy parsers
        "pascal",
        "delphi",
    }
)

# Basename markers: manifests, mains, framework boots (inventory + codemap).
ENTRYPOINT_NAMES: frozenset[str] = frozenset(
    {
        # Python
        "package.json",  # also JS — listed once
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "requirements.txt",
        "main.py",
        "app.py",
        "manage.py",
        "wsgi.py",
        "asgi.py",
        "routes.py",
        "views.py",
        "urls.py",
        "handler.py",
        "handlers.py",
        "controller.py",
        "controllers.py",
        "api.py",
        "__main__.py",
        # JS / TS
        "server.js",
        "server.ts",
        "index.js",
        "index.ts",
        "index.mjs",
        "app.js",
        "app.ts",
        "main.js",
        "main.ts",
        "next.config.js",
        "next.config.mjs",
        "vite.config.ts",
        "vite.config.js",
        "nuxt.config.ts",
        "angular.json",
        # Go / Rust
        "go.mod",
        "go.sum",
        "main.go",
        "Cargo.toml",
        "Cargo.lock",
        "main.rs",
        "lib.rs",
        # C / C++ build + mains
        "CMakeLists.txt",
        "Makefile",
        "makefile",
        "GNUmakefile",
        "meson.build",
        "configure.ac",
        "configure.in",
        "Makefile.am",
        "conanfile.txt",
        "conanfile.py",
        "vcpkg.json",
        "main.c",
        "main.cpp",
        "main.cc",
        "main.cxx",
        "Main.cpp",
        "Main.c",
        "app.c",
        "app.cpp",
        "program.cpp",
        # Ada
        "main.adb",
        "Main.adb",
        "alire.toml",
        # Java / JVM
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "Main.java",
        "Application.java",
        "App.java",
        "build.sbt",
        "build.xml",  # Ant
        # Perl
        "Makefile.PL",
        "Build.PL",
        "cpanfile",
        "app.psgi",
        "cpanfile.snapshot",
        # Ruby / PHP
        "Gemfile",
        "Rakefile",
        "config.ru",
        "composer.json",
        "index.php",
        "artisan",
        # .NET
        "Program.cs",
        "Startup.cs",
        "Program.fs",
        "global.json",
        "Directory.Build.props",
        # Swift / Apple
        "Package.swift",
        "main.swift",
        "AppDelegate.swift",
        # Elixir / Erlang
        "mix.exs",
        "rebar.config",
        # Haskell / OCaml
        "stack.yaml",
        "cabal.project",
        "dune-project",
        # Containers / deploy (surface markers)
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "Containerfile",
        # Misc mains
        "main.d",
        "main.zig",
        "main.nim",
        "main.go",
        "Main.pas",
        "program.pas",
        # Fortran
        "main.f90",
        "main.f",
        "program.f90",
    }
)

# Suffix-based project / solution files treated as entrypoints when basename
# is not in the fixed set (e.g. MyApp.gpr, Foo.sln, Bar.vcxproj).
ENTRYPOINT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".gpr",  # Ada GNAT project
        ".sln",
        ".vcxproj",
        ".csproj",
        ".fsproj",
        ".vbproj",
        ".vcproj",
        ".xcodeproj",  # directory often; suffix match on name rare
        ".pbxproj",
        ".pro",  # qmake
        ".cbp",  # Code::Blocks
    }
)

# Package / workspace markers for codemap package roots.
PACKAGE_MARKERS: frozenset[str] = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Pipfile",
        "go.mod",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "composer.json",
        "Gemfile",
        "mix.exs",
        "__init__.py",
        "CMakeLists.txt",
        "meson.build",
        "Makefile",
        "makefile",
        "alire.toml",
        "cpanfile",
        "Makefile.PL",
        "Build.PL",
        "Package.swift",
        "stack.yaml",
        "cabal.project",
        "dune-project",
        "build.sbt",
        "rebar.config",
        "vcpkg.json",
        "conanfile.txt",
        "conanfile.py",
        "Directory.Build.props",
        "global.json",
    }
)

# Runnable PoC extensions (workshop / develop_poc).
POC_CODE_EXTS: frozenset[str] = frozenset(
    {
        ".py",
        ".sh",
        ".ps1",
        ".c",
        ".cpp",
        ".cc",
        ".h",
        ".go",
        ".js",
        ".ts",
        ".rb",
        ".rs",
        ".java",
        ".pl",
        ".pm",
        ".adb",
        ".ads",
        ".cs",
        ".php",
        ".lua",
        ".zig",
    }
)

# Special basenames always treated as code for sink scan (no extension).
CODE_BASENAMES: frozenset[str] = frozenset(
    {
        "Dockerfile",
        "Containerfile",
        "Makefile",
        "makefile",
        "GNUmakefile",
        "CMakeLists.txt",
        "meson.build",
        "Rakefile",
        "Gemfile",
        "cpanfile",
        "Vagrantfile",
    }
)


def language_for_extension(ext: str | None) -> Optional[str]:
    """Map a file extension (with or without dot) to a language id."""
    if not ext:
        return None
    e = str(ext).strip().lower()
    if not e:
        return None
    if not e.startswith("."):
        e = "." + e
    # .R is stored with capital R in EXT_TO_LANGUAGE; normalize
    if e == ".r":
        return "r"
    return EXT_TO_LANGUAGE.get(e)


def language_for_path(path: str | Path) -> Optional[str]:
    p = Path(path)
    return language_for_extension(p.suffix)


def languages_from_extensions(
    extensions: Mapping[str, Any] | None,
    *,
    limit: int = 30,
) -> dict[str, int]:
    """Aggregate extension histogram into language-name → count."""
    counts: Counter[str] = Counter()
    if not extensions:
        return {}
    for ext, n in extensions.items():
        try:
            num = int(n)
        except (TypeError, ValueError):
            continue
        if num <= 0:
            continue
        e = str(ext).strip().lower()
        if not e or e == "<none>":
            continue
        if not e.startswith("."):
            e = "." + e
        lang = language_for_extension(e) or e.lstrip(".")
        counts[lang] += num
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if limit > 0:
        items = items[:limit]
    return {k: int(v) for k, v in items}


# Case-insensitive main basenames (Windows trees / mixed case checkouts).
_ENTRYPOINT_NAMES_LOWER: frozenset[str] = frozenset(n.lower() for n in ENTRYPOINT_NAMES)

_CASEFOLD_MAINS: frozenset[str] = frozenset(
    {
        "main.c",
        "main.cpp",
        "main.cc",
        "main.cxx",
        "main.adb",
        "main.java",
        "application.java",
        "app.java",
        "program.cs",
        "main.go",
        "main.rs",
        "main.py",
        "main.f90",
        "main.swift",
        "main.zig",
        "main.nim",
    }
)


def is_entrypoint_name(name: str) -> bool:
    """True when basename (or path leaf) is an entrypoint/project marker."""
    base = Path(str(name).replace("\\", "/")).name
    if base in ENTRYPOINT_NAMES:
        return True
    low = base.lower()
    if low in _CASEFOLD_MAINS:
        return True
    # Exact case-insensitive match against known markers (package.json etc.)
    if low in _ENTRYPOINT_NAMES_LOWER and low not in {
        "makefile",
        "gnumakefile",
    }:
        # Allow common case variants of listed names (e.g. Dockerfile)
        if any(n.lower() == low for n in ENTRYPOINT_NAMES):
            return True
    suf = Path(base).suffix.lower()
    if suf in ENTRYPOINT_SUFFIXES:
        return True
    return False


def is_source_extension(ext: str | None) -> bool:
    if not ext:
        return False
    e = str(ext).strip().lower()
    if not e.startswith("."):
        e = "." + e
    return e in SOURCE_EXTS


def is_code_extension(ext: str | None, name: str | None = None) -> bool:
    if name and Path(name).name in CODE_BASENAMES:
        return True
    if not ext:
        return False
    e = str(ext).strip().lower()
    if not e.startswith("."):
        e = "." + e
    return e in CODE_EXTS


def is_memory_safety_language(lang: str | None) -> bool:
    if not lang:
        return False
    return str(lang).strip().lower() in MEMORY_SAFETY_LANGUAGES


def inventory_languages(inventory: Mapping[str, Any] | None) -> dict[str, int]:
    """Prefer inventory['languages']; else derive from extensions."""
    if not inventory:
        return {}
    langs = inventory.get("languages")
    if isinstance(langs, dict) and langs:
        out: dict[str, int] = {}
        for k, v in langs.items():
            try:
                out[str(k)] = int(v)
            except (TypeError, ValueError):
                continue
        return out
    return languages_from_extensions(inventory.get("extensions") or {})


def source_ext_set_for_profile() -> set[str]:
    """Broad set used by CodeStaticProfile binary-vs-source heuristic."""
    return set(SOURCE_EXTS)


def summarize_stack(extensions: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compact stack summary for packets / UI."""
    langs = languages_from_extensions(extensions)
    native = {
        k: v
        for k, v in langs.items()
        if is_memory_safety_language(k)
    }
    return {
        "languages": langs,
        "native_or_memory_safety": native,
        "has_c_cpp": any(k in langs for k in ("c", "cpp", "objc", "objcpp")),
        "has_ada": "ada" in langs,
        "has_java": any(k in langs for k in ("java", "kotlin", "scala", "groovy")),
        "has_perl": any(k in langs for k in ("perl", "raku")),
        "has_managed_web": any(
            k in langs
            for k in ("python", "javascript", "typescript", "php", "ruby", "go")
        ),
    }


def attach_languages_to_inventory(inv: dict[str, Any]) -> dict[str, Any]:
    """Mutate/return inventory with languages + stack_summary fields."""
    exts = inv.get("extensions") or {}
    langs = languages_from_extensions(exts if isinstance(exts, dict) else {})
    inv["languages"] = langs
    inv["stack_summary"] = summarize_stack(exts if isinstance(exts, dict) else {})
    return inv
