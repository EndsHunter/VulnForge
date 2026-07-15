"""
Init-time run strategies: plan hunt queues without (or with) recon.

Strategies (stored in runs.config_json run.strategy):
  - discovery     — enqueue recon only (default)
  - file_by_file  — enqueue hunts for each source file x default classes
  - recon_docs    — ingest docs + recon with operator brief from digest
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Optional

from vulnforge.hunt_profiles import active_class_ids
from vulnforge.tools.grep_index import build_file_index
from vulnforge.util import normalize_relpath

# Source-ish extensions worth hunting; skip media/binary by default.
SOURCE_EXTS = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".rb",
        ".php",
        ".cs",
        ".fs",
        ".swift",
        ".m",
        ".mm",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".hh",
        ".sql",
        ".graphql",
        ".gql",
        ".vue",
        ".svelte",
        ".r",
        ".jl",
        ".lua",
        ".pl",
        ".pm",
        ".ex",
        ".exs",
        ".erl",
        ".hs",
        ".clj",
        ".cljs",
        ".dart",
        ".zig",
        ".nim",
        ".sh",
        ".bash",
        ".ps1",
        ".bat",
        ".cmd",
    }
)

BINARY_EXTS = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".o",
        ".a",
        ".lib",
        ".obj",
        ".class",
        ".pyc",
        ".pyo",
        ".wasm",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".mp3",
        ".mp4",
        ".wav",
        ".avi",
        ".mov",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".7z",
        ".rar",
        ".pdf",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".jar",
        ".war",
        ".ear",
        ".whl",
        ".egg",
        ".min.js",  # not a real ext; handled below
    }
)

# Priority: entrypoints and shallow paths first (lower number = higher priority).
ENTRYPOINT_NAMES = frozenset(
    {
        "main.py",
        "app.py",
        "manage.py",
        "server.js",
        "index.js",
        "index.ts",
        "main.go",
        "main.rs",
        "main.c",
        "main.cpp",
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
        "app.js",
        "app.ts",
    }
)

# Skip files larger than this (bytes) as "huge".
MAX_FILE_BYTES = 400_000
# Heuristic: high null-byte ratio => binary-ish
BINARY_NULL_PROBE = 8192


def _is_binary_ish(path: Path) -> bool:
    ext = path.suffix.lower()
    if ext in BINARY_EXTS:
        return True
    name = path.name.lower()
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    try:
        with path.open("rb") as f:
            chunk = f.read(BINARY_NULL_PROBE)
        if not chunk:
            return False
        if b"\x00" in chunk:
            return True
        # High non-text control character ratio
        textish = sum(1 for b in chunk if b in (9, 10, 13) or 32 <= b < 127)
        if textish / max(1, len(chunk)) < 0.75:
            return True
    except OSError:
        return True
    return False


def _is_source_candidate(path: Path, rel: str) -> bool:
    if path.suffix.lower() not in SOURCE_EXTS:
        return False
    if _is_binary_ish(path):
        return False
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    return True


def _priority_key(rel: str) -> tuple:
    """Sort key: entrypoints first, then shallow paths, then name."""
    rel_n = normalize_relpath(rel)
    name = Path(rel_n).name
    depth = rel_n.count("/")
    is_entry = 0 if name in ENTRYPOINT_NAMES else 1
    # Prefer non-test paths slightly
    is_test = 1 if (
        "/test" in f"/{rel_n.lower()}"
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.js")
        or name.endswith(".spec.ts")
        or name.endswith(".spec.js")
    ) else 0
    return (is_entry, is_test, depth, rel_n)


def list_source_files(
    target: Path,
    ignore: Optional[Iterable[str]] = None,
) -> list[str]:
    """Return normalized relative paths of hunt-worthy source files, priority-sorted."""
    target = Path(target).resolve()
    inv = build_file_index(target, list(ignore or []))
    # Prefer full walk over sample_paths (sample is capped at 500)
    globs = list(ignore or [])
    from vulnforge.tools.grep_index import _ignored  # local helper

    rels: list[str] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        rel = normalize_relpath(str(path.relative_to(target)))
        if _ignored(rel, globs):
            continue
        if not _is_source_candidate(path, rel):
            continue
        rels.append(rel)
    # If walk empty but index has samples, fall back
    if not rels:
        for rel in inv.get("sample_paths") or []:
            p = target / rel
            if p.is_file() and _is_source_candidate(p, rel):
                rels.append(normalize_relpath(rel))
    rels.sort(key=_priority_key)
    return rels


def plan_file_by_file_hunts(
    target: Path,
    ignore: Optional[Iterable[str]] = None,
    max_tasks: int = 50,
    classes: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """
    Plan hunt task payloads: each source file x class, capped by max_tasks.

    Priority order (entrypoints / shallow first). Skips huge and binary-ish files.
    Area is the top-level directory (or 'app' for root files).
    """
    target = Path(target).resolve()
    use_classes = list(classes) if classes else list(active_class_ids())
    if not use_classes:
        use_classes = list(active_class_ids())
    max_tasks = max(0, int(max_tasks))
    if max_tasks == 0:
        return []

    files = list_source_files(target, ignore)
    payloads: list[dict[str, Any]] = []
    for rel in files:
        if len(payloads) >= max_tasks:
            break
        rel_n = normalize_relpath(rel)
        parts = rel_n.split("/")
        area = parts[0] if len(parts) > 1 else "app"
        for cls in use_classes:
            if len(payloads) >= max_tasks:
                break
            payloads.append(
                {
                    "area": area,
                    "class": cls,
                    "path_hints": [rel_n],
                    "strategy": "file_by_file",
                    "operator_notes": (
                        f"file_by_file strategy: focus on `{rel_n}` "
                        f"for weakness class `{cls}`."
                    ),
                }
            )
    return payloads


STRATEGY_DISCOVERY = "discovery"
STRATEGY_FILE_BY_FILE = "file_by_file"
STRATEGY_RECON_DOCS = "recon_docs"
VALID_STRATEGIES = frozenset(
    {STRATEGY_DISCOVERY, STRATEGY_FILE_BY_FILE, STRATEGY_RECON_DOCS}
)
