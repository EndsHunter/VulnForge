"""Orchestrate symbol extraction for codemap build."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vulnforge.tools.symbols.heuristic import extract_file_symbols, language_for_path
from vulnforge.tools.symbols.types import as_symbol_dict
from vulnforge.util import normalize_relpath

# Prefer code-ish extensions (aligned with languages.CODE_EXTS subset + more)
_CODE_EXTS = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hpp",
        ".hh",
        ".hxx",
        ".rb",
        ".php",
        ".cs",
        ".kt",
        ".kts",
        ".swift",
        ".pl",
        ".pm",
        ".ads",
        ".adb",
    }
)


def symbol_backend_available(backend: str = "auto") -> dict[str, Any]:
    """Report which backends can run in this environment."""
    b = (backend or "auto").strip().lower()
    tree = False
    try:
        import tree_sitter  # noqa: F401

        tree = True
    except ImportError:
        tree = False
    if b == "none":
        resolved = "none"
    elif b == "tree_sitter":
        resolved = "tree_sitter" if tree else "none"
    elif b == "heuristic":
        resolved = "heuristic"
    else:  # auto
        resolved = "tree_sitter" if tree else "heuristic"
    return {
        "requested": b,
        "resolved": resolved,
        "tree_sitter": tree,
        "heuristic": True,
    }


def extract_symbols(
    root: Path,
    files: list[str],
    *,
    cfg: Optional[dict] = None,
    module_paths: Optional[list[str]] = None,
    module_for_path=None,
) -> dict[str, Any]:
    """Extract symbols for *files* under *root*.

    Returns dict:
      symbols: list[dict]
      files: list[dict]  (file index with counts)
      backend: str
      truncated: bool
      languages: list[str]
    """
    opts = _opts(cfg)
    if not opts["symbols_enabled"] or opts["backend"] == "none":
        return {
            "symbols": [],
            "files": [],
            "backend": "none",
            "truncated": False,
            "languages": [],
        }

    info = symbol_backend_available(opts["backend"])
    resolved = info["resolved"]
    if resolved == "none":
        return {
            "symbols": [],
            "files": [],
            "backend": "none",
            "truncated": False,
            "languages": [],
        }

    # Prefer tree_sitter when resolved; fall back to heuristic on failure.
    use_tree = resolved == "tree_sitter"
    root = Path(root)
    code_files = [
        normalize_relpath(f)
        for f in files
        if Path(f).suffix.lower() in _CODE_EXTS
    ]
    # Stable shallow-first scan
    code_files = sorted(code_files, key=lambda f: (f.count("/"), f))[
        : opts["max_symbol_files"]
    ]

    symbols: list[dict[str, Any]] = []
    file_recs: list[dict[str, Any]] = []
    langs: set[str] = set()
    truncated = False
    mod_paths = list(module_paths or [])

    for rel in code_files:
        if len(symbols) >= opts["max_symbols"]:
            truncated = True
            break
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Cap read size for pathological files
        if len(text) > 1_500_000:
            text = text[:1_500_000]
            truncated = True

        per_file_cap = min(
            opts["max_symbols_per_file"],
            opts["max_symbols"] - len(symbols),
        )
        if per_file_cap <= 0:
            truncated = True
            break

        file_syms: list[dict[str, Any]] = []
        if use_tree:
            try:
                from vulnforge.tools.symbols.tree_sitter_backend import (
                    extract_file_symbols_tree_sitter,
                )

                file_syms = extract_file_symbols_tree_sitter(
                    rel,
                    text,
                    max_symbols=per_file_cap,
                    max_sig_chars=opts["max_signature_chars"],
                )
            except Exception:
                file_syms = []
            if not file_syms and language_for_path(rel):
                # fall back per-file if grammar missing
                file_syms = extract_file_symbols(
                    rel,
                    text,
                    max_symbols=per_file_cap,
                    max_sig_chars=opts["max_signature_chars"],
                )
        else:
            file_syms = extract_file_symbols(
                rel,
                text,
                max_symbols=per_file_cap,
                max_sig_chars=opts["max_signature_chars"],
            )

        mod_id = ""
        if callable(module_for_path) and mod_paths:
            try:
                mp = module_for_path(rel, mod_paths)
                if mp:
                    mod_id = f"mod:{normalize_relpath(mp)}"
            except Exception:
                mod_id = ""

        for s in file_syms:
            s = as_symbol_dict(s)
            s["module_id"] = mod_id or s.get("module_id") or ""
            s["path"] = rel
            if s.get("language"):
                langs.add(str(s["language"]))
            symbols.append(s)
            if len(symbols) >= opts["max_symbols"]:
                truncated = True
                break

        lang = language_for_path(rel) or (
            str(file_syms[0].get("language") or "") if file_syms else ""
        )
        if lang:
            langs.add(lang)
        file_recs.append(
            {
                "path": rel,
                "module_id": mod_id,
                "language": lang,
                "symbol_count": len(file_syms),
            }
        )

    backend_label = resolved
    if use_tree and not any(s.get("language") for s in symbols[:1]) and symbols:
        pass
    # If tree was requested but we only got heuristic content, still report
    # tree_sitter when import worked — actual quality may be mixed (partial).
    if use_tree and info.get("tree_sitter") and not symbols and file_recs:
        backend_label = "partial"

    return {
        "symbols": symbols,
        "files": file_recs,
        "backend": backend_label,
        "truncated": truncated,
        "languages": sorted(langs),
    }


def _opts(cfg: Optional[dict]) -> dict[str, Any]:
    c = (cfg or {}).get("codemap") if isinstance(cfg, dict) else None
    if not isinstance(c, dict):
        c = {}
    backend = str(c.get("symbol_backend") or "auto").strip().lower()
    if backend not in ("auto", "tree_sitter", "heuristic", "none"):
        backend = "auto"
    return {
        "symbols_enabled": bool(c.get("symbols_enabled", True)),
        "backend": backend,
        "max_symbol_files": max(0, int(c.get("max_symbol_files", 5000))),
        "max_symbols": max(0, int(c.get("max_symbols", 100_000))),
        "max_symbols_per_file": max(1, int(c.get("max_symbols_per_file", 500))),
        "max_signature_chars": max(40, int(c.get("max_signature_chars", 240))),
    }
