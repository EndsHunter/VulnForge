"""Heuristic symbol / definition finder (no full language server)."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from vulnforge.tools.grep_index import _ignored, _iter_candidate_files, _norm_grep_extension
from vulnforge.tools.scope import attach_scope_warning, maybe_soft_jail, scope_roots_for_scan
from vulnforge.util import normalize_relpath

# Language-ish definition patterns. {name} is replaced with escaped symbol.
_DEF_TEMPLATES: list[tuple[str, str]] = [
    ("python", r"^\s*(?:async\s+)?def\s+{name}\s*\("),
    ("python_class", r"^\s*class\s+{name}\b"),
    ("js_fn", r"^\s*(?:export\s+)?(?:async\s+)?function\s+{name}\s*\("),
    ("js_const", r"^\s*(?:export\s+)?(?:const|let|var)\s+{name}\s*="),
    ("go", r"^\s*func\s+(?:\([^)]+\)\s*)?{name}\s*\("),
    ("rust", r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{name}\s*[<\(]"),
    ("rust_struct", r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type)\s+{name}\b"),
    ("java", r"^\s*(?:public|private|protected|static|\s)+\s*[\w.<>,\[\]]+\s+{name}\s*\("),
    ("java_type", r"^\s*(?:public|private|protected)?\s*(?:class|interface|enum|record)\s+{name}\b"),
    ("c_fn", r"^\s*[\w\s\*]+\b{name}\s*\([^;]*\)\s*\{?\s*$"),
    ("c_define", r"^\s*#\s*define\s+{name}\b"),
    ("ada", r"^\s*(?:procedure|function)\s+{name}\b"),
    ("generic", r"^\s*(?:def|fn|func|function|class|struct|interface|type)\s+{name}\b"),
]


def find_symbol(
    ctx: dict,
    symbol: str,
    *,
    path: str | None = None,
    glob: str | None = None,
    extension: str | None = None,
    max_matches: int | None = None,
    definitions_only: bool = True,
) -> dict[str, Any]:
    """Locate likely definitions (and optionally all references) for a symbol."""
    try:
        name = str(symbol or "").strip()
        if not name or len(name) > 128:
            return {
                "ok": False,
                "error": "symbol required (non-empty, max 128 chars)",
            }
        if not re.match(r"^[A-Za-z_][\w\.]*$", name.replace("::", "_").replace(".", "_")):
            # Still allow common C++ / nested forms by relaxing check
            if not re.match(r"^[A-Za-z_~][\w:.\-]*$", name):
                return {"ok": False, "error": "symbol has invalid characters"}

        if path:
            soft = maybe_soft_jail(ctx, path)
            if soft is not None:
                return soft

        tools_cfg = (ctx.get("cfg") or {}).get("tools") or {}
        cap = int(max_matches or tools_cfg.get("max_symbol_matches", 40))
        cap = max(1, min(200, cap))
        timeout_s = float(tools_cfg.get("grep_timeout_seconds", 8.0))
        max_files = int(tools_cfg.get("max_grep_files", 8000))
        line_cap = int(tools_cfg.get("max_grep_line_chars", 200))

        root = Path(ctx["target_root"]).resolve()
        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        scope_roots = scope_roots_for_scan(ctx)
        scan_roots = [normalize_relpath(path)] if path else scope_roots
        ext_f = _norm_grep_extension(extension)
        glob_pat = str(glob).strip() if glob else None
        if ext_f and not glob_pat:
            glob_pat = f"*{ext_f}"

        escaped = re.escape(name)
        # Use replace (not str.format) so regex braces like [<\(] stay intact.
        def_rxs = [
            re.compile(tmpl.replace("{name}", escaped), re.MULTILINE)
            for _, tmpl in _DEF_TEMPLATES
        ]
        ref_rx = re.compile(rf"\b{escaped}\b")

        hits: list[dict[str, Any]] = []
        from fnmatch import fnmatch

        t0 = time.monotonic()
        files_scanned = 0
        truncated = False

        for path_obj in _iter_candidate_files(root, ignore, glob_pat, scan_roots):
            if time.monotonic() - t0 > timeout_s:
                truncated = True
                break
            if not path_obj.is_file():
                continue
            try:
                rel = normalize_relpath(str(path_obj.relative_to(root)))
            except ValueError:
                continue
            if _ignored(rel, ignore):
                continue
            if glob_pat and not fnmatch(rel, glob_pat) and not fnmatch(path_obj.name, glob_pat):
                continue
            if ext_f and path_obj.suffix.lower() != ext_f:
                continue
            if scan_roots:
                if not any(
                    rel == sr
                    or rel.startswith(sr.rstrip("/") + "/")
                    or sr.startswith(rel.rstrip("/") + "/")
                    for sr in scan_roots
                ):
                    continue
            files_scanned += 1
            if files_scanned > max_files:
                truncated = True
                break
            try:
                text = path_obj.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                kind = None
                for rx in def_rxs:
                    if rx.search(line):
                        kind = "definition"
                        break
                if kind is None and not definitions_only and ref_rx.search(line):
                    kind = "reference"
                if kind is None:
                    continue
                hits.append(
                    {
                        "path": rel,
                        "line": i,
                        "kind": kind,
                        "text": line.strip()[:line_cap],
                        "symbol": name,
                    }
                )
                if len(hits) >= cap:
                    truncated = True
                    break
            if len(hits) >= cap:
                break

        # Prefer definitions first in output
        hits.sort(key=lambda h: (0 if h.get("kind") == "definition" else 1, h.get("path"), h.get("line")))
        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("find_symbol")
        result: dict[str, Any] = {
            "ok": True,
            "symbol": name,
            "matches": hits,
            "match_count": len(hits),
            "files_scanned": files_scanned,
            "truncated": truncated,
            "definitions_only": definitions_only,
            "scoped": bool(scope_roots),
        }
        if not hits:
            result["hint"] = (
                "No definition-like matches. Try definitions_only=false for references, "
                "narrow path=, or grep(literal=true) for the symbol name."
            )
        return attach_scope_warning(result, ctx)
    except Exception as e:
        return {"ok": False, "error": str(e)}
