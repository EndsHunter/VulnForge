"""Grep / search and mechanical file index."""

from __future__ import annotations

import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

from vulnforge.languages import (
    ENTRYPOINT_NAMES,
    attach_languages_to_inventory,
    is_entrypoint_name,
)
from vulnforge.tools.scope import attach_scope_warning, scope_roots_for_scan
from vulnforge.util import normalize_relpath

# Nested quantifiers / classic ReDoS shapes — reject rather than hang.
# Do NOT reject stacked .* / .+ (e.g. foo.*bar.*baz) — common multi-hop greps.
_NESTED_QUANTIFIER = re.compile(
    r"\([^)]*[+*][^)]*\)[+*]|"  # (a+)+ or (a*)*
    r"\([^)]*[+*][^)]*\)\{|"  # (a+){2,
    r"\([^)]*\{[^}]+\}[^)]*\)[+*]"  # (a{1,})+
)

DEFAULT_MAX_PATTERN_LEN = 200
DEFAULT_GREP_TIMEOUT_S = 8.0
DEFAULT_MAX_FILES_SCAN = 8000


def _ignored(rel: str, ignore_globs: list[str]) -> bool:
    from fnmatch import fnmatch

    rel_n = normalize_relpath(rel)
    for g in ignore_globs:
        g_n = g.replace("\\", "/")
        if fnmatch(rel_n, g_n) or fnmatch(Path(rel_n).name, g_n):
            return True
        if g_n.startswith("**/") and fnmatch(rel_n, g_n[3:]):
            return True
    return False

# Cap on paths injected into recon packet / default hunt seeds.
# Full-tree walk still counts every file; hunts can grep/read anywhere.
# This is NOT a Ralph/recon stop — only a packet seed size budget.
SAMPLE_PATHS_CAP = 500


def stratified_sample_paths(files: list[str], cap: int = SAMPLE_PATHS_CAP) -> list[str]:
    """Pick up to ``cap`` paths spread across top-level directories.

    Avoids alphabetical blindness where ``bulk/`` fills the seed and
    ``packages/`` / late dirs never appear. Round-robin per top dir.
    """
    if cap <= 0:
        return []
    if len(files) <= cap:
        return list(files)
    from collections import defaultdict

    buckets: dict[str, list[str]] = defaultdict(list)
    for p in files:
        top = p.split("/", 1)[0] if "/" in p else "."
        buckets[top].append(p)
    keys = sorted(buckets.keys())
    indices = {k: 0 for k in keys}
    out: list[str] = []
    while len(out) < cap:
        progressed = False
        for k in keys:
            i = indices[k]
            blist = buckets[k]
            if i < len(blist):
                out.append(blist[i])
                indices[k] = i + 1
                progressed = True
                if len(out) >= cap:
                    break
        if not progressed:
            break
    return out


def build_file_index(target_root: Path, ignore_globs: list[str] | None = None) -> dict:
    target_root = Path(target_root).resolve()
    globs = list(ignore_globs or [])
    files: list[str] = []
    ext_hist: Counter[str] = Counter()
    entrypoints: list[str] = []
    for path in sorted(target_root.rglob("*")):
        if not path.is_file():
            continue
        rel = normalize_relpath(str(path.relative_to(target_root)))
        if _ignored(rel, globs):
            continue
        files.append(rel)
        ext_hist[path.suffix.lower() or "<none>"] += 1
        if is_entrypoint_name(path.name):
            entrypoints.append(rel)

    sample = stratified_sample_paths(files, SAMPLE_PATHS_CAP)
    # Prefer entrypoints in the seed (replace trailing slots if at cap).
    if entrypoints and SAMPLE_PATHS_CAP > 0:
        seen = set(sample)
        for e in entrypoints:
            if e in seen:
                continue
            if len(sample) < SAMPLE_PATHS_CAP:
                sample.append(e)
            else:
                # replace from end until entrypoint fits
                for i in range(len(sample) - 1, -1, -1):
                    if sample[i] not in entrypoints:
                        old = sample[i]
                        sample[i] = e
                        seen.discard(old)
                        seen.add(e)
                        break
            seen.add(e)

    inv = {
        "file_count": len(files),
        "extensions": dict(ext_hist),
        "entrypoints": entrypoints,
        # Packet / default-seed only. Full file_count is authoritative inventory size.
        # Hunts + Ralph are not limited to this list.
        "sample_paths": sample[:SAMPLE_PATHS_CAP],
        "sample_paths_cap": SAMPLE_PATHS_CAP,
        "sample_paths_partial": len(files) > SAMPLE_PATHS_CAP,
    }
    return attach_languages_to_inventory(inv)


def validate_grep_pattern(pattern: str, max_len: int = DEFAULT_MAX_PATTERN_LEN) -> str | None:
    """
    Return error message if pattern is unsafe/invalid; else None.
    """
    if pattern is None or not str(pattern):
        return "pattern required"
    p = str(pattern)
    if len(p) > max_len:
        return f"pattern too long (max {max_len} chars)"
    if _NESTED_QUANTIFIER.search(p):
        return (
            "pattern rejected: nested or stacked quantifiers are unsafe "
            "(possible ReDoS); use a simpler/literal pattern"
        )
    # Other heavy constructs
    if p.count("(") > 20 or p.count("*") > 15 or p.count("+") > 15:
        return "pattern rejected: too many quantifiers/groups"
    try:
        re.compile(p)
    except re.error as e:
        return f"bad regex: {e}"
    return None


def _iter_candidate_files(
    root: Path,
    ignore: list[str],
    glob: str | None,
    scope_roots: list[str] | None,
):
    from fnmatch import fnmatch

    def _yield_under(base: Path):
        if base.is_file():
            yield base
            return
        if not base.is_dir():
            return
        yield from base.rglob("*")

    if scope_roots:
        seen: set[Path] = set()
        for sr in scope_roots:
            base = (root / sr).resolve()
            try:
                base.relative_to(root)
            except ValueError:
                continue
            if not base.exists():
                # try as prefix match on files later â€” still try parent
                parent = base.parent
                if parent.exists() and parent not in seen:
                    for path in _yield_under(parent):
                        if path in seen:
                            continue
                        seen.add(path)
                        yield path
                continue
            for path in _yield_under(base):
                if path in seen:
                    continue
                seen.add(path)
                yield path
    else:
        yield from root.rglob("*")


def _norm_grep_extension(extension: str | None) -> str | None:
    if extension is None:
        return None
    e = str(extension).strip().lower()
    if not e:
        return None
    if e.startswith("*."):
        e = e[1:]
    if not e.startswith("."):
        e = "." + e
    return e


def _coerce_context_n(value: Any, default: int = 0, *, cap: int = 20) -> int:
    try:
        n = int(value if value is not None else default)
    except (TypeError, ValueError):
        n = default
    return max(0, min(cap, n))


def _normalize_path_roots(
    path: str | None,
    paths: list[str] | None,
) -> list[str]:
    roots: list[str] = []
    for raw in ([path] if path else []) + list(paths or []):
        if raw is None:
            continue
        n = normalize_relpath(str(raw).strip())
        if n and n not in roots:
            roots.append(n)
    return roots


def grep(
    ctx: dict,
    pattern: str,
    glob: str | None = None,
    max_matches: int | None = None,
    *,
    extension: str | None = None,
    files_only: bool = False,
    match_path: bool = False,
    path: str | None = None,
    paths: list[str] | None = None,
    context: int | None = None,
    context_before: int | None = None,
    context_after: int | None = None,
    case_insensitive: bool = False,
    max_line_chars: int | None = None,
    literal: bool = False,
) -> dict[str, Any]:
    """Search target files for a regex (or literal string).

    Extra args:
    - ``extension``: file-type filter (``.cu`` / ``cu`` / ``*.cu``)
    - ``files_only``: return unique matching paths only (files-with-matches)
    - ``match_path``: also match pattern against relative path / filename
    - ``path`` / ``paths``: limit scan to relative file or directory roots
    - ``context`` / ``context_before`` / ``context_after``: surrounding lines
    - ``case_insensitive``: ``re.I``
    - ``max_line_chars``: truncate match line text (default 200)
    - ``literal``: escape pattern as a fixed string
    """
    try:
        from vulnforge.tools.scope import maybe_soft_jail

        tools_cfg = (ctx.get("cfg") or {}).get("tools") or {}
        max_pat = int(tools_cfg.get("max_grep_pattern_len", DEFAULT_MAX_PATTERN_LEN))
        # Empty pattern + (extension|glob|match_path|path) → path listing mode
        pattern_s = "" if pattern is None else str(pattern)
        path_roots = _normalize_path_roots(path, paths)
        path_list_mode = (not pattern_s.strip()) and (
            bool(extension) or bool(glob) or match_path or bool(path_roots)
        )
        if path_list_mode:
            pattern_s = ".*"
            match_path = True
            files_only = True
        else:
            if literal:
                pattern_s = re.escape(pattern_s)
            err = validate_grep_pattern(pattern_s, max_len=max_pat)
            if err:
                return {"ok": False, "error": err}

        # Soft jail on explicit path roots (same widen policy as list/read).
        for pr in path_roots:
            soft = maybe_soft_jail(ctx, pr)
            if soft is not None:
                return soft

        root = Path(ctx["target_root"]).resolve()
        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        cap = max_matches or int(tools_cfg.get("max_grep_matches", 50))
        timeout_s = float(tools_cfg.get("grep_timeout_seconds", DEFAULT_GREP_TIMEOUT_S))
        max_files = int(tools_cfg.get("max_grep_files", DEFAULT_MAX_FILES_SCAN))
        line_cap = int(
            max_line_chars
            if max_line_chars is not None
            else tools_cfg.get("max_grep_line_chars", 200)
        )
        line_cap = max(40, min(2000, line_cap))
        ctx_cap = int(tools_cfg.get("max_grep_context", 10))
        ctx_n = _coerce_context_n(context, 0, cap=ctx_cap)
        before_n = _coerce_context_n(
            context_before if context_before is not None else ctx_n,
            ctx_n,
            cap=ctx_cap,
        )
        after_n = _coerce_context_n(
            context_after if context_after is not None else ctx_n,
            ctx_n,
            cap=ctx_cap,
        )
        want_context = (not files_only) and (before_n > 0 or after_n > 0)

        ext_f = _norm_grep_extension(extension)
        glob_pat = str(glob).strip() if glob else None
        if ext_f and not glob_pat:
            glob_pat = f"*{ext_f}"

        # Soft jail: limit file iteration to path_hints roots until widened.
        # Explicit path roots further narrow the scan (intersection with soft scope).
        scope_roots = scope_roots_for_scan(ctx)
        scan_roots = path_roots if path_roots else scope_roots

        flags = re.IGNORECASE if case_insensitive else 0
        rx = re.compile(pattern_s, flags)
        hits: list[dict] = []
        seen_paths: set[str] = set()
        from fnmatch import fnmatch

        t0 = time.monotonic()
        files_scanned = 0
        truncated_time = False
        truncated_files = False
        cap_hit = False

        def _under_roots(rel: str, roots: list[str] | None) -> bool:
            if not roots:
                return True
            return any(
                rel == sr
                or rel.startswith(sr.rstrip("/") + "/")
                or sr.startswith(rel.rstrip("/") + "/")
                for sr in roots
            )

        def _emit_path_hit(
            rel: str,
            line: int = 0,
            text: str = "",
            *,
            all_lines: list[str] | None = None,
        ) -> bool:
            """Record a match; return True if cap reached."""
            if files_only:
                if rel in seen_paths:
                    return False
                seen_paths.add(rel)
                hits.append({"path": rel})
                return len(hits) >= cap
            hit: dict[str, Any] = {
                "path": rel,
                "line": line,
                "text": text[:line_cap],
            }
            if want_context and all_lines is not None and line > 0:
                idx = line - 1
                if before_n > 0 and idx > 0:
                    start = max(0, idx - before_n)
                    hit["before"] = [
                        {"line": j + 1, "text": all_lines[j][:line_cap]}
                        for j in range(start, idx)
                    ]
                if after_n > 0 and idx + 1 < len(all_lines):
                    end = min(len(all_lines), idx + 1 + after_n)
                    hit["after"] = [
                        {"line": j + 1, "text": all_lines[j][:line_cap]}
                        for j in range(idx + 1, end)
                    ]
            hits.append(hit)
            return len(hits) >= cap

        for path_obj in _iter_candidate_files(root, ignore, glob_pat, scan_roots):
            if time.monotonic() - t0 > timeout_s:
                truncated_time = True
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
            if not _under_roots(rel, scan_roots):
                continue
            # When soft-jailed and explicit path roots used, still honor soft scope.
            if scope_roots and path_roots and not _under_roots(rel, scope_roots):
                continue
            files_scanned += 1
            if files_scanned > max_files:
                truncated_files = True
                break

            # Path/filename match (optional or path-list mode)
            if match_path and (rx.search(rel) or rx.search(path_obj.name)):
                if _emit_path_hit(rel, line=0, text=f"[path] {rel}"):
                    cap_hit = True
                    break
                if path_list_mode or files_only:
                    continue

            if path_list_mode:
                continue

            try:
                text = path_obj.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            file_lines = text.splitlines()
            for i, line in enumerate(file_lines, 1):
                if rx.search(line):
                    if _emit_path_hit(rel, line=i, text=line, all_lines=file_lines):
                        cap_hit = True
                        break
                    if files_only:
                        break
            if cap_hit:
                break

        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("grep")
        result: dict[str, Any] = {
            "ok": True,
            "matches": hits,
            "truncated": truncated_time or truncated_files or cap_hit,
            "files_scanned": files_scanned,
            "scoped": bool(scope_roots),
        }
        if path_roots:
            result["path_roots"] = path_roots
        if files_only:
            result["files_only"] = True
            result["paths"] = [h["path"] for h in hits]
        if ext_f:
            result["extension"] = ext_f
        if glob_pat:
            result["glob"] = glob_pat
        if match_path:
            result["match_path"] = True
        if case_insensitive:
            result["case_insensitive"] = True
        if literal and not path_list_mode:
            result["literal"] = True
        if want_context:
            result["context_before"] = before_n
            result["context_after"] = after_n
        if truncated_time:
            result["timeout"] = True
        if not hits:
            hints: list[str] = []
            if scope_roots:
                hints.append(
                    "Search was soft-scoped to path_hints; widen via list_dir/read_file "
                    "out of scope once, or call file_inventory after widen."
                )
            hints.append(
                "0 matches. Try file_inventory(extension=...), grep(path='subdir'), "
                "extension=/glob=, match_path=true, or case_insensitive=true. "
                "Avoid repeating the same empty pattern."
            )
            result["hint"] = " ".join(hints)
        return attach_scope_warning(result, ctx)
    except re.error as e:
        return {"ok": False, "error": f"bad regex: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
