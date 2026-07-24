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


def grep(
    ctx: dict,
    pattern: str,
    glob: str | None = None,
    max_matches: int | None = None,
    *,
    extension: str | None = None,
    files_only: bool = False,
    match_path: bool = False,
) -> dict[str, Any]:
    """Search target files for a regex.

    Extra args (tool-gap driven):
    - ``extension``: file-type filter (``.cu`` / ``cu`` / ``*.cu``)
    - ``files_only``: return unique matching paths only (files-with-matches)
    - ``match_path``: also match pattern against relative path / filename
      (helps locate implementation files by name without content hits)
    """
    try:
        tools_cfg = (ctx.get("cfg") or {}).get("tools") or {}
        max_pat = int(tools_cfg.get("max_grep_pattern_len", DEFAULT_MAX_PATTERN_LEN))
        # Empty pattern + (extension|glob|match_path) → path listing mode via match_path
        pattern_s = "" if pattern is None else str(pattern)
        path_list_mode = (not pattern_s.strip()) and (
            bool(extension) or bool(glob) or match_path
        )
        if path_list_mode:
            # List files by path filter only (no content scan)
            pattern_s = ".*"
            match_path = True
            files_only = True
        else:
            err = validate_grep_pattern(pattern_s, max_len=max_pat)
            if err:
                return {"ok": False, "error": err}

        root = Path(ctx["target_root"]).resolve()
        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        cap = max_matches or int(tools_cfg.get("max_grep_matches", 50))
        timeout_s = float(tools_cfg.get("grep_timeout_seconds", DEFAULT_GREP_TIMEOUT_S))
        max_files = int(tools_cfg.get("max_grep_files", DEFAULT_MAX_FILES_SCAN))
        ext_f = _norm_grep_extension(extension)
        glob_pat = str(glob).strip() if glob else None
        if ext_f and not glob_pat:
            glob_pat = f"*{ext_f}"

        # Soft jail: limit file iteration to path_hints roots until widened.
        # Grep does not soft-block-then-widen per call (unlike list/read); it
        # silently scopes matches. Model learns scope via packet + list/read.
        scope_roots = scope_roots_for_scan(ctx)

        rx = re.compile(pattern_s)
        hits: list[dict] = []
        seen_paths: set[str] = set()
        from fnmatch import fnmatch

        t0 = time.monotonic()
        files_scanned = 0
        truncated_time = False
        truncated_files = False
        cap_hit = False

        def _emit_path_hit(rel: str, line: int = 0, text: str = "") -> bool:
            """Record a match; return True if cap reached."""
            if files_only:
                if rel in seen_paths:
                    return False
                seen_paths.add(rel)
                hits.append({"path": rel})
                return len(hits) >= cap
            hits.append({"path": rel, "line": line, "text": text[:200]})
            return len(hits) >= cap

        for path in _iter_candidate_files(root, ignore, glob_pat, scope_roots):
            if time.monotonic() - t0 > timeout_s:
                truncated_time = True
                break
            if not path.is_file():
                continue
            try:
                rel = normalize_relpath(str(path.relative_to(root)))
            except ValueError:
                continue
            if _ignored(rel, ignore):
                continue
            if glob_pat and not fnmatch(rel, glob_pat) and not fnmatch(path.name, glob_pat):
                continue
            if ext_f and path.suffix.lower() != ext_f:
                continue
            # When soft-jailed, only match files under scope roots
            if scope_roots:
                if not any(
                    rel == sr
                    or rel.startswith(sr.rstrip("/") + "/")
                    or sr.startswith(rel.rstrip("/") + "/")
                    for sr in scope_roots
                ):
                    continue
            files_scanned += 1
            if files_scanned > max_files:
                truncated_files = True
                break

            # Path/filename match (optional or path-list mode)
            if match_path and (rx.search(rel) or rx.search(path.name)):
                if _emit_path_hit(rel, line=0, text=f"[path] {rel}"):
                    cap_hit = True
                    break
                if path_list_mode or files_only:
                    # path listing / files_only: one hit per file is enough
                    continue

            if path_list_mode:
                continue

            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    if _emit_path_hit(rel, line=i, text=line):
                        cap_hit = True
                        break
                    if files_only:
                        break  # one content hit enough for this path
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
        if files_only:
            result["files_only"] = True
            result["paths"] = [h["path"] for h in hits]
        if ext_f:
            result["extension"] = ext_f
        if glob_pat:
            result["glob"] = glob_pat
        if match_path:
            result["match_path"] = True
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
                "0 matches. Try file_inventory(extension=...) to locate files by type, "
                "grep(glob='*.ext') / extension=, or match_path=true for filename search. "
                "Avoid repeating the same empty pattern."
            )
            result["hint"] = " ".join(hints)
        return attach_scope_warning(result, ctx)
    except re.error as e:
        return {"ok": False, "error": f"bad regex: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
