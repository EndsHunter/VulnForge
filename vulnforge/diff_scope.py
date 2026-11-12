"""Diff-scoped audits: ``vf init --diff base..head`` (#185).

Mechanical, no LLM. Computes a **scope manifest** for a run:

- ``changed`` — files that differ between the *base* and *head* commit trees,
  inside the target, hunt-able (code, not ignored, not deleted). Each entry
  carries the new-side line ranges (hunks) of the change.
- ``expanded`` — callers and callees of the changed symbols, found by a
  heuristic name-based call scan over the mechanical codemap (configurable
  depth). Not a resolved call graph and not taint analysis.
- ``excluded`` — changed paths that are *not* hunted, with a reason.

The two commit trees are compared directly (``git diff <base> <head>``).
A three-dot / merge-base diff is refused: it can differ from the tree diff.

The target tree stays read-only. Git runs without a shell, with optional
locks off (no index refresh), hooks/fsmonitor/external diff/textconv off,
submodules ignored, and no worktree diff (which would run clean filters).
Worktree drift on changed files is detected by hashing file bytes in Python.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional

from vulnforge.languages import is_code_extension
from vulnforge.tools.grep_index import _ignored
from vulnforge.util import normalize_relpath, utc_now_iso

SCHEMA = "vulnforge/diff-scope@1"

DISCLAIMER = (
    "Scope = files changed between the base and head commit trees, plus callers/"
    "callees found by a heuristic name-based call scan over the codemap. It is "
    "not a resolved call graph or a taint proof; code outside the scope was not "
    "hunted by automatic planning."
)

# Names too generic to expand on (would pull in half the tree).
_STOP_NAMES = frozenset(
    {
        "main",
        "run",
        "get",
        "set",
        "put",
        "post",
        "init",
        "new",
        "len",
        "str",
        "int",
        "list",
        "dict",
        "open",
        "close",
        "read",
        "write",
        "print",
        "format",
        "update",
        "start",
        "stop",
        "call",
        "apply",
        "test",
        "setup",
        "handle",
        "execute",
        "process",
        "__init__",
        "__call__",
        "__str__",
        "__repr__",
        "constructor",
        "toString",
    }
)
_SYMBOL_KINDS = frozenset({"function", "method", "class", "def", "func", "fn"})
_MAX_DEFS_PER_NAME = 3
_MAX_HUNKS_PER_FILE = 64
_MAX_HUNK_FILES = 300
_HUNK_RE = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)
# Revision names: no whitespace/control chars, no pathspec/tree syntax (``:``).
_SAFE_REF_RE = re.compile(r"^[^\s\x00-\x1f\x7f:?*\[\\]+$")

# Env vars that would redirect git at another repo / config / diff program.
_GIT_ENV_DROP = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_EXTERNAL_DIFF",
    "GIT_DIFF_OPTS",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_PAGER",
    "GIT_EXEC_PATH",
)
# Clamp repo config that could run code, write, or change output shape.
_GIT_CLAMPS = (
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.quotePath=false",
    "diff.external=",
    "diff.noprefix=false",
    "diff.mnemonicPrefix=false",
    "diff.relative=false",
    "diff.renames=true",
    "submodule.recurse=false",
    "gc.auto=0",
    "maintenance.auto=false",
)


class DiffScopeError(ValueError):
    """Bad diff spec, unresolvable revision, or unusable target for --diff."""


# ---------------------------------------------------------------------------
# Spec + git plumbing
# ---------------------------------------------------------------------------


def parse_diff_spec(spec: str) -> tuple[str, str]:
    """Parse ``base..head`` (or ``base..`` = ``base..HEAD``).

    Three-dot (merge-base) specs are refused: the issue requires a direct
    tree-to-tree compare.
    """
    raw = str(spec or "").strip()
    if not raw:
        raise DiffScopeError("--diff needs base..head")
    if "..." in raw:
        raise DiffScopeError(
            "--diff does not accept base...head (merge-base diff); "
            "use base..head to compare the two commit trees directly"
        )
    if raw.count("..") != 1:
        raise DiffScopeError(f"--diff must be base..head, got {raw!r}")
    base, head = raw.split("..", 1)
    base, head = base.strip(), head.strip() or "HEAD"
    if not base:
        raise DiffScopeError("--diff base revision is empty (want base..head)")
    for ref in (base, head):
        if ref.startswith("-") or not _SAFE_REF_RE.match(ref):
            raise DiffScopeError(f"invalid revision in --diff: {ref!r}")
    return base, head


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP}
    env["GIT_OPTIONAL_LOCKS"] = "0"  # never refresh/write the index
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["LC_ALL"] = "C"
    return env


def _git(cwd: Path, *args: str, timeout: float = 60.0) -> bytes:
    cmd = ["git", "--no-pager", "--literal-pathspecs"]
    for c in _GIT_CLAMPS:
        cmd += ["-c", c]
    cmd += list(args)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=_git_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise DiffScopeError("git is not installed; --diff needs git") from e
    except subprocess.TimeoutExpired as e:
        raise DiffScopeError(f"git {args[0]} timed out") from e
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        tail = msg[-1] if msg else f"exit {proc.returncode}"
        raise DiffScopeError(f"git {args[0]} failed: {tail}")
    return proc.stdout


def _git_text(cwd: Path, *args: str) -> str:
    return _git(cwd, *args).decode("utf-8", "replace").strip()


def resolve_commit(cwd: Path, ref: str) -> str:
    try:
        return _git_text(
            cwd, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}"
        )
    except DiffScopeError as e:
        raise DiffScopeError(f"cannot resolve revision {ref!r} to a commit") from e


def _name_status(cwd: Path, base_sha: str, head_sha: str) -> list[dict[str, Any]]:
    """Two-tree name-status (repo-root relative). Never a merge-base diff."""
    out = _git(
        cwd,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--no-relative",
        "--ignore-submodules=all",
        "--name-status",
        "-z",
        "-M",
        base_sha,
        head_sha,
        "--",
    )
    parts = out.split(b"\x00")
    rows: list[dict[str, Any]] = []
    i = 0
    while i < len(parts):
        status = parts[i].decode("utf-8", "replace")
        i += 1
        if not status:
            continue
        code = status[:1]
        if code in ("R", "C"):
            if i + 1 >= len(parts):
                break
            old = parts[i].decode("utf-8", "surrogateescape")
            new = parts[i + 1].decode("utf-8", "surrogateescape")
            i += 2
            rows.append({"status": code, "path": new, "old_path": old})
        else:
            path = parts[i].decode("utf-8", "surrogateescape") if i < len(parts) else ""
            i += 1
            rows.append({"status": code, "path": path})
    return [r for r in rows if r.get("path")]


def _hunks_for(cwd: Path, base_sha: str, head_sha: str, row: dict[str, Any]) -> list[list[int]]:
    """New-side line ranges of the change for one file (``-U0`` hunks)."""
    paths = [row["path"]]
    if row.get("old_path"):
        paths.insert(0, row["old_path"])
    out = _git(
        cwd,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--no-relative",
        "--ignore-submodules=all",
        "-U0",
        "-M",
        base_sha,
        head_sha,
        "--",
        *paths,
    )
    hunks: list[list[int]] = []
    for m in _HUNK_RE.finditer(out):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        if count <= 0:
            # Pure deletion: lines removed after `start` on the new side.
            hunks.append([max(1, start), max(1, start)])
        else:
            hunks.append([start, start + count - 1])
        if len(hunks) >= _MAX_HUNKS_PER_FILE:
            break
    return hunks


def _blob_hash(data: bytes, algo: str) -> str:
    h = hashlib.sha256() if algo == "sha256" else hashlib.sha1()
    h.update(b"blob %d\x00" % len(data))
    h.update(data)
    return h.hexdigest()


def _worktree_drift(
    cwd: Path, toplevel: Path, head_sha: str, repo_paths: list[str]
) -> list[str]:
    """Changed files whose worktree bytes differ from the head blob.

    Hashes in Python (no ``git diff``/``hash-object`` on the worktree, which can
    run repo clean filters). Line-ending or filter normalization can show up as
    drift; this is a warning only.
    """
    if not repo_paths:
        return []
    try:
        algo = _git_text(cwd, "rev-parse", "--show-object-format") or "sha1"
    except DiffScopeError:
        algo = "sha1"
    out = _git(cwd, "ls-tree", "-z", "--full-tree", head_sha, "--", *repo_paths)
    blobs: dict[str, tuple[str, str]] = {}
    for entry in out.split(b"\x00"):
        if not entry or b"\t" not in entry:
            continue
        meta, path_b = entry.split(b"\t", 1)
        fields = meta.decode("ascii", "replace").split()
        if len(fields) != 3:
            continue
        blobs[path_b.decode("utf-8", "surrogateescape")] = (fields[0], fields[2])
    drift: list[str] = []
    for rp in repo_paths:
        mode_sha = blobs.get(rp)
        if mode_sha is None or not mode_sha[0].startswith("100"):
            continue
        fp = toplevel / rp
        try:
            if fp.is_symlink() or not fp.is_file():
                drift.append(rp)
                continue
            data = fp.read_bytes()
        except OSError:
            drift.append(rp)
            continue
        if _blob_hash(data, algo) != mode_sha[1]:
            drift.append(rp)
    return drift


# ---------------------------------------------------------------------------
# Collect changed set
# ---------------------------------------------------------------------------


def collect_changes(
    target: Path,
    spec: str,
    *,
    ignore_globs: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Resolve the spec and classify changed paths (target-relative).

    Raises :class:`DiffScopeError` when the target is not a git checkout, a
    revision does not resolve, or the checkout's HEAD is not *head* (hunts read
    the working tree, so it must be the head revision).
    """
    target = Path(target).resolve()
    if not target.is_dir():
        raise DiffScopeError("--diff needs a directory target inside a git repository")
    base_ref, head_ref = parse_diff_spec(spec)
    try:
        toplevel = Path(_git_text(target, "rev-parse", "--show-toplevel")).resolve()
        prefix = normalize_relpath(_git_text(target, "rev-parse", "--show-prefix"))
    except DiffScopeError as e:
        raise DiffScopeError(f"target is not inside a git work tree: {target}") from e
    prefix = prefix.rstrip("/")
    # The repo's work tree must contain the target at exactly that prefix. A
    # repo-config core.worktree pointing elsewhere would aim hashing/reads at
    # another directory, so refuse it.
    expected = (toplevel / prefix).resolve() if prefix else toplevel
    if expected != target:
        raise DiffScopeError(
            f"git work tree {toplevel} does not contain the target at {prefix or '.'!r} "
            "(core.worktree or an unusual checkout); --diff needs the target inside its own work tree"
        )
    base_sha = resolve_commit(target, base_ref)
    head_sha = resolve_commit(target, head_ref)
    if base_sha == head_sha:
        raise DiffScopeError(f"--diff {spec!r}: base and head are the same commit")
    checkout_sha = resolve_commit(target, "HEAD")
    if checkout_sha != head_sha:
        raise DiffScopeError(
            f"target checkout is at {checkout_sha[:12]}, not head {head_ref} "
            f"({head_sha[:12]}). Hunts read the working tree, so check out the head "
            "revision first (for example in a separate `git worktree`), or use base..HEAD."
        )

    ignore = list(ignore_globs or [])
    changed: list[dict[str, Any]] = []
    deleted: list[str] = []
    excluded: list[dict[str, Any]] = []
    rows = _name_status(target, base_sha, head_sha)
    in_target_rows: list[tuple[dict[str, Any], str]] = []
    for row in rows:
        repo_path = normalize_relpath(row["path"])
        if prefix:
            if not repo_path.startswith(prefix + "/"):
                excluded.append({"path": repo_path, "reason": "outside_target"})
                continue
            rel = repo_path[len(prefix) + 1 :]
        else:
            rel = repo_path
        status = row["status"]
        if status == "D":
            deleted.append(rel)
            excluded.append({"path": rel, "reason": "deleted"})
            continue
        if _ignored(rel, ignore):
            excluded.append({"path": rel, "reason": "ignored"})
            continue
        if not is_code_extension(Path(rel).suffix, Path(rel).name):
            excluded.append({"path": rel, "reason": "non_code"})
            continue
        if not (target / rel).is_file():
            excluded.append({"path": rel, "reason": "missing_in_worktree"})
            continue
        entry: dict[str, Any] = {"path": rel, "status": status}
        if row.get("old_path"):
            old = normalize_relpath(row["old_path"])
            if prefix and old.startswith(prefix + "/"):
                old = old[len(prefix) + 1 :]
            entry["old_path"] = old
        changed.append(entry)
        in_target_rows.append((row, rel))

    for idx, (row, _rel) in enumerate(in_target_rows):
        entry = changed[idx]
        if entry["status"] == "A" or idx >= _MAX_HUNK_FILES:
            entry["hunks"] = []  # whole file is new / not itemized
            entry["whole_file"] = True
            continue
        # Repo-root paths: run from the top level (a subdir cwd would not match).
        entry["hunks"] = _hunks_for(toplevel, base_sha, head_sha, row)
        entry["whole_file"] = not entry["hunks"]

    drift_repo = _worktree_drift(
        target, toplevel, head_sha, [normalize_relpath(r["path"]) for r, _ in in_target_rows]
    )
    drift = [
        (p[len(prefix) + 1 :] if prefix and p.startswith(prefix + "/") else p)
        for p in drift_repo
    ]
    return {
        "spec": str(spec).strip(),
        "compare": "two_tree",
        "base": {"ref": base_ref, "sha": base_sha},
        "head": {"ref": head_ref, "sha": head_sha},
        "repo_root": str(toplevel),
        "target_prefix": prefix,
        "changed": changed,
        "deleted": deleted,
        "excluded": excluded,
        "worktree": {"head_sha": checkout_sha, "head_matches": True, "drift": drift},
    }


# ---------------------------------------------------------------------------
# Caller / callee expansion (heuristic)
# ---------------------------------------------------------------------------


def _symbols_by_path(codemap: dict) -> dict[str, list[dict[str, Any]]]:
    by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in codemap.get("symbols") or []:
        if not isinstance(s, dict):
            continue
        kind = str(s.get("kind") or "").lower()
        if kind and kind not in _SYMBOL_KINDS:
            continue
        p = normalize_relpath(str(s.get("path") or ""))
        name = str(s.get("name") or "")
        try:
            line = int(s.get("line") or 0)
            end = int(s.get("end_line") or line)
        except (TypeError, ValueError):
            continue
        if p and name and line > 0:
            by_path[p].append({"name": name, "line": line, "end_line": max(line, end)})
    return by_path


def _bare(name: str) -> str:
    return str(name).split(".")[-1].split("::")[-1]


def _expandable(name: str, defs: dict[str, set[str]]) -> bool:
    b = _bare(name)
    if len(b) < 3 or b in _STOP_NAMES or b.startswith("test_"):
        return False
    if not re.match(r"^[A-Za-z_][\w]*$", b):
        return False
    return len(defs.get(b, ())) <= _MAX_DEFS_PER_NAME


def _overlaps(sym: dict[str, Any], hunks: list[list[int]]) -> bool:
    return any(sym["line"] <= e and s <= sym["end_line"] for s, e in hunks)


def _read_lines(root: Path, rel: str, cache: dict[str, list[str]]) -> list[str]:
    if rel not in cache:
        try:
            fp = root / rel
            if fp.stat().st_size > 400_000:
                cache[rel] = []
            else:
                cache[rel] = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[rel] = []
    return cache[rel]


def _source_files(codemap: dict, root: Path, ignore: list[str], cap: int) -> list[str]:
    out: list[str] = []
    for f in codemap.get("files") or []:
        p = normalize_relpath(str(f.get("path") if isinstance(f, dict) else f or ""))
        if p and not _ignored(p, ignore):
            out.append(p)
    if not out:
        for p in sorted(_symbols_by_path(codemap)):
            if not _ignored(p, ignore):
                out.append(p)
    return sorted(set(out))[:cap]


def expand_scope(
    target_root: Path,
    codemap: Optional[dict],
    changed: list[dict[str, Any]],
    *,
    depth: int = 1,
    max_files: int = 40,
    max_scan_files: int = 2000,
    ignore_globs: Optional[list[str]] = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Callers + callees of changed symbols, BFS to *depth* (heuristic).

    Seeds are codemap symbols in changed files whose line range overlaps a
    changed hunk (all symbols when the file is new or no hunk overlaps).
    Callers: files with ``name(`` call sites of a frontier symbol.
    Callees: symbols defined in other files that a frontier symbol body calls.
    """
    depth = max(0, min(3, int(depth)))
    max_files = max(0, int(max_files))
    meta: dict[str, Any] = {
        "depth": depth,
        "max_files": max_files,
        "method": "codemap_symbols+call_heuristic",
        "truncated": False,
        "ambiguous_symbols": [],
    }
    if depth == 0 or max_files == 0 or not changed or not isinstance(codemap, dict):
        if not isinstance(codemap, dict) or not codemap.get("symbols"):
            meta["note"] = "no codemap symbols; scope = changed files only"
        return [], meta

    root = Path(target_root)
    ignore = list(ignore_globs or [])
    by_path = _symbols_by_path(codemap)
    defs: dict[str, set[str]] = defaultdict(set)
    for p, syms in by_path.items():
        for s in syms:
            defs[_bare(s["name"])].add(p)
    files = _source_files(codemap, root, ignore, max(1, int(max_scan_files)))
    cache: dict[str, list[str]] = {}
    changed_paths = {c["path"] for c in changed}
    ambiguous: set[str] = set()

    # Frontier = (path, symbol dict)
    frontier: list[tuple[str, dict[str, Any]]] = []
    for c in changed:
        syms = by_path.get(c["path"], [])
        hunks = c.get("hunks") or []
        hit = [s for s in syms if hunks and _overlaps(s, hunks)]
        frontier.extend((c["path"], s) for s in (hit or syms))

    found: dict[str, dict[str, Any]] = {}
    seen_syms: set[tuple[str, str, int]] = {(p, s["name"], s["line"]) for p, s in frontier}

    def _enclosing(rel: str, line: int) -> Optional[dict[str, Any]]:
        best = None
        for s in by_path.get(rel, []):
            if s["line"] <= line <= s["end_line"]:
                if best is None or s["line"] >= best["line"]:
                    best = s
        return best

    def _add(rel: str, via: str, symbol: str, origin: str, d: int) -> bool:
        if rel in changed_paths or rel in found:
            return True
        if len(found) >= max_files:
            meta["truncated"] = True
            return False
        found[rel] = {"path": rel, "via": via, "symbol": symbol, "from": origin, "depth": d}
        return True

    for d in range(1, depth + 1):
        nxt: list[tuple[str, dict[str, Any]]] = []
        for src_path, sym in frontier:
            name = _bare(sym["name"])
            if not _expandable(name, defs):
                if len(name) >= 3 and name not in _STOP_NAMES:
                    ambiguous.add(name)
                continue
            # Callers of this symbol
            call_rx = re.compile(rf"\b{re.escape(name)}\s*\(")
            def_rx = re.compile(
                rf"^\s*(?:export\s+)?(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?"
                rf"(?:def|function|func|fn|class)\s+(?:\([^)]*\)\s*)?{re.escape(name)}\b"
            )
            for rel in files:
                lines = _read_lines(root, rel, cache)
                for i, line in enumerate(lines, 1):
                    if not call_rx.search(line) or def_rx.search(line):
                        continue
                    if rel == src_path and sym["line"] <= i <= sym["end_line"]:
                        continue
                    if not _add(rel, "caller", name, src_path, d):
                        break
                    enc = _enclosing(rel, i)
                    if enc is not None:
                        key = (rel, enc["name"], enc["line"])
                        if key not in seen_syms:
                            seen_syms.add(key)
                            nxt.append((rel, enc))
                    break  # one hit per file is enough for scope
            # Callees from this symbol's body
            body = _read_lines(root, src_path, cache)[sym["line"] - 1 : sym["end_line"]]
            text = "\n".join(body)
            for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
                callee = m.group(1)
                if callee == name or callee not in defs:
                    continue
                if not _expandable(callee, defs):
                    if callee not in _STOP_NAMES and len(callee) >= 3:
                        ambiguous.add(callee)
                    continue
                for def_path in sorted(defs[callee]):
                    if def_path == src_path:
                        continue
                    if not _add(def_path, "callee", callee, src_path, d):
                        break
                    for s in by_path.get(def_path, []):
                        if _bare(s["name"]) == callee:
                            key = (def_path, s["name"], s["line"])
                            if key not in seen_syms:
                                seen_syms.add(key)
                                nxt.append((def_path, s))
            if meta["truncated"]:
                break
        frontier = nxt
        if meta["truncated"] or not frontier:
            break
    meta["ambiguous_symbols"] = sorted(ambiguous)[:50]
    return sorted(found.values(), key=lambda e: (e["depth"], e["path"])), meta


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def diff_cfg(cfg: Optional[dict]) -> dict[str, int]:
    c = (cfg or {}).get("diff") if isinstance(cfg, dict) else None
    c = c if isinstance(c, dict) else {}

    def _int(key: str, default: int, lo: int, hi: int) -> int:
        try:
            v = int(c.get(key, default))
        except (TypeError, ValueError):
            v = default
        return max(lo, min(hi, v))

    return {
        "expand_depth": _int("expand_depth", 1, 0, 3),
        "max_expanded_files": _int("max_expanded_files", 40, 0, 500),
        "max_scan_files": _int("max_scan_files", 2000, 1, 50_000),
    }


def require_changes(changes: dict[str, Any]) -> None:
    """Refuse a diff with nothing to hunt (an empty run would look like a clean audit)."""
    if changes.get("changed"):
        return
    excl = changes.get("excluded") or []
    reasons = ", ".join(sorted({str(e.get("reason")) for e in excl})) or "none"
    raise DiffScopeError(
        f"--diff {changes.get('spec')!r} has no hunt-able code changes inside the "
        f"target ({len(excl)} changed path(s) excluded: {reasons})"
    )


def build_diff_scope(
    target: Path,
    spec: str,
    *,
    codemap: Optional[dict] = None,
    cfg: Optional[dict] = None,
    ignore_globs: Optional[list[str]] = None,
    depth: Optional[int] = None,
    changes: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Full scope manifest (``vulnforge/diff-scope@1``). Raises DiffScopeError.

    *changes* is a prior :func:`collect_changes` result (init validates the
    spec before creating the run dir, then expands once the codemap exists).
    """
    opts = diff_cfg(cfg)
    if depth is not None:
        opts["expand_depth"] = max(0, min(3, int(depth)))
    manifest = dict(changes) if changes is not None else collect_changes(
        target, spec, ignore_globs=ignore_globs
    )
    require_changes(manifest)
    expanded, meta = expand_scope(
        Path(target),
        codemap,
        manifest["changed"],
        depth=opts["expand_depth"],
        max_files=opts["max_expanded_files"],
        max_scan_files=opts["max_scan_files"],
        ignore_globs=ignore_globs,
    )
    manifest["expanded"] = expanded
    manifest["expansion"] = meta
    scope_files = sorted({c["path"] for c in manifest["changed"]} | {e["path"] for e in expanded})
    manifest["scope_files"] = scope_files
    # Modules with no scoped file (count + capped list; codemap is not authority)
    untouched: list[str] = []
    for m in (codemap or {}).get("modules") or []:
        if not isinstance(m, dict):
            continue
        mp = normalize_relpath(str(m.get("path") or ""))
        if not mp or mp == ".":
            continue
        if not any(f == mp or f.startswith(mp.rstrip("/") + "/") for f in scope_files):
            untouched.append(mp)
    manifest["untouched_modules"] = {"count": len(untouched), "sample": sorted(untouched)[:20]}
    manifest["schema"] = SCHEMA
    manifest["generated_at"] = utc_now_iso()
    manifest["disclaimer"] = DISCLAIMER
    return manifest


# ---------------------------------------------------------------------------
# Applying the scope
# ---------------------------------------------------------------------------


def scope_files(manifest: Optional[dict]) -> list[str]:
    if not isinstance(manifest, dict):
        return []
    return [normalize_relpath(str(p)) for p in manifest.get("scope_files") or [] if p]


def changed_paths(manifest: Optional[dict]) -> list[str]:
    if not isinstance(manifest, dict):
        return []
    return [str(c.get("path")) for c in manifest.get("changed") or [] if c.get("path")]


def path_in_scope(path: str, manifest: Optional[dict]) -> bool:
    """True if *path* (target-relative file) is a scope file."""
    p = normalize_relpath(str(path or ""))
    return bool(p) and p in set(scope_files(manifest))


def clip_hints_to_scope(hints: Iterable[Any], manifest: Optional[dict], *, cap: int = 15) -> list[str]:
    """Rewrite path hints to scope *files* only.

    File hints in scope are kept. Directory hints (or ``.``) become the scope
    files beneath them — never the directory itself, because the hunt soft jail
    treats a directory hint as a prefix over the whole module. Changed files
    are ordered before callers/callees.
    """
    files = scope_files(manifest)
    if not files:
        return []
    changed = set(changed_paths(manifest))
    out: list[str] = []
    for h in hints or []:
        hn = normalize_relpath(str(h or ""))
        if hn in ("", "."):
            picks = files
        elif hn in files:
            picks = [hn]
        else:
            pre = hn.rstrip("/") + "/"
            picks = [f for f in files if f.startswith(pre)]
        for f in picks:
            if f not in out:
                out.append(f)
    order = {f: i for i, f in enumerate(out)}
    out.sort(key=lambda f: (f not in changed, order[f]))
    return out[:cap]


def _area_for(path: str, codemap: Optional[dict]) -> str:
    if isinstance(codemap, dict):
        try:
            from vulnforge.tools.flows import resolve_module_for_path

            mod = resolve_module_for_path(codemap, path)
            if mod and mod != ".":
                return mod
        except Exception as exc:
            from vulnforge.errors import note_swallowed

            note_swallowed(exc, context="diff_scope.area_for")
    parts = normalize_relpath(path).split("/")
    return parts[0] if len(parts) > 1 else "app"


def hunt_diff_context(manifest: Optional[dict], hints: Iterable[Any]) -> dict[str, Any]:
    """Short per-hunt diff block (not the whole manifest)."""
    if not isinstance(manifest, dict):
        return {}
    hint_set = {normalize_relpath(str(h)) for h in hints or [] if h}
    changed = [
        {"path": c["path"], "hunks": (c.get("hunks") or [])[:12], "whole_file": bool(c.get("whole_file"))}
        for c in manifest.get("changed") or []
        if c.get("path") in hint_set
    ]
    context = [
        {"path": e["path"], "via": e.get("via"), "symbol": e.get("symbol"), "from": e.get("from")}
        for e in manifest.get("expanded") or []
        if e.get("path") in hint_set
    ]
    return {
        "spec": manifest.get("spec"),
        "base": (manifest.get("base") or {}).get("sha"),
        "head": (manifest.get("head") or {}).get("sha"),
        "changed": changed[:15],
        "context": context[:15],
    }


def scope_hunt_tasks(
    tasks: list[dict],
    manifest: Optional[dict],
    *,
    classes: Iterable[str],
    codemap: Optional[dict] = None,
) -> list[dict]:
    """Restrict planned hunt payloads to the diff scope.

    1. Each task's hints are rewritten to scope files (dir hints expanded to
       the scope files beneath them); tasks left with no hint are dropped.
    2. Changed files that no remaining task covers get area × class tasks
       (allowed run classes) so every change is hunted.

    Callers clip to ``run.max_tasks`` afterwards.
    """
    if not isinstance(manifest, dict) or not manifest.get("scope_files"):
        return list(tasks)
    out: list[dict] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for t in tasks or []:
        hints = clip_hints_to_scope(t.get("path_hints") or [], manifest)
        if not hints:
            continue
        key = (str(t.get("area")), str(t.get("class")), tuple(hints))
        if key in seen:
            continue
        seen.add(key)
        nt = dict(t)
        nt["path_hints"] = hints
        out.append(nt)

    covered = {h for t in out for h in t["path_hints"]}
    uncovered = [p for p in changed_paths(manifest) if p not in covered]
    if uncovered:
        from vulnforge.stages.recon import balanced_product_tasks

        by_area: dict[str, list[str]] = defaultdict(list)
        for p in uncovered:
            by_area[_area_for(p, codemap)].append(p)
        units = []
        for area, paths in sorted(by_area.items()):
            ctx_files = [
                e["path"]
                for e in manifest.get("expanded") or []
                if e.get("from") in paths and e["path"] not in paths
            ]
            units.append((area, (paths + ctx_files)[:15]))
        out.extend(balanced_product_tasks(units, list(classes or []), max_tasks=None))

    for t in out:
        t["diff_scope"] = hunt_diff_context(manifest, t.get("path_hints") or [])
    return out


def recon_brief(manifest: Optional[dict], *, max_files: int = 40) -> str:
    """Operator-brief section that focuses recon on the change."""
    if not isinstance(manifest, dict):
        return ""
    base = manifest.get("base") or {}
    head = manifest.get("head") or {}
    lines = [
        "## Diff-scoped audit",
        f"This run reviews the change {base.get('ref')}..{head.get('ref')} "
        f"({str(base.get('sha'))[:12]} → {str(head.get('sha'))[:12]}, two-tree compare).",
        "Focus the architecture and hunt_focus on the changed code and how untrusted input "
        "reaches it. Use only these paths in hunt_focus path_hints; the harness drops hunts "
        "outside this scope.",
        "",
        "Changed files (new-side line ranges):",
    ]
    for c in (manifest.get("changed") or [])[:max_files]:
        rng = ", ".join(f"{s}-{e}" for s, e in (c.get("hunks") or [])[:8]) or "whole file"
        lines.append(f"- `{c['path']}` [{c.get('status')}] lines {rng}")
    exp = manifest.get("expanded") or []
    if exp:
        lines.append("")
        lines.append("Callers / callees (heuristic, context for the change):")
        for e in exp[:max_files]:
            lines.append(f"- `{e['path']}` ({e.get('via')} of `{e.get('symbol')}`)")
    return "\n".join(lines)


def scope_brief(manifest: Optional[dict]) -> Optional[dict[str, Any]]:
    """Counts for summaries / exports headers."""
    if not isinstance(manifest, dict):
        return None
    excl = manifest.get("excluded") or []
    reasons: dict[str, int] = defaultdict(int)
    for e in excl:
        reasons[str(e.get("reason"))] += 1
    return {
        "spec": manifest.get("spec"),
        "compare": manifest.get("compare"),
        "base": manifest.get("base"),
        "head": manifest.get("head"),
        "changed": len(manifest.get("changed") or []),
        "expanded": len(manifest.get("expanded") or []),
        "scope_files": len(manifest.get("scope_files") or []),
        "excluded": len(excl),
        "excluded_by_reason": dict(reasons),
        "untouched_modules": (manifest.get("untouched_modules") or {}).get("count", 0),
        "expand_depth": (manifest.get("expansion") or {}).get("depth"),
    }


def report_md_lines(
    manifest: Optional[dict],
    finding_paths: Iterable[str] = (),
    hunted_paths: Optional[Iterable[str]] = None,
) -> list[str]:
    """Markdown "Diff scope" section for REPORT.md / exports.

    *hunted_paths* (path hints of hunt tasks) lets the section name changed
    files that got no hunt task (e.g. ``run.max_tasks`` budget).
    """
    if not isinstance(manifest, dict):
        return []
    b = scope_brief(manifest) or {}
    base = manifest.get("base") or {}
    head = manifest.get("head") or {}
    lines = [
        "## Diff scope",
        "",
        f"- **Diff:** `{base.get('ref')}..{head.get('ref')}` "
        f"(`{str(base.get('sha'))[:12]}` → `{str(head.get('sha'))[:12]}`, two-tree compare)",
        f"- **Changed:** {b.get('changed', 0)} | **Callers/callees:** "
        f"{b.get('expanded', 0)} (depth {b.get('expand_depth')}) | **Excluded:** "
        f"{b.get('excluded', 0)} | **Untouched modules:** {b.get('untouched_modules', 0)}",
        "",
        f"> {manifest.get('disclaimer') or DISCLAIMER}",
        "",
        "### Changed files",
        "",
    ]
    for c in manifest.get("changed") or []:
        rng = ", ".join(f"{s}-{e}" for s, e in (c.get("hunks") or [])[:8]) or "whole file"
        lines.append(f"- `{c['path']}` [{c.get('status')}] lines {rng}")
    exp = manifest.get("expanded") or []
    if exp:
        lines += ["", "### Callers / callees (heuristic)", ""]
        for e in exp:
            lines.append(
                f"- `{e['path']}` — {e.get('via')} of `{e.get('symbol')}` "
                f"(from `{e.get('from')}`, depth {e.get('depth')})"
            )
    excl = manifest.get("excluded") or []
    if excl:
        lines += ["", "### Excluded from the scope", ""]
        for e in excl[:100]:
            lines.append(f"- `{e.get('path')}` — {e.get('reason')}")
        if any(e.get("reason") == "outside_target" for e in excl):
            lines.append("- (`outside_target` paths are repo-root relative)")
        if len(excl) > 100:
            lines.append(f"- … {len(excl) - 100} more")
    if hunted_paths is not None:
        hunted = {normalize_relpath(str(p)) for p in hunted_paths if p}
        unhunted = [p for p in changed_paths(manifest) if p not in hunted]
        if unhunted:
            lines += [
                "",
                "**Changed files with no hunt task yet** (budget or not planned): "
                + ", ".join(f"`{p}`" for p in unhunted[:30]),
            ]
    um = manifest.get("untouched_modules") or {}
    if um.get("count"):
        sample = ", ".join(f"`{m}`" for m in um.get("sample") or [])
        lines += ["", f"**Untouched modules (not hunted):** {um['count']} — {sample}"]
    amb = (manifest.get("expansion") or {}).get("ambiguous_symbols") or []
    if amb:
        lines.append(
            "**Not expanded (generic or multiply-defined names):** "
            + ", ".join(f"`{a}`" for a in amb[:20])
        )
    drift = (manifest.get("worktree") or {}).get("drift") or []
    if drift:
        lines.append(
            "**Warning:** worktree differs from the head commit for "
            + ", ".join(f"`{d}`" for d in drift[:20])
            + " (hunts read the worktree)."
        )
    outside = sorted({normalize_relpath(p) for p in finding_paths if p and not path_in_scope(p, manifest)})
    if outside:
        lines.append(
            "**Findings citing code outside the scope** (reached by a widened hunt): "
            + ", ".join(f"`{p}`" for p in outside[:20])
        )
    lines.append("")
    return lines
