"""Read-only filesystem tools against the audit target."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from vulnforge.tools.path_coerce import coerce_target_relpath
from vulnforge.tools.scope import attach_scope_warning, maybe_soft_jail
from vulnforge.util import normalize_relpath

# Default caps for recursive inventory (overridable via cfg.tools)
DEFAULT_MAX_INVENTORY_ENTRIES = 2000
DEFAULT_MAX_INVENTORY_DEPTH = 10


def resolve_target_path(target_root: Path, rel: str) -> Path:
    root = target_root.resolve()
    rel_n = normalize_relpath(rel or ".")
    if rel_n in ("", "."):
        return root
    p = (root / rel_n).resolve()
    if p != root and root not in p.parents:
        raise PermissionError(f"path escape: {rel}")
    return p


def list_dir(ctx: dict, path: str = ".", max_entries: int | None = None) -> dict[str, Any]:
    try:
        rel, cerr = coerce_target_relpath(ctx, path, default=".", tool="list_dir")
        if cerr is not None:
            return cerr
        assert rel is not None
        soft = maybe_soft_jail(ctx, rel)
        if soft is not None:
            # Ensure soft jail always exposes structured out_of_scope
            soft.setdefault("code", soft.get("error") or "out_of_scope")
            return soft
        root = Path(ctx["target_root"])
        try:
            p = resolve_target_path(root, rel)
        except PermissionError:
            return {
                "ok": False,
                "error": "path_escape",
                "code": "path_escape",
                "path": rel,
                "hint": (
                    "list_dir: path escapes the audit target. "
                    "Use a relative path under the target root (e.g. '.')."
                ),
            }
        if not p.exists():
            return {
                "ok": False,
                "error": "path_not_found",
                "code": "path_not_found",
                "path": rel,
                "hint": "Path does not exist under the target. Try file_inventory or list_dir on parent.",
            }
        if not p.is_dir():
            return {
                "ok": False,
                "error": "not_a_directory",
                "code": "not_a_directory",
                "path": rel,
                "hint": "list_dir needs a directory. Use read_file for files.",
            }
        cap = max_entries or int((ctx.get("cfg") or {}).get("tools", {}).get("max_list_entries", 200))
        try:
            cap = max(1, int(cap))
        except (TypeError, ValueError):
            cap = 200
        all_children = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        total = len(all_children)
        entries = []
        for e in all_children[:cap]:
            entries.append({"name": e.name, "is_dir": e.is_dir()})
        result = {
            "ok": True,
            "path": rel,
            "entries": entries,
            "total": total,
            "truncated": total > len(entries),
            "max_entries": cap,
        }
        if path and normalize_relpath(str(path)) not in (rel, normalize_relpath(rel)):
            # Absolute-under-target was trimmed
            if str(path).replace("\\", "/") != rel:
                result["rewritten"] = True
                result["original_path"] = path
        return attach_scope_warning(result, ctx)
    except PermissionError as e:
        return {
            "ok": False,
            "error": "path_escape",
            "code": "path_escape",
            "hint": str(e),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "code": "list_dir_error"}


def _norm_extension(extension: str | None) -> str | None:
    if extension is None:
        return None
    e = str(extension).strip().lower()
    if not e:
        return None
    if e.startswith("*."):
        e = e[1:]  # "*.cu" → ".cu"
    if not e.startswith("."):
        e = "." + e
    return e


def _path_matches_filters(
    rel: str,
    name: str,
    *,
    extension: str | None,
    glob_pat: str | None,
) -> bool:
    from fnmatch import fnmatch

    if extension and Path(name).suffix.lower() != extension:
        return False
    if glob_pat:
        if not fnmatch(rel, glob_pat) and not fnmatch(name, glob_pat):
            return False
    return True


def _ignored_rel(rel: str, ignore_globs: list[str]) -> bool:
    from vulnforge.tools.grep_index import _ignored

    return _ignored(rel, ignore_globs)


_SKIP_DIR_NAMES = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", ".cache"}
)


def _collect_inventory_files(
    root: Path,
    base: Path,
    *,
    depth_cap: int,
    entry_cap: int,
    ignore: list[str],
    extension: str | None,
    glob_pat: str | None,
) -> tuple[list[str], Counter[str], bool]:
    """Walk ``base`` under ``root``; return (files, ext_hist, truncated)."""
    files: list[str] = []
    ext_hist: Counter[str] = Counter()
    truncated = False
    # stack: (dir_path, depth)
    stack: list[tuple[Path, int]] = [(base, 0)]
    while stack:
        dpath, depth = stack.pop()
        try:
            children = sorted(
                dpath.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())
            )
        except OSError:
            continue
        dirs_here: list[Path] = []
        for child in children:
            try:
                is_d = child.is_dir()
                is_f = child.is_file()
            except OSError:
                continue
            try:
                crel = normalize_relpath(str(child.relative_to(root)))
            except ValueError:
                continue
            if is_d:
                if child.name in _SKIP_DIR_NAMES:
                    continue
                if _ignored_rel(crel + "/", ignore) or _ignored_rel(crel + "/**", ignore):
                    continue
                dirs_here.append(child)
            elif is_f:
                if _ignored_rel(crel, ignore):
                    continue
                if not _path_matches_filters(
                    crel, child.name, extension=extension, glob_pat=glob_pat
                ):
                    continue
                if len(files) >= entry_cap:
                    truncated = True
                    return files, ext_hist, truncated
                files.append(crel)
                ext_hist[child.suffix.lower() or "<none>"] += 1
        if depth < depth_cap:
            for dchild in reversed(dirs_here):
                stack.append((dchild, depth + 1))
        elif dirs_here:
            truncated = True
    return files, ext_hist, truncated


def _paths_to_tree(files: list[str], root_label: str = ".") -> str:
    """Indented directory tree from relative file paths."""
    trie: dict[str, Any] = {}
    prefix_parts = (
        [p for p in root_label.split("/") if p]
        if root_label and root_label not in (".", "")
        else []
    )
    for f in files:
        parts = [p for p in normalize_relpath(f).split("/") if p]
        if prefix_parts and parts[: len(prefix_parts)] == prefix_parts:
            parts = parts[len(prefix_parts) :]
        if not parts:
            continue
        node = trie
        for i, part in enumerate(parts):
            is_file = i == len(parts) - 1
            entry = node.setdefault(part, {"file": False, "kids": {}})
            if is_file:
                entry["file"] = True
            node = entry["kids"]

    lines: list[str] = []

    def walk(n: dict[str, Any], indent: str) -> None:
        # dirs (have kids) first-ish, then files — stable by name
        names = sorted(
            n.keys(),
            key=lambda x: (0 if n[x]["kids"] else 1, x.lower()),
        )
        for name in names:
            meta = n[name]
            kids = meta["kids"]
            if kids:
                lines.append(f"{indent}{name}/")
                walk(kids, indent + "  ")
            if meta["file"] and not kids:
                lines.append(f"{indent}{name}")
            elif meta["file"] and kids:
                lines.append(f"{indent}{name}  (file)")

    header = f"{root_label}/" if root_label not in (".", "") else "."
    walk(trie, "")
    body = "\n".join(lines)
    return f"{header}\n{body}" if body else header


def file_inventory(
    ctx: dict,
    path: str = ".",
    *,
    max_depth: int | None = None,
    max_entries: int | None = None,
    extension: str | None = None,
    glob: str | None = None,
    format: str = "tree",
) -> dict[str, Any]:
    """Recursive scoped inventory / directory tree in one tool call.

    Reduces list_dir thrash: compact tree and/or file list with optional
    extension/glob filters (e.g. find all ``.cu`` files).
    """
    try:
        rel, cerr = coerce_target_relpath(ctx, path, default=".", tool="file_inventory")
        if cerr is not None:
            return cerr
        assert rel is not None
        soft = maybe_soft_jail(ctx, rel)
        if soft is not None:
            soft.setdefault("code", soft.get("error") or "out_of_scope")
            return soft

        root = Path(ctx["target_root"]).resolve()
        try:
            base = resolve_target_path(root, rel)
        except PermissionError:
            return {
                "ok": False,
                "error": "path_escape",
                "code": "path_escape",
                "path": rel,
                "hint": "file_inventory: path escapes the audit target.",
            }
        path = rel  # normalized for display below
        if not base.exists():
            return {"ok": False, "error": "path not found", "path": path}
        if base.is_file():
            rel = normalize_relpath(str(base.relative_to(root)))
            sess = ctx.setdefault("session", {})
            sess.setdefault("tools_used", []).append("file_inventory")
            return attach_scope_warning(
                {
                    "ok": True,
                    "path": rel,
                    "format": "list",
                    "files": [rel],
                    "file_count": 1,
                    "dir_count": 0,
                    "tree": rel,
                    "extensions": {base.suffix.lower() or "<none>": 1},
                    "truncated": False,
                },
                ctx,
            )
        if not base.is_dir():
            return {"ok": False, "error": "not a directory or file"}

        tools_cfg = (ctx.get("cfg") or {}).get("tools") or {}
        depth_cap = max(
            0,
            int(
                max_depth
                if max_depth is not None
                else tools_cfg.get("max_inventory_depth", DEFAULT_MAX_INVENTORY_DEPTH)
            ),
        )
        entry_cap = max(
            1,
            int(
                max_entries
                if max_entries is not None
                else tools_cfg.get(
                    "max_inventory_entries", DEFAULT_MAX_INVENTORY_ENTRIES
                )
            ),
        )
        ext_f = _norm_extension(extension)
        glob_pat = str(glob).strip() if glob else None
        fmt = (format or "tree").strip().lower()
        if fmt not in ("tree", "list", "both"):
            fmt = "tree"

        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        base_rel = normalize_relpath(str(base.relative_to(root)))
        if base_rel in ("", "."):
            base_rel = ""
        display_path = base_rel or "."

        files, ext_hist, truncated = _collect_inventory_files(
            root,
            base,
            depth_cap=depth_cap,
            entry_cap=entry_cap,
            ignore=ignore,
            extension=ext_f,
            glob_pat=glob_pat,
        )

        parents = {
            str(Path(f).parent).replace("\\", "/")
            for f in files
            if str(Path(f).parent).replace("\\", "/") not in (".", "")
        }
        want_tree = fmt in ("tree", "both")
        want_list = fmt in ("list", "both") or bool(ext_f or glob_pat)

        result: dict[str, Any] = {
            "ok": True,
            "path": display_path,
            "format": fmt,
            "file_count": len(files),
            "dir_count": len(parents),
            "extensions": dict(ext_hist),
            "truncated": truncated,
            "max_depth": depth_cap,
            "max_entries": entry_cap,
        }
        if ext_f:
            result["extension"] = ext_f
        if glob_pat:
            result["glob"] = glob_pat
        if want_tree:
            result["tree"] = _paths_to_tree(files, root_label=display_path)
        if want_list:
            result["files"] = files
        if not files and (ext_f or glob_pat):
            result["hint"] = (
                "No files matched extension/glob under this path. "
                "Try path='.', drop the filter, or widen soft path_hints."
            )

        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("file_inventory")
        return attach_scope_warning(result, ctx)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _read_one_file(
    ctx: dict,
    path: str,
    *,
    start_line: int | None = None,
    end_line: int | None = None,
    around_line: int | None = None,
    radius: int | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Read a single path; returns ok dict or error dict (no session append)."""
    rel, cerr = coerce_target_relpath(ctx, path, default="", tool="read_file")
    if cerr is not None:
        return cerr
    if not rel:
        return {
            "ok": False,
            "error": "path_required",
            "code": "path_required",
            "hint": "read_file requires path relative to the target root.",
        }
    soft = maybe_soft_jail(ctx, rel)
    if soft is not None:
        soft.setdefault("code", soft.get("error") or "out_of_scope")
        return soft
    root = Path(ctx["target_root"])
    try:
        p = resolve_target_path(root, rel)
    except PermissionError:
        return {
            "ok": False,
            "error": "path_escape",
            "code": "path_escape",
            "path": rel,
            "hint": "read_file: path escapes the audit target.",
        }
    if not p.exists():
        # Suggest siblings under parent when possible
        hint = "Path not found. Use file_inventory or list_dir on the parent."
        try:
            parent = p.parent
            if parent.is_dir() and root.resolve() in (parent.resolve(), *parent.resolve().parents):
                names = sorted(e.name for e in parent.iterdir())[:12]
                if names:
                    hint += f" Parent contains: {', '.join(names)}"
        except OSError:
            pass
        return {"ok": False, "error": "path not found", "path": rel, "hint": hint}
    if not p.is_file():
        return {
            "ok": False,
            "error": "not a file",
            "path": rel,
            "hint": "Use list_dir or file_inventory for directories.",
        }

    tools_cfg = (ctx.get("cfg") or {}).get("tools") or {}
    budget = int(
        max_bytes
        if max_bytes is not None
        else tools_cfg.get("max_read_bytes", 65536)
    )
    budget = max(1024, min(budget, int(tools_cfg.get("max_read_bytes_hard", 262144))))

    try:
        raw = p.read_bytes()
    except OSError as e:
        return {"ok": False, "error": f"unreadable: {e}", "path": rel}

    import hashlib

    sha = hashlib.sha256(raw).hexdigest()[:16]
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    total = len(lines)

    # around_line + radius takes precedence when set
    if around_line is not None:
        try:
            center = int(around_line)
        except (TypeError, ValueError):
            return {"ok": False, "error": "around_line must be an integer", "path": rel}
        try:
            rad = int(radius if radius is not None else tools_cfg.get("default_read_radius", 40))
        except (TypeError, ValueError):
            rad = 40
        rad = max(0, min(200, rad))
        if center < 1:
            center = 1
        if center > total and total > 0:
            center = total
        s = max(0, center - 1 - rad)
        e = min(total, center + rad)
        chunk_lines = lines[s:e]
        start_1 = s + 1
        end_1 = e
    elif start_line is not None or end_line is not None:
        s = max(1, int(start_line or 1)) - 1
        e = int(end_line) if end_line is not None else total
        e = max(s, e)
        chunk_lines = lines[s:e]
        start_1 = s + 1
        end_1 = min(total, e) if total else 0
    else:
        chunk_lines = lines
        start_1 = 1 if total else 0
        end_1 = total

    joined = "\n".join(chunk_lines)
    truncated = False
    encoded = joined.encode("utf-8", errors="replace")
    if len(encoded) > budget:
        joined = encoded[:budget].decode("utf-8", errors="replace")
        truncated = True

    return {
        "ok": True,
        "path": rel,
        "content": joined,
        "total_lines": total,
        "start_line": start_1,
        "end_line": end_1,
        "truncated": truncated,
        "sha256_16": sha,
        "size_bytes": len(raw),
    }


def read_file(
    ctx: dict,
    path: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
    *,
    around_line: int | None = None,
    radius: int | None = None,
    max_bytes: int | None = None,
    paths: list[str] | None = None,
) -> dict[str, Any]:
    """Read a text file (or line range / around a line) from the audit target.

    Batch mode: pass ``paths`` (list of relative paths) with a shared line window
    and per-file byte budget. Returns ``files`` array; overall ok if any succeed.
    """
    try:
        tools_cfg = (ctx.get("cfg") or {}).get("tools") or {}
        batch_paths: list[str] = []
        if paths is not None:
            if isinstance(paths, str):
                batch_paths = [paths]
            elif isinstance(paths, list):
                batch_paths = [str(p) for p in paths if p]
        if path and str(path).strip():
            # Single path wins when paths not used; if both, path is first
            p0 = str(path).strip()
            if not batch_paths:
                batch_paths = [p0]
            elif p0 not in batch_paths:
                batch_paths.insert(0, p0)

        if not batch_paths:
            return {
                "ok": False,
                "error": "path or paths required",
                "hint": "Pass path='file.py' or paths=['a.py','b.py'].",
            }

        max_batch = int(tools_cfg.get("max_read_batch", 8))
        max_batch = max(1, min(20, max_batch))
        if len(batch_paths) > max_batch:
            batch_paths = batch_paths[:max_batch]
            batch_truncated = True
        else:
            batch_truncated = False

        # Per-file budget shrinks in batch mode
        per_budget = max_bytes
        if per_budget is None and len(batch_paths) > 1:
            base = int(tools_cfg.get("max_read_bytes", 65536))
            per_budget = max(4096, base // len(batch_paths))

        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("read_file")

        if len(batch_paths) == 1:
            result = _read_one_file(
                ctx,
                batch_paths[0],
                start_line=start_line,
                end_line=end_line,
                around_line=around_line,
                radius=radius,
                max_bytes=per_budget,
            )
            return attach_scope_warning(result, ctx)

        files_out: list[dict[str, Any]] = []
        any_ok = False
        for bp in batch_paths:
            one = _read_one_file(
                ctx,
                bp,
                start_line=start_line,
                end_line=end_line,
                around_line=around_line,
                radius=radius,
                max_bytes=per_budget,
            )
            files_out.append(one)
            if one.get("ok"):
                any_ok = True
        result: dict[str, Any] = {
            "ok": any_ok,
            "files": files_out,
            "file_count": len(files_out),
            "batch": True,
        }
        if batch_truncated:
            result["batch_truncated"] = True
            result["max_read_batch"] = max_batch
        if not any_ok:
            result["error"] = "all paths failed"
        return attach_scope_warning(result, ctx)
    except Exception as e:
        return {"ok": False, "error": str(e)}
