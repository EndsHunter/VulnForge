"""Read-only filesystem tools against the audit target."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

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
        soft = maybe_soft_jail(ctx, path or ".")
        if soft is not None:
            return soft
        root = Path(ctx["target_root"])
        p = resolve_target_path(root, path)
        if not p.is_dir():
            return {"ok": False, "error": "not a directory"}
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
            "path": path,
            "entries": entries,
            "total": total,
            "truncated": total > len(entries),
            "max_entries": cap,
        }
        return attach_scope_warning(result, ctx)
    except Exception as e:
        return {"ok": False, "error": str(e)}


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
        soft = maybe_soft_jail(ctx, path or ".")
        if soft is not None:
            return soft

        root = Path(ctx["target_root"]).resolve()
        base = resolve_target_path(root, path)
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


def read_file(
    ctx: dict,
    path: str,
    start_line: int | None = None,
    end_line: int | None = None,
) -> dict[str, Any]:
    try:
        soft = maybe_soft_jail(ctx, path or "")
        if soft is not None:
            return soft
        root = Path(ctx["target_root"])
        p = resolve_target_path(root, path)
        if not p.is_file():
            return {"ok": False, "error": "not a file"}
        max_bytes = int((ctx.get("cfg") or {}).get("tools", {}).get("max_read_bytes", 65536))
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)
        if start_line is not None or end_line is not None:
            s = max(1, int(start_line or 1)) - 1
            e = int(end_line) if end_line is not None else total
            e = max(s, e)
            chunk_lines = lines[s:e]
        else:
            chunk_lines = lines
        joined = "\n".join(chunk_lines)
        truncated = False
        if len(joined.encode("utf-8", errors="replace")) > max_bytes:
            joined = joined.encode("utf-8", errors="replace")[:max_bytes].decode(
                "utf-8", errors="replace"
            )
            truncated = True
        # track tool use
        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("read_file")
        result = {
            "ok": True,
            "path": normalize_relpath(path),
            "content": joined,
            "total_lines": total,
            "truncated": truncated,
        }
        return attach_scope_warning(result, ctx)
    except Exception as e:
        return {"ok": False, "error": str(e)}
