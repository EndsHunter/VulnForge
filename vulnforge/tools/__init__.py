"""Allowlisted tools for agent tool-calls."""

from __future__ import annotations

import importlib
from typing import Any, Callable

from vulnforge.tools.evidence_write import write_evidence
from vulnforge.tools.extra_registry import get_extra_spec
from vulnforge.tools.fs_read import file_inventory, list_dir, read_file
from vulnforge.tools.ghidra_tools import GHIDRA_TOOL_FUNCS
from vulnforge.tools.grep_index import grep
from vulnforge.tools.queue_note import note
from vulnforge.tools.request_hunt import list_hunt_profiles, request_hunt

# Model-facing aliases → canonical name (tool-gap transcripts often invent these).
_INVENTORY_ALIASES = frozenset(
    {
        "file_inventory",
        "inventory",
        "directory_tree",
        "get_directory_tree",
        "dir_tree",
    }
)


def _dispatch_extra(name: str, ctx: dict, args: dict) -> dict[str, Any] | None:
    """Run an operator-integrated extra tool; None if not registered."""
    spec = get_extra_spec(name)
    if not spec:
        return None
    mod_path = str(spec.get("module") or "").strip()
    callable_name = str(spec.get("callable") or spec.get("name") or "").strip()
    if not mod_path or not callable_name:
        return {"ok": False, "error": f"extra tool {name} misconfigured"}
    try:
        mod = importlib.import_module(mod_path)
        fn = getattr(mod, callable_name)
    except Exception as e:
        return {"ok": False, "error": f"extra tool import failed: {e}"}
    # Pass only kwargs the function accepts when possible; otherwise full args.
    try:
        import inspect

        sig = inspect.signature(fn)
        params = sig.parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return fn(ctx, **(args or {}))
        allowed = {
            k: v
            for k, v in (args or {}).items()
            if k in params and k != "ctx"
        }
        return fn(ctx, **allowed)
    except TypeError:
        return fn(ctx, **(args or {}))


def build_tool_handler(ctx: dict) -> Callable[[str, dict], dict]:
    """
    Return callable(name, args) -> result.
    Session-bound submit_* are optional callables on ctx.
    """

    def handler(name: str, args: dict) -> dict[str, Any]:
        args = args or {}
        try:
            if name == "list_dir":
                return list_dir(ctx, **{k: args[k] for k in ("path",) if k in args})
            if name in _INVENTORY_ALIASES:
                return file_inventory(
                    ctx,
                    path=args.get("path", ".") or ".",
                    max_depth=args.get("max_depth"),
                    max_entries=args.get("max_entries"),
                    extension=args.get("extension"),
                    glob=args.get("glob"),
                    format=args.get("format", "tree") or "tree",
                )
            if name == "read_file":
                return read_file(
                    ctx,
                    path=args.get("path", ""),
                    start_line=args.get("start_line"),
                    end_line=args.get("end_line"),
                )
            if name == "grep":
                return grep(
                    ctx,
                    pattern=args.get("pattern", ""),
                    glob=args.get("glob"),
                    max_matches=args.get("max_matches"),
                    extension=args.get("extension"),
                    files_only=bool(args.get("files_only") or args.get("files_with_matches")),
                    match_path=bool(args.get("match_path")),
                )
            if name == "write_evidence":
                return write_evidence(
                    ctx,
                    relpath=args.get("relpath", ""),
                    content=args.get("content", ""),
                    evidence_id=args.get("evidence_id"),
                )
            if name == "note":
                return note(ctx, kind=args.get("kind", ""), payload=args.get("payload", {}))
            if name == "list_hunt_profiles":
                return list_hunt_profiles(ctx)
            if name == "request_hunt":
                hints = args.get("path_hints")
                if hints is not None and not isinstance(hints, list):
                    hints = [hints]
                return request_hunt(
                    ctx,
                    profile=str(args.get("profile") or args.get("class") or ""),
                    reason=str(args.get("reason") or ""),
                    area=args.get("area"),
                    path_hints=hints,
                    force_depth=bool(
                        args["force_depth"] if "force_depth" in args else True
                    ),
                )
            if name == "submit_architecture":
                fn = ctx.get("submit_architecture")
                if not fn:
                    return {"ok": False, "error": "submit_architecture not available"}
                return fn(args)
            if name == "submit_candidate":
                fn = ctx.get("submit_candidate")
                if not fn:
                    return {"ok": False, "error": "submit_candidate not available"}
                return fn(args)
            if name == "submit_none":
                fn = ctx.get("submit_none")
                if not fn:
                    return {"ok": False, "error": "submit_none not available"}
                return fn(args)
            if name in GHIDRA_TOOL_FUNCS:
                result = GHIDRA_TOOL_FUNCS[name](ctx, **(args or {}))
                # Depth tracking for binary_re is_shallow (decompile/xrefs/…)
                sess = ctx.get("session")
                if (
                    isinstance(sess, dict)
                    and isinstance(result, dict)
                    and result.get("ok")
                ):
                    used = sess.setdefault("tools_used", [])
                    if name not in used:
                        used.append(name)
                return result
            extra = _dispatch_extra(name, ctx, args)
            if extra is not None:
                return extra
            return {"ok": False, "error": f"unknown tool {name}"}
        except TypeError as e:
            return {"ok": False, "error": f"bad args: {e}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    return handler
