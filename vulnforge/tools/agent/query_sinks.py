"""Agent tool: query_sinks — mechanical sink preindex lookup."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.scope import attach_scope_warning, maybe_soft_jail, scope_hints
from vulnforge.util import normalize_relpath

SPEC = ToolSpec(
    name="query_sinks",
    stages=("recon", "hunt"),
    description=(
        "Query mechanical security-relevant sinks (sql, exec, path, auth, jwt, "
        "llm, template, deserialize, ssrf, memory) from the preindex or a "
        "bounded live scan. Prefer this over inventing sink locations. "
        "Filter by kind and/or path. Returns path:line + short text. "
        "Not a proof of vulnerability — only candidate locations to read."
    ),
    parameters={
        "kind": {
            "type": "string",
            "description": (
                "Sink family: sql, exec, path, auth, jwt, llm, template, "
                "deserialize, ssrf, memory. Omit for all kinds."
            ),
        },
        "kinds": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Multiple sink families (alternative to kind).",
        },
        "path": {
            "type": "string",
            "description": "Limit to this relative path prefix (dir or file).",
        },
        "max_matches": {
            "type": "integer",
            "description": "Max sinks to return (default 24, max 100).",
        },
        "rescan": {
            "type": "boolean",
            "description": (
                "If true, rebuild sinks with a live scan when index is empty "
                "(slower). Default false."
            ),
        },
    },
    required=(),
    aliases=("list_sinks", "sinks"),
)


def _load_sinks(ctx: dict, *, rescan: bool) -> list[dict[str, Any]]:
    sinks: list[dict[str, Any]] = []
    # 1) task payload seed
    payload = ctx.get("task_payload") or {}
    raw = payload.get("seed_sinks")
    if isinstance(raw, list) and raw:
        sinks = [s for s in raw if isinstance(s, dict)]
    # 2) architecture inventory
    if not sinks:
        db = ctx.get("db")
        arch: dict = {}
        if db is not None:
            try:
                arch = db.get_architecture() or {}
            except Exception:
                arch = {}
        if not arch and isinstance(ctx.get("architecture"), dict):
            arch = ctx["architecture"]
        inv = arch.get("inventory") or {}
        raw2 = inv.get("seed_sinks") or arch.get("seed_sinks") or []
        if isinstance(raw2, list):
            sinks = [s for s in raw2 if isinstance(s, dict)]
    # 3) optional live rescan (or first-time build when empty + rescan)
    if rescan:
        from vulnforge.tools.sink_preindex import build_sink_preindex

        root = Path(str(ctx["target_root"]))
        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        try:
            sinks = build_sink_preindex(root, ignore, max_files=2000, max_sinks=300)
        except Exception:
            sinks = sinks or []
    return sinks


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    path = args.get("path")
    if path:
        soft = maybe_soft_jail(ctx, str(path))
        if soft is not None:
            return soft

    kinds: set[str] = set()
    if args.get("kind"):
        kinds.add(str(args["kind"]).strip().lower())
    raw_kinds = args.get("kinds")
    if isinstance(raw_kinds, list):
        for k in raw_kinds:
            if k:
                kinds.add(str(k).strip().lower())
    elif isinstance(raw_kinds, str) and raw_kinds.strip():
        kinds.add(raw_kinds.strip().lower())

    try:
        top_k = int(args.get("max_matches") or 24)
    except (TypeError, ValueError):
        top_k = 24
    top_k = max(1, min(100, top_k))
    rescan = bool(args.get("rescan"))

    sinks = _load_sinks(ctx, rescan=rescan)
    # Soft path_hints when no explicit path
    path_filter: list[str] = []
    if path:
        path_filter = [normalize_relpath(str(path))]
    else:
        hints = scope_hints(ctx)
        if hints and not (ctx.get("scope") or {}).get("widened"):
            path_filter = hints

    from vulnforge.tools.sink_preindex import filter_sinks_for_paths

    filtered = filter_sinks_for_paths(
        sinks,
        path_filter or None,
        top_k=top_k,
        kinds=kinds or None,
    )
    # If soft-scoped filter emptied and we have an index, do not global-fallback
    # when path_filter was set (filter_sinks already does this).

    sess = ctx.setdefault("session", {})
    sess.setdefault("tools_used", []).append("query_sinks")
    result: dict[str, Any] = {
        "ok": True,
        "sinks": filtered,
        "count": len(filtered),
        "kinds": sorted(kinds) if kinds else None,
        "path_filter": path_filter or None,
        "index_size": len(sinks),
    }
    if not sinks:
        result["hint"] = (
            "No sink index in session/architecture. Call with rescan=true for a "
            "bounded live scan, or grep for sql/exec patterns yourself."
        )
    elif not filtered:
        result["hint"] = (
            "0 sinks under current filters. Drop kind=, widen path_hints, "
            "or try path= with a broader prefix."
        )
    return attach_scope_warning(result, ctx)
