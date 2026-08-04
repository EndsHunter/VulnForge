"""Agent tool: query_codemap — mechanical codemap modules/entrypoints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.scope import attach_scope_warning, maybe_soft_jail
from vulnforge.util import normalize_relpath

SPEC = ToolSpec(
    name="query_codemap",
    stages=("recon", "hunt"),
    description=(
        "Query the mechanical codemap (modules, package roots, languages, "
        "entrypoints, path signals). Ground truth for structure — not "
        "vulnerabilities. Filter by path prefix, signal token (auth, sql, …), "
        "or language. Use when the packet codemap slice is truncated."
    ),
    parameters={
        "path": {
            "type": "string",
            "description": "Limit modules/entrypoints under this relative path.",
        },
        "signal": {
            "type": "string",
            "description": (
                "Filter modules that list this signal token "
                "(e.g. auth, sql, crypto, upload)."
            ),
        },
        "language": {
            "type": "string",
            "description": "Filter by language id if present on modules (e.g. python, c).",
        },
        "max_modules": {
            "type": "integer",
            "description": "Max modules to return (default 20).",
        },
        "include_entrypoints": {
            "type": "boolean",
            "description": "Include entrypoints list (default true).",
        },
        "rebuild": {
            "type": "boolean",
            "description": "If true and no codemap in DB, build a mechanical map now.",
        },
    },
    required=(),
    aliases=("codemap", "get_codemap"),
)


def _load_codemap(ctx: dict, *, rebuild: bool) -> dict[str, Any]:
    cm: dict[str, Any] = {}
    db = ctx.get("db")
    if db is not None:
        try:
            cm = db.get_codemap() or {}
        except Exception:
            cm = {}
    if not cm and isinstance(ctx.get("codemap"), dict):
        cm = ctx["codemap"]
    if (not cm or not (cm.get("modules") or cm.get("entrypoints"))) and rebuild:
        from vulnforge.tools.codemap import build_codemap

        root = Path(str(ctx["target_root"]))
        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        try:
            cm = build_codemap(root, cfg=ctx.get("cfg"), ignore_globs=ignore)
        except Exception:
            cm = cm or {}
    return cm if isinstance(cm, dict) else {}


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    path = args.get("path")
    if path:
        soft = maybe_soft_jail(ctx, str(path))
        if soft is not None:
            return soft

    rebuild = bool(args.get("rebuild"))
    cm = _load_codemap(ctx, rebuild=rebuild)
    if not cm or not (cm.get("modules") or cm.get("entrypoints")):
        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("query_codemap")
        return {
            "ok": True,
            "summary": {},
            "modules": [],
            "entrypoints": [],
            "hint": (
                "No codemap available yet. Recon usually builds one; "
                "call with rebuild=true to compute a mechanical map now."
            ),
        }

    from vulnforge.tools.codemap import slice_codemap

    try:
        max_mod = int(args.get("max_modules") or 20)
    except (TypeError, ValueError):
        max_mod = 20
    max_mod = max(1, min(50, max_mod))
    include_ep = args.get("include_entrypoints")
    if include_ep is None:
        include_ep = True

    path_hints = [normalize_relpath(str(path))] if path else None
    sliced = slice_codemap(cm, path_hints=path_hints, area="")
    modules = list(sliced.get("modules") or [])
    signal = str(args.get("signal") or "").strip().lower()
    language = str(args.get("language") or "").strip().lower()
    if signal:
        modules = [
            m
            for m in modules
            if isinstance(m, dict)
            and signal in [str(s).lower() for s in (m.get("signals") or [])]
        ]
    if language:
        modules = [
            m
            for m in modules
            if isinstance(m, dict)
            and (
                language in str(m.get("language") or "").lower()
                or language
                in [str(x).lower() for x in (m.get("languages") or [])]
            )
        ]
    slim = []
    for m in modules[:max_mod]:
        if not isinstance(m, dict):
            continue
        slim.append(
            {
                "path": m.get("path"),
                "kind": m.get("kind"),
                "label": m.get("label"),
                "file_count": m.get("file_count"),
                "signals": (m.get("signals") or [])[:10],
                "languages": m.get("languages") or m.get("language"),
            }
        )
    entrypoints = []
    if include_ep:
        for e in (sliced.get("entrypoints") or [])[:20]:
            if isinstance(e, dict):
                entrypoints.append(e.get("path") or e)
            else:
                entrypoints.append(e)

    sess = ctx.setdefault("session", {})
    sess.setdefault("tools_used", []).append("query_codemap")
    result = {
        "ok": True,
        "summary": sliced.get("summary") or cm.get("summary") or {},
        "modules": slim,
        "entrypoints": entrypoints,
        "module_count": len(slim),
        "path_filter": path_hints,
        "signal": signal or None,
        "language": language or None,
    }
    if not slim and not entrypoints:
        result["hint"] = (
            "Codemap empty under filters. Drop path/signal or rebuild=true."
        )
    return attach_scope_warning(result, ctx)
