"""Agent tool: query_codemap — mechanical codemap modules/entrypoints/symbols."""

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
        "entrypoints, and function/class symbols). Ground truth for structure — "
        "not vulnerabilities. Filter by path prefix, signal token (auth, sql, …), "
        "language, symbol name, or kind. "
        "When path= is set, includes symbols under that path by default "
        "(area insight). Full map is in the DB; this returns a filtered slice. "
        "Use when the packet codemap slice is truncated."
    ),
    parameters={
        "path": {
            "type": "string",
            "description": "Limit modules/files/symbols under this relative path.",
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
            "description": "Filter by language id if present on modules/symbols (e.g. python, c).",
        },
        "symbol": {
            "type": "string",
            "description": "Substring match on symbol name (case-insensitive).",
        },
        "kind": {
            "type": "string",
            "description": (
                "Symbol kind filter: function, method, class, interface, type, …"
            ),
        },
        "max_modules": {
            "type": "integer",
            "description": "Max modules to return (default 20).",
        },
        "max_symbols": {
            "type": "integer",
            "description": "Max symbols to return (default 40 when included).",
        },
        "include_entrypoints": {
            "type": "boolean",
            "description": "Include entrypoints list (default true).",
        },
        "include_symbols": {
            "type": "boolean",
            "description": (
                "Include function/class symbols. Default true when path is set, "
                "false otherwise (modules-only overview)."
            ),
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
    if (not cm or not (cm.get("modules") or cm.get("entrypoints") or cm.get("symbols"))) and rebuild:
        from vulnforge.tools.codemap import build_codemap

        root = Path(str(ctx["target_root"]))
        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        try:
            cm = build_codemap(root, cfg=ctx.get("cfg"), ignore_globs=ignore)
            if db is not None and cm:
                try:
                    db.set_codemap(cm, source=str(cm.get("source") or "mechanical"))
                except Exception:
                    pass
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
    if not cm or not (cm.get("modules") or cm.get("entrypoints") or cm.get("symbols")):
        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("query_codemap")
        return {
            "ok": True,
            "summary": {},
            "modules": [],
            "files": [],
            "symbols": [],
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
    try:
        max_sym = int(args.get("max_symbols") or 40)
    except (TypeError, ValueError):
        max_sym = 40
    max_sym = max(0, min(200, max_sym))

    include_ep = args.get("include_entrypoints")
    if include_ep is None:
        include_ep = True

    path_n = normalize_relpath(str(path)) if path else ""
    include_syms = args.get("include_symbols")
    if include_syms is None:
        include_syms = bool(path_n)
    else:
        include_syms = bool(include_syms)

    path_hints = [path_n] if path_n else None
    sliced = slice_codemap(
        cm,
        path_hints=path_hints,
        area="",
        max_modules=max_mod,
        max_files=40 if include_syms else 0,
        max_symbols=max_sym if include_syms else 0,
        include_symbols=include_syms,
    )
    modules = list(sliced.get("modules") or [])
    signal = str(args.get("signal") or "").strip().lower()
    language = str(args.get("language") or "").strip().lower()
    symbol_q = str(args.get("symbol") or "").strip().lower()
    kind_q = str(args.get("kind") or "").strip().lower()

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
        ] or modules  # language often only on files/symbols

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
                "symbol_count": m.get("symbol_count"),
                "signals": (m.get("signals") or [])[:10],
                "languages": m.get("languages") or m.get("language"),
            }
        )

    files_out = []
    for f in (sliced.get("files") or [])[:40]:
        if not isinstance(f, dict):
            continue
        if language and language not in str(f.get("language") or "").lower():
            continue
        files_out.append(
            {
                "path": f.get("path"),
                "language": f.get("language"),
                "symbol_count": f.get("symbol_count"),
            }
        )

    symbols_out = []
    for s in sliced.get("symbols") or []:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name") or "")
        if symbol_q and symbol_q not in name.lower():
            continue
        if kind_q and kind_q != str(s.get("kind") or "").lower():
            continue
        if language and language not in str(s.get("language") or "").lower():
            continue
        symbols_out.append(
            {
                "path": s.get("path"),
                "name": s.get("name"),
                "kind": s.get("kind"),
                "line": s.get("line"),
                "signature": (str(s.get("signature") or ""))[:200],
                "parent": s.get("parent") or None,
                "language": s.get("language"),
            }
        )
        if symbols_out[-1]["parent"] is None:
            symbols_out[-1].pop("parent", None)
        if len(symbols_out) >= max_sym:
            break

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
        "files": files_out,
        "symbols": symbols_out,
        "entrypoints": entrypoints,
        "module_count": len(slim),
        "symbol_count": len(symbols_out),
        "path_filter": path_hints,
        "signal": signal or None,
        "language": language or None,
        "include_symbols": include_syms,
    }
    if not slim and not entrypoints and not symbols_out:
        result["hint"] = (
            "Codemap empty under filters. Drop path/signal or rebuild=true."
        )
    return attach_scope_warning(result, ctx)
