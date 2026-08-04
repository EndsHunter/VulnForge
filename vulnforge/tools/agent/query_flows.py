"""Agent tool: query_flows — coarse import / call reachability (not taint)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.flows import (
    call_sites,
    import_neighborhood,
    tag_sinks_on_nodes,
)
from vulnforge.tools.scope import attach_scope_warning, maybe_soft_jail, scope_hints
from vulnforge.util import normalize_relpath

SPEC = ToolSpec(
    name="query_flows",
    stages=("recon", "hunt"),
    description=(
        "Coarse reachability helpers — NOT dataflow or taint proof. "
        "mode=imports: BFS on codemap module import edges around a path. "
        "mode=calls: heuristic name-based call sites for a symbol "
        "(who might call search_users?). "
        "mode=both: combine when path and/or symbol given. "
        "Use to prioritize read_file/grep. Never treat edges as exploit paths."
    ),
    parameters={
        "mode": {
            "type": "string",
            "description": "imports | calls | both (default both).",
        },
        "path": {
            "type": "string",
            "description": "Anchor file/dir for import graph (soft-jailed).",
        },
        "symbol": {
            "type": "string",
            "description": "Function/class name for call mode.",
        },
        "direction": {
            "type": "string",
            "description": (
                "Import BFS direction: from (outgoing), to (incoming), both. "
                "Default both."
            ),
        },
        "max_depth": {
            "type": "integer",
            "description": "Import BFS hops (default 1, max 3).",
        },
        "max_edges": {
            "type": "integer",
            "description": "Cap import edges returned (default 40, max 100).",
        },
        "include_sinks": {
            "type": "boolean",
            "description": (
                "If true, tag import nodes that overlap seed_sinks under the same paths."
            ),
        },
        "rebuild": {
            "type": "boolean",
            "description": "If true and no codemap in DB, build mechanical map now.",
        },
    },
    required=(),
    aliases=("reachability", "import_graph"),
)


def _load_codemap(ctx: dict, *, rebuild: bool) -> dict[str, Any]:
    # Same load path as query_codemap
    cm: dict[str, Any] = {}
    db = ctx.get("db")
    if db is not None:
        try:
            cm = db.get_codemap() or {}
        except Exception:
            cm = {}
    if not cm and isinstance(ctx.get("codemap"), dict):
        cm = ctx["codemap"]
    if (
        not cm or not (cm.get("modules") or cm.get("edges") or cm.get("symbols"))
    ) and rebuild:
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


def _load_seed_sinks(ctx: dict) -> list[dict[str, Any]]:
    payload = ctx.get("task_payload") or {}
    raw = payload.get("seed_sinks")
    if isinstance(raw, list) and raw:
        return [s for s in raw if isinstance(s, dict)]
    db = ctx.get("db")
    arch: dict = {}
    if db is not None:
        try:
            arch = db.get_architecture() or {}
        except Exception:
            arch = {}
    if not arch and isinstance(ctx.get("architecture"), dict):
        arch = ctx["architecture"]
    inv = arch.get("inventory") if isinstance(arch.get("inventory"), dict) else {}
    raw2 = inv.get("seed_sinks") or arch.get("seed_sinks") or []
    if isinstance(raw2, list):
        return [s for s in raw2 if isinstance(s, dict)]
    return []


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    path = args.get("path")
    symbol = str(args.get("symbol") or "").strip()
    if path:
        soft = maybe_soft_jail(ctx, str(path))
        if soft is not None:
            return soft

    mode = str(args.get("mode") or "both").strip().lower()
    if mode not in ("imports", "calls", "both"):
        mode = "both"

    tools_cfg = (ctx.get("cfg") or {}).get("tools") or {}
    try:
        max_depth = int(args.get("max_depth") or tools_cfg.get("max_flow_depth", 1))
    except (TypeError, ValueError):
        max_depth = 1
    try:
        max_edges = int(args.get("max_edges") or tools_cfg.get("max_flow_edges", 40))
    except (TypeError, ValueError):
        max_edges = 40
    try:
        max_call_files = int(tools_cfg.get("max_flow_call_files", 200))
    except (TypeError, ValueError):
        max_call_files = 200
    try:
        timeout_s = float(tools_cfg.get("grep_timeout_seconds", 8.0))
    except (TypeError, ValueError):
        timeout_s = 8.0

    direction = str(args.get("direction") or "both")
    include_sinks = bool(args.get("include_sinks"))
    rebuild = bool(args.get("rebuild"))

    # imports need path; calls need symbol; both needs at least one
    if mode == "imports" and not path:
        return {
            "ok": False,
            "error": "path required for mode=imports",
        }
    if mode == "calls" and not symbol:
        return {
            "ok": False,
            "error": "symbol required for mode=calls",
        }
    if mode == "both" and not path and not symbol:
        return {
            "ok": False,
            "error": "provide path and/or symbol for mode=both",
        }

    sess = ctx.setdefault("session", {})
    sess.setdefault("tools_used", []).append("query_flows")

    result: dict[str, Any] = {
        "ok": True,
        "mode": mode,
        "disclaimer": (
            "Coarse reachability only — not dataflow, taint, or exploit proof."
        ),
    }

    cm: dict[str, Any] = {}
    if mode in ("imports", "both") and path:
        cm = _load_codemap(ctx, rebuild=rebuild)
        imp = import_neighborhood(
            cm,
            path=str(path),
            direction=direction,
            max_depth=max_depth,
            max_edges=max_edges,
        )
        if include_sinks and imp.get("ok") and imp.get("nodes"):
            sinks = _load_seed_sinks(ctx)
            imp["nodes"] = tag_sinks_on_nodes(imp["nodes"], sinks)
        result["imports"] = imp

    if mode in ("calls", "both") and symbol:
        if not cm and mode == "both":
            cm = _load_codemap(ctx, rebuild=rebuild)
        elif not cm and mode == "calls":
            # optional codemap for caller attribution
            cm = _load_codemap(ctx, rebuild=False)

        hints: list[str] = []
        if path:
            hints = [normalize_relpath(str(path))]
        else:
            sh = scope_hints(ctx)
            if sh and not (ctx.get("scope") or {}).get("widened"):
                hints = sh

        root = Path(str(ctx["target_root"]))
        ignore = list((ctx.get("cfg") or {}).get("run", {}).get("ignore_globs") or [])
        calls = call_sites(
            root,
            symbol,
            path_hints=hints or None,
            ignore_globs=ignore,
            max_files=max_call_files,
            max_hits=max(1, min(100, max_edges)),
            timeout_s=timeout_s,
            codemap=cm or None,
        )
        result["calls"] = calls

    return attach_scope_warning(result, ctx)
