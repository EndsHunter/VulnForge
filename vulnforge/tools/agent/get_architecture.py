"""Agent tool: get_architecture — recon map + hunt brief for this task."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec

SPEC = ToolSpec(
    name="get_architecture",
    stages=("hunt",),
    description=(
        "Return a compact architecture brief for this hunt: recon summary, "
        "trust boundaries, components/path_hints for this area, and the "
        "current task's class/path_hints/seed sink count. "
        "Use when the packet was truncated or you need to re-ground the map. "
        "Does not finish the task."
    ),
    parameters={
        "max_chars": {
            "type": "integer",
            "description": "Soft cap on summary text (default 2000).",
        },
        "include_components": {
            "type": "boolean",
            "description": "Include component list (default true).",
        },
    },
    required=(),
    aliases=("architecture", "hunt_brief"),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    try:
        max_chars = int(args.get("max_chars") or 2000)
    except (TypeError, ValueError):
        max_chars = 2000
    max_chars = max(400, min(8000, max_chars))
    include_components = args.get("include_components")
    if include_components is None:
        include_components = True

    arch: dict[str, Any] = {}
    db = ctx.get("db")
    if db is not None:
        try:
            arch = db.get_architecture() or {}
        except Exception:
            arch = {}
    if not arch and isinstance(ctx.get("architecture"), dict):
        arch = ctx["architecture"]

    payload = ctx.get("task_payload") if isinstance(ctx.get("task_payload"), dict) else {}
    summary = str(arch.get("summary") or "")[:max_chars]
    trust = list(arch.get("trust_boundaries") or [])[:20]
    components = []
    if include_components:
        for c in (arch.get("components") or [])[:30]:
            if isinstance(c, dict):
                components.append(
                    {
                        "name": c.get("name"),
                        "path_hints": (c.get("path_hints") or [])[:12],
                        "role": c.get("role"),
                    }
                )
            elif c:
                components.append({"name": str(c)})

    area = payload.get("area") or payload.get("component") or ""
    path_hints = list(payload.get("path_hints") or [])
    weakness = payload.get("class") or payload.get("weakness_class") or payload.get("profile")
    seeds = payload.get("seed_sinks") or []
    seed_n = len(seeds) if isinstance(seeds, list) else 0

    # Known findings count for near-dup awareness
    finding_count = None
    if db is not None:
        try:
            finding_count = len(list(db.list_findings() or []))
        except Exception:
            finding_count = None

    sess = ctx.setdefault("session", {})
    sess.setdefault("tools_used", []).append("get_architecture")
    result: dict[str, Any] = {
        "ok": True,
        "summary": summary,
        "trust_boundaries": trust,
        "components": components if include_components else None,
        "task": {
            "area": area,
            "class": weakness,
            "path_hints": path_hints,
            "seed_sink_count": seed_n,
            "force_depth": bool(payload.get("force_depth")),
        },
        "finding_count": finding_count,
    }
    if not summary and not components:
        result["hint"] = (
            "No architecture map in DB yet — recon may still be running, "
            "or call query_codemap(rebuild=true) for structure only."
        )
    return result
