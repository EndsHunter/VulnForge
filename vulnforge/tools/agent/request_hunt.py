"""Agent tool: request_hunt — enqueue a sibling hunt for another profile."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.request_hunt import request_hunt as _request_hunt

SPEC = ToolSpec(
    name="request_hunt",
    stages=("hunt",),
    description=(
        "Queue a separate Ralph hunt for another registered profile "
        "(does not finish this task). "
        "Use when the current area clearly needs a different class skill "
        "(e.g. auth code found during injection → access-control). "
        "Rejected if that profile is already queued/leased, if it would "
        "circularly re-queue a profile on this spawn chain (A→B→A), "
        "or if spawn caps are hit. "
        "Do not re-run the same profile as this task. "
        "Still finish THIS hunt with submit_candidate or submit_none."
    ),
    parameters={
        "profile": {
            "type": "string",
            "description": (
                "Registered hunt profile id "
                "(e.g. injection, access-control). "
                "Use list_hunt_profiles if unsure."
            ),
        },
        "reason": {
            "type": "string",
            "description": (
                "Why that class should run on this area (path or symbol evidence)."
            ),
        },
        "area": {
            "type": "string",
            "description": "Optional area override (default: this task's area).",
        },
        "path_hints": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Optional paths to bound the spawned hunt "
                "(default: this task's path_hints)."
            ),
        },
        "force_depth": {
            "type": "boolean",
            "description": (
                "If true (default), spawned hunt must use deeper "
                "tools before submit_none."
            ),
        },
    },
    required=("profile", "reason"),
    critical_for=("hunt",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    hints = args.get("path_hints")
    if hints is not None and not isinstance(hints, list):
        hints = [hints]
    return _request_hunt(
        ctx,
        profile=str(args.get("profile") or args.get("class") or ""),
        reason=str(args.get("reason") or ""),
        area=args.get("area"),
        path_hints=hints,
        force_depth=bool(args["force_depth"] if "force_depth" in args else True),
    )
