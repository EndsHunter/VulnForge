"""Agent tool: continue_hunt — spawn a child hunt with a fresh context window."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.continue_task import enqueue_continuation

SPEC = ToolSpec(
    name="continue_hunt",
    stages=("hunt",),
    aliases=("handoff_hunt", "spawn_continue_hunt"),
    description=(
        "Finish THIS hunt by queueing a child hunt that continues the same "
        "area×class with a fresh context window. "
        "Call this when the harness says context is high/critical, or when "
        "you still have remaining work that will not fit in this conversation. "
        "handoff must list paths already inspected, what remains, and the "
        "next concrete steps. After a successful call, do not keep exploring "
        "or call submit_* — this task is done; Ralph runs the child. "
        "Not a sibling skill request (use request_hunt for a different class)."
    ),
    parameters={
        "handoff": {
            "type": "string",
            "description": (
                "Required. What you already did, remaining work, and what the "
                "child should investigate next. Include paths/symbols."
            ),
        },
        "explored_paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Paths already read/grepped (child should not redo these first).",
        },
        "remaining_paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Optional path_hints for the child (defaults to this hunt's hints)."
            ),
        },
        "remaining_work": {
            "type": "string",
            "description": "Optional extra remaining-work notes.",
        },
    },
    required=("handoff",),
    critical_for=("hunt",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return enqueue_continuation(
        ctx,
        kind="hunt",
        handoff=str(args.get("handoff") or args.get("reason") or ""),
        explored_paths=args.get("explored_paths"),
        remaining_paths=args.get("remaining_paths") or args.get("path_hints"),
        remaining_work=str(args.get("remaining_work") or ""),
        auto=False,
    )
