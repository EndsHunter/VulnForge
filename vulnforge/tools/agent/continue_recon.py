"""Agent tool: continue_recon — spawn a child recon with a fresh context window."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.continue_task import enqueue_continuation

SPEC = ToolSpec(
    name="continue_recon",
    stages=("recon",),
    aliases=("handoff_recon", "spawn_continue_recon"),
    description=(
        "Finish THIS recon by queueing a child recon that continues mapping "
        "with a fresh context window. "
        "Call this when the harness says context is high/critical, or when "
        "the architecture map is still incomplete and more inspection will "
        "not fit. handoff must say what you mapped, what is still unknown, "
        "and which paths the child should inspect next. "
        "After a successful call, do not keep exploring or call "
        "submit_architecture — this task is done; Ralph runs the child. "
        "The child refines the prior architecture; it does not blank-overwrite."
    ),
    parameters={
        "handoff": {
            "type": "string",
            "description": (
                "Required. Mapped so far, remaining unknown areas, and next paths "
                "the child should inspect."
            ),
        },
        "explored_paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Paths already inventoried/read (child should deepen elsewhere first).",
        },
        "remaining_paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional focus_paths for the child.",
        },
        "remaining_work": {
            "type": "string",
            "description": "Optional extra remaining-work notes.",
        },
    },
    required=("handoff",),
    critical_for=("recon",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return enqueue_continuation(
        ctx,
        kind="recon",
        handoff=str(args.get("handoff") or args.get("reason") or args.get("summary") or ""),
        explored_paths=args.get("explored_paths"),
        remaining_paths=args.get("remaining_paths")
        or args.get("focus_paths")
        or args.get("path_hints"),
        remaining_work=str(args.get("remaining_work") or ""),
        auto=False,
    )
