"""Agent tool: submit_none — finish hunt with no solid finding."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec

SPEC = ToolSpec(
    name="submit_none",
    stages=("hunt",),
    description=(
        "Finish hunt with no solid finding after a real search. "
        "reason must say what you checked and why nothing met the bar "
        "(not just 'looks fine'). "
        "Do not use submit_none to skip work; use tools first. "
        "Do not call submit_candidate after submit_none."
    ),
    parameters={
        "reason": {
            "type": "string",
            "description": (
                "Concrete negative result: paths/patterns checked "
                "and residual uncertainty if any."
            ),
        },
    },
    required=("reason",),
    critical_for=("hunt",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    fn = ctx.get("submit_none")
    if not fn:
        return {"ok": False, "error": "submit_none not available"}
    return fn(args)
