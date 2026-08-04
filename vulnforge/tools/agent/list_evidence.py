"""Agent tool: list_evidence — list files in the task evidence pack."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.evidence_write import list_evidence as _list_evidence

SPEC = ToolSpec(
    name="list_evidence",
    stages=("hunt", "develop_poc"),
    description=(
        "List files under this task's evidence pack (evidence/<id>/ only — "
        "never the audit target). "
        "Use after write_evidence or during develop_poc to see notes/PoC files. "
        "Optional evidence_id defaults to the task/session pack."
    ),
    parameters={
        "evidence_id": {
            "type": "string",
            "description": "Pack id (default: session/task pack).",
        },
        "max_entries": {
            "type": "integer",
            "description": "Max files to return (default from config).",
        },
    },
    required=(),
    critical_for=("develop_poc",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _list_evidence(
        ctx,
        evidence_id=args.get("evidence_id"),
        max_entries=args.get("max_entries"),
    )
