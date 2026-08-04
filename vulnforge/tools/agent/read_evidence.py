"""Agent tool: read_evidence — read a file from the evidence pack only."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.evidence_write import read_evidence as _read_evidence

SPEC = ToolSpec(
    name="read_evidence",
    stages=("hunt", "develop_poc"),
    description=(
        "Read a text file from this task's evidence pack only "
        "(never the audit target — use read_file for target source). "
        "relpath is relative to the pack (e.g. 'notes.md', 'poc.py', "
        "'poc_develop.md'). Use list_evidence first if unsure of names."
    ),
    parameters={
        "relpath": {
            "type": "string",
            "description": "Path inside the evidence pack.",
        },
        "evidence_id": {
            "type": "string",
            "description": "Pack id (default: session/task pack).",
        },
        "max_bytes": {
            "type": "integer",
            "description": "Optional read budget (capped).",
        },
    },
    required=("relpath",),
    critical_for=("develop_poc",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _read_evidence(
        ctx,
        relpath=args.get("relpath", ""),
        evidence_id=args.get("evidence_id"),
        max_bytes=args.get("max_bytes"),
    )
