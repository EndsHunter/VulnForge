"""Agent tool: write_evidence — write files under evidence/ only."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.evidence_write import write_evidence as _write_evidence

_HUNT_PROPS = {
    "relpath": {
        "type": "string",
        "description": (
            "Path inside the evidence pack only, e.g. 'notes.md'. "
            "No '..' or absolute paths."
        ),
    },
    "content": {
        "type": "string",
        "description": "Full file contents to write (UTF-8 text).",
    },
}

_POC_PROPS = {
    "relpath": {
        "type": "string",
        "description": (
            "Path inside the evidence pack, e.g. 'poc.py', 'poc_develop.md'."
        ),
    },
    "content": {
        "type": "string",
        "description": "Full file contents (UTF-8 text).",
    },
    "evidence_id": {
        "type": "string",
        "description": "Evidence pack id for this finding (use the task pack id).",
    },
}

SPEC = ToolSpec(
    name="write_evidence",
    stages=("hunt", "develop_poc"),
    description=(
        "Write a text file into this task's evidence pack under evidence/ "
        "(never into the audit target). "
        "Use for notes, excerpts, or draft PoC material. "
        "relpath is relative to the pack root (e.g. 'notes.md', 'excerpt.c')."
    ),
    parameters=_HUNT_PROPS,
    required=("relpath", "content"),
    critical_for=("develop_poc",),
    stage_descriptions={
        "hunt": (
            "Write a text file into this task's evidence pack under evidence/ "
            "(never into the audit target). "
            "Use for notes, excerpts, or draft PoC material. "
            "relpath is relative to the pack root (e.g. 'notes.md', 'excerpt.c')."
        ),
        "develop_poc": (
            "Write a file into the evidence pack (not the audit target). "
            "Prefer runnable PoC scripts: poc.py, poc.sh, poc.ps1, or poc.c. "
            "Also write/update hub poc_develop.md with run instructions only — "
            "do not rewrite the finding narrative. "
            "relpath is relative to the pack (or pack selected by evidence_id)."
        ),
    },
    stage_parameters={
        "hunt": _HUNT_PROPS,
        "develop_poc": _POC_PROPS,
    },
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _write_evidence(
        ctx,
        relpath=args.get("relpath", ""),
        content=args.get("content", ""),
        evidence_id=args.get("evidence_id"),
    )
