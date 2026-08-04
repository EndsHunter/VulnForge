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
            "No '..' or absolute paths. Nested paths create parent dirs."
        ),
    },
    "content": {
        "type": "string",
        "description": "Full file contents to write (UTF-8 text), or chunk to append.",
    },
    "append": {
        "type": "boolean",
        "description": (
            "If true, append content to an existing pack file (or create it). "
            "Final file must still meet the min non-vacuous size."
        ),
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
        "description": "Full file contents (UTF-8 text), or chunk to append.",
    },
    "evidence_id": {
        "type": "string",
        "description": "Evidence pack id for this finding (use the task pack id).",
    },
    "append": {
        "type": "boolean",
        "description": (
            "If true, append content to an existing pack file "
            "(useful for notes; prefer full rewrite for poc.py)."
        ),
    },
}

SPEC = ToolSpec(
    name="write_evidence",
    stages=("hunt", "develop_poc"),
    description=(
        "Write a text file into this task's evidence pack under evidence/ "
        "(never into the audit target — absolute/target paths are auto-rewritten "
        "to pack-relative basenames or rejected with suggested_relpath). "
        "Use for notes, excerpts, or draft PoC material. "
        "relpath is relative to the pack root (e.g. 'notes.md', 'excerpt.c'). "
        "append=true appends to an existing file. "
        "Use list_evidence / read_evidence to inspect the pack."
    ),
    parameters=_HUNT_PROPS,
    required=("relpath", "content"),
    critical_for=("develop_poc",),
    stage_descriptions={
        "hunt": (
            "Write a text file into this task's evidence pack under evidence/ "
            "(never into the audit target). "
            "Use for notes, excerpts, or draft PoC material. "
            "relpath is relative to the pack root (e.g. 'notes.md', 'excerpt.c'). "
            "append=true to extend notes without rewriting the whole file."
        ),
        "develop_poc": (
            "Write a file into the evidence pack (not the audit target). "
            "Prefer runnable PoC scripts: poc.py, poc.sh, poc.ps1, or poc.c. "
            "Also write/update hub poc_develop.md with run instructions only — "
            "do not rewrite the finding narrative. "
            "relpath is relative to the pack (or pack selected by evidence_id). "
            "Use list_evidence / read_evidence to re-open prior drafts."
        ),
    },
    stage_parameters={
        "hunt": _HUNT_PROPS,
        "develop_poc": _POC_PROPS,
    },
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    # Models often pass path= (target-style) instead of relpath= — accept both.
    rel = args.get("relpath")
    if rel is None or str(rel).strip() == "":
        rel = args.get("path") or args.get("file") or ""
    return _write_evidence(
        ctx,
        relpath=str(rel or ""),
        content=args.get("content", ""),
        evidence_id=args.get("evidence_id"),
        append=bool(args.get("append")),
    )
