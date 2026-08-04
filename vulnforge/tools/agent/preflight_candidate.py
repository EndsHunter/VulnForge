"""Agent tool: preflight_candidate — dry-run submit_candidate gates."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.candidate_preflight import preflight_candidate as _preflight

SPEC = ToolSpec(
    name="preflight_candidate",
    stages=("hunt",),
    description=(
        "Dry-run the same gates submit_candidate will enforce: schema, "
        "non-vacuous threat_model, citation paths/lines on disk, evidence pack "
        "written in this session, plus near-duplicate hints. "
        "Does NOT store a finding and does NOT finish the hunt. "
        "Pass the same fields you would pass to submit_candidate. "
        "When ready=true, call submit_candidate with those fields."
    ),
    parameters={
        "title": {
            "type": "string",
            "description": "Short specific title (not just the class name).",
        },
        "summary": {
            "type": "string",
            "description": "What is wrong, where, and why it matters.",
        },
        "weakness_class": {
            "type": "string",
            "description": "Weakness / hunt class id.",
        },
        "threat_model": {
            "type": "object",
            "description": "attacker, boundary, impact (same as submit_candidate).",
            "properties": {
                "attacker": {"type": "string"},
                "boundary": {"type": "string"},
                "impact": {"type": "string"},
            },
        },
        "citations": {
            "type": "array",
            "description": "Code locations with path and optional lines.",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                    "symbol": {"type": "string"},
                },
            },
        },
        "evidence_id": {
            "type": "string",
            "description": "Evidence pack id from write_evidence.",
        },
        "poc_relpath": {
            "type": "string",
            "description": "Optional PoC path inside the pack.",
        },
        "severity_claim": {
            "type": "string",
            "description": "Optional CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL.",
        },
    },
    required=(),
    critical_for=("hunt",),
    aliases=("check_candidate", "validate_candidate"),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _preflight(ctx, body=dict(args) if args else {})
