"""Agent tool: submit_candidate — finish hunt with one vulnerability candidate."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec

SPEC = ToolSpec(
    name="submit_candidate",
    stages=("hunt",),
    description=(
        "Finish hunt with one vulnerability candidate (not confirmed). "
        "Requires path-backed citations from files you read. "
        "weakness_class should match this hunt's class when possible. "
        "threat_model must state attacker, boundary crossed, and impact. "
        "This is not exploit proof — human review decides confirmed. "
        "Do not call submit_none after a successful candidate."
    ),
    parameters={
        "title": {
            "type": "string",
            "description": "Short specific title (not just the class name).",
        },
        "summary": {
            "type": "string",
            "description": (
                "What is wrong, where, and why it matters. Ground in citations."
            ),
        },
        "weakness_class": {
            "type": "string",
            "description": (
                "Weakness / hunt class id, e.g. injection, "
                "access-control, memory-safety."
            ),
        },
        "threat_model": {
            "type": "object",
            "description": (
                "Who attacks, what trust boundary is crossed, and concrete "
                "impact. Avoid placeholders (n/a, unknown) and vacuous lines "
                "like 'could be bad' or 'if they have write access…'."
            ),
            "properties": {
                "attacker": {
                    "type": "string",
                    "description": (
                        "Who can reach the sink with what capability "
                        "(e.g. unauthenticated HTTP client, local CLI user, "
                        "tenant-scoped API token). Not n/a/unknown."
                    ),
                },
                "boundary": {
                    "type": "string",
                    "description": (
                        "Trust boundary crossed "
                        "(e.g. untrusted query param → SQL engine; "
                        "user A → user B object). Not n/a/none/unknown."
                    ),
                },
                "impact": {
                    "type": "string",
                    "description": (
                        "Concrete damage if exploited: exact effect "
                        "(RCE, authz bypass, secret/PII leak, tenant data "
                        "read, DoS…). One sentence: attacker does X → gets Z. "
                        "Not 'security risk' or 'could potentially…'."
                    ),
                },
            },
            "required": ["attacker", "boundary", "impact"],
        },
        "citations": {
            "type": "array",
            "description": (
                "One or more code locations. path required; "
                "include start_line/end_line when known."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path under the target.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "1-based start line.",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "1-based end line (inclusive).",
                    },
                    "symbol": {
                        "type": "string",
                        "description": "Optional function/type name.",
                    },
                },
                "required": ["path"],
            },
        },
        "evidence_id": {
            "type": "string",
            "description": "Optional evidence pack id if you wrote supporting files.",
        },
        "poc_relpath": {
            "type": "string",
            "description": "Optional path of a PoC file inside the evidence pack.",
        },
        "severity_claim": {
            "type": "string",
            "enum": [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFORMATIONAL",
            ],
            "description": (
                "Optional severity rating only — CRITICAL, HIGH, MEDIUM, "
                "LOW, or INFORMATIONAL. Not free-text impact (use "
                "threat_model.impact). Cap at MEDIUM when many attacker "
                "preconditions or non-prod-only impact. HIGH/CRITICAL need "
                "concrete impact (authz, secrets, RCE, data, …)."
            ),
        },
    },
    required=("title", "summary", "weakness_class", "threat_model", "citations"),
    critical_for=("hunt",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    fn = ctx.get("submit_candidate")
    if not fn:
        return {"ok": False, "error": "submit_candidate not available"}
    return fn(args)
