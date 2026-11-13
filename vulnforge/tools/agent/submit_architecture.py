"""Agent tool: submit_architecture — finish recon with an architecture map.

Accepts v1 fields (summary, components, trust_boundaries, input_surfaces,
hunt_focus, relations) and the v2 slices (zones, component zone /
entrypoints / sinks, boundaries, cited relations). Everything except
``summary`` is optional; the stage normalizes and validates citations.
"""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec

# path + line citation (1-based line you actually read)
_LOC = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "Relative path, e.g. app.py"},
        "line": {"type": "integer", "description": "1-based line you read"},
    },
}

SPEC = ToolSpec(
    name="submit_architecture",
    stages=("recon",),
    description=(
        "Finish recon: submit the architecture map (not vulnerabilities). "
        "Call exactly once when done exploring. Only summary is required. "
        "Start from the mechanical skeleton in the prompt: keep its component "
        "ids when you rename or relabel, give each component a zone, and cite "
        "path + line you actually read for entrypoints, sinks, boundaries and "
        "relations. A relation without a line you read is fine: set "
        "confidence 'inferred'. "
        "hunt_focus.class must be a registered hunt class id (never invent ids). "
        "Do not call submit_candidate or submit_none in recon."
    ),
    parameters={
        "summary": {
            "type": "string",
            "description": (
                "1–3 paragraphs: what the system is, main modules, "
                "and attacker-relevant shape. Non-empty required."
            ),
        },
        "trust_boundaries": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Boundaries untrusted input crosses, e.g. "
                "'CLI argv → libopensc', 'PKCS#11 app → token', "
                "'config file → parser'."
            ),
        },
        "zones": {
            "type": "array",
            "description": (
                "Trust zones. kind: internet | authenticated | internal | "
                "external | build. Example: {id: 'internet', kind: 'internet', "
                "label: 'Public HTTP', evidence: [{path: 'app.py', line: 12}]}."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"type": "string"},
                    "label": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": _LOC,
                    },
                },
            },
        },
        "components": {
            "type": "array",
            "description": (
                "Major modules with path_hints you inspected. Reuse skeleton ids "
                "(e.g. id 'app') to relabel; new id only for a new component."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Stable slug, e.g. api-invoices (keep skeleton id).",
                    },
                    "name": {
                        "type": "string",
                        "description": "Component name (e.g. pkcs11, tools)",
                    },
                    "kind": {
                        "type": "string",
                        "description": "e.g. http_router, worker, cli, library, datastore.",
                    },
                    "zone": {
                        "type": "string",
                        "description": "Zone id or kind, e.g. internet.",
                    },
                    "path_hints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Relative paths under the target (dirs or key files)."
                        ),
                    },
                    "role": {
                        "type": "string",
                        "description": "Optional short role description.",
                    },
                    "entrypoints": {
                        "type": "array",
                        "description": (
                            "Where input enters, e.g. "
                            "{label: 'GET /search', path: 'app.py', line: 40}."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string"},
                                "path": {"type": "string"},
                                "line": {"type": "integer"},
                            },
                        },
                    },
                    "sinks": {
                        "type": "array",
                        "description": (
                            "Dangerous calls, e.g. {kind: 'sql', path: 'app.py', line: 52}."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {"type": "string"},
                                "path": {"type": "string"},
                                "line": {"type": "integer"},
                            },
                        },
                    },
                },
            },
        },
        "boundaries": {
            "type": "array",
            "description": (
                "Zone crossings and the control that guards them, e.g. "
                "{from_zone: 'internet', to_zone: 'authenticated', "
                "control: 'login_required', path: 'auth.py', line: 18}."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "from_zone": {"type": "string"},
                    "to_zone": {"type": "string"},
                    "control": {"type": "string"},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                },
            },
        },
        "input_surfaces": {
            "type": "array",
            "description": (
                "Where untrusted data enters. Prefer short path-backed "
                "strings, or objects with name + path_hints."
            ),
            "items": {
                "anyOf": [
                    {"type": "string"},
                    {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "path_hints": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "protocol": {"type": "string"},
                        },
                    },
                ]
            },
        },
        "hunt_focus": {
            "type": "array",
            "description": (
                "Optional small set of area × registered class × path_hints "
                "for later hunts. Omit weak/generic focus."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "area": {
                        "type": "string",
                        "description": "Logical area name (often a component).",
                    },
                    "class": {
                        "type": "string",
                        "description": (
                            "Registered hunt class id only "
                            "(e.g. injection, memory-safety, cryptography)."
                        ),
                    },
                    "path_hints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to bound the hunt.",
                    },
                },
            },
        },
        "relations": {
            "type": "array",
            "description": (
                "Edges between component ids. kind: calls | data_flow | imports | "
                "queue | db | http_out | auth_gate | depends_on | trust_boundary. "
                "evidence = the path + line you read that shows the edge. "
                "No line? still emit it with confidence 'inferred'. "
                "Example: {from: 'api', to: 'datastore', kind: 'db', "
                "evidence: {path: 'app.py', line: 52}}."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "from": {
                        "type": "string",
                        "description": "Source component id (match components).",
                    },
                    "to": {
                        "type": "string",
                        "description": "Target component id (match components).",
                    },
                    "kind": {
                        "type": "string",
                        "description": "One of the kinds listed above.",
                    },
                    "evidence": _LOC,
                    "confidence": {
                        "type": "string",
                        "description": "cited (you read the line) or inferred.",
                    },
                    "note": {
                        "type": "string",
                        "description": "Optional short note (role, not exploit text).",
                    },
                },
                "required": ["from", "to"],
            },
        },
    },
    required=("summary",),
    critical_for=("recon",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    fn = ctx.get("submit_architecture")
    if not fn:
        return {"ok": False, "error": "submit_architecture not available"}
    return fn(args)
