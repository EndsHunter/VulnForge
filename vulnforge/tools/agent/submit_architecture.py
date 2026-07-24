"""Agent tool: submit_architecture — finish recon with an architecture map."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec

SPEC = ToolSpec(
    name="submit_architecture",
    stages=("recon",),
    description=(
        "Finish recon: submit the architecture map (not vulnerabilities). "
        "Call exactly once when done exploring. "
        "summary is required and must be non-empty. "
        "Prefer path-backed components, input_surfaces, and hunt_focus "
        "from files you actually listed/read/grepped. "
        "hunt_focus.class must be a registered hunt class id from the "
        "prompt registry (never invent ids). "
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
        "components": {
            "type": "array",
            "description": "Major modules/packages with path_hints you inspected.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Component name (e.g. pkcs11, tools)",
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
    },
    required=("summary",),
    critical_for=("recon",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    fn = ctx.get("submit_architecture")
    if not fn:
        return {"ok": False, "error": "submit_architecture not available"}
    return fn(args)
