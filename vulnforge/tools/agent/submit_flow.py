"""Agent tool: submit_flow — finish a flow-tracer recon task with data flows.

A flow is a steering hint for hunts (entrypoint -> steps -> sink), never a
finding and never evidence. The stage validates every ``path:line`` against
the read-only target tree: steps it cannot verify make the flow ``inferred``.
"""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec

_END_PROPS = {
    "component": {"type": "string", "description": "Component id from the map."},
    "path": {"type": "string", "description": "Relative path, e.g. app.py"},
    "line": {"type": "integer", "description": "1-based line you read"},
}

_FLOW = {
    "type": "object",
    "properties": {
        "title": {
            "type": "string",
            "description": "Short title, e.g. 'search q -> SQL query'.",
        },
        "source": {
            "type": "object",
            "description": "Where untrusted data enters (your entrypoint).",
            "properties": {
                **_END_PROPS,
                "label": {
                    "type": "string",
                    "description": "e.g. 'GET /search?q' or 'argv[1]'.",
                },
            },
        },
        "steps": {
            "type": "array",
            "description": (
                "Each hop the data takes, in order. Cite a line you read; "
                "note what happens there (e.g. 'q concatenated into sql')."
            ),
            "items": {
                "type": "object",
                "properties": {
                    **_END_PROPS,
                    "note": {"type": "string"},
                },
            },
        },
        "sink": {
            "type": "object",
            "description": "Where the data lands, e.g. {kind: 'sql', path, line}.",
            "properties": {
                **_END_PROPS,
                "kind": {
                    "type": "string",
                    "description": "sql | exec | path | template | http_out | deserialize | ...",
                },
            },
        },
        "classes": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Registered hunt class ids that fit, e.g. ['injection']. "
                "Unknown ids are dropped."
            ),
        },
        "crosses": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional zone ids crossed, e.g. ['internet', 'internal'].",
        },
    },
}

SPEC = ToolSpec(
    name="submit_flow",
    stages=("recon",),
    description=(
        "Finish the flow-tracer task: submit the data flows you traced from "
        "the given entrypoint (one call, one or more flows). Every source, "
        "step and sink should cite a path + line you actually read. "
        "Found nothing? Call with flows: [] and a reason. Never invent a flow. "
        "Flows are hints for hunts, not findings."
    ),
    parameters={
        "flows": {
            "type": "array",
            "description": (
                "Flows. Example: [{title: 'search q -> SQL', "
                "source: {component: 'app', label: 'search_users(q)', path: 'app.py', line: 9}, "
                "steps: [{path: 'app.py', line: 11, note: 'q formatted into sql'}], "
                "sink: {component: 'datastore', kind: 'sql', path: 'app.py', line: 12}, "
                "classes: ['injection']}]"
            ),
            "items": _FLOW,
        },
        "reason": {
            "type": "string",
            "description": "Why no (or few) flows were found. Required when flows is empty.",
        },
    },
    required=(),
    critical_for=("recon",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    fn = ctx.get("submit_flow")
    if not fn:
        return {
            "ok": False,
            "error": "submit_flow not available (only the flow-tracer recon agent submits flows)",
        }
    return fn(args)
