"""Agent tool: list_dir — one directory level under the audit target."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.fs_read import list_dir as _list_dir

SPEC = ToolSpec(
    name="list_dir",
    stages=("recon", "hunt", "develop_poc"),
    description=(
        "List ONE directory level under the audit target (read-only). "
        "Paths are relative to the target root (use '.' for root). "
        "Returns names + is_dir only — not recursive. "
        "Prefer file_inventory for a full subtree or tree in one call; "
        "use list_dir when you only need children of a known folder."
    ),
    parameters={
        "path": {
            "type": "string",
            "description": (
                "Directory relative to target root. "
                "Default '.' if omitted. No leading slash; no '..'."
            ),
        },
        "max_entries": {
            "type": "integer",
            "description": (
                "Max children to return (default from config, often 200). "
                "If truncated is true, narrow path or raise cap carefully."
            ),
        },
    },
    required=(),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if "path" in args:
        kwargs["path"] = args["path"]
    if "max_entries" in args:
        kwargs["max_entries"] = args["max_entries"]
    return _list_dir(ctx, **kwargs)
