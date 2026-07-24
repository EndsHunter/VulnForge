"""Agent tool: read_file — read text (or line range) from the audit target."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.fs_read import read_file as _read_file

SPEC = ToolSpec(
    name="read_file",
    stages=("recon", "hunt", "develop_poc"),
    description=(
        "Read a text file (or line range) from the audit target (read-only). "
        "path is relative to the target root. "
        "start_line/end_line are 1-based inclusive line numbers "
        "(omit both to read from the start, subject to max size). "
        "Large files are truncated — use a line range for long sources. "
        "Prefer grep to find a symbol, then read_file around that line. "
        "Never invent path contents; only cite what this tool returns."
    ),
    parameters={
        "path": {
            "type": "string",
            "description": (
                "File path relative to target root, e.g. 'src/tools/opensc-tool.c'. "
                "Must be a file, not a directory."
            ),
        },
        "start_line": {
            "type": "integer",
            "description": (
                "First line to include (1-based). Default 1 if end_line is set. "
                "Omit both start and end to read from line 1 (may truncate)."
            ),
        },
        "end_line": {
            "type": "integer",
            "description": (
                "Last line to include (1-based, inclusive). "
                "Omit to read through end of file (or max bytes)."
            ),
        },
    },
    required=("path",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _read_file(
        ctx,
        path=args.get("path", ""),
        start_line=args.get("start_line"),
        end_line=args.get("end_line"),
    )
