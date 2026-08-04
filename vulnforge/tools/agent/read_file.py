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
        "around_line + radius reads a window around a known line "
        "(prefer after grep hits). "
        "paths=[] reads several files in one call (shared window; tight byte budget). "
        "Response includes total_lines, start_line/end_line, sha256_16, truncated. "
        "Large files are truncated — use a line range for long sources. "
        "Prefer grep to find a symbol, then read_file around that line. "
        "Never invent path contents; only cite what this tool returns."
    ),
    parameters={
        "path": {
            "type": "string",
            "description": (
                "File path relative to target root, e.g. 'src/tools/opensc-tool.c'. "
                "Must be a file, not a directory. Optional when paths is set."
            ),
        },
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Batch-read these relative paths (max ~8). Returns files[] array. "
                "Use for comparing a few related modules in one round."
            ),
        },
        "start_line": {
            "type": "integer",
            "description": (
                "First line to include (1-based). Default 1 if end_line is set. "
                "Omit both start and end to read from line 1 (may truncate). "
                "Ignored when around_line is set."
            ),
        },
        "end_line": {
            "type": "integer",
            "description": (
                "Last line to include (1-based, inclusive). "
                "Omit to read through end of file (or max bytes). "
                "Ignored when around_line is set."
            ),
        },
        "around_line": {
            "type": "integer",
            "description": (
                "Center line (1-based) for a ±radius window. "
                "Preferred after a grep hit instead of guessing start/end."
            ),
        },
        "radius": {
            "type": "integer",
            "description": (
                "Lines before/after around_line (default ~40, max 200)."
            ),
        },
        "max_bytes": {
            "type": "integer",
            "description": (
                "Optional per-file byte budget (capped by config). "
                "Lower for huge generated files."
            ),
        },
    },
    required=(),
    aliases=("cat",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    paths = args.get("paths")
    if paths is not None and not isinstance(paths, list):
        paths = [paths]
    return _read_file(
        ctx,
        path=args.get("path"),
        start_line=args.get("start_line"),
        end_line=args.get("end_line"),
        around_line=args.get("around_line"),
        radius=args.get("radius"),
        max_bytes=args.get("max_bytes"),
        paths=paths,
    )
