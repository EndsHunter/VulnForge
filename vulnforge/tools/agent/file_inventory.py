"""Agent tool: file_inventory — recursive inventory / directory tree."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.fs_read import file_inventory as _file_inventory

SPEC = ToolSpec(
    name="file_inventory",
    stages=("recon", "hunt", "develop_poc"),
    description=(
        "Recursive file inventory / directory tree under a path (read-only). "
        "Prefer this over many list_dir rounds. "
        "Filter with extension (e.g. '.c', 'py', '*.go') or glob ('**/pkcs11/*'). "
        "format=tree for structure, list for paths, both for both. "
        "If truncated, narrow path/depth or add extension/glob — do not re-walk "
        "the whole tree with the same args."
    ),
    parameters={
        "path": {
            "type": "string",
            "description": (
                "Subtree root relative to target (default '.'). "
                "E.g. 'src/libopensc' to inventory one package."
            ),
        },
        "max_depth": {
            "type": "integer",
            "description": (
                "Max directory depth from path (default from config, often 10). "
                "Lower depth for huge trees."
            ),
        },
        "max_entries": {
            "type": "integer",
            "description": (
                "Max files to return (default from config, often 2000). "
                "Response includes truncated=true when capped."
            ),
        },
        "extension": {
            "type": "string",
            "description": (
                "Keep only this file extension: '.c', 'c', or '*.c' all work. "
                "Case-insensitive."
            ),
        },
        "glob": {
            "type": "string",
            "description": (
                "fnmatch on full relative path or basename, e.g. '*.go', "
                "'**/tools/*', 'Makefile*'."
            ),
        },
        "format": {
            "type": "string",
            "enum": ["tree", "list", "both"],
            "description": (
                "tree (default): indented tree string; "
                "list: paths array; both: tree + paths."
            ),
        },
    },
    required=(),
    aliases=(
        "inventory",
        "directory_tree",
        "get_directory_tree",
        "dir_tree",
    ),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _file_inventory(
        ctx,
        path=args.get("path", ".") or ".",
        max_depth=args.get("max_depth"),
        max_entries=args.get("max_entries"),
        extension=args.get("extension"),
        glob=args.get("glob"),
        format=args.get("format", "tree") or "tree",
    )
