"""Agent tool: find_symbol — heuristic definition / reference search."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.symbol_find import find_symbol as _find_symbol

SPEC = ToolSpec(
    name="find_symbol",
    stages=("recon", "hunt", "develop_poc"),
    description=(
        "Locate likely definitions of a function/class/type name in the target "
        "(heuristic regex — not a full language server). "
        "Prefer this over inventing paths. "
        "symbol is the identifier (e.g. 'search_users', 'AuthService'). "
        "Optional path/glob/extension narrow the scan. "
        "definitions_only=true (default) returns def/class/fn-like lines; "
        "set false to include other references. "
        "Soft-scoped to path_hints on hunt until widened."
    ),
    parameters={
        "symbol": {
            "type": "string",
            "description": "Identifier to find (function, class, type, or macro name).",
        },
        "path": {
            "type": "string",
            "description": "Optional relative directory or file to bound the search.",
        },
        "glob": {
            "type": "string",
            "description": "Optional fnmatch, e.g. '*.py'.",
        },
        "extension": {
            "type": "string",
            "description": "Optional extension filter, e.g. '.go' or 'c'.",
        },
        "definitions_only": {
            "type": "boolean",
            "description": "If true (default), only definition-like lines; else include references.",
        },
        "max_matches": {
            "type": "integer",
            "description": "Stop after this many hits (default ~40).",
        },
    },
    required=("symbol",),
    aliases=("find_def", "goto_def"),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    defs_only = args.get("definitions_only")
    if defs_only is None:
        defs_only = True
    return _find_symbol(
        ctx,
        symbol=str(args.get("symbol") or ""),
        path=args.get("path"),
        glob=args.get("glob"),
        extension=args.get("extension"),
        max_matches=args.get("max_matches"),
        definitions_only=bool(defs_only),
    )
