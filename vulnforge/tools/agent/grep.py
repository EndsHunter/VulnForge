"""Agent tool: grep — regex search over the audit target."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.grep_index import grep as _grep

SPEC = ToolSpec(
    name="grep",
    stages=("recon", "hunt", "develop_poc"),
    description=(
        "Search target files with a regex (read-only). "
        "pattern is a Python/PCRE-style regex over file lines "
        "(or over path/filename when match_path=true). "
        "Narrow with extension and/or glob before broad searches on large trees. "
        "files_only=true returns unique paths only (faster inventory of hits). "
        "Empty pattern + extension or glob lists matching files by path "
        "(prefer file_inventory for directory trees). "
        "On 0 matches, read the response hint — do not repeat the same empty query. "
        "Avoid catastrophic regex (nested quantifiers are rejected)."
    ),
    parameters={
        "pattern": {
            "type": "string",
            "description": (
                "Regex to match file lines (default mode). "
                "With match_path=true, also matches relative path/filename. "
                "Empty string allowed only with extension/glob/match_path "
                "for path-listing mode."
            ),
        },
        "glob": {
            "type": "string",
            "description": (
                "Limit scan to paths matching fnmatch, e.g. '*.py', "
                "'**/pkcs11/*', 'src/tools/*'."
            ),
        },
        "extension": {
            "type": "string",
            "description": ("Limit scan to this extension: '.c', 'c', or '*.c'."),
        },
        "files_only": {
            "type": "boolean",
            "description": (
                "If true, return unique matching paths only "
                "(no line text). Good for building a read list."
            ),
        },
        "match_path": {
            "type": "boolean",
            "description": (
                "If true, also match pattern against relative path and "
                "basename (filename search)."
            ),
        },
        "max_matches": {
            "type": "integer",
            "description": (
                "Stop after this many hits (default from config). "
                "Lower on huge trees to keep responses small."
            ),
        },
    },
    required=(),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _grep(
        ctx,
        pattern=args.get("pattern", ""),
        glob=args.get("glob"),
        max_matches=args.get("max_matches"),
        extension=args.get("extension"),
        files_only=bool(args.get("files_only") or args.get("files_with_matches")),
        match_path=bool(args.get("match_path")),
    )
