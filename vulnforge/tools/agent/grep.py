"""Agent tool: grep — regex/literal search over the audit target."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.grep_index import grep as _grep

SPEC = ToolSpec(
    name="grep",
    stages=("recon", "hunt", "develop_poc"),
    description=(
        "Search target files with a regex or literal string (read-only). "
        "pattern is a Python/PCRE-style regex over file lines "
        "(or over path/filename when match_path=true). Use literal=true for "
        "fixed-string search. "
        "Narrow with path/paths, extension, and/or glob before broad searches. "
        "context / context_before / context_after return surrounding lines "
        "(prefer this over a second read_file for sink review). "
        "files_only=true returns unique paths only. "
        "Empty pattern + extension/glob/path lists matching files by path "
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
                "With literal=true, treated as a fixed string (escaped). "
                "Empty string allowed only with extension/glob/match_path/path "
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
        "path": {
            "type": "string",
            "description": (
                "Limit scan to this relative file or directory under the target "
                "(e.g. 'src/auth'). Prefer over whole-tree greps."
            ),
        },
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Additional relative path roots to scan (same as path).",
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
        "context": {
            "type": "integer",
            "description": (
                "Lines of context before AND after each match (0–10, default 0). "
                "Shorthand for setting both context_before and context_after."
            ),
        },
        "context_before": {
            "type": "integer",
            "description": "Lines of context before each match (overrides context).",
        },
        "context_after": {
            "type": "integer",
            "description": "Lines of context after each match (overrides context).",
        },
        "case_insensitive": {
            "type": "boolean",
            "description": "If true, match case-insensitively.",
        },
        "literal": {
            "type": "boolean",
            "description": (
                "If true, treat pattern as a fixed string (regex-escaped). "
                "Useful for finding exact call sites."
            ),
        },
        "max_line_chars": {
            "type": "integer",
            "description": (
                "Max characters of match line text (default 200, max 2000). "
                "Raise for long SQL/f-string lines."
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
    aliases=("search",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    paths = args.get("paths")
    if paths is not None and not isinstance(paths, list):
        paths = [paths]
    return _grep(
        ctx,
        pattern=args.get("pattern", ""),
        glob=args.get("glob"),
        max_matches=args.get("max_matches"),
        extension=args.get("extension"),
        files_only=bool(args.get("files_only") or args.get("files_with_matches")),
        match_path=bool(args.get("match_path")),
        path=args.get("path"),
        paths=paths,
        context=args.get("context"),
        context_before=args.get("context_before"),
        context_after=args.get("context_after"),
        case_insensitive=bool(args.get("case_insensitive")),
        max_line_chars=args.get("max_line_chars"),
        literal=bool(args.get("literal")),
    )
