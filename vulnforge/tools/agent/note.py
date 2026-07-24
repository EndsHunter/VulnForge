"""Agent tool: note — wishlist / sibling_seed / codemap notes."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.queue_note import note as _note

SPEC = ToolSpec(
    name="note",
    stages=("recon", "hunt", "develop_poc"),
    description=(
        "Store a short operator-facing note (not a finding). "
        "kind=codemap: interesting path/symbol for the project CODEMAP. "
        "kind=wishlist: missing tool or capability you wished you had. "
        "kind=sibling_seed: area/class/path idea for a future hunt sibling. "
        "Does not finish the task — still call submit_* when done."
    ),
    parameters={
        "kind": {
            "type": "string",
            "enum": ["wishlist", "sibling_seed", "codemap"],
            "description": "Note category (see tool description).",
        },
        "payload": {
            "description": (
                "Object or string body. "
                'codemap: {"path": "...", "symbol": "...", "note": "..."} '
                "or a short string. "
                'wishlist: {"need": "...", "why": "..."} or string. '
                'sibling_seed: {"area": "...", "class": "injection", '
                '"path_hints": ["..."]}.'
            ),
        },
    },
    required=("kind", "payload"),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _note(
        ctx,
        kind=args.get("kind", ""),
        payload=args.get("payload", {}),
    )
