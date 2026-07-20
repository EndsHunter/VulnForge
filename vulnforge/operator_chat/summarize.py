"""Safe truncation for operator-chat tool payloads."""

from __future__ import annotations

import json
from typing import Any

MAX_JSON_CHARS = 12_000
MAX_TEXT_CHARS = 6_000
MAX_LIST = 80
MAX_SUMMARY = 400


def clip_text(s: Any, n: int = MAX_TEXT_CHARS) -> str:
    t = str(s or "")
    if len(t) <= n:
        return t
    return t[: n - 20] + f"\n…[{len(t) - n + 20} more chars]"


def clip_summary(s: Any, n: int = MAX_SUMMARY) -> str:
    t = " ".join(str(s or "").split())
    if len(t) <= n:
        return t
    return t[: n - 1] + "…"


def dumps_clipped(obj: Any, max_chars: int = MAX_JSON_CHARS) -> str:
    try:
        raw = json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        raw = json.dumps({"error": "unserializable", "repr": clip_text(repr(obj), 500)})
    if len(raw) <= max_chars:
        return raw
    return raw[: max_chars - 40] + f'…"[truncated {len(raw)} chars]"'


def cap_list(items: list[Any], n: int = MAX_LIST) -> list[Any]:
    if len(items) <= n:
        return items
    return items[:n]


def tool_result_content(obj: Any) -> str:
    """JSON string for tool role message."""
    if isinstance(obj, dict) and obj.get("ok") is False:
        return dumps_clipped(obj, max_chars=4000)
    return dumps_clipped(obj)
