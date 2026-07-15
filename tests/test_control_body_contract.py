"""Contract mirror for vh/ui/static/app.js controlBodyFromSettings.

Keep this table in sync with the JS helper. JS has no unit-test runner here;
this file documents and locks the rules the dashboard client must implement.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest


def control_body_from_settings(settings: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Python mirror of app.js controlBodyFromSettings (parseInt / isFinite rules)."""
    s = settings or {}

    def _parse_int(val: Any) -> Optional[int]:
        # JS parseInt(x, 10): undefined/null/"" → NaN; "12px" → 12; floats truncated
        if val is None or val is True or val is False:
            return None
        if isinstance(val, bool):
            return None
        if isinstance(val, int) and not isinstance(val, bool):
            return val
        if isinstance(val, float):
            if val != val:  # NaN
                return None
            return int(val)  # toward zero like parseInt of number string path
        text = str(val).strip()
        if not text:
            return None
        # mimic parseInt: leading digits only
        sign = 1
        i = 0
        if text[0] in "+-":
            if text[0] == "-":
                sign = -1
            i = 1
        digits = []
        while i < len(text) and text[i].isdigit():
            digits.append(text[i])
            i += 1
        if not digits:
            return None
        return sign * int("".join(digits))

    mt = _parse_int(s.get("max_tasks"))
    max_tasks = mt if mt is not None and mt > 0 else 50
    body: dict[str, Any] = {"max_tasks": max_tasks, "task_timeout": 900}
    w = _parse_int(s.get("max_concurrent_agents"))
    if w is not None and w > 0:
        body["workers"] = w
    return body


@pytest.mark.parametrize(
    "settings,expected",
    [
        # happy path
        (
            {"max_tasks": 12, "max_concurrent_agents": 3, "timeout_seconds": 30},
            {"max_tasks": 12, "task_timeout": 900, "workers": 3},
        ),
        # missing keys → defaults; workers omitted when not set
        ({}, {"max_tasks": 50, "task_timeout": 900}),
        (None, {"max_tasks": 50, "task_timeout": 900}),
        # invalid / NaN max_tasks → 50
        ({"max_tasks": "nope"}, {"max_tasks": 50, "task_timeout": 900}),
        ({"max_tasks": 0}, {"max_tasks": 50, "task_timeout": 900}),
        ({"max_tasks": -3}, {"max_tasks": 50, "task_timeout": 900}),
        # workers omitted when missing, zero, or invalid
        ({"max_tasks": 8}, {"max_tasks": 8, "task_timeout": 900}),
        (
            {"max_tasks": 8, "max_concurrent_agents": 0},
            {"max_tasks": 8, "task_timeout": 900},
        ),
        (
            {"max_tasks": 8, "max_concurrent_agents": "x"},
            {"max_tasks": 8, "task_timeout": 900},
        ),
        # timeout_seconds must never become task_timeout
        (
            {"max_tasks": 5, "timeout_seconds": 30},
            {"max_tasks": 5, "task_timeout": 900},
        ),
        # string ints ok (parseInt)
        (
            {"max_tasks": "25", "max_concurrent_agents": "2"},
            {"max_tasks": 25, "task_timeout": 900, "workers": 2},
        ),
    ],
)
def test_control_body_from_settings_table(settings, expected):
    assert control_body_from_settings(settings) == expected
