"""Contract mirror for vulnforge/ui/static/app.js controlBodyFromSettings.

Keep this table in sync with the JS helper. JS has no unit-test runner here;
this file documents and locks the rules the dashboard client must implement.

Operator Mission Start/Resume: no loop profile, no wall, unlimited Ralph
progress budget (max_tasks null). Settings max_tasks is enqueue planning only.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest


def control_body_from_settings(settings: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Python mirror of app.js controlBodyFromSettings (parseInt / isFinite rules)."""
    s = settings or {}

    def _parse_int(val: Any) -> Optional[int]:
        if val is None or val is True or val is False:
            return None
        if isinstance(val, bool):
            return None
        if isinstance(val, int) and not isinstance(val, bool):
            return val
        if isinstance(val, float):
            if val != val:  # NaN
                return None
            return int(val)
        text = str(val).strip()
        if not text:
            return None
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

    body: dict[str, Any] = {
        "max_tasks": None,
        "max_wall_seconds": None,
        "task_timeout": 900,
        "max_iterations": 10000,
    }
    w = _parse_int(s.get("max_concurrent_agents"))
    if w is not None and w > 0:
        body["workers"] = w
    return body


@pytest.mark.parametrize(
    "settings,expected",
    [
        (
            {"max_tasks": 12, "max_concurrent_agents": 3, "timeout_seconds": 30},
            {
                "max_tasks": None,
                "max_wall_seconds": None,
                "task_timeout": 900,
                "max_iterations": 10000,
                "workers": 3,
            },
        ),
        (
            {},
            {
                "max_tasks": None,
                "max_wall_seconds": None,
                "task_timeout": 900,
                "max_iterations": 10000,
            },
        ),
        (
            None,
            {
                "max_tasks": None,
                "max_wall_seconds": None,
                "task_timeout": 900,
                "max_iterations": 10000,
            },
        ),
        # Settings max_tasks is ignored for Ralph start body
        (
            {"max_tasks": 50},
            {
                "max_tasks": None,
                "max_wall_seconds": None,
                "task_timeout": 900,
                "max_iterations": 10000,
            },
        ),
        (
            {"max_concurrent_agents": "2"},
            {
                "max_tasks": None,
                "max_wall_seconds": None,
                "task_timeout": 900,
                "max_iterations": 10000,
                "workers": 2,
            },
        ),
        # workers omitted when zero or invalid
        (
            {"max_concurrent_agents": 0},
            {
                "max_tasks": None,
                "max_wall_seconds": None,
                "task_timeout": 900,
                "max_iterations": 10000,
            },
        ),
    ],
)
def test_control_body_from_settings_table(settings, expected):
    assert control_body_from_settings(settings) == expected


def test_control_body_never_sends_loop_profile():
    body = control_body_from_settings({"max_tasks": 50, "max_concurrent_agents": 1})
    assert "loop_profile_id" not in body
    assert body["max_wall_seconds"] is None
    assert body["max_tasks"] is None
