"""Agent tool: list_hunt_profiles — ids available for request_hunt."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec
from vulnforge.tools.request_hunt import list_hunt_profiles as _list_hunt_profiles

SPEC = ToolSpec(
    name="list_hunt_profiles",
    stages=("hunt",),
    description=(
        "List registered hunt profile ids (and titles) you may pass to "
        "request_hunt. Prefer active profiles. "
        "No arguments. Call before request_hunt if you are unsure of ids."
    ),
    parameters={},
    required=(),
    critical_for=("hunt",),
)


def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return _list_hunt_profiles(ctx)
