"""Operator-integrated extra tools (toolgen integrate).

Integrated drafts append specs here so runtime discovery does not require
hand-editing packet.py / code_static allowlist for every new tool.

Each entry:
  {
    "name": "my_tool",
    "module": "vulnforge.tools.my_tool",   # import path
    "callable": "my_tool",                # attribute on module
    "stages": ["hunt", "recon"],
    "description": "...",
    "parameters": { "type": "object", "properties": {...}, "required": [...] },
    "aliases": [],                        # optional model-facing aliases
  }
"""

from __future__ import annotations

from typing import Any

# toolgen integrate appends / replaces by name. Keep stable for git diffs.
EXTRA_TOOL_SPECS: list[dict[str, Any]] = []


def list_extra_specs() -> list[dict[str, Any]]:
    return list(EXTRA_TOOL_SPECS)


def extra_tool_names() -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for s in EXTRA_TOOL_SPECS:
        n = str(s.get("name") or "").strip()
        if n and n not in seen:
            seen.add(n)
            names.append(n)
    return names


def get_extra_spec(name: str) -> dict[str, Any] | None:
    want = str(name or "").strip()
    for s in EXTRA_TOOL_SPECS:
        if str(s.get("name") or "").strip() == want:
            return dict(s)
        for a in s.get("aliases") or []:
            if str(a).strip() == want:
                return dict(s)
    return None


def upsert_extra_spec(spec: dict[str, Any]) -> None:
    """Replace or append a spec by name (in-memory; caller persists file)."""
    global EXTRA_TOOL_SPECS
    name = str(spec.get("name") or "").strip()
    if not name:
        raise ValueError("extra tool spec requires name")
    out: list[dict[str, Any]] = []
    found = False
    for s in EXTRA_TOOL_SPECS:
        if str(s.get("name") or "").strip() == name:
            out.append(dict(spec))
            found = True
        else:
            out.append(s)
    if not found:
        out.append(dict(spec))
    EXTRA_TOOL_SPECS = out


def remove_extra_spec(name: str) -> bool:
    global EXTRA_TOOL_SPECS
    want = str(name or "").strip()
    before = len(EXTRA_TOOL_SPECS)
    EXTRA_TOOL_SPECS = [
        s for s in EXTRA_TOOL_SPECS if str(s.get("name") or "").strip() != want
    ]
    return len(EXTRA_TOOL_SPECS) < before
