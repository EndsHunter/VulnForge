"""Discover agent tool SPECs and project schemas / allowlists / critical sets."""

from __future__ import annotations

import importlib
import pkgutil
from functools import lru_cache
from typing import Any, Callable, Optional

from vulnforge.tools.base import ToolRunner, ToolSpec

# Stages that participate in operator default_tools narrowing.
STAGE_KEYS = ("recon", "hunt", "develop_poc")


def _discover_agent_modules() -> list[str]:
    """Import paths for modules under vulnforge.tools.agent (one tool each)."""
    try:
        import vulnforge.tools.agent as agent_pkg
    except ImportError:
        return []
    names: list[str] = []
    prefix = agent_pkg.__name__ + "."
    for mod in pkgutil.iter_modules(agent_pkg.__path__, prefix):
        if mod.ispkg:
            continue
        leaf = mod.name.rsplit(".", 1)[-1]
        if leaf.startswith("_"):
            continue
        names.append(mod.name)
    return sorted(names)


@lru_cache(maxsize=1)
def _load_agent_entries() -> tuple[tuple[ToolSpec, ToolRunner], ...]:
    entries: list[tuple[ToolSpec, ToolRunner]] = []
    for mod_path in _discover_agent_modules():
        try:
            mod = importlib.import_module(mod_path)
        except Exception:
            continue
        spec = getattr(mod, "SPEC", None)
        run = getattr(mod, "run", None)
        if not isinstance(spec, ToolSpec):
            continue
        if not callable(run):
            continue
        entries.append((spec, run))
    # Stable order: name
    entries.sort(key=lambda x: x[0].name)
    return tuple(entries)


def clear_registry_cache() -> None:
    """Drop cached discovery (tests / after toolgen integrate)."""
    _load_agent_entries.cache_clear()


def list_agent_specs() -> list[ToolSpec]:
    return [spec for spec, _ in _load_agent_entries()]


def get_agent_spec(name: str) -> Optional[ToolSpec]:
    want = str(name or "").strip()
    for spec, _ in _load_agent_entries():
        if spec.name == want:
            return spec
        if want in (spec.aliases or ()):
            return spec
    return None


def get_agent_runner(name: str) -> Optional[ToolRunner]:
    want = str(name or "").strip()
    for spec, run in _load_agent_entries():
        if spec.name == want or want in (spec.aliases or ()):
            return run
    return None


def resolve_canonical_name(name: str) -> Optional[str]:
    """Map alias → canonical SPEC name; None if unknown to agent registry."""
    spec = get_agent_spec(name)
    return spec.name if spec else None


def agent_tool_names() -> list[str]:
    """Canonical built-in agent tool names (no extras)."""
    return [spec.name for spec, _ in _load_agent_entries()]


def allowed_tool_names(*, include_extras: bool = True) -> list[str]:
    """Profile allowlist projection: agent SPECs + optional extra_registry names."""
    names = agent_tool_names()
    if not include_extras:
        return list(names)
    try:
        from vulnforge.tools.extra_registry import extra_tool_names

        seen = set(names)
        for n in extra_tool_names():
            if n not in seen:
                names.append(n)
                seen.add(n)
    except Exception:
        pass
    return names


def critical_tools_for(stage: str) -> frozenset[str]:
    """Tools that must survive operator default narrowing for ``stage``."""
    stage_key = str(stage or "").strip()
    out: set[str] = set()
    for spec, _ in _load_agent_entries():
        if stage_key in (spec.critical_for or ()):
            out.add(spec.name)
    return frozenset(out)


def stage_critical_map() -> dict[str, frozenset[str]]:
    return {s: critical_tools_for(s) for s in STAGE_KEYS}


def openai_schemas_for_stage(
    stage: str,
    *,
    include_extras: bool = True,
) -> list[dict[str, Any]]:
    """OpenAI-style tool schemas for a packet stage (no default_tools filter)."""
    stage_key = str(stage or "").strip()
    if stage_key == "disprove":
        return []

    tools: list[dict[str, Any]] = []
    seen: set[str] = set()
    for spec, _ in _load_agent_entries():
        if not spec.applies_to_stage(stage_key):
            continue
        if spec.name in seen:
            continue
        tools.append(spec.openai_schema(stage_key))
        seen.add(spec.name)

    if include_extras:
        try:
            from vulnforge.tools.extra_registry import list_extra_specs

            for raw in list_extra_specs():
                name = str(raw.get("name") or "").strip()
                if not name or name in seen:
                    continue
                stages = {str(s) for s in (raw.get("stages") or [])}
                if stages and stage_key not in stages:
                    continue
                params = (
                    raw.get("parameters")
                    if isinstance(raw.get("parameters"), dict)
                    else {}
                )
                props = (
                    params.get("properties")
                    if isinstance(params.get("properties"), dict)
                    else {}
                )
                req = (
                    params.get("required")
                    if isinstance(params.get("required"), list)
                    else []
                )
                tools.append(
                    {
                        "type": "function",
                        "function": {
                            "name": name,
                            "description": str(raw.get("description") or name),
                            "parameters": {
                                "type": "object",
                                "properties": dict(props),
                                "required": [str(x) for x in req],
                            },
                        },
                    }
                )
                seen.add(name)
        except Exception:
            pass
    return tools


def dispatch_map() -> dict[str, ToolRunner]:
    """Canonical name and aliases → run callable."""
    out: dict[str, ToolRunner] = {}
    for spec, run in _load_agent_entries():
        out[spec.name] = run
        for a in spec.aliases or ():
            out[str(a)] = run
    return out
