"""Discover agent tool SPECs and project schemas / allowlists / critical sets."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from functools import lru_cache
from typing import Any, Optional

from vulnforge.tools.base import ToolRunner, ToolSpec

log = logging.getLogger(__name__)

# Stages that participate in operator default_tools narrowing.
STAGE_KEYS = ("recon", "hunt", "develop_poc")

# When an extra tool omits stages, default here (fail-closed — not all stages).
_DEFAULT_EXTRA_STAGES = ("hunt",)


def _discover_agent_modules() -> list[str]:
    """Import paths for modules under vulnforge.tools.agent (one tool each)."""
    try:
        import vulnforge.tools.agent as agent_pkg
    except ImportError as e:
        log.warning("agent tools package unavailable: %s", e)
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
    seen_names: set[str] = set()
    for mod_path in _discover_agent_modules():
        try:
            mod = importlib.import_module(mod_path)
        except Exception as e:
            log.warning("failed to import agent tool module %s: %s", mod_path, e)
            continue
        spec = getattr(mod, "SPEC", None)
        run = getattr(mod, "run", None)
        if not isinstance(spec, ToolSpec):
            log.warning("agent module %s missing ToolSpec SPEC; skipped", mod_path)
            continue
        if not callable(run):
            log.warning("agent module %s missing callable run(); skipped", mod_path)
            continue
        if spec.name in seen_names:
            log.warning(
                "duplicate agent tool SPEC name %r from %s; keeping first",
                spec.name,
                mod_path,
            )
            continue
        seen_names.add(spec.name)
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
    except Exception as e:
        log.warning("extra_tool_names failed: %s", e)
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


def _extra_stages(raw: dict[str, Any]) -> set[str]:
    """Resolve stages for an extra tool; empty/missing → fail-closed default hunt."""
    stages_raw = raw.get("stages")
    if not stages_raw:
        name = str(raw.get("name") or "?")
        log.warning(
            "extra tool %r has empty stages; defaulting to %s (fail-closed)",
            name,
            list(_DEFAULT_EXTRA_STAGES),
        )
        return set(_DEFAULT_EXTRA_STAGES)
    return {str(s).strip() for s in stages_raw if str(s).strip()}


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
                stages = _extra_stages(raw)
                if stage_key not in stages:
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
        except Exception as e:
            log.warning("list_extra_specs failed for stage %s: %s", stage_key, e)
    return tools


def dispatch_map() -> dict[str, ToolRunner]:
    """Canonical name and aliases → run callable."""
    out: dict[str, ToolRunner] = {}
    for spec, run in _load_agent_entries():
        out[spec.name] = run
        for a in spec.aliases or ():
            out[str(a)] = run
    return out
