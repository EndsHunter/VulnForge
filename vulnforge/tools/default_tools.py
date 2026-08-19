"""Operator-controlled global default tools per stage (recon / hunt / develop_poc).

Config lives at config/default_tools.json (mirrors hunt_profiles path resolution).
null per stage means use built-in packet / code_static defaults.
A non-null list narrows the stage tool surface (intersected with the safe catalog).
Stage-critical tools are always retained. Unrestricted shell/exec is never allowed.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from vulnforge.paths import CONFIG_ROOT, PROJECT_ROOT

DEFAULT_CONFIG_PATH = CONFIG_ROOT / "default_tools.json"

STAGES = ("recon", "hunt", "develop_poc")

# Never expose unrestricted process execution via stage defaults (code_static).
BLOCKED_TOOLS = frozenset(
    {
        "shell",
        "bash",
        "sh",
        "exec",
        "execute",
        "run_shell",
        "run_command",
        "run_cmd",
        "subprocess",
        "os_system",
        "system",
        "pty",
        "terminal",
        "cmd",
        "powershell",
        "pwsh",
    }
)


_CRITICAL_FALLBACK: dict[str, frozenset[str]] = {
    "recon": frozenset({"submit_architecture", "continue_recon"}),
    "hunt": frozenset(
        {
            "submit_candidate",
            "submit_none",
            "list_hunt_profiles",
            "request_hunt",
            "continue_hunt",
        }
    ),
    "develop_poc": frozenset({"write_evidence"}),
}


def stage_critical_tools(stage: str) -> frozenset[str]:
    """Live critical set for ``stage`` (from SPECs; not import-time frozen)."""
    stage_key = str(stage or "").strip()
    try:
        from vulnforge.tools.registry import critical_tools_for

        crit = critical_tools_for(stage_key)
        if crit:
            return crit
    except Exception:
        pass
    return _CRITICAL_FALLBACK.get(stage_key, frozenset())


class _LiveCriticalMap:
    """Mapping-like view that always re-queries the agent registry."""

    def get(self, stage: str, default: frozenset[str] | None = None) -> frozenset[str]:
        stage_key = str(stage or "").strip()
        if stage_key not in STAGES:
            return default if default is not None else frozenset()
        return stage_critical_tools(stage_key)

    def __getitem__(self, stage: str) -> frozenset[str]:
        return stage_critical_tools(stage)

    def items(self):
        return ((s, stage_critical_tools(s)) for s in STAGES)

    def keys(self):
        return iter(STAGES)

    def values(self):
        return (stage_critical_tools(s) for s in STAGES)

    def __contains__(self, stage: object) -> bool:
        return str(stage or "") in STAGES

    def __iter__(self):
        return iter(STAGES)


# Compat name: mapping always reflects ToolSpec.critical_for (live).
STAGE_CRITICAL_TOOLS = _LiveCriticalMap()

_EMPTY: dict[str, Any] = {
    "recon": None,
    "hunt": None,
    "develop_poc": None,
}

_path_override: Optional[Path] = None


class DefaultToolsError(ValueError):
    """Invalid default tools config or operation."""


def set_default_tools_path(path: Path | str | None) -> None:
    """Override config path (tests). Pass None to clear."""
    global _path_override
    if path is None:
        _path_override = None
    else:
        _path_override = Path(path).resolve()


def reset_default_tools_path_override() -> None:
    set_default_tools_path(None)


def default_tools_path() -> Path:
    if _path_override is not None:
        return _path_override
    env = (os.environ.get("VULNFORGE_DEFAULT_TOOLS_PATH") or "").strip()
    if env:
        return Path(env).resolve()
    return DEFAULT_CONFIG_PATH


def _empty_config() -> dict[str, Any]:
    return deepcopy(_EMPTY)


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _safe_tool_pool(built_in: list[str] | None = None) -> set[str]:
    """Names that may appear in operator defaults (built-in ∪ profile ∪ extras, no shell).

    Does not import packet/catalog (avoids circular import when called from tool_schemas_for).
    """
    pool: set[str] = set(built_in or [])
    try:
        from vulnforge.profiles.code_static import CodeStaticProfile

        pool |= set(CodeStaticProfile().allowed_tools())
    except Exception:
        pass
    try:
        from vulnforge.tools.extra_registry import extra_tool_names

        pool |= set(extra_tool_names())
    except Exception:
        pass
    pool -= BLOCKED_TOOLS
    return pool


def _coerce_stage_list(value: object) -> Optional[list[str]]:
    if value is None:
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
        return parts or None
    if not isinstance(value, list):
        raise DefaultToolsError("stage tools must be a list of names or null")
    out: list[str] = []
    seen: set[str] = set()
    for x in value:
        name = str(x).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out or None


def _normalize_config(raw: dict[str, Any]) -> dict[str, Any]:
    out = _empty_config()
    for stage in STAGES:
        if stage not in raw:
            continue
        out[stage] = _coerce_stage_list(raw.get(stage))
    return out


def _filter_against_pool(
    names: list[str], pool: set[str], *, stage: str
) -> list[str]:
    """Keep known safe names; drop blocked; always re-add critical if in pool/built-in."""
    selected: list[str] = []
    seen: set[str] = set()
    for n in names:
        if n in BLOCKED_TOOLS or n not in pool:
            continue
        if n in seen:
            continue
        selected.append(n)
        seen.add(n)
    for c in STAGE_CRITICAL_TOOLS.get(stage, frozenset()):
        if c in seen:
            continue
        if c in pool or c in STAGE_CRITICAL_TOOLS.get(stage, frozenset()):
            # Critical tools that are part of the stage surface are forced in.
            # If not in pool they may still be stage-critical built-ins.
            selected.append(c)
            seen.add(c)
    return selected


def load_default_tools() -> dict[str, Any]:
    """Load operator defaults; missing/corrupt file → all-null built-in defaults."""
    path = default_tools_path()
    if not path.is_file():
        return _empty_config()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_config()
    if not isinstance(raw, dict):
        return _empty_config()
    try:
        return _normalize_config(raw)
    except DefaultToolsError:
        return _empty_config()


def save_default_tools(data: dict[str, Any]) -> dict[str, Any]:
    """Validate, sanitize, and persist defaults. Returns the stored config."""
    if not isinstance(data, dict):
        raise DefaultToolsError("defaults must be an object")
    pool = _safe_tool_pool()
    # If catalog is empty (early boot), allow only non-blocked names we see —
    # still reject blocked shells.
    normalized = _empty_config()
    for stage in STAGES:
        if stage not in data:
            continue
        coerced = _coerce_stage_list(data.get(stage))
        if coerced is None:
            normalized[stage] = None
            continue
        # When pool is non-empty, intersect; always drop blocked.
        if pool:
            cleaned = _filter_against_pool(coerced, pool, stage=stage)
        else:
            cleaned = [n for n in coerced if n not in BLOCKED_TOOLS]
            for c in STAGE_CRITICAL_TOOLS.get(stage, frozenset()):
                if c not in cleaned:
                    cleaned.append(c)
        # Empty after sanitize → treat as invalid narrow list; keep explicit empty
        # only if operator intentionally sent []? Spec: null = built-in. Empty list
        # after filter would leave only critical tools — that is intentional.
        normalized[stage] = cleaned
    path = default_tools_path()
    _atomic_write_json(path, normalized)
    return normalized


def resolve_stage_tools(stage: str, built_in: list[str]) -> list[str]:
    """Resolve effective tool names for a stage.

    - Config null → return built_in unchanged.
    - Config list → intersect with safe catalog ∪ built_in; always keep critical.
    - Empty result after filter → fall back to built_in (never leave stage unusable).
    """
    stage_key = str(stage or "").strip()
    base = [str(n).strip() for n in (built_in or []) if str(n).strip()]
    if stage_key not in STAGES:
        return list(base)

    cfg = load_default_tools()
    raw = cfg.get(stage_key)
    if raw is None:
        return list(base)

    if not isinstance(raw, list):
        return list(base)

    pool = _safe_tool_pool(base)
    # Prefer names that exist on this stage's built-in surface when possible,
    # but allow operator to include extras known to the profile/catalog.
    want = [str(n).strip() for n in raw if str(n).strip()]
    selected: list[str] = []
    seen: set[str] = set()
    for n in want:
        if n in BLOCKED_TOOLS:
            continue
        if n not in pool:
            continue
        if n in seen:
            continue
        selected.append(n)
        seen.add(n)

    critical = STAGE_CRITICAL_TOOLS.get(stage_key, frozenset())
    base_set = set(base)
    for c in critical:
        if c in seen:
            continue
        # Always keep critical if they exist on the built-in stage surface
        if c in base_set or c in pool:
            selected.append(c)
            seen.add(c)

    if not selected:
        return list(base)

    # Stable order: follow built_in order, then any extra selected names
    order = {n: i for i, n in enumerate(base)}
    selected.sort(key=lambda n: (0, order[n]) if n in order else (1, n))
    return selected


def defaults_for_api() -> dict[str, Any]:
    """Payload for GET /api/tools/defaults including resolved builtin baselines."""
    stored = load_default_tools()
    # Builtin name lists per stage (without applying defaults) via packet.
    builtin: dict[str, list[str]] = {}
    try:
        from vulnforge.packet import tool_schemas_for

        for stage in STAGES:
            tools = tool_schemas_for("code_static", stage, apply_defaults=False)
            names: list[str] = []
            for t in tools:
                fn = (t.get("function") or {}) if isinstance(t, dict) else {}
                n = fn.get("name") if isinstance(fn, dict) else None
                if n:
                    names.append(str(n))
            builtin[stage] = names
    except Exception:
        for stage in STAGES:
            builtin[stage] = []

    effective: dict[str, list[str]] = {}
    for stage in STAGES:
        effective[stage] = resolve_stage_tools(stage, builtin.get(stage) or [])

    return {
        "ok": True,
        "defaults": stored,
        "builtin": builtin,
        "effective": effective,
        "stages": list(STAGES),
        "critical": {k: sorted(v) for k, v in STAGE_CRITICAL_TOOLS.items()},
        "blocked": sorted(BLOCKED_TOOLS),
        "path": str(default_tools_path()),
    }
