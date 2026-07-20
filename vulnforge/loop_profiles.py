"""
Named Ralph loop profiles — first-class outer-loop configs for the Harness builder.

Stored under config/harnesses/*.yaml (schema harness.loop/v1).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml

from vulnforge.cli import PROJECT_ROOT

SCHEMA = "harness.loop/v1"
HARNESSES_DIR = PROJECT_ROOT / "config" / "harnesses"

_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

DEFAULT_PROFILE: dict[str, Any] = {
    "schema": SCHEMA,
    "id": "default-campaign",
    "title": "Default Ralph campaign",
    "tags": ["default"],
    "loop": {
        # Safety rail only — not a campaign budget. null max_tasks = run until idle.
        "max_iterations": 10000,
        "max_tasks": None,
        "task_timeout_s": 900,
        "max_wall_seconds": None,
        "sleep_seconds": 2.0,
        "max_infra_retries": 5,
        "infra_backoff_base": 5.0,
        "workers": 1,
    },
    "run": {
        "max_leases_parallel": 1,
        "max_task_attempts": 3,
        "lease_ttl_seconds": 1800,
        "max_split_depth": 2,
        "max_recon_auto_retries": 2,
        "auto_tool_gaps": False,
    },
}


def harnesses_dir() -> Path:
    HARNESSES_DIR.mkdir(parents=True, exist_ok=True)
    return HARNESSES_DIR


def _profile_path(profile_id: str) -> Path:
    return harnesses_dir() / f"{profile_id}.yaml"


def ensure_default_profile() -> dict[str, Any]:
    """Write default profile if missing; return it."""
    path = _profile_path("default-campaign")
    if not path.is_file():
        save_profile(DEFAULT_PROFILE)
    return load_profile("default-campaign") or dict(DEFAULT_PROFILE)


def list_profiles() -> list[dict[str, Any]]:
    ensure_default_profile()
    out: list[dict[str, Any]] = []
    for p in sorted(harnesses_dir().glob("*.yaml")):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict):
            continue
        out.append(
            {
                "id": data.get("id") or p.stem,
                "title": data.get("title") or p.stem,
                "tags": data.get("tags") or [],
                "path": str(p.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                "loop": data.get("loop") or {},
                "run": data.get("run") or {},
            }
        )
    return out


def load_profile(profile_id: str) -> Optional[dict[str, Any]]:
    if not profile_id or not _ID_RE.match(profile_id):
        return None
    path = _profile_path(profile_id)
    if not path.is_file():
        if profile_id == "default-campaign":
            return ensure_default_profile()
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("id", profile_id)
    data.setdefault("schema", SCHEMA)
    data.setdefault("loop", {})
    data.setdefault("run", {})
    return data


def save_profile(data: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(data.get("id") or "").strip()
    if not _ID_RE.match(profile_id):
        raise ValueError("invalid profile id (use letters, digits, ._- ; max 64)")
    out = {
        "schema": SCHEMA,
        "id": profile_id,
        "title": str(data.get("title") or profile_id),
        "tags": list(data.get("tags") or []),
        "loop": dict(data.get("loop") or {}),
        "run": dict(data.get("run") or {}),
    }
    # Merge defaults for missing loop keys
    for k, v in DEFAULT_PROFILE["loop"].items():
        out["loop"].setdefault(k, v)
    for k, v in DEFAULT_PROFILE["run"].items():
        out["run"].setdefault(k, v)
    path = _profile_path(profile_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(out, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return out


def delete_profile(profile_id: str) -> bool:
    if profile_id == "default-campaign":
        raise ValueError("cannot delete default-campaign")
    if not _ID_RE.match(profile_id or ""):
        return False
    path = _profile_path(profile_id)
    if not path.is_file():
        return False
    path.unlink()
    return True


def profile_to_start_kwargs(profile: dict[str, Any]) -> dict[str, Any]:
    """Map a loop profile to runctl.start_run kwargs."""
    loop = profile.get("loop") if isinstance(profile.get("loop"), dict) else {}
    run = profile.get("run") if isinstance(profile.get("run"), dict) else {}
    max_tasks = loop.get("max_tasks")
    if max_tasks is not None:
        try:
            max_tasks = int(max_tasks)
        except (TypeError, ValueError):
            max_tasks = 50
    max_wall = loop.get("max_wall_seconds")
    if max_wall is not None:
        try:
            max_wall = float(max_wall)
        except (TypeError, ValueError):
            max_wall = None
    workers = loop.get("workers")
    if workers is None:
        workers = run.get("max_leases_parallel") or 1
    try:
        workers = max(1, int(workers))
    except (TypeError, ValueError):
        workers = 1
    try:
        task_timeout = float(loop.get("task_timeout_s") or 900)
    except (TypeError, ValueError):
        task_timeout = 900.0
    try:
        max_iterations = int(loop.get("max_iterations") or 10_000)
    except (TypeError, ValueError):
        max_iterations = 10_000
    return {
        "task_timeout": task_timeout,
        "max_tasks": max_tasks,  # None = unlimited Ralph progress budget
        "max_iterations": max_iterations,
        "max_wall_seconds": max_wall,
        "workers": workers,
        "loop_profile_id": profile.get("id"),
    }
