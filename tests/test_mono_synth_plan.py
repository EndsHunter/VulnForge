"""H2–H3: document large-repo harness behaviors on a synthetic monorepo.

These tests measure planning seed size and active-set fan-out.
Domain-pack budget was removed; inactive profiles are optional via hunt_focus only.
Monorepo hard-cap of 24 was removed — only run.max_tasks binds plan size.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.mono_synth_builder import (
    CANARY_MARKER,
    CANARY_REL,
    DEFAULT_N_BULK,
    build_mono_synth,
    canary_relative_path,
)
from vulnforge.hunt_profiles import active_class_ids, all_class_ids
from vulnforge.stages.recon import (
    _fallback_hunt_tasks,
    partition_by_top_dir,
    plan_hunt_tasks,
)
from vulnforge.tools.grep_index import build_file_index
from vulnforge.util import normalize_relpath


def _active() -> list[str]:
    return list(active_class_ids())


def _cfg(max_tasks: int = 50) -> dict:
    return {"run": {"max_tasks": max_tasks, "ignore_globs": []}}


def _large_default_inv(*, file_count: int = 501) -> tuple[dict, dict]:
    """Synthetic inventory+arch that yields many active-fallback tasks.

    Components drive areas so fan-out is 6 * len(active) == 30 with 5 active
    classes before max_tasks clipping.
    """
    components = [
        {"name": f"comp{i:02d}", "path_hints": [f"comp{i:02d}/a.py"]}
        for i in range(12)
    ]
    inv = {
        "file_count": file_count,
        "sample_paths": [c["path_hints"][0] for c in components],
        "entrypoints": [],
        "seed_sinks": [],
        "dir_partitions": [],
    }
    arch = {
        "summary": "large synth",
        "components": components,
        "hunt_focus": [],
    }
    return arch, inv


# ---------------------------------------------------------------------------
# H3 — active_fallback respects max_tasks only (no monorepo hard-cap)
# ---------------------------------------------------------------------------


def test_h3_active_fallback_respects_max_tasks_not_hard_cap_24():
    """file_count > 500 + empty hunt_focus → active_fallback; max_tasks binds only."""
    arch, inv = _large_default_inv(file_count=501)
    uncapped = _fallback_hunt_tasks(arch, inv)
    assert len(uncapped) == 6 * len(_active())
    assert len(uncapped) > 24

    tasks, source = plan_hunt_tasks(arch, inv, _cfg(max_tasks=50))
    assert source == "active_fallback"
    # Full active plan fits under max_tasks=50 (30 with seed active set)
    assert len(tasks) == len(uncapped)
    assert len(tasks) == 30
    assert {t["class"] for t in tasks} <= set(_active())


def test_h3_file_count_does_not_force_24_cap():
    """Large trees no longer force a 24-task hard-cap independent of settings."""
    arch, inv = _large_default_inv(file_count=500)
    uncapped = _fallback_hunt_tasks(arch, inv)
    assert len(uncapped) == 6 * len(_active())  # 30 with seed active set

    tasks, source = plan_hunt_tasks(arch, inv, _cfg(max_tasks=50))
    assert source == "active_fallback"
    assert len(tasks) == 30


def test_h3_hunt_focus_path_still_honors_max_tasks():
    """hunt_focus path is clipped by max_tasks only."""
    active = _active()
    focus = [
        {
            "area": f"area{i // 5}",
            "class": active[i % len(active)],
            "path_hints": [f"area{i // 5}/f{i}.py"],
        }
        for i in range(30)
    ]
    inv = {
        "file_count": 501,
        "sample_paths": [f["path_hints"][0] for f in focus],
        "entrypoints": [],
        "seed_sinks": [],
    }
    arch = {"summary": "focus path", "components": [], "hunt_focus": focus}
    tasks, source = plan_hunt_tasks(arch, inv, _cfg(max_tasks=50))
    assert source == "hunt_focus"
    assert len(tasks) == 30


def test_h3_max_tasks_clips_large_active_fallback():
    """cfg max_tasks is the only plan-size bind for active_fallback."""
    arch, inv = _large_default_inv(file_count=501)
    uncapped = _fallback_hunt_tasks(arch, inv)
    assert len(uncapped) > 10

    tasks, source = plan_hunt_tasks(arch, inv, _cfg(max_tasks=10))
    assert source == "active_fallback"
    assert len(tasks) == 10


def test_h3b_partition_fallback_areas_capped_at_6():
    """Empty components → areas from dir_partitions, always partitions[:6]."""
    sample_paths = [f"pkg{i:02d}/mod.py" for i in range(20)]
    inv = {
        "file_count": 250,
        "sample_paths": sample_paths,
        "entrypoints": [],
        "dir_partitions": partition_by_top_dir(sample_paths),
    }
    assert len(inv["dir_partitions"]) >= 6
    arch = {"summary": "many areas", "components": [], "hunt_focus": []}
    tasks = _fallback_hunt_tasks(arch, inv)
    areas = {t["area"] for t in tasks}
    assert len(areas) == 6
    assert len(tasks) == 6 * len(_active())


def test_h3b_component_areas_capped_at_6_when_file_count_gt_200():
    """_fallback_hunt_tasks: max_areas = 6 if file_count > 200 (components path)."""
    components = [
        {"name": f"comp{i:02d}", "path_hints": [f"comp{i:02d}/a.py"]} for i in range(12)
    ]
    inv = {
        "file_count": 250,
        "sample_paths": [c["path_hints"][0] for c in components],
        "entrypoints": [],
        "dir_partitions": [],
    }
    arch = {"summary": "many components", "components": components, "hunt_focus": []}
    tasks = _fallback_hunt_tasks(arch, inv)
    areas = {t["area"] for t in tasks}
    assert len(areas) == 6
    assert len(tasks) == 6 * len(_active())


def test_h3b_component_areas_allow_8_when_file_count_le_200():
    """_fallback_hunt_tasks: max_areas = 8 when file_count ≤ 200 (components path)."""
    components = [
        {"name": f"comp{i:02d}", "path_hints": [f"comp{i:02d}/a.py"]} for i in range(12)
    ]
    inv = {
        "file_count": 100,
        "sample_paths": [c["path_hints"][0] for c in components],
        "entrypoints": [],
        "dir_partitions": [],
    }
    arch = {
        "summary": "small tree many components",
        "components": components,
        "hunt_focus": [],
    }
    tasks = _fallback_hunt_tasks(arch, inv)
    areas = {t["area"] for t in tasks}
    assert len(areas) == 8
    assert len(tasks) == 8 * len(_active())


def test_h3b_max_areas_boundary_200_vs_201():
    """Boundary: file_count=200 → max_areas 8; file_count=201 → max_areas 6."""
    components = [
        {"name": f"comp{i:02d}", "path_hints": [f"comp{i:02d}/a.py"]} for i in range(12)
    ]
    for file_count, expected_areas in ((200, 8), (201, 6)):
        inv = {
            "file_count": file_count,
            "sample_paths": [c["path_hints"][0] for c in components],
            "entrypoints": [],
            "dir_partitions": [],
        }
        arch = {
            "summary": f"boundary fc={file_count}",
            "components": components,
            "hunt_focus": [],
        }
        tasks = _fallback_hunt_tasks(arch, inv)
        areas = {t["area"] for t in tasks}
        assert len(areas) == expected_areas, file_count
        assert len(tasks) == expected_areas * len(_active())


def test_h3_fallback_uses_active_classes_only():
    arch, inv = _large_default_inv(file_count=250)
    tasks = _fallback_hunt_tasks(arch, inv)
    classes = {t["class"] for t in tasks}
    assert classes == set(_active())
    inactive = set(all_class_ids()) - set(_active())
    assert not (classes & inactive)


# ---------------------------------------------------------------------------
# H4 — hunt_focus can include inactive (optional) profiles; max_tasks binds
# ---------------------------------------------------------------------------


def test_h4_huge_hunt_focus_clipped_by_max_tasks_only():
    """Many areas × many classes: max_tasks binds (no domain-pack budget)."""
    class_pool = list(all_class_ids())
    areas = [f"area{i:02d}" for i in range(20)]

    focus: list[dict] = []
    for area in areas:
        for cls in class_pool:
            focus.append(
                {
                    "area": area,
                    "class": cls,
                    "path_hints": [f"{area}/{cls.replace('-', '_')}.py"],
                }
            )
    raw_n = len(focus)
    assert raw_n == 20 * len(class_pool)
    assert raw_n > 50

    inv = {
        "file_count": 100,
        "sample_paths": [f["path_hints"][0] for f in focus[:80]],
        "entrypoints": ["packages/api/routes.py"],
        "seed_sinks": [],
    }
    arch = {
        "summary": "model class bingo",
        "components": [{"name": a} for a in areas],
        "hunt_focus": focus,
    }
    max_tasks = 50
    tasks, source = plan_hunt_tasks(arch, inv, _cfg(max_tasks=max_tasks))
    assert source == "hunt_focus"
    assert len(tasks) == max_tasks
    # Optional classes may appear (no domain budget drop)
    assert any(t.get("class") not in set(_active()) for t in tasks) or len(class_pool) == len(
        _active()
    )


def test_h4_inactive_class_allowed_in_hunt_focus():
    """Inactive registered profiles are valid hunt_focus targets."""
    inactive = [c for c in all_class_ids() if c not in set(_active())]
    assert inactive, "seed should leave some profiles inactive"
    cls = inactive[0]
    focus = [{"area": "api", "class": cls, "path_hints": ["api/main.py"]}]
    inv = {
        "file_count": 50,
        "sample_paths": ["api/main.py"],
        "entrypoints": [],
        "seed_sinks": [],
    }
    arch = {"summary": "optional class", "components": [], "hunt_focus": focus}
    tasks, source = plan_hunt_tasks(arch, inv, _cfg(max_tasks=50))
    assert source == "hunt_focus"
    assert len(tasks) == 1
    assert tasks[0]["class"] == cls


def test_builder_default_bulk_exceeds_sample_cap(tmp_path: Path):
    """Sanity: default n_bulk alone exceeds 500 after seed files."""
    root = build_mono_synth(tmp_path / "m", n_bulk=DEFAULT_N_BULK)
    inv = build_file_index(root, [])
    assert inv["file_count"] >= DEFAULT_N_BULK + 5
    assert inv.get("sample_paths_partial") is True
    assert any(p.startswith("zzz_canary/") for p in inv["sample_paths"])
