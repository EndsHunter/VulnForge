"""Run-scoped hunt skill modes: resolve + plan_hunt_tasks filtering."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.hunt_profiles import (
    HUNT_SKILL_MODES,
    ensure_collection,
    list_profiles,
    reset_collection_root_override,
    resolve_run_class_ids,
    save_profile,
    set_collection_root,
    skill_policy_from_run_cfg,
)
from vulnforge.stages.recon import plan_hunt_tasks


@pytest.fixture
def profiles_root(tmp_path: Path):
    root = tmp_path / "hunt_profiles"
    set_collection_root(root)
    ensure_collection()
    yield root
    reset_collection_root_override()


def test_hunt_skill_modes_constant():
    assert HUNT_SKILL_MODES == frozenset(
        {"all_active", "seed_active", "custom_only", "explicit"}
    )


def test_resolve_all_active_matches_active(profiles_root: Path):
    ids = resolve_run_class_ids("all_active")
    assert ids
    # Default seed set has active seeds
    assert "injection" in ids
    assert "wildcard" in ids


def test_resolve_seed_active_only_seeds(profiles_root: Path):
    # Add a custom active profile — must not appear in seed_active
    save_profile(
        "my-widget-hunt",
        body_md="# Hunt class: my-widget-hunt\n\nWidgets.\n",
        title="Widget",
        active=True,
        source="custom",
        create=True,
    )
    seeds = resolve_run_class_ids("seed_active")
    assert seeds
    assert "my-widget-hunt" not in seeds
    for pid in seeds:
        meta = next(p for p in list_profiles() if p["id"] == pid)
        assert meta.get("source") == "seed"
        assert meta.get("active") is True


def test_resolve_custom_only_excludes_seeds(profiles_root: Path):
    save_profile(
        "custom-a",
        body_md="# Hunt class: custom-a\n\nA.\n",
        active=True,
        source="custom",
        create=True,
    )
    save_profile(
        "gen-b",
        body_md="# Hunt class: gen-b\n\nB.\n",
        active=True,
        source="generated",
        create=True,
    )
    save_profile(
        "import-c",
        body_md="# Hunt class: import-c\n\nC.\n",
        active=False,
        source="import",
        create=True,
    )
    customs = resolve_run_class_ids("custom_only")
    assert set(customs) == {"custom-a", "gen-b"}
    assert "injection" not in customs
    assert "import-c" not in customs  # inactive

    # prefer_active=False includes inactive customs still not seeds
    all_custom = resolve_run_class_ids("custom_only", prefer_active=False)
    assert "import-c" in all_custom
    assert "injection" not in all_custom


def test_resolve_custom_only_empty_when_none(profiles_root: Path):
    # Only seeds in fresh collection
    customs = resolve_run_class_ids("custom_only")
    assert customs == []


def test_resolve_seed_active_empty_when_none_active(profiles_root: Path):
    # Deactivate all seeds
    for p in list_profiles():
        if p.get("source") == "seed":
            save_profile(p["id"], active=False)
    assert resolve_run_class_ids("seed_active") == []
    # Does not silently fall back to all seeds with prefer_active
    assert resolve_run_class_ids("seed_active", prefer_active=False)


def test_resolve_explicit(profiles_root: Path):
    ids = resolve_run_class_ids(
        "explicit",
        ["injection", "no-such-skill", "sqli", "access-control"],
    )
    # sqli aliases to injection; de-duped; unknown dropped
    assert ids == ["injection", "access-control"]


def test_skill_policy_from_cfg_and_payload():
    cfg = {"run": {"hunt_skill_mode": "seed_active", "hunt_skill_ids": []}}
    mode, ids = skill_policy_from_run_cfg(cfg)
    assert mode == "seed_active"
    assert ids == []
    mode2, ids2 = skill_policy_from_run_cfg(
        cfg, payload={"hunt_skill_mode": "explicit", "hunt_skill_ids": ["injection"]}
    )
    assert mode2 == "explicit"
    assert ids2 == ["injection"]


def test_plan_hunt_tasks_custom_only_excludes_seeds(profiles_root: Path):
    save_profile(
        "only-custom",
        body_md="# Hunt class: only-custom\n\nCustom.\n",
        active=True,
        source="custom",
        create=True,
    )
    inv = {"entrypoints": ["app.py"], "sample_paths": ["app.py"]}
    cfg = {"run": {"max_tasks": 50, "hunt_skill_mode": "custom_only"}}
    tasks, source = plan_hunt_tasks(
        {"summary": "x", "hunt_focus": [], "components": [{"name": "app"}]},
        inv,
        cfg,
    )
    assert source == "active_fallback"
    assert tasks
    classes = {t["class"] for t in tasks}
    assert classes == {"only-custom"}
    assert "injection" not in classes


def test_plan_hunt_tasks_custom_only_empty_zero_tasks(profiles_root: Path):
    inv = {"entrypoints": ["app.py"], "sample_paths": ["app.py"]}
    cfg = {"run": {"max_tasks": 50, "hunt_skill_mode": "custom_only"}}
    tasks, source = plan_hunt_tasks(
        {"summary": "x", "hunt_focus": [], "components": [{"name": "app"}]},
        inv,
        cfg,
    )
    assert source == "active_fallback"
    assert tasks == []


def test_plan_hunt_tasks_focus_filtered_to_allowlist(profiles_root: Path):
    inv = {"entrypoints": ["app.py"], "sample_paths": ["app.py"]}
    cfg = {
        "run": {
            "max_tasks": 50,
            "hunt_skill_mode": "explicit",
            "hunt_skill_ids": ["injection"],
        }
    }
    tasks, source = plan_hunt_tasks(
        {
            "summary": "x",
            "hunt_focus": [
                {"area": "a", "class": "injection", "path_hints": ["app.py"]},
                {"area": "a", "class": "cryptography", "path_hints": ["app.py"]},
            ],
            "components": [],
        },
        inv,
        cfg,
    )
    assert source == "hunt_focus"
    assert len(tasks) == 1
    assert tasks[0]["class"] == "injection"


def test_plan_hunt_tasks_uses_resolve(profiles_root: Path):
    """Sanity: plan_hunt_tasks path goes through resolve_run_class_ids."""
    inv = {"entrypoints": ["app.py"], "sample_paths": ["app.py"]}
    cfg = {
        "run": {
            "max_tasks": 50,
            "hunt_skill_mode": "explicit",
            "hunt_skill_ids": ["wildcard"],
        }
    }
    tasks, _ = plan_hunt_tasks(
        {"summary": "x", "hunt_focus": [], "components": []},
        inv,
        cfg,
    )
    assert {t["class"] for t in tasks} == {"wildcard"}
