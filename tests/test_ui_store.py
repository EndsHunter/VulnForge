"""Dashboard store / runner status (no live server)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.cli import EXIT_PROGRESS, main
from vulnforge.ui import runner as runctl
from vulnforge.ui import store
from vulnforge.ui.app import ControlBody, control_start_kwargs, incomplete_from_flags, with_runner_flags


def test_discover_and_card(tmp_path: Path, toy_sqli: Path):
    runs = tmp_path / "runs"
    code = main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    assert code == EXIT_PROGRESS
    refs = store.discover_runs(runs)
    assert len(refs) == 1
    card = store.run_card(refs[0])
    assert card["total_tasks"] >= 1
    assert "tasks" in card
    snap = store.run_snapshot(refs[0])
    assert snap["tasks"]
    # Pre-recon: manifest file_count only; hunt plan unknown
    ih = snap["inventory_honesty"]
    assert ih["file_count"] is not None and ih["file_count"] >= 1
    assert ih["sample_paths_cap"] == store.SAMPLE_PATHS_CAP
    assert ih["sample_truncated"] is False
    assert ih["hunt_plan_source"] is None
    assert ih["hunt_enqueued"] is None
    st = runctl.runner_status(refs[0].path)
    assert st["state"] in ("idle", "paused", "busy")


def test_inventory_honesty_from_arch_and_recon(tmp_path: Path, toy_sqli: Path):
    """Snapshot prefers arch inventory file_count; recon result supplies plan source."""
    from vulnforge.db import Database

    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    db = Database.open(ref.path / "harness.db")
    try:
        db.set_architecture(
            {
                "summary": "toy",
                "components": [],
                "inventory": {"file_count": 612},
            }
        )
        # init already enqueued recon â€” complete it with honesty fields
        recon = next(t for t in db.list_tasks() if t.kind == "recon")
        db.complete_task(
            recon.id,
            {
                "status": "succeeded",
                "hunt_enqueued": 8,
                "hunt_plan_source": "active_fallback",
                "file_count": 612,
            },
        )
    finally:
        db.close()

    snap = store.run_snapshot(ref)
    ih = snap["inventory_honesty"]
    assert ih["file_count"] == 612
    assert ih["sample_paths_cap"] == 500
    assert ih["sample_truncated"] is True
    assert ih["hunt_plan_source"] == "active_fallback"
    assert ih["hunt_enqueued"] == 8


def test_inventory_honesty_hunt_focus(tmp_path: Path, toy_sqli: Path):
    from vulnforge.db import Database

    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    db = Database.open(ref.path / "harness.db")
    try:
        db.set_architecture(
            {
                "summary": "toy",
                "inventory": {"file_count": 40},
            }
        )
        recon = next(t for t in db.list_tasks() if t.kind == "recon")
        db.complete_task(
            recon.id,
            {
                "status": "succeeded",
                "hunt_enqueued": 3,
                "hunt_plan_source": "hunt_focus",
                "file_count": 40,
            },
        )
    finally:
        db.close()

    ih = store.run_snapshot(ref)["inventory_honesty"]
    assert ih["file_count"] == 40
    assert ih["sample_truncated"] is False
    assert ih["hunt_plan_source"] == "hunt_focus"
    assert ih["hunt_enqueued"] == 3
    assert ih.get("last_recon") is not None
    assert ih["last_recon"]["state"] == "succeeded"


def test_inventory_last_recon_failure(tmp_path: Path, toy_sqli: Path):
    from vulnforge.db import Database

    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    db = Database.open(ref.path / "harness.db")
    try:
        recon = next(t for t in db.list_tasks() if t.kind == "recon")
        db.fail_task(
            recon.id,
            "failed_task",
            "no_submit",
            result_extra={
                "recon_requeued": True,
                "child_task_id": 99,
            },
        )
    finally:
        db.close()

    ih = store.run_snapshot(ref)["inventory_honesty"]
    assert ih["recon_done"] is False
    lr = ih["last_recon"]
    assert lr is not None
    assert lr["state"] == "failed_task"
    assert lr["error"] == "no_submit"
    assert lr["recon_requeued"] is True


@pytest.mark.parametrize(
    "file_count,truncated",
    [
        (500, False),
        (501, True),
    ],
)
def test_inventory_honesty_sample_truncated_boundary(file_count: int, truncated: bool):
    """sample_truncated is strict file_count > SAMPLE_PATHS_CAP (500)."""
    ref = store.RunRef("t", "r", Path("."))
    ih = store._inventory_honesty(
        ref, {"inventory": {"file_count": file_count}}, []
    )
    assert ih["file_count"] == file_count
    assert ih["sample_paths_cap"] == 500
    assert ih["sample_truncated"] is truncated


def test_inventory_honesty_arch_precedes_manifest(tmp_path: Path, toy_sqli: Path):
    """Arch inventory file_count wins over target_manifest.json and recon result."""
    import json

    from vulnforge.db import Database

    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    man_path = ref.path / "target_manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    man["file_count"] = 999
    man_path.write_text(json.dumps(man), encoding="utf-8")

    db = Database.open(ref.path / "harness.db")
    try:
        db.set_architecture(
            {
                "summary": "toy",
                "inventory": {"file_count": 10},
            }
        )
        recon = next(t for t in db.list_tasks() if t.kind == "recon")
        db.complete_task(
            recon.id,
            {
                "status": "succeeded",
                "hunt_enqueued": 1,
                "hunt_plan_source": "hunt_focus",
                "file_count": 999,
            },
        )
    finally:
        db.close()

    ih = store.run_snapshot(ref)["inventory_honesty"]
    assert ih["file_count"] == 10
    assert ih["sample_truncated"] is False
    assert _manifest_count(ref) == 999


def _manifest_count(ref: store.RunRef) -> int:
    import json

    return int(json.loads((ref.path / "target_manifest.json").read_text())["file_count"])


def test_pause_creates_stop(tmp_path: Path, toy_sqli: Path):
    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    run_dir = next(next(runs.iterdir()).iterdir())
    r = runctl.pause_run(run_dir)
    assert r["ok"]
    assert (run_dir / "STOP").is_file()
    st = runctl.runner_status(run_dir)
    assert st["stop"] is True


@pytest.mark.parametrize(
    "has_work,runner_state,expected",
    [
        (True, "idle", True),
        (True, "paused", True),
        (True, None, True),
        (True, "running", False),
        (True, "pausing", False),
        (True, "busy", False),
        (False, "idle", False),
        (False, "running", False),
    ],
)
def test_incomplete_from_flags_matrix(has_work, runner_state, expected):
    """P0.4: incomplete = has_work && runner not alive."""
    assert incomplete_from_flags(has_work, runner_state) is expected


def test_with_runner_flags_incomplete_when_idle_with_work(
    tmp_path: Path, toy_sqli: Path, monkeypatch
):
    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    card = store.run_card(ref)
    # Fresh init has recon queued â†’ has_work true
    assert card.get("has_work") is True

    monkeypatch.setattr(
        "vulnforge.ui.runner.runner_status",
        lambda _p: {"state": "idle", "pid": None, "stop": False},
    )
    out = with_runner_flags(dict(card), ref.path)
    assert out["incomplete"] is True
    assert out["runner"]["state"] == "idle"

    monkeypatch.setattr(
        "vulnforge.ui.runner.runner_status",
        lambda _p: {"state": "running", "pid": 1, "stop": False},
    )
    out_run = with_runner_flags(dict(card), ref.path)
    assert out_run["incomplete"] is False


_CONTROL_KW_KEYS = {
    "task_timeout",
    "max_tasks",
    "max_iterations",
    "max_wall_seconds",
    "workers",
}


def test_control_start_kwargs_prefers_body_over_ui():
    """Start/resume kwargs: explicit body wins; None falls back to UI settings.

    ControlBody.max_tasks defaults to None so empty POST â†’ UI settings â†’ 50.
    Dashboard client still sends Settings values when available.
    """
    ui = {"max_tasks": 12, "max_concurrent_agents": 3}
    body = ControlBody(max_tasks=25, workers=2, task_timeout=600)
    kw = control_start_kwargs(body, ui=ui)
    assert set(kw.keys()) == _CONTROL_KW_KEYS
    assert kw["max_tasks"] == 25
    assert kw["workers"] == 2
    assert kw["task_timeout"] == 600
    assert kw["max_iterations"] == 200
    assert kw["max_wall_seconds"] is None

    # Omit workers â†’ UI max_concurrent_agents; keep body max_tasks
    body2 = ControlBody(max_tasks=7, task_timeout=900)
    kw2 = control_start_kwargs(body2, ui=ui)
    assert kw2["max_tasks"] == 7
    assert kw2["workers"] == 3

    # max_tasks=None â†’ UI
    body3 = ControlBody(max_tasks=None)
    kw3 = control_start_kwargs(body3, ui=ui)
    assert kw3["max_tasks"] == 12
    assert kw3["workers"] == 3


def test_control_start_kwargs_default_body_uses_ui():
    """Empty ControlBody() must not hardcode max_tasks=50 over UI settings."""
    ui = {"max_tasks": 12, "max_concurrent_agents": 3}
    kw = control_start_kwargs(ControlBody(), ui=ui)
    assert set(kw.keys()) == _CONTROL_KW_KEYS
    assert kw["max_tasks"] == 12
    assert kw["workers"] == 3
    assert kw["task_timeout"] == 900


def test_control_start_kwargs_empty_ui_fallbacks():
    """Missing UI keys â†’ last-resort max_tasks=50, workers=1."""
    kw = control_start_kwargs(ControlBody(), ui={})
    assert set(kw.keys()) == _CONTROL_KW_KEYS
    assert kw["max_tasks"] == 50
    assert kw["workers"] == 1
    assert kw["task_timeout"] == 900
    assert kw["max_iterations"] == 200
    assert kw["max_wall_seconds"] is None
