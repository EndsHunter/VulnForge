"""Dashboard store / runner status (no live server)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.cli import EXIT_PROGRESS, main
from vulnforge.db import Database
from vulnforge.ui import runner as runctl
from vulnforge.ui import store
from vulnforge.ui.app import (
    ControlBody,
    control_start_kwargs,
    create_app,
    incomplete_from_flags,
    with_runner_flags,
)


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
    ih = snap["target_inventory"]
    assert ih["file_count"] is not None and ih["file_count"] >= 1
    assert ih["sample_paths_cap"] == store.SAMPLE_PATHS_CAP
    assert ih["planning_seed_partial"] is False
    assert ih["hunt_plan_source"] is None
    assert ih["hunt_enqueued"] is None
    st = runctl.runner_status(refs[0].path)
    assert st["state"] in ("idle", "paused", "busy")


def test_target_inventory_from_arch_and_recon(tmp_path: Path, toy_sqli: Path):
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
        # init already enqueued recon — lease then complete with honesty fields
        recon = next(t for t in db.list_tasks() if t.kind == "recon")
        leased = db.lease_next_task("w-test", ttl_seconds=60)
        assert leased is not None and leased.id == recon.id
        assert db.complete_task(
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
    ih = snap["target_inventory"]
    assert ih["file_count"] == 612
    assert ih["sample_paths_cap"] == 500
    assert ih["planning_seed_partial"] is True
    assert ih["hunt_plan_source"] == "active_fallback"
    assert ih["hunt_enqueued"] == 8


def test_target_inventory_hunt_focus(tmp_path: Path, toy_sqli: Path):
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
        leased = db.lease_next_task("w-test", ttl_seconds=60)
        assert leased is not None and leased.id == recon.id
        assert db.complete_task(
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

    ih = store.run_snapshot(ref)["target_inventory"]
    assert ih["file_count"] == 40
    assert ih["planning_seed_partial"] is False
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
        leased = db.lease_next_task("w-test", ttl_seconds=60)
        assert leased is not None and leased.id == recon.id
        assert db.fail_task(
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

    ih = store.run_snapshot(ref)["target_inventory"]
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
def test_target_inventory_planning_seed_partial_boundary(file_count: int, truncated: bool):
    """planning_seed_partial is strict file_count > SAMPLE_PATHS_CAP (500)."""
    ref = store.RunRef("t", "r", Path("."))
    ih = store._target_inventory(
        ref, {"inventory": {"file_count": file_count}}, []
    )
    assert ih["file_count"] == file_count
    assert ih["sample_paths_cap"] == 500
    assert ih["planning_seed_partial"] is truncated


def test_target_inventory_arch_precedes_manifest(tmp_path: Path, toy_sqli: Path):
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
        leased = db.lease_next_task("w-test", ttl_seconds=60)
        assert leased is not None and leased.id == recon.id
        assert db.complete_task(
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

    ih = store.run_snapshot(ref)["target_inventory"]
    assert ih["file_count"] == 10
    assert ih["planning_seed_partial"] is False
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
    assert r["killed"] is False
    assert r["draining"] is False
    assert r["reclaimed_leases"] == 0
    assert r["lock_cleared"] is True
    assert (run_dir / "STOP").is_file()
    st = runctl.runner_status(run_dir)
    assert st["stop"] is True
    assert st["state"] == "paused"
    assert st["alive"] is False


def test_pause_keeps_live_worker_lease(tmp_path: Path, toy_sqli: Path):
    """Pause writes STOP and leaves the in-flight lease with the live worker."""
    import json
    import subprocess
    import sys

    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    run_dir = next(next(runs.iterdir()).iterdir())
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        (run_dir / "ralph.pid").write_text(
            json.dumps({"pid": proc.pid}), encoding="utf-8"
        )
        (run_dir / "run.lock").write_text(
            json.dumps({"pid": proc.pid}), encoding="utf-8"
        )
        db = Database.open(run_dir / "harness.db")
        try:
            db.enqueue_task("recon", {"agent_ids": ["surface-mapper"]}, priority=11)
            leased = db.lease_next_task(
                f"vf-{proc.pid}-drain", ttl_seconds=1800, max_parallel=1
            )
            assert leased is not None
            leased_id = leased.id
        finally:
            db.close()
        r = runctl.pause_run(run_dir)
        assert r["ok"] is True
        assert r["killed"] is False
        assert r["draining"] is True
        assert r["reclaimed_leases"] == 0
        assert r["lock_cleared"] is False
        assert r["lock_holder"] == proc.pid
        assert r["status"]["state"] == "pausing"
        assert r["status"]["alive"] is True
        assert r["status"]["stop"] is True
        assert runctl._pid_alive(proc.pid) is True
        assert (run_dir / "ralph.pid").is_file()
        db = Database.open(run_dir / "harness.db")
        try:
            assert db.count_leased_tasks() == 1
            task = db.get_task(leased_id)
            assert task is not None
            assert task.state == "leased"
            assert task.lease_owner == f"vf-{proc.pid}-drain"
        finally:
            db.close()
    finally:
        proc.kill()
        proc.wait(timeout=3)


def test_hard_stop_reclaims_orphaned_leases(tmp_path: Path, toy_sqli: Path):
    """Hard stop requeues leased tasks so the queue is not stuck."""
    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    run_dir = next(next(runs.iterdir()).iterdir())
    db = Database.open(run_dir / "harness.db")
    try:
        db.enqueue_task("recon", {"agent_ids": ["surface-mapper"]}, priority=11)
        leased = db.lease_next_task("orphan-worker", ttl_seconds=1800, max_parallel=1)
        assert leased is not None
        assert db.count_leased_tasks() == 1
    finally:
        db.close()
    r = runctl.stop_run_hard(run_dir)
    assert r["ok"]
    assert r.get("reclaimed_leases", 0) >= 1
    db = Database.open(run_dir / "harness.db")
    try:
        assert db.count_leased_tasks() == 0
        states = {t.id: t.state for t in db.list_tasks() if t.id == leased.id}
        assert states.get(leased.id) == "queued"
    finally:
        db.close()


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
    """Start/resume: explicit max_tasks wins; None stays unlimited (not UI enqueue cap).

    UI settings max_tasks is hunt enqueue planning only — not Ralph budget.
    """
    ui = {"max_tasks": 12, "max_concurrent_agents": 3}
    body = ControlBody(max_tasks=25, workers=2, task_timeout=600)
    kw = control_start_kwargs(body, ui=ui)
    assert set(kw.keys()) == _CONTROL_KW_KEYS
    assert kw["max_tasks"] == 25
    assert kw["workers"] == 2
    assert kw["task_timeout"] == 600
    assert kw["max_iterations"] == 10_000
    assert kw["max_wall_seconds"] is None

    # Omit workers → UI max_concurrent_agents; keep body max_tasks
    body2 = ControlBody(max_tasks=7, task_timeout=900)
    kw2 = control_start_kwargs(body2, ui=ui)
    assert kw2["max_tasks"] == 7
    assert kw2["workers"] == 3

    # max_tasks=None → unlimited Ralph (UI enqueue cap ignored)
    body3 = ControlBody(max_tasks=None)
    kw3 = control_start_kwargs(body3, ui=ui)
    assert kw3["max_tasks"] is None
    assert kw3["workers"] == 3
    assert kw3["max_wall_seconds"] is None


def test_control_start_kwargs_default_body_unlimited():
    """Empty ControlBody() → no Ralph max_tasks / wall; workers from UI agents."""
    ui = {"max_tasks": 12, "max_concurrent_agents": 3}
    kw = control_start_kwargs(ControlBody(), ui=ui)
    assert set(kw.keys()) == _CONTROL_KW_KEYS
    assert kw["max_tasks"] is None
    assert kw["workers"] == 3
    assert kw["task_timeout"] == 900
    assert kw["max_iterations"] == 10_000
    assert kw["max_wall_seconds"] is None


def test_control_start_kwargs_empty_ui_fallbacks():
    """Missing UI keys → unlimited max_tasks, workers=1, no wall."""
    kw = control_start_kwargs(ControlBody(), ui={})
    assert set(kw.keys()) == _CONTROL_KW_KEYS
    assert kw["max_tasks"] is None
    assert kw["workers"] == 1
    assert kw["task_timeout"] == 900
    assert kw["max_iterations"] == 10_000
    assert kw["max_wall_seconds"] is None


def _succeed_all_tasks(ref: store.RunRef) -> None:
    db = Database.open(ref.path / "harness.db")
    try:
        db.conn.execute(
            "UPDATE tasks SET state='succeeded', lease_owner=NULL, lease_until=NULL"
        )
        db.conn.commit()
    finally:
        db.close()


def test_run_card_status_paused_while_stop_present(tmp_path: Path, toy_sqli: Path):
    """Mission card status follows STOP; the durable runs.status row stays active."""
    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    assert store.run_card(ref)["status"] == "active"
    (ref.path / "STOP").write_text("paused_at=test\n", encoding="utf-8")
    card = store.run_card(ref)
    assert card["status"] == "paused"
    assert card["stop"] is True
    db = Database.open(ref.path / "harness.db")
    try:
        assert db.get_run()["status"] == "active"
    finally:
        db.close()


def test_run_card_status_idle_when_campaign_finished(tmp_path: Path, toy_sqli: Path):
    """No remaining work and no STOP: card and durable runs.status are idle."""
    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs), "--no-enqueue-hunts"])
    ref = store.discover_runs(runs)[0]
    _succeed_all_tasks(ref)
    db = Database.open(ref.path / "harness.db")
    try:
        assert db.summary()["has_work"] is False
        assert db.get_run()["status"] == "active"
    finally:
        db.close()

    card = store.run_card(ref)
    assert card["status"] == "idle"
    assert card["has_work"] is False
    assert card["stop"] is False
    assert card["active"] is False
    assert card["progress"] == 1.0
    db = Database.open(ref.path / "harness.db")
    try:
        assert db.get_run()["status"] == "idle"
    finally:
        db.close()
    again = store.run_card(ref)
    assert again["status"] == "idle"

    with TestClient(create_app(runs_root=runs)) as client:
        listed = client.get("/api/runs")
        assert listed.status_code == 200
        body = listed.json()
        match = next(r for r in body["runs"] if r["run_id"] == ref.run_id)
        assert match["status"] == "idle"
        assert match["has_work"] is False


def test_run_card_status_active_when_work_returns(tmp_path: Path, toy_sqli: Path):
    """A finished idle row becomes active again once a task is queued."""
    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs), "--no-enqueue-hunts"])
    ref = store.discover_runs(runs)[0]
    _succeed_all_tasks(ref)
    assert store.run_card(ref)["status"] == "idle"
    db = Database.open(ref.path / "harness.db")
    try:
        db.enqueue_task("hunt", {"area": "app"})
    finally:
        db.close()
    card = store.run_card(ref)
    assert card["has_work"] is True
    assert card["status"] == "active"
    db = Database.open(ref.path / "harness.db")
    try:
        assert db.get_run()["status"] == "active"
    finally:
        db.close()


def test_run_card_stop_does_not_rewrite_finished_durable_status(
    tmp_path: Path, toy_sqli: Path
):
    """STOP still paints the card paused and does not store paused on the row."""
    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs), "--no-enqueue-hunts"])
    ref = store.discover_runs(runs)[0]
    _succeed_all_tasks(ref)
    (ref.path / "STOP").write_text("paused_at=test\n", encoding="utf-8")
    card = store.run_card(ref)
    assert card["status"] == "paused"
    assert card["has_work"] is False
    db = Database.open(ref.path / "harness.db")
    try:
        assert db.get_run()["status"] == "active"
    finally:
        db.close()


def _posix_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    Database.create(run_dir / "harness.db").close()
    return run_dir


def _spawn_session_lock_holder(run_dir: Path) -> "subprocess.Popen[bytes]":
    """Session leader plus a child that left the group and holds run.lock.

    Mirrors Ralph (`start_new_session=True`) and a run-once that would survive
    a leader-only SIGTERM. The child calls setpgrp so group-kill alone is not
    enough; the tree walk has to find it.
    """
    import subprocess
    import sys

    script = run_dir / "_hold_lock.py"
    script.write_text(
        "\n".join(
            [
                "import json, os, sys, time, subprocess",
                "from pathlib import Path",
                "run = Path(sys.argv[1])",
                "role = sys.argv[2]",
                "if role == 'child':",
                "    os.setpgrp()",
                "    payload = {'pid': os.getpid(), 'ts': time.time()}",
                "    (run / 'run.lock').write_text(json.dumps(payload))",
                "    (run / 'child.pid').write_text(str(os.getpid()))",
                "    time.sleep(120)",
                "else:",
                "    subprocess.Popen([sys.executable, sys.argv[0], sys.argv[1], 'child'])",
                "    for _ in range(100):",
                "        if (run / 'child.pid').is_file():",
                "            break",
                "        time.sleep(0.05)",
                "    else:",
                "        raise SystemExit(2)",
                "    (run / 'parent.ready').write_text(str(os.getpid()))",
                "    time.sleep(120)",
            ]
        ),
        encoding="utf-8",
    )
    return subprocess.Popen(
        [sys.executable, str(script), str(run_dir), "parent"],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_file(path: Path, timeout: float = 5.0) -> None:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {path}")


def _kill_session(pid: int) -> None:
    import os
    import signal

    if os.name == "nt" or pid <= 1:
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def test_pause_leaves_session_child_and_lease(tmp_path: Path):
    """Pause must not reap Ralph or the run-once that holds the live lease."""
    import os

    if os.name == "nt":
        pytest.skip("POSIX process-group kill")
    run_dir = _posix_run_dir(tmp_path)
    proc = _spawn_session_lock_holder(run_dir)
    try:
        _wait_file(run_dir / "parent.ready")
        _wait_file(run_dir / "run.lock")
        child = int((run_dir / "child.pid").read_text(encoding="utf-8"))
        assert child != proc.pid
        assert os.getpgid(child) != os.getpgid(proc.pid)
        (run_dir / "ralph.pid").write_text(
            '{"pid": %d}' % proc.pid, encoding="utf-8"
        )
        db = Database.open(run_dir / "harness.db")
        try:
            db.enqueue_task("hunt", {"class": "injection"}, priority=20)
            leased = db.lease_next_task("vf-drain", ttl_seconds=1800, max_parallel=1)
            assert leased is not None
            leased_id = leased.id
        finally:
            db.close()
        paused = runctl.pause_run(run_dir)
        assert paused["ok"] is True, paused
        assert paused["killed"] is False
        assert paused["draining"] is True
        assert paused["reclaimed_leases"] == 0
        assert paused["lock_cleared"] is False
        assert (run_dir / "run.lock").is_file()
        assert (run_dir / "STOP").is_file()
        assert runctl._pid_alive(proc.pid) is True
        assert runctl._pid_alive(child) is True
        assert paused["status"]["state"] == "pausing"
        db = Database.open(run_dir / "harness.db")
        try:
            task = db.get_task(leased_id)
            assert task is not None and task.state == "leased"
        finally:
            db.close()
    finally:
        _kill_session(proc.pid)
        try:
            child = int((run_dir / "child.pid").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            child = 0
        if child:
            try:
                os.kill(child, 9)
            except OSError:
                pass
        proc.wait(timeout=3)


def test_hard_stop_kills_session_child_and_clears_lock(tmp_path: Path):
    """Hard stop reaps a new-session Ralph and the run-once holding run.lock."""
    import os

    if os.name == "nt":
        pytest.skip("POSIX process-group kill")
    run_dir = _posix_run_dir(tmp_path)
    proc = _spawn_session_lock_holder(run_dir)
    try:
        _wait_file(run_dir / "parent.ready")
        _wait_file(run_dir / "run.lock")
        child = int((run_dir / "child.pid").read_text(encoding="utf-8"))
        assert child != proc.pid
        assert os.getpgid(child) != os.getpgid(proc.pid)
        (run_dir / "ralph.pid").write_text(
            '{"pid": %d}' % proc.pid, encoding="utf-8"
        )
        db = Database.open(run_dir / "harness.db")
        try:
            db.enqueue_task("hunt", {"class": "injection"}, priority=20)
            leased = db.lease_next_task("vf-hard", ttl_seconds=1800, max_parallel=1)
            assert leased is not None
            leased_id = leased.id
        finally:
            db.close()
        stopped = runctl.stop_run_hard(run_dir)
        assert stopped["ok"] is True, stopped
        assert stopped["lock_cleared"] is True
        assert stopped["killed"] is True
        assert stopped["reclaimed_leases"] >= 1
        assert not (run_dir / "run.lock").exists()
        assert runctl._pid_alive(proc.pid) is False
        assert runctl._pid_alive(child) is False
        status = stopped["status"]
        assert status["state"] == "paused"
        assert status["locked"] is False
        db = Database.open(run_dir / "harness.db")
        try:
            task = db.get_task(leased_id)
            assert task is not None and task.state == "queued"
        finally:
            db.close()
    finally:
        _kill_session(proc.pid)
        try:
            child = int((run_dir / "child.pid").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            child = 0
        if child:
            try:
                os.kill(child, 9)
            except OSError:
                pass
        proc.wait(timeout=3)


def test_resume_kills_orphan_lock_then_starts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A live lock with no Ralph worker is killed before resume spawns Ralph."""
    import os

    if os.name == "nt":
        pytest.skip("POSIX process-group kill")
    run_dir = _posix_run_dir(tmp_path)
    (run_dir / "STOP").write_text("paused\n", encoding="utf-8")
    proc = _spawn_session_lock_holder(run_dir)
    started: list[Path] = []

    def fake_start(path, **kwargs):
        started.append(Path(path))
        return {"ok": True, "pid": 99, "status": {"state": "running", "alive": True}}

    monkeypatch.setattr(runctl, "start_run", fake_start)
    try:
        _wait_file(run_dir / "run.lock")
        child = int((run_dir / "child.pid").read_text(encoding="utf-8"))
        resumed = runctl.resume_run(run_dir)
        assert resumed["ok"] is True, resumed
        assert resumed["lock_cleared"] is True
        assert started == [run_dir.resolve()]
        assert not (run_dir / "STOP").exists()
        assert not (run_dir / "run.lock").exists()
        assert runctl._pid_alive(child) is False
    finally:
        _kill_session(proc.pid)
        proc.wait(timeout=3)


def test_resume_refuses_when_lock_holder_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Do not report a clean resume while a live PID still owns run.lock."""
    run_dir = _posix_run_dir(tmp_path)
    (run_dir / "STOP").write_text("paused\n", encoding="utf-8")
    (run_dir / "run.lock").write_text('{"pid": 424242}', encoding="utf-8")
    monkeypatch.setattr(runctl, "_lock_holder_alive", lambda _d: 424242)

    def no_kill(_pid: int) -> bool:
        return False

    def no_start(*_a, **_k):
        raise AssertionError("start_run must not run while the lock is held")

    monkeypatch.setattr(runctl, "_kill_pid", no_kill)
    monkeypatch.setattr(runctl, "start_run", no_start)
    resumed = runctl.resume_run(run_dir)
    assert resumed["ok"] is False
    assert resumed["lock_cleared"] is False
    assert resumed["lock_holder"] == 424242
    assert "424242" in resumed["error"]
    assert (run_dir / "STOP").is_file()
    assert (run_dir / "run.lock").is_file()


def test_pause_leaves_live_lock_holder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Drain does not signal a live lock holder. Hard stop reports that failure."""
    run_dir = _posix_run_dir(tmp_path)
    (run_dir / "run.lock").write_text('{"pid": 424242}', encoding="utf-8")
    monkeypatch.setattr(runctl, "_lock_holder_alive", lambda _d: 424242)
    monkeypatch.setattr(runctl, "_read_lock_pid", lambda _d: 424242)
    killed: list[int] = []

    def no_kill(pid: int) -> bool:
        killed.append(pid)
        return False

    monkeypatch.setattr(runctl, "_kill_pid", no_kill)
    paused = runctl.pause_run(run_dir)
    assert killed == []
    assert paused["ok"] is True
    assert paused["killed"] is False
    assert paused["draining"] is False
    assert paused["reclaimed_leases"] == 0
    assert paused["lock_cleared"] is False
    assert paused["lock_holder"] == 424242
    assert paused["status"]["state"] == "paused"
    assert (run_dir / "STOP").is_file()
    assert (run_dir / "run.lock").is_file()


def test_hard_stop_not_ok_when_lock_holder_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    run_dir = _posix_run_dir(tmp_path)
    (run_dir / "run.lock").write_text('{"pid": 424242}', encoding="utf-8")
    monkeypatch.setattr(runctl, "_lock_holder_alive", lambda _d: 424242)
    monkeypatch.setattr(runctl, "_read_lock_pid", lambda _d: 424242)
    monkeypatch.setattr(runctl, "_kill_pid", lambda _pid: False)
    stopped = runctl.stop_run_hard(run_dir)
    assert stopped["ok"] is False
    assert stopped["lock_cleared"] is False
    assert stopped["lock_holder"] == 424242
    assert "424242" in stopped["error"]
    assert (run_dir / "STOP").is_file()


def test_pid_alive_false_for_zombie_child():
    """Exited Ralph child must not count as alive (kill 0 is true for zombies)."""
    import subprocess
    import sys
    import time

    proc = subprocess.Popen(
        [sys.executable, "-c", "raise SystemExit(0)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 2
    while time.time() < deadline:
        if runctl._pid_is_zombie(proc.pid) or proc.poll() is not None:
            break
        time.sleep(0.05)
    assert runctl._pid_alive(proc.pid) is False
    proc.wait(timeout=2)


def test_run_card_llm_usage_missing_and_by_model(tmp_path: Path, toy_sqli: Path):
    """Missing usage is zeros; multi-model summary is attached to the card."""
    from vulnforge.llm import TokenUsage
    from vulnforge.usage import record_usage

    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    empty = store.run_card(ref)["llm_usage"]
    assert empty["prompt_tokens"] == 0
    assert empty["completion_tokens"] == 0
    assert empty["total_tokens"] == 0
    assert empty["by_model"] == {}

    (ref.path / "llm_usage_summary.json").write_text("not-json", encoding="utf-8")
    broken = store.run_card(ref)["llm_usage"]
    assert broken["total_tokens"] == 0
    assert broken["by_model"] == {}

    record_usage(
        ref.path,
        task_id=1,
        kind="recon",
        model_id="grok-4",
        usage=TokenUsage(
            prompt_tokens=100, completion_tokens=20, total_tokens=120, source="provider"
        ),
    )
    record_usage(
        ref.path,
        task_id=2,
        kind="hunt:injection",
        model_id="claude-sonnet-4",
        usage=TokenUsage(
            prompt_tokens=50, completion_tokens=10, total_tokens=60, source="provider"
        ),
    )
    used = store.run_card(ref)["llm_usage"]
    assert used["prompt_tokens"] == 150
    assert used["completion_tokens"] == 30
    assert used["total_tokens"] == 180
    assert used["by_model"]["grok-4"]["prompt_tokens"] == 100
    assert used["by_model"]["grok-4"]["completion_tokens"] == 20
    assert used["by_model"]["grok-4"]["total_tokens"] == 120
    assert used["by_model"]["claude-sonnet-4"]["total_tokens"] == 60

    snap = store.run_snapshot(ref)
    assert snap["llm_usage"]["by_model"]["grok-4"]["total_tokens"] == 120
