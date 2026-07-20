"""Concurrent agent multi-lease: cap and serial lock skip."""

from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.util import build_target_manifest, write_json


def _db(tmp_path: Path, toy_sqli: Path) -> tuple[Path, Database]:
    run = tmp_path / "run-001"
    run.mkdir()
    (run / "evidence").mkdir()
    write_json(run / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    return run, db


def test_run_once_lease_wait_returns_busy_not_progress(tmp_path: Path, toy_sqli: Path):
    """Waiting for a peer lease must not count as Ralph progress (exit 11, not 0)."""
    from vulnforge.cli import cmd_run_once, load_config
    from vulnforge.control.exit_codes import EXIT_BUSY, EXIT_PROGRESS
    from vulnforge.util import write_json

    run = tmp_path / "runs" / "busy" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run(
        "run-001",
        str(toy_sqli),
        "code_static",
        "pin",
        {"run": {"max_leases_parallel": 2, "max_tasks": 50}},
    )
    # One leased, one queued — second worker should get busy if cap is 1... use
    # max_parallel=1 effectively by leasing one with cap 1 via exclusive path:
    # Hold one lease with max_parallel=2 and no queued → busy while leased.
    t1 = db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=50)
    leased = db.lease_next_task("holder", ttl_seconds=600, max_parallel=2)
    assert leased is not None and leased.id == t1
    # No more queued — only leased remains → busy (peer working)
    db.close()
    write_json(run / "target_manifest.json", {"files": {}})
    cfg = load_config()
    cfg.setdefault("run", {})["max_leases_parallel"] = 2
    cfg.setdefault("run", {})["runs_root"] = str(tmp_path / "runs")

    class Args:
        run_dir = run
        config = None

    code = cmd_run_once(Args(), cfg)
    assert code == EXIT_BUSY, f"expected EXIT_BUSY (11), got {code}"
    assert code != EXIT_PROGRESS


def test_lease_respects_max_parallel(tmp_path: Path, toy_sqli: Path):
    _run, db = _db(tmp_path, toy_sqli)
    for i in range(4):
        db.enqueue_task("hunt", {"area": f"a{i}", "class": "injection"}, priority=50)

    t1 = db.lease_next_task("w1", ttl_seconds=60, max_parallel=2)
    t2 = db.lease_next_task("w2", ttl_seconds=60, max_parallel=2)
    t3 = db.lease_next_task("w3", ttl_seconds=60, max_parallel=2)
    assert t1 is not None and t2 is not None
    assert t1.id != t2.id
    assert t3 is None  # cap
    assert db.count_leased_tasks() == 2

    db.complete_task(t1.id, {"status": "succeeded"})
    t4 = db.lease_next_task("w3", ttl_seconds=60, max_parallel=2)
    assert t4 is not None
    assert db.count_leased_tasks() == 2
    db.close()


def test_lease_serial_default_allows_one(tmp_path: Path, toy_sqli: Path):
    _run, db = _db(tmp_path, toy_sqli)
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=50)
    db.enqueue_task("hunt", {"area": "b", "class": "injection"}, priority=50)
    a = db.lease_next_task("w1", ttl_seconds=60, max_parallel=1)
    b = db.lease_next_task("w2", ttl_seconds=60, max_parallel=1)
    assert a is not None
    assert b is None
    db.close()


def test_reclaim_all_leased_tasks(tmp_path: Path, toy_sqli: Path):
    _run, db = _db(tmp_path, toy_sqli)
    db.enqueue_task("recon", {"agent_ids": ["default-map"]}, priority=10)
    db.enqueue_task("recon", {"agent_ids": ["surface-mapper"]}, priority=11)
    t1 = db.lease_next_task("w1", ttl_seconds=600, max_parallel=2)
    t2 = db.lease_next_task("w2", ttl_seconds=600, max_parallel=2)
    assert t1 and t2
    assert db.count_leased_tasks() == 2
    n = db.reclaim_all_leased_tasks(reason="pause_kill_orphan")
    assert n == 2
    assert db.count_leased_tasks() == 0
    states = {r.id: r.state for r in db.list_tasks()}
    assert states[t1.id] == "queued"
    assert states[t2.id] == "queued"
    db.close()


def test_reclaim_dead_owner_leases(tmp_path: Path, toy_sqli: Path):
    """Hard-killed worker leaves vf-{pid}-* lease; dead PID must requeue immediately."""
    from vulnforge.db import pid_from_lease_owner

    assert pid_from_lease_owner("vf-17332-31bdfad0") == 17332
    assert pid_from_lease_owner("not-a-worker") is None

    _run, db = _db(tmp_path, toy_sqli)
    db.enqueue_task("recon", {"agent_ids": ["auth-model"]}, priority=13)
    # Use a PID that cannot be alive on this machine
    dead_owner = "vf-9999999-deadbeef"
    leased = db.lease_next_task(dead_owner, ttl_seconds=1800, max_parallel=1)
    assert leased is not None
    assert db.count_leased_tasks() == 1
    n = db.reclaim_dead_owner_leases()
    assert n == 1
    assert db.count_leased_tasks() == 0
    assert db.list_tasks()[0].state == "queued"
    # Live owner must not be reclaimed
    db.enqueue_task("recon", {"agent_ids": ["x"]}, priority=14)
    import os

    live = f"vf-{os.getpid()}-alive001"
    t2 = db.lease_next_task(live, ttl_seconds=1800, max_parallel=1)
    assert t2 is not None
    assert db.reclaim_dead_owner_leases() == 0
    assert db.count_leased_tasks() == 1
    db.close()


def test_control_start_kwargs_caps_workers_to_lease_cap():
    from vulnforge.ui.app import ControlBody, control_start_kwargs

    ui = {"max_concurrent_agents": 1, "max_tasks": 50}
    # Client asks for 4 workers but lease cap is 1
    body = ControlBody(workers=4, max_tasks=50)
    kw = control_start_kwargs(body, ui)
    assert kw["workers"] == 1

    ui2 = {"max_concurrent_agents": 3, "max_tasks": 50}
    body2 = ControlBody(workers=2, max_tasks=50)
    kw2 = control_start_kwargs(body2, ui2)
    assert kw2["workers"] == 2
