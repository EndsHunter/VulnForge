from __future__ import annotations

import time
from pathlib import Path

import pytest

from vulnforge.db import Database, RunLock, compute_stable_key


def test_create_enqueue_lease_complete(tmp_path: Path):
    db_path = tmp_path / "harness.db"
    db = Database.create(db_path)
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="abc",
        config={"x": 1},
    )
    t1 = db.enqueue_task("recon", {}, priority=10)
    t2 = db.enqueue_task("hunt", {"class": "injection"}, priority=50)
    assert t1 != t2

    leased = db.lease_next_task("worker-1", ttl_seconds=60, max_parallel=2)
    assert leased is not None
    assert leased.kind == "recon"  # lower priority number first
    assert leased.state == "leased"

    still = db.lease_next_task("worker-2", ttl_seconds=60, max_parallel=2)
    assert still is not None
    assert still.kind == "hunt"

    none = db.lease_next_task("worker-3", ttl_seconds=60, max_parallel=2)
    assert none is None

    # Default max_parallel=1 only allows a single live lease
    db.complete_task(leased.id, {"ok": True})
    db.complete_task(still.id, {"ok": True})
    a = db.enqueue_task("hunt", {"class": "x"}, priority=50)
    b = db.enqueue_task("hunt", {"class": "y"}, priority=50)
    assert a and b
    one = db.lease_next_task("worker-1", ttl_seconds=60)  # default max_parallel=1
    two = db.lease_next_task("worker-2", ttl_seconds=60)
    assert one is not None
    assert two is None
    db.close()


def test_cancel_queued_task(tmp_path: Path):
    db_path = tmp_path / "harness.db"
    db = Database.create(db_path)
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="abc",
        config={},
    )
    tid = db.enqueue_task("hunt", {"class": "injection"}, priority=50)
    assert db.cancel_queued_task(tid, reason="operator_cancel") is True
    t = db.get_task(tid)
    assert t is not None
    assert t.state == "cancelled"
    assert t.result and t.result.get("operator_cancelled") is True
    # second cancel fails
    assert db.cancel_queued_task(tid) is False
    # leased cannot be cancelled via this path
    q = db.enqueue_task("hunt", {"class": "x"}, priority=50)
    leased = db.lease_next_task("w1", ttl_seconds=60)
    assert leased is not None and leased.id == q
    assert db.cancel_queued_task(q) is False
    db.close()


def test_reclaim_expired_lease(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("r", "/t", "code_static", "pin", {})
    tid = db.enqueue_task("hunt", {})
    task = db.lease_next_task("w", ttl_seconds=1)
    assert task is not None
    # force expiry
    db.conn.execute(
        "UPDATE tasks SET lease_until=? WHERE id=?",
        ("2000-01-01T00:00:00Z", task.id),
    )
    db.conn.commit()
    n = db.reclaim_expired_leases()
    assert n == 1
    again = db.lease_next_task("w2", ttl_seconds=60)
    assert again is not None
    assert again.id == tid
    db.close()


def test_stable_key_path_separators():
    body_a = {
        "weakness_class": "injection",
        "threat_model": {"attacker": "unauth"},
        "citations": [{"path": r"src\app.py", "symbol": "search"}],
    }
    body_b = {
        "weakness_class": "injection",
        "threat_model": {"attacker": "unauth"},
        "citations": [{"path": "src/app.py", "symbol": "search"}],
    }
    assert compute_stable_key("code_static", body_a) == compute_stable_key(
        "code_static", body_b
    )


def test_finding_upsert_by_stable_key(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    body = {
        "title": "x",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "app.py"}],
    }
    id1 = db.insert_finding(body, state="candidate")
    id2 = db.insert_finding({**body, "title": "y"}, state="candidate")
    assert id1 == id2
    f = db.get_finding(id1)
    assert f is not None
    assert f.body["title"] == "y"
    db.close()


def test_coverage_matrix_includes_hunt_task_classes(tmp_path: Path):
    """Matrix columns must include domain packs used in hunts, not only facts/core."""
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("r", "/t", "code_static", "pin", {})
    # Only a core class has a fact row
    db.upsert_coverage_fact(
        "app", "injection", path="a.py", visit_delta=1, last_depth="shallow"
    )
    # Domain packs only present as hunt tasks (no fact yet)
    db.enqueue_task("hunt", {"area": "app", "class": "ai-llm", "path_hints": ["b.py"]})
    db.enqueue_task("hunt", {"area": "worker", "class": "feature-abuse"})
    m = db.coverage_matrix()
    assert "injection" in m["classes"]
    assert "ai-llm" in m["classes"]
    assert "feature-abuse" in m["classes"]
    assert "worker" in m["areas"]
    # Core catalog order before domain packs
    assert m["classes"].index("injection") < m["classes"].index("ai-llm")
    cell_keys = {(c["area"], c["class"]) for c in m["cells"]}
    assert ("app", "ai-llm") in cell_keys
    assert ("worker", "feature-abuse") in cell_keys
    db.close()


def test_run_lock_exclusive(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    with RunLock(run):
        with pytest.raises(RuntimeError, match="locked"):
            RunLock(run).acquire()
    # after release, acquire works
    with RunLock(run):
        pass


def test_requeue_and_deadletter(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("r", "/t", "code_static", "pin", {})
    tid = db.enqueue_task("hunt", {})
    task = db.lease_next_task("w", ttl_seconds=60)
    assert task is not None
    assert task.attempt == 1
    db.requeue_task(tid, error="connection refused")
    t = db.get_task(tid)
    assert t is not None
    assert t.state == "queued"
    assert t.result and t.result.get("error") == "connection refused"
    task2 = db.lease_next_task("w", ttl_seconds=60)
    assert task2 is not None
    assert task2.attempt == 2
    db.deadletter_task(tid, "connection refused")
    t2 = db.get_task(tid)
    assert t2 is not None
    assert t2.state == "deadletter"
    counts = db.count_tasks_by_state()
    assert counts.get("deadletter") == 1
    db.close()
