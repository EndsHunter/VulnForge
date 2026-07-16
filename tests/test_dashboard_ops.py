"""Dashboard operator actions: coverage requeue, cell detail, mode, selection hunt."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.db import Database
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest, utc_now_iso


def _init_run(tmp_path: Path, toy_sqli: Path) -> Path:
    run = tmp_path / "runs" / "t" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run(
        "run-001",
        str(toy_sqli),
        "code_static",
        "pin",
        {"run": {"max_tasks": 50}},
    )
    db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "injection",
            "path_hints": ["app.py"],
        },
        priority=50,
    )
    db.upsert_coverage_fact("app", "injection", path="app.py", visit_delta=1, last_depth="shallow")
    # mark task complete with shallow none-ish result
    t = db.list_tasks()[0]
    db.conn.execute(
        "UPDATE tasks SET state='succeeded', result_json=? WHERE id=?",
        (
            json.dumps(
                {
                    "status": "succeeded",
                    "none_found": True,
                    "shallow": True,
                    "reason": "no solid issue",
                }
            ),
            t.id,
        ),
    )
    db.conn.commit()
    db.set_architecture(
        {
            "summary": "toy app",
            "components": [{"name": "app", "path_hints": ["app.py"]}],
            "hunt_focus": [],
            "inventory": {"file_count": 3, "entrypoints": ["app.py"]},
        }
    )
    db.close()
    return run


def test_cell_detail_reasons(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    detail = dashops.cell_detail(run, "app", "injection")
    assert detail["area"] == "app"
    assert detail["class"] == "injection"
    assert detail["last_depth"] == "shallow"
    assert detail["visit_count"] >= 1
    assert "shallow" in detail["depth_blurb"].lower()
    assert any("shallow" in r.lower() or "none" in r.lower() for r in detail["reasons"])
    assert detail["can_requeue"] is True


def test_requeue_hunt(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.requeue_hunt(
        run, area="app", attack_class="injection", force_depth=True
    )
    assert r["ok"] is True
    assert r["task_id"] > 0
    db = Database.open(run / "harness.db")
    try:
        tasks = [t for t in db.list_tasks() if t.kind == "hunt"]
        assert any(t.state == "queued" and t.payload.get("operator_requested") for t in tasks)
    finally:
        db.close()


def test_coverage_mode_select_path_targets(tmp_path: Path, toy_sqli: Path):
    """Custom select with a file/folder path target seeds path_hints."""
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.apply_coverage_mode(
        run,
        mode="select",
        areas=[],
        classes=["injection"],
        path_targets=[{"path": "app.py", "is_dir": False}],
        enqueue=True,
    )
    assert r["ok"] is True
    assert r["enqueued_count"] >= 1
    assert any(t.get("path") == "app.py" for t in (r.get("path_targets") or []))
    db = Database.open(run / "harness.db")
    try:
        hunts = [
            t
            for t in db.list_tasks()
            if t.kind == "hunt" and t.state == "queued" and t.payload.get("area") == "app.py"
        ]
        assert hunts
        assert "app.py" in (hunts[0].payload.get("path_hints") or [])
        assert hunts[0].payload.get("class") == "injection"
    finally:
        db.close()


def test_coverage_select_path_like_areas_and_generated_skill(
    tmp_path: Path, toy_sqli: Path
):
    """Custom select: path-like areas become path targets; generated skills are queueable."""
    from vulnforge.hunt_profiles import (
        reset_collection_root_override,
        save_profile,
        set_collection_root,
    )

    coll = tmp_path / "hunt_coll"
    set_collection_root(coll)
    try:
        save_profile(
            "gen-foo",
            body_md="# Generated\n\nLook for foo.\n",
            title="Generated",
            active=False,
            source="generated",
            create=True,
        )
        run = _init_run(tmp_path, toy_sqli)
        r = dashops.apply_coverage_mode(
            run,
            mode="select",
            areas=["app.py", "worker"],  # file path + abstract name
            classes=["gen-foo"],
            enqueue=True,
        )
        assert r["ok"] is True
        assert r["enqueued_count"] >= 1
        paths = {t.get("path") for t in (r.get("path_targets") or [])}
        assert "app.py" in paths
        db = Database.open(run / "harness.db")
        try:
            hunts = [
                t
                for t in db.list_tasks()
                if t.kind == "hunt"
                and t.state == "queued"
                and t.payload.get("class") == "gen-foo"
            ]
            assert hunts, "generated skill should enqueue under select"
            areas = {t.payload.get("area") for t in hunts}
            assert "app.py" in areas or "worker" in areas
        finally:
            db.close()
    finally:
        reset_collection_root_override()


def test_coverage_mode_all_enqueues(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.apply_coverage_mode(run, mode="all", enqueue=True)
    assert r["ok"] is True
    assert r["enqueued_count"] >= 1
    assert r["policy"]["mode"] == "all"
    db = Database.open(run / "harness.db")
    try:
        cfg = dashops.get_run_config(db)
        assert cfg.get("coverage_policy", {}).get("mode") == "all"
        queued = [t for t in db.list_tasks() if t.state == "queued"]
        assert len(queued) >= 1
    finally:
        db.close()


def test_coverage_mode_auto_no_enqueue(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    before = Database.open(run / "harness.db")
    try:
        n0 = len(before.list_tasks())
    finally:
        before.close()
    r = dashops.apply_coverage_mode(run, mode="auto", enqueue=True)
    assert r["ok"] is True
    assert r["enqueued_count"] == 0
    after = Database.open(run / "harness.db")
    try:
        assert len(after.list_tasks()) == n0
    finally:
        after.close()


def test_target_list_and_read(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    listing = dashops.target_list(run, path=".")
    assert listing["ok"] is True
    names = {e["name"] for e in listing["entries"]}
    assert "app.py" in names
    read = dashops.target_read(run, "app.py", start_line=1, end_line=5)
    assert read["ok"] is True
    assert "content" in read
    assert len(read["content"]) > 0


def test_target_path_escape_blocked(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.target_read(run, "../secrets")
    assert r.get("ok") is False


def test_hunt_from_selection(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.hunt_from_selection(
        run,
        path="app.py",
        start_line=1,
        end_line=10,
        attack_class="injection",
        note="look here",
    )
    assert r["ok"] is True
    assert r["payload"]["selection"]["path"] == "app.py"
    assert r["payload"]["force_depth"] is True
    db = Database.open(run / "harness.db")
    try:
        t = db.get_task(r["task_id"])
        assert t is not None
        assert t.state == "queued"
        assert t.payload.get("path_hints") == ["app.py"]
    finally:
        db.close()


def test_hunt_from_selection_all_registered_classes(tmp_path: Path, toy_sqli: Path):
    """Operator selection must accept every registered class (not only active)."""
    from vulnforge.hunt_profiles import all_class_ids

    run = _init_run(tmp_path, toy_sqli)
    for cls in all_class_ids():
        r = dashops.hunt_from_selection(
            run,
            path="app.py",
            attack_class=cls,
            note=f"class {cls}",
        )
        assert r["ok"] is True, (cls, r)
        assert r["payload"]["class"] == cls


def test_architecture_summary():
    s = dashops.architecture_summary(
        {
            "summary": "hello",
            "components": [{"name": "api", "path_hints": ["a.py"]}],
            "input_surfaces": ["http"],
            "trust_boundaries": ["edge"],
        }
    )
    assert s["has_architecture"] is True
    assert s["summary"] == "hello"
    assert s["components"][0]["name"] == "api"


def test_depth_reason_text():
    assert "shallow" in dashops.depth_reason_text("shallow").lower()
    assert "abort" in dashops.depth_reason_text("aborted").lower()


def test_cancel_queued_task(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    db = Database.open(run / "harness.db")
    try:
        tid = db.enqueue_task("hunt", {"area": "app", "class": "injection"}, priority=50)
        leased_id = db.enqueue_task(
            "hunt", {"area": "other", "class": "injection"}, priority=40
        )
        leased = db.lease_next_task("w1", ttl_seconds=60)
        assert leased is not None
        assert leased.id == leased_id
    finally:
        db.close()

    r = dashops.cancel_queued_task(run, tid, reason="ui_remove")
    assert r["ok"] is True
    assert r["state"] == "cancelled"
    assert r["task_id"] == tid

    db = Database.open(run / "harness.db")
    try:
        t = db.get_task(tid)
        assert t is not None
        assert t.state == "cancelled"
        assert t.result and t.result.get("operator_cancelled") is True
        # Cancelled must not be leasable
        nxt = db.lease_next_task("w2", ttl_seconds=60)
        assert nxt is None  # only leased remains; queue empty of queued
        assert db.has_queued_or_leased() is True  # leased still counts
    finally:
        db.close()

    # cannot cancel leased / missing
    bad = dashops.cancel_queued_task(run, leased_id)
    assert bad["ok"] is False
    assert "queued" in bad["error"]
    missing = dashops.cancel_queued_task(run, 999999)
    assert missing["ok"] is False
    assert "not found" in missing["error"]


def test_set_task_priority_tier(tmp_path: Path, toy_sqli: Path):
    run = tmp_path / "runs" / "prio" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    a = db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=50)
    b = db.enqueue_task("hunt", {"area": "b", "class": "injection"}, priority=50)
    c = db.enqueue_task("hunt", {"area": "c", "class": "injection"}, priority=50)
    # Complete one so only queued can be reordered
    db.complete_task(c, {"ok": True}, state="succeeded")
    db.close()

    r = dashops.set_task_priority_tier(run, b, "run_next")
    assert r["ok"] is True
    assert r["priority"] < 50
    assert r["tier"] == "run_next"

    db = Database.open(run / "harness.db")
    try:
        first = db.lease_next_task("w1", ttl_seconds=60)
        assert first is not None
        assert first.id == b  # run_next jumps ahead of a
        db.complete_task(first.id, {"ok": True})
        second = db.lease_next_task("w1", ttl_seconds=60)
        assert second is not None
        assert second.id == a
    finally:
        db.close()

    # high / normal / low fixed bands
    run2 = tmp_path / "runs" / "prio2" / "run-001"
    run2.mkdir(parents=True)
    (run2 / "evidence").mkdir()
    db = Database.create(run2 / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    tid = db.enqueue_task("hunt", {"area": "x", "class": "wildcard"}, priority=50)
    db.close()
    assert dashops.set_task_priority_tier(run2, tid, "high")["priority"] == 30
    assert dashops.set_task_priority_tier(run2, tid, "normal")["priority"] == 50
    assert dashops.set_task_priority_tier(run2, tid, "low")["priority"] == 90

    # reject non-queued
    db = Database.open(run2 / "harness.db")
    db.complete_task(tid, {"ok": True})
    db.close()
    bad = dashops.set_task_priority_tier(run2, tid, "high")
    assert bad["ok"] is False
    assert "queued" in bad["error"]


def test_requeue_recon_with_notes(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.requeue_recon(
        run,
        operator_notes="Deepen auth map and SQL sinks",
        focus_paths=["app.py"],
        include_prior_architecture=True,
        enqueue_hunts=True,
    )
    assert r["ok"] is True
    assert r["task_id"] > 0
    assert r["payload"]["operator_requested"] is True
    assert "Deepen auth" in r["payload"]["operator_notes"]
    assert r["payload"]["focus_paths"] == ["app.py"]
    assert r["payload"]["include_prior_architecture"] is True
    assert r["payload"]["enqueue_hunts"] is True
    db = Database.open(run / "harness.db")
    try:
        t = db.get_task(r["task_id"])
        assert t is not None
        assert t.kind == "recon"
        assert t.state == "queued"
        assert t.priority <= 10
    finally:
        db.close()


def test_requeue_recon_arch_only(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.requeue_recon(run, enqueue_hunts=False, operator_notes="fix summary")
    assert r["ok"] is True
    assert r["payload"]["enqueue_hunts"] is False


def test_requeue_hunt_with_operator_notes(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.requeue_hunt(
        run,
        area="app",
        attack_class="injection",
        operator_notes="Check raw SQL in handlers",
    )
    assert r["ok"] is True
    assert r["payload"]["operator_notes"] == "Check raw SQL in handlers"


def test_pack_recon_includes_operator_brief():
    from vulnforge.packet import pack_recon
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "prompts" / "v1"
    pkt = pack_recon(
        {"llm": {"context_tokens": 32768, "max_context_fraction": 0.25}},
        root,
        {"file_count": 3, "extensions": {".py": 1}, "entrypoints": ["app.py"], "sample_paths": ["app.py"]},
        architecture_so_far='{"summary":"old"}',
        operator_brief="Focus on auth",
        focus_paths=["app.py"],
    )
    assert "Operator brief" in pkt.user
    assert "Focus on auth" in pkt.user
    assert "Prior architecture" in pkt.user
    assert "app.py" in pkt.user
