"""Coverage generate-skill enqueue (no live LLM)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.db import Database
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest


def _init_run(tmp_path: Path, target: Path) -> Path:
    run = tmp_path / "runs" / "t" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    # minimal manifest for tools that expect it
    try:
        build_target_manifest(target, run / "target_manifest.json")
    except Exception:
        pass
    db = Database.create(run / "harness.db")
    db.insert_run(
        "run-001",
        str(target),
        "code_static",
        "pin",
        {"run": {"max_tasks": 50}},
    )
    db.set_architecture(
        {
            "summary": "toy",
            "components": [{"name": "app", "path_hints": ["app.py"]}],
            "hunt_focus": [],
        }
    )
    db.close()
    return run


def test_coverage_generate_skill_enqueues_task(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.coverage_generate_skill(
        run,
        brief="Hunt for SQLi in app.py",
        suggested_id="toy-sqli-skill",
        activate=False,
        enqueue_hunts=True,
        areas=["app"],
        path_targets=[{"path": "app.py", "is_dir": False}],
    )
    assert r["ok"] is True
    assert r["task_id"]
    db = Database.open(run / "harness.db")
    try:
        tasks = [t for t in db.list_tasks() if t.kind == "generate_skill"]
        assert len(tasks) == 1
        pl = tasks[0].payload
        assert pl.get("brief")
        assert pl.get("enqueue_hunts") is True
        assert pl.get("activate") is False
        assert "app.py" in (pl.get("path_hints") or [])
        assert pl.get("suggested_id") == "toy-sqli-skill"
    finally:
        db.close()


def test_coverage_generate_skill_requires_brief(tmp_path: Path, toy_sqli: Path):
    run = _init_run(tmp_path, toy_sqli)
    r = dashops.coverage_generate_skill(run, brief="  ")
    assert r["ok"] is False


def test_generate_skill_multi_path_hunts(tmp_path: Path, toy_sqli: Path):
    """Stage enqueue: multiple path_hints ??? multiple hunts with override."""
    from vulnforge.stages import generate_skill as gen_stage

    run = _init_run(tmp_path, toy_sqli)
    db = Database.open(run / "harness.db")
    try:
        tid = db.enqueue_task(
            "generate_skill",
            {
                "brief": "test",
                "enqueue_hunts": True,
                "activate": False,
                "area": "app",
                "path_hints": ["app.py", "other.py"],
                "reason": "test_multi",
            },
        )
        task = db.get_task(tid)

        # Fake generate path: monkeypatch skill creation by calling hunt fan-out
        # through a minimal stub of generate_hunt_skill + save
        class T:
            id = tid
            payload = task.payload

        skill = {
            "id": "multi-path-skill",
            "title": "Multi",
            "description": "d",
            "body_md": "# Mission\n\n## Method\n\n## Anti-patterns\n\n## Submit\n\n| a | b |\n|---|---|\n| x | y |\n",
            "tags": [],
            "cwe": [],
            "angle_ids": [],
            "sink_families": [],
            "model_id": "fake",
        }

        import vulnforge.stages.generate_skill as gs

        orig_gen = gs.generate_hunt_skill
        orig_save = gs.save_generated_profile

        def fake_gen(*a, **k):
            return dict(skill)

        def fake_save(sk, **k):
            return {
                "id": sk["id"],
                "title": sk.get("title"),
                "active": False,
                "source": "generated",
            }

        gs.generate_hunt_skill = fake_gen  # type: ignore
        gs.save_generated_profile = fake_save  # type: ignore
        try:
            result = gen_stage.run(T(), db, run, {"run": {"max_tasks": 50}})
        finally:
            gs.generate_hunt_skill = orig_gen  # type: ignore
            gs.save_generated_profile = orig_save  # type: ignore

        assert result.get("status") == "succeeded", result
        assert result.get("hunt_enqueued") == 2
        hunts = [t for t in db.list_tasks() if t.kind == "hunt"]
        assert len(hunts) == 2
        for h in hunts:
            assert h.payload.get("class") == "multi-path-skill"
            assert h.payload.get("class_body_override")
            assert h.payload.get("path_hints")
    finally:
        db.close()
