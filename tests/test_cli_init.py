from __future__ import annotations

from pathlib import Path

from vulnforge.cli import EXIT_PROGRESS, main
from vulnforge.db import Database


def test_init_toy_sqli(toy_sqli: Path, tmp_path: Path):
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
        ]
    )
    assert code == EXIT_PROGRESS
    targets = list(runs.iterdir())
    assert len(targets) == 1
    runs_list = list(targets[0].iterdir())
    assert len(runs_list) == 1
    run_dir = runs_list[0]
    assert (run_dir / "harness.db").is_file()
    assert (run_dir / "target_manifest.json").is_file()
    db = Database.open(run_dir / "harness.db")
    s = db.summary()
    assert s["tasks"].get("queued") == 1
    db.close()


def test_init_missing_target(tmp_path: Path):
    code = main(["init", "--target", str(tmp_path / "nope")])
    assert code == 30


def test_init_no_enqueue_hunts_stores_flag(toy_sqli: Path, tmp_path: Path):
    """Architecture-only / manual: recon queued, enqueue_hunts=false on payload + config."""
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
            "--no-enqueue-hunts",
        ]
    )
    assert code == EXIT_PROGRESS
    run_dir = next(next(runs.iterdir()).iterdir())
    db = Database.open(run_dir / "harness.db")
    try:
        cfg = db.get_run()
        assert cfg is not None
        import json

        config = json.loads(cfg["config_json"] or "{}")
        assert config.get("run", {}).get("enqueue_hunts") is False
        tasks = db.list_tasks(limit=20)
        recon = [t for t in tasks if t.kind == "recon"]
        hunts = [t for t in tasks if t.kind == "hunt"]
        assert recon, "expected recon task"
        assert not hunts, "should not pre-enqueue hunts"
        for t in recon:
            assert t.payload.get("enqueue_hunts") is False
    finally:
        db.close()


def test_init_file_by_file_no_enqueue_hunts(toy_sqli: Path, tmp_path: Path):
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
            "--strategy",
            "file_by_file",
            "--no-enqueue-hunts",
        ]
    )
    assert code == EXIT_PROGRESS
    run_dir = next(next(runs.iterdir()).iterdir())
    db = Database.open(run_dir / "harness.db")
    try:
        tasks = db.list_tasks(limit=50)
        assert not any(t.kind == "hunt" for t in tasks)
        assert not any(t.kind == "recon" for t in tasks)
    finally:
        db.close()
