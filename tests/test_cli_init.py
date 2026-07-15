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
