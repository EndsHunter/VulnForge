"""Delete run: store helper + CLI --yes safety."""

from __future__ import annotations

from pathlib import Path

from vulnforge.cli import EXIT_CONFIG, EXIT_PROGRESS, cmd_delete_run, main
from vulnforge.db import Database
from vulnforge.ui import store as run_store
from vulnforge.util import build_target_manifest, write_json


def _make_run(tmp_path: Path, toy_sqli: Path, name: str = "run-001") -> Path:
    runs = tmp_path / "runs"
    run = runs / "toy" / name
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    (run / "evidence" / "e1").mkdir()
    (run / "evidence" / "e1" / "n.txt").write_text("x")
    man = build_target_manifest(toy_sqli, [])
    write_json(run / "target_manifest.json", man)
    db = Database.create(run / "harness.db")
    db.insert_run(name, str(toy_sqli), "code_static", "pin", {})
    db.close()
    return run


def test_delete_run_removes_dir_and_empty_parent(tmp_path: Path, toy_sqli: Path):
    run = _make_run(tmp_path, toy_sqli)
    runs_root = tmp_path / "runs"
    assert run.is_dir()
    r = run_store.delete_run(runs_root, "toy", "run-001", force=True)
    assert r["ok"] is True
    assert not run.exists()
    assert r.get("removed_parent") is True
    assert not (runs_root / "toy").exists()


def test_delete_run_keeps_sibling(tmp_path: Path, toy_sqli: Path):
    a = _make_run(tmp_path, toy_sqli, "run-001")
    b = _make_run(tmp_path, toy_sqli, "run-002")
    runs_root = tmp_path / "runs"
    r = run_store.delete_run(runs_root, "toy", "run-001", force=True)
    assert r["ok"] is True
    assert not a.exists()
    assert b.exists()
    assert r.get("removed_parent") is False


def test_delete_run_path_escape(tmp_path: Path):
    r = run_store.delete_run(tmp_path / "runs", "..", "x", force=True)
    assert r["ok"] is False
    assert "invalid" in (r.get("error") or "")


def test_cli_delete_requires_yes(tmp_path: Path, toy_sqli: Path):
    run = _make_run(tmp_path, toy_sqli)
    from types import SimpleNamespace

    args = SimpleNamespace(run_dir=run, yes=False, force=False)
    cfg = {"run": {"runs_root": str(tmp_path / "runs")}}
    # resolve_runs_root uses PROJECT_ROOT-relative unless absolute â€” pass absolute
    code = cmd_delete_run(args, cfg)
    assert code == EXIT_CONFIG
    assert run.exists()


def test_cli_delete_with_yes(tmp_path: Path, toy_sqli: Path):
    run = _make_run(tmp_path, toy_sqli)
    from types import SimpleNamespace

    runs_root = (tmp_path / "runs").resolve()
    args = SimpleNamespace(run_dir=run, yes=True, force=False)
    cfg = {"run": {"runs_root": str(runs_root)}}
    code = cmd_delete_run(args, cfg)
    assert code == EXIT_PROGRESS
    assert not run.exists()
