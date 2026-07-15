from __future__ import annotations

from pathlib import Path

from vulnforge.util import (
    build_target_manifest,
    hash_file,
    hash_prompt_bundle,
    normalize_relpath,
    next_run_id,
    target_id_from_path,
    append_event,
)


def test_normalize_relpath_windows_and_posix():
    assert normalize_relpath(r"src\app.py") == "src/app.py"
    assert normalize_relpath("./src/app.py") == "src/app.py"
    assert normalize_relpath("/src/app.py") == "src/app.py"


def test_target_id_stable(tmp_path: Path):
    d = tmp_path / "My App"
    d.mkdir()
    a = target_id_from_path(d)
    b = target_id_from_path(d)
    assert a == b
    assert "My" in a or "App" in a or a.startswith("My")


def test_next_run_id(tmp_path: Path):
    root = tmp_path / "runs"
    tid = "t1"
    assert next_run_id(root, tid) == "run-001"
    (root / tid / "run-001").mkdir(parents=True)
    (root / tid / "run-002").mkdir(parents=True)
    assert next_run_id(root, tid) == "run-003"


def test_manifest_and_hash(toy_sqli: Path, tmp_path: Path):
    man = build_target_manifest(toy_sqli, ignore_globs=[".git/**"])
    assert man["file_count"] >= 1
    assert "app.py" in man["files"] or any("app.py" in k for k in man["files"])
    # hash_file works
    app = toy_sqli / "app.py"
    assert len(hash_file(app)) == 64


def test_hash_prompt_bundle(prompts_v1: Path):
    h1 = hash_prompt_bundle(prompts_v1)
    h2 = hash_prompt_bundle(prompts_v1)
    assert h1 == h2
    assert len(h1) == 64


def test_append_event(tmp_path: Path):
    run = tmp_path / "run"
    append_event(run, {"event": "test", "n": 1})
    lines = (run / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert "test" in lines[0]
