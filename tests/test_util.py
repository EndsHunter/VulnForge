from __future__ import annotations

from pathlib import Path

from vulnforge.util import (
    build_target_manifest,
    hash_file,
    hash_prompt_bundle,
    match_manifest_fingerprint,
    meta_fingerprint,
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


def test_match_manifest_fingerprint_sha_and_meta(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text("hello", encoding="utf-8")
    sha = hash_file(f)
    meta = meta_fingerprint(f)
    assert match_manifest_fingerprint(f, sha)
    assert match_manifest_fingerprint(f, meta)
    assert not match_manifest_fingerprint(f, "meta:0:0")
    assert not match_manifest_fingerprint(f, "0" * 64)


def test_hash_prompt_bundle(prompts_v1: Path):
    h1 = hash_prompt_bundle(prompts_v1)
    h2 = hash_prompt_bundle(prompts_v1)
    assert h1 == h2
    assert len(h1) == 64


def test_hash_cap_fingerprints_remaining_and_still_matches_sha(tmp_path: Path):
    root = tmp_path / "tree"
    root.mkdir()
    for i in range(2001):
        (root / f"f{i:04d}.txt").write_bytes(b"x")
    events: list[dict] = []
    man = build_target_manifest(
        root,
        max_hash_files=2000,
        max_list_files=12000,
        progress=events.append,
    )
    assert man["hashed_files"] == 2000
    assert man["fingerprinted_files"] == 1
    assert man["file_count"] == 2001
    assert man["incomplete"] is True
    assert man["listing_capped"] is False
    assert any(
        isinstance(p.get("hashed"), int)
        and isinstance(p.get("fingerprinted"), int)
        and "hashed 2000" in str(p.get("message", ""))
        and "fingerprinted" in str(p.get("message", ""))
        for p in events
    )
    sha_rel = next(
        rel
        for rel, digest in man["files"].items()
        if not str(digest).startswith("meta:")
    )
    path = root / sha_rel
    assert match_manifest_fingerprint(path, man["files"][sha_rel]) is True
    path.write_bytes(b"y")
    assert match_manifest_fingerprint(path, man["files"][sha_rel]) is False


def test_small_tree_default_cap_is_fully_hashed(tmp_path: Path):
    root = tmp_path / "small"
    root.mkdir()
    for i in range(3):
        (root / f"a{i}.txt").write_bytes(b"z")
    man = build_target_manifest(root)
    assert man["file_count"] == 3
    assert man["fingerprinted_files"] == 0
    assert man["incomplete"] is False


def test_single_file_manifest_has_no_hash_cap_wording(tmp_path: Path):
    target = tmp_path / "only.txt"
    target.write_bytes(b"a")
    events: list[dict] = []
    man = build_target_manifest(target, progress=events.append)
    assert man["fingerprinted_files"] == 0
    assert man["hashed_files"] == 1
    assert all("2000" not in str(p.get("message", "")) for p in events)
    assert all(
        isinstance(p.get("hashed"), int) and isinstance(p.get("fingerprinted"), int)
        for p in events
    )


def test_append_event(tmp_path: Path):
    run = tmp_path / "run"
    append_event(run, {"event": "test", "n": 1})
    lines = (run / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert "test" in lines[0]
