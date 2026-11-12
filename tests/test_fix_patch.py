"""fix_patch: parse / check / materialize / git export / cited diffs (offline)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from vulnforge.fix_patch import (
    PatchError,
    check_patch,
    cited_region_diff,
    export_git_tree,
    materialize_patched_tree,
    new_scratch_dir,
    parse_patch,
    remove_scratch_dir,
    resolve_git_commit,
    safe_relpath,
    validate_git_rev,
)

SQLI_FIX = """\
--- a/app.py
+++ b/app.py
@@ -9,4 +9,4 @@
 def search_users(db_cursor, q: str):
     # INTENTIONALLY VULNERABLE — fixture only
-    sql = f"SELECT * FROM users WHERE name = '{q}'"
-    return db_cursor.execute(sql)
+    sql = "SELECT * FROM users WHERE name = ?"
+    return db_cursor.execute(sql, (q,))
"""


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.is_symlink()
    }


def test_check_patch_applies_and_never_writes(toy_sqli: Path):
    before = _snapshot(toy_sqli)
    r = check_patch(toy_sqli, SQLI_FIX)
    assert r["parse_ok"] and r["applies"], r
    assert r["files"][0]["path"] == "app.py"
    assert r["files"][0]["added"] == 2 and r["files"][0]["removed"] == 2
    assert _snapshot(toy_sqli) == before


def test_offset_hunk_applies_when_unique(toy_sqli: Path):
    shifted = SQLI_FIX.replace("@@ -9,4 +9,4 @@", "@@ -3,4 +3,4 @@")
    r = check_patch(toy_sqli, shifted)
    assert r["applies"], r
    assert r["files"][0]["offsets"] == [6]


def test_context_mismatch_does_not_apply(toy_sqli: Path):
    bad = SQLI_FIX.replace("INTENTIONALLY VULNERABLE", "SOMETHING ELSE")
    r = check_patch(toy_sqli, bad)
    assert r["parse_ok"] and not r["applies"]
    assert any("context_mismatch" in e for e in r["errors"])


def test_ambiguous_context_refused(tmp_path: Path):
    (tmp_path / "f.py").write_text("x = 1\ny = 2\nx = 1\ny = 2\n", encoding="utf-8")
    patch = "--- a/f.py\n+++ b/f.py\n@@ -40,2 +40,2 @@\n x = 1\n-y = 2\n+y = 3\n"
    r = check_patch(tmp_path, patch)
    assert not r["applies"]
    assert any("ambiguous_context" in e for e in r["errors"])


@pytest.mark.parametrize(
    "path",
    ["../etc/passwd", "/etc/passwd", "a\\b.py", ".git/config", "x/../../y", "C:/win.ini"],
)
def test_unsafe_paths_refused(path: str):
    with pytest.raises(PatchError):
        safe_relpath(path)
    patch = f"--- {path}\n+++ {path}\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(PatchError):
        parse_patch(patch)


@pytest.mark.parametrize(
    "text,err",
    [
        ("diff --git a/x b/y\nrename from x\nrename to y\n", "rename_refused"),
        ("diff --git a/x b/x\nGIT binary patch\nliteral 3\n", "binary_patch_refused"),
        ("Binary files a/x and b/x differ\n", "binary_patch_refused"),
        ("--- a/x\n+++ b/y\n@@ -1 +1 @@\n-a\n+b\n", "rename_refused"),
        ("just prose, no diff\n", "no_file_headers"),
        ("", "empty_patch"),
        ("--- a/x\n+++ b/x\n@@ -1,3 +1,3 @@\n-a\n+b\n", "hunk_count_mismatch"),
    ],
)
def test_refused_patch_shapes(text: str, err: str):
    with pytest.raises(PatchError) as ei:
        parse_patch(text)
    assert err in str(ei.value)


def test_add_and_delete_files(tmp_path: Path):
    (tmp_path / "old.txt").write_text("bye\n", encoding="utf-8")
    patch = (
        "--- /dev/null\n+++ b/new/helper.py\n@@ -0,0 +1,2 @@\n+def ok():\n+    return 1\n"
        "--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye\n"
    )
    r = check_patch(tmp_path, patch)
    assert r["applies"], r
    dest = tmp_path.parent / "out_tree"
    materialize_patched_tree(tmp_path, patch, dest)
    assert (dest / "new" / "helper.py").read_text() == "def ok():\n    return 1\n"
    assert not (dest / "old.txt").exists()
    assert (tmp_path / "old.txt").is_file()  # source untouched


def test_no_newline_at_eof_round_trip(tmp_path: Path):
    (tmp_path / "f.txt").write_bytes(b"a\nb")
    patch = "--- a/f.txt\n+++ b/f.txt\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
    dest = tmp_path.parent / "nl_tree"
    materialize_patched_tree(tmp_path, patch, dest)
    assert (dest / "f.txt").read_bytes() == b"a\nc"


def test_symlink_component_refused_on_read(tmp_path: Path):
    src = tmp_path / "src"
    outside = tmp_path / "outside"
    src.mkdir()
    outside.mkdir()
    (outside / "victim.py").write_text("secret = 1\n", encoding="utf-8")
    os.symlink(outside, src / "link")
    patch = "--- a/link/victim.py\n+++ b/link/victim.py\n@@ -1 +1 @@\n-secret = 1\n+secret = 2\n"
    r = check_patch(src, patch)
    assert not r["applies"]
    assert any("symlink_in_path" in e for e in r["errors"])
    with pytest.raises(PatchError):
        materialize_patched_tree(src, patch, tmp_path / "dest")
    assert (outside / "victim.py").read_text() == "secret = 1\n"


def test_symlinked_add_target_refused(tmp_path: Path):
    src = tmp_path / "src"
    outside = tmp_path / "outside"
    src.mkdir()
    outside.mkdir()
    os.symlink(outside, src / "link")
    patch = "--- /dev/null\n+++ b/link/new.py\n@@ -0,0 +1 @@\n+pwn = 1\n"
    with pytest.raises(PatchError):
        materialize_patched_tree(src, patch, tmp_path / "dest")
    assert not (outside / "new.py").exists()


def test_materialize_skips_symlinks_and_git(tmp_path: Path, toy_sqli: Path):
    (toy_sqli / ".git").mkdir()
    (toy_sqli / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    os.symlink("/etc/passwd", toy_sqli / "passwd_link")
    dest = tmp_path / "tree"
    info = materialize_patched_tree(toy_sqli, SQLI_FIX, dest)
    assert info["copy"]["skipped_symlinks"] == 1
    assert not (dest / ".git").exists()
    assert not (dest / "passwd_link").exists()
    assert "execute(sql, (q,))" in (dest / "app.py").read_text()
    assert "{q}" in (toy_sqli / "app.py").read_text()


def test_scratch_removal_is_confined(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d = new_scratch_dir(run_dir, 7)
    (d / "tree").mkdir()
    other = tmp_path / "keep_me"
    other.mkdir()
    assert remove_scratch_dir(run_dir, other) is False
    assert other.is_dir()
    assert remove_scratch_dir(run_dir, run_dir / "scratch" / "verify_fix") is False
    assert remove_scratch_dir(run_dir, d) is True
    assert not d.exists()


def test_cited_region_diff(tmp_path: Path, toy_sqli: Path):
    dest = tmp_path / "tree"
    materialize_patched_tree(toy_sqli, SQLI_FIX, dest)
    cites = [{"path": "app.py", "start_line": 11}]
    d = cited_region_diff(toy_sqli, dest, cites)
    assert d["any_region_changed"] is True
    assert d["cited_code_unchanged"] is False
    assert "+    sql = \"SELECT" in d["files"][0]["diff"]
    # A citation far from the change: file changed, region not.
    far = cited_region_diff(toy_sqli, dest, [{"path": "app.py", "start_line": 1, "end_line": 2}])
    assert far["any_file_changed"] is True and far["any_region_changed"] is False
    same = cited_region_diff(toy_sqli, toy_sqli, cites)
    assert same["cited_code_unchanged"] is True


@pytest.mark.parametrize("rev", ["-c", "--output=/tmp/x", "a..b", "a b", "", "x;rm"])
def test_bad_git_revs_refused(rev: str):
    with pytest.raises(PatchError):
        validate_git_rev(rev)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_export_git_tree_raw_blobs_no_filters(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}

    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, env=env, capture_output=True)

    git("init", "-q")
    (repo / "sub").mkdir()
    (repo / "sub" / "app.py").write_text("v = 1\n", encoding="utf-8")
    (repo / "top.txt").write_text("top\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "one")
    (repo / "sub" / "app.py").write_text("v = 2\n", encoding="utf-8")
    git("commit", "-q", "-am", "two")
    # A hostile smudge filter must never run during export.
    marker = tmp_path / "filter_ran"
    git("config", "filter.evil.smudge", f"touch {marker}; cat")
    (repo / ".gitattributes").write_text("*.py filter=evil\n", encoding="utf-8")
    before = _snapshot(repo)

    sha1 = resolve_git_commit(repo, "HEAD~1")
    out = tmp_path / "out"
    info = export_git_tree(repo, "HEAD~1", out, subdir="sub")
    assert info["commit"] == sha1
    assert (out / "app.py").read_text() == "v = 1\n"
    assert not (out / "top.txt").exists()
    assert not marker.exists()
    assert _snapshot(repo) == before
    with pytest.raises(PatchError):
        export_git_tree(repo, "no-such-rev", tmp_path / "out2")
