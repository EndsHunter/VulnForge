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


# --------------------------------------------------------------------------- review regressions


def test_modes_preserved_in_scratch_copy(tmp_path: Path):
    src = tmp_path / "src"
    (src / "open_dir").mkdir(parents=True)
    (src / "ro_dir").mkdir()
    (src / "config.yml").write_text("k: v\n", encoding="utf-8")
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    (src / "ro_dir" / "locked.py").write_text("y = 1\n", encoding="utf-8")
    os.chmod(src / "config.yml", 0o666)
    os.chmod(src / "open_dir", 0o777)
    os.chmod(src / "ro_dir" / "locked.py", 0o444)
    os.chmod(src / "ro_dir", 0o555)
    patch = (
        "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
        "--- a/ro_dir/locked.py\n+++ b/ro_dir/locked.py\n@@ -1 +1 @@\n-y = 1\n+y = 2\n"
    )
    dest = tmp_path / "dest"
    try:
        materialize_patched_tree(src, patch, dest)
        mode = lambda p: os.stat(p).st_mode & 0o7777  # noqa: E731
        assert mode(dest / "config.yml") == 0o666
        assert mode(dest / "open_dir") == 0o777
        assert mode(dest / "ro_dir") == 0o555
        assert mode(dest / "ro_dir" / "locked.py") == 0o444
        assert (dest / "ro_dir" / "locked.py").read_text() == "y = 2\n"
        run_dir = tmp_path / "run"
        scratch = new_scratch_dir(run_dir, 1)
        materialize_patched_tree(src, patch, scratch / "tree")
        assert remove_scratch_dir(run_dir, scratch) is True
    finally:
        os.chmod(src / "ro_dir", 0o755)
        if (dest / "ro_dir").exists():
            os.chmod(dest / "ro_dir", 0o755)


def test_mixed_newlines_and_form_feed_untouched(tmp_path: Path):
    (tmp_path / "m.txt").write_bytes(b"a\nb\r\nc\n")
    (tmp_path / "ff.txt").write_bytes(b"a\x0cb\nz\n")
    patch = (
        "--- a/m.txt\n+++ b/m.txt\n@@ -3 +3 @@\n-c\n+C\n"
        "--- a/ff.txt\n+++ b/ff.txt\n@@ -2 +2 @@\n-z\n+Z\n"
    )
    dest = tmp_path.parent / "nl_mixed"
    materialize_patched_tree(tmp_path, patch, dest)
    assert (dest / "m.txt").read_bytes() == b"a\nb\r\nC\n"
    assert (dest / "ff.txt").read_bytes() == b"a\x0cb\nZ\n"


def test_crlf_file_keeps_crlf(tmp_path: Path):
    (tmp_path / "w.txt").write_bytes(b"one\r\ntwo\r\n")
    patch = "--- a/w.txt\n+++ b/w.txt\n@@ -1,2 +1,3 @@\n one\n-two\n+TWO\n+three\n"
    dest = tmp_path.parent / "crlf"
    materialize_patched_tree(tmp_path, patch, dest)
    assert (dest / "w.txt").read_bytes() == b"one\r\nTWO\r\nthree\r\n"


def test_patch_without_final_newline_keeps_file_newline(toy_sqli: Path, tmp_path: Path):
    r = check_patch(toy_sqli, SQLI_FIX.rstrip("\n"))
    assert r["applies"], r
    dest = tmp_path / "t"
    materialize_patched_tree(toy_sqli, SQLI_FIX.rstrip("\n"), dest)
    assert (dest / "app.py").read_bytes().endswith(b"(q,))\n")


@pytest.mark.parametrize("old,new", [("c", "w"), ("i", "w"), ("a", "b")])
def test_mnemonic_prefixes(toy_sqli: Path, old: str, new: str):
    text = SQLI_FIX.replace("--- a/", f"--- {old}/").replace("+++ b/", f"+++ {new}/")
    files = parse_patch(text)
    assert files[0].path == "app.py"
    assert check_patch(toy_sqli, text)["applies"]


def test_unprefixed_real_dir_named_a_not_stripped():
    files = parse_patch("--- a/x.py\n+++ a/x.py\n@@ -1 +1 @@\n-1\n+2\n")
    assert files[0].path == "a/x.py"


def test_scratch_inside_source_refused(tmp_path: Path):
    src = tmp_path / "target"
    src.mkdir()
    (src / "f.py").write_text("x = 1\n", encoding="utf-8")
    before = _snapshot(src)
    with pytest.raises(PatchError, match="scratch_inside_source"):
        materialize_patched_tree(src, "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n", src / "runs" / "tree")
    assert _snapshot(src) == before
    assert not (src / "runs").exists()


def test_scratch_symlink_refused(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, run_dir / "scratch")
    with pytest.raises(PatchError, match="scratch_symlink_refused"):
        new_scratch_dir(run_dir, 1)
    assert list(elsewhere.iterdir()) == []


def test_parser_keeps_form_feed_and_bare_cr_in_context(tmp_path: Path):
    (tmp_path / "ff.txt").write_bytes(b"a\x0cb\nz\n")
    (tmp_path / "cr.txt").write_bytes(b"a\rb\nz\n")
    patch = (
        "--- a/ff.txt\n+++ b/ff.txt\n@@ -1,2 +1,2 @@\n a\x0cb\n-z\n+Z\n"
        "--- a/cr.txt\n+++ b/cr.txt\n@@ -1,2 +1,2 @@\n a\rb\n-z\n+Z\n"
    )
    dest = tmp_path.parent / "ff_ctx"
    materialize_patched_tree(tmp_path, patch, dest)
    assert (dest / "ff.txt").read_bytes() == b"a\x0cb\nZ\n"
    assert (dest / "cr.txt").read_bytes() == b"a\rb\nZ\n"


@pytest.mark.parametrize(
    "header,want_old,want_new",
    [
        ("--- /dev/null\n+++ a/hello.py\n", None, "a/hello.py"),
        ("--- b/settings.py\n+++ /dev/null\n", "b/settings.py", None),
        ("--- /dev/null\n+++ w/new.py\n", None, "new.py"),
        ("--- c/old.py\n+++ /dev/null\n", "old.py", None),
    ],
)
def test_one_sided_prefix_rules(header: str, want_old, want_new):
    body = "@@ -0,0 +1 @@\n+x\n" if want_old is None else "@@ -1 +0,0 @@\n-x\n"
    fp = parse_patch(header + body)[0]
    assert (fp.old_path, fp.new_path) == (want_old, want_new)


def test_mismatched_prefix_pair_is_rename():
    with pytest.raises(PatchError, match="rename_refused"):
        parse_patch("--- a/x.py\n+++ w/x.py\n@@ -1 +1 @@\n-1\n+2\n")
