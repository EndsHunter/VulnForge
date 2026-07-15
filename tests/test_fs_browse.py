"""Host filesystem browse for New audit path pickers."""

from __future__ import annotations

from pathlib import Path

from vulnforge.control.ops import browse_host_fs, list_fs_roots


def test_list_fs_roots_nonempty():
    roots = list_fs_roots()
    assert isinstance(roots, list)
    assert len(roots) >= 1
    assert all(r.get("is_dir") for r in roots)


def test_browse_empty_returns_roots():
    r = browse_host_fs("", mode="dirs")
    assert r["ok"] is True
    assert r["is_root"] is True
    assert len(r["entries"]) >= 1


def test_browse_directory(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "readme.md").write_text("hi", encoding="utf-8")
    r = browse_host_fs(str(tmp_path), mode="dirs")
    assert r["ok"] is True
    names = {e["name"] for e in r["entries"]}
    assert "sub" in names
    assert "readme.md" not in names  # dirs mode

    r2 = browse_host_fs(str(tmp_path), mode="any")
    names2 = {e["name"] for e in r2["entries"]}
    assert "sub" in names2
    assert "readme.md" in names2


def test_browse_missing_path():
    r = browse_host_fs("C:\\does\\not\\exist\\vf-browse-test-xyz", mode="dirs")
    assert r["ok"] is False
    assert "error" in r
