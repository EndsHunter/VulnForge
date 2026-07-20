"""Host filesystem browse for New audit path pickers."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.control.ops import browse_host_fs, list_fs_roots
from vulnforge.ui.app import create_app


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
    # Entries expose is_file / is_dir for UI folder vs file styling
    by_name = {e["name"]: e for e in r2["entries"]}
    assert by_name["sub"]["is_dir"] is True
    assert by_name["readme.md"]["is_file"] is True
    assert by_name["readme.md"]["is_dir"] is False


def test_browse_file_path_returns_parent_and_selected(tmp_path: Path):
    pe = tmp_path / "app.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 64)
    (tmp_path / "other.dll").write_bytes(b"MZ" + b"\x00" * 32)
    r = browse_host_fs(str(pe), mode="any")
    assert r["ok"] is True
    assert r.get("selected_file")
    assert Path(r["selected_file"]).name == "app.exe"
    names = {e["name"] for e in r["entries"]}
    assert "app.exe" in names
    assert "other.dll" in names


def test_browse_missing_path():
    r = browse_host_fs("C:\\does\\not\\exist\\vf-browse-test-xyz", mode="dirs")
    assert r["ok"] is False
    assert "error" in r


def test_api_fs_browse_any_includes_files(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "app.exe").write_bytes(b"MZ" + b"\x00" * 64)
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    r = client.get("/api/fs/browse", params={"path": str(tmp_path), "mode": "any"})
    assert r.status_code == 200, r.text
    body = r.json()
    names = {e["name"] for e in body.get("entries") or []}
    assert "sub" in names
    assert "app.exe" in names
    r_dirs = client.get("/api/fs/browse", params={"path": str(tmp_path), "mode": "dirs"})
    assert r_dirs.status_code == 200
    dir_names = {e["name"] for e in r_dirs.json().get("entries") or []}
    assert "sub" in dir_names
    assert "app.exe" not in dir_names
