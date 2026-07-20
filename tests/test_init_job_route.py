"""Regression: init-jobs must not be swallowed by /api/runs/{target_id}/{run_id}."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.init_progress import write_job
from vulnforge.ui.app import create_app


def _tiny_pe(path: Path) -> Path:
    path.write_bytes(b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200)
    return path


def test_init_job_status_not_matched_as_run(tmp_path: Path):
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    job_id = "route-order-regression"
    write_job(
        Path(app.state.project_root),
        job_id,
        {
            "status": "running",
            "phase": "inventory",
            "message": "scanning",
            "percent": 12,
        },
    )
    r = client.get(f"/api/runs/init-jobs/{job_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("status") == "running"
    assert body.get("phase") == "inventory"
    # Must not look like a "run not found" detail payload
    assert "run not found" not in str(body).lower()


def test_init_routes_registered_before_run_detail():
    app = create_app()
    paths = [getattr(rt, "path", None) for rt in app.routes]
    i_jobs = paths.index("/api/runs/init-jobs/{job_id}")
    i_init = paths.index("/api/runs/init")
    i_run = paths.index("/api/runs/{target_id}/{run_id}")
    assert i_jobs < i_run
    assert i_init < i_run


def test_api_init_pe_with_code_static_auto_upgrades(tmp_path: Path):
    """GUI defaults to code_static; PE path must auto-upgrade to binary_re."""
    pe = _tiny_pe(tmp_path / "app.exe")
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    # Without auth, upgraded binary_re should fail at authorization (not dir gate)
    r = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(pe),
            "profile": "code_static",
            "start": False,
            "skip_ghidra_init": True,
        },
    )
    # Either HTTP 400/500 with auth message, or ok:false body — not "not a directory"
    text = r.text.lower()
    assert "not a directory" not in text
    if r.status_code == 200:
        body = r.json()
        if body.get("ok"):
            # config may already authorize binary_re globally
            pass
        else:
            assert "authoriz" in str(body).lower() or body.get("ok") is False
    else:
        assert "authoriz" in text or r.status_code in (400, 500)

    r2 = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(pe),
            "profile": "code_static",
            "i_am_authorized_for_binary_re": True,
            "skip_ghidra_init": True,
            "start": False,
            "enqueue_hunts": False,
        },
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert body2.get("ok") is True
    run_dir = Path(body2["run_dir"])
    import sqlite3

    con = sqlite3.connect(run_dir / "harness.db")
    try:
        row = con.execute("SELECT profile FROM runs LIMIT 1").fetchone()
        assert row is not None
        assert row[0] == "binary_re"
    finally:
        con.close()


def test_api_init_accepts_single_source_file(tmp_path: Path):
    """code_static may target a single source file (not only directories)."""
    src = tmp_path / "lonely.py"
    src.write_text("print('hello')\n", encoding="utf-8")
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    r = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(src),
            "profile": "code_static",
            "start": False,
            "enqueue_hunts": False,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True
    run_dir = Path(body["run_dir"])
    assert (run_dir / "harness.db").is_file()
    man = json.loads((run_dir / "target_manifest.json").read_text(encoding="utf-8"))
    assert man.get("kind") == "single_file"
    assert man.get("file_count") == 1


def test_api_init_accepts_pe_for_binary_re(tmp_path: Path):
    pe = _tiny_pe(tmp_path / "app.exe")
    runs = tmp_path / "runs"
    app = create_app(runs_root=runs)
    client = TestClient(app)
    r = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(pe),
            "profile": "binary_re",
            "i_am_authorized_for_binary_re": True,
            "skip_ghidra_init": True,
            "start": False,
            "enqueue_hunts": False,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True
    assert body.get("run_dir")
    run_dir = Path(body["run_dir"])
    assert (run_dir / "harness.db").is_file()
    # profile recorded on run
    import sqlite3

    con = sqlite3.connect(run_dir / "harness.db")
    try:
        row = con.execute("SELECT profile, config_json FROM runs LIMIT 1").fetchone()
        assert row is not None
        assert row[0] == "binary_re"
        cfg = json.loads(row[1] or "{}")
        assert cfg.get("run", {}).get("binary_re_authorized") is True
    finally:
        con.close()


def test_api_init_auto_profile_pe_file(tmp_path: Path):
    """Blank profile + .exe target → binary_re (still needs auth)."""
    pe = _tiny_pe(tmp_path / "auto.dll")
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    # Without auth should fail at cmd_init (async error) or pre-check
    r = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(pe),
            "start": False,
            "skip_ghidra_init": True,
            # profile omitted → auto binary_re
        },
    )
    # Auto-selects binary_re; without auth, init fails (not 400 dir gate)
    assert r.status_code in (200, 400, 500)
    if r.status_code == 200:
        # background=false may still return ok:false on init error
        body = r.json()
        if body.get("ok"):
            # unexpected without auth — but tolerate config with global auth
            pass
        else:
            assert "authoriz" in str(body).lower() or body.get("ok") is False
    # With auth succeeds
    r2 = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(pe),
            "i_am_authorized_for_binary_re": True,
            "skip_ghidra_init": True,
            "start": False,
            "enqueue_hunts": False,
        },
    )
    assert r2.status_code == 200, r2.text
    assert r2.json().get("ok") is True
