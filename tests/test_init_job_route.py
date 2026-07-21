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


def test_api_init_rejects_pe(tmp_path: Path):
    """PE binaries are not supported (source analysis only)."""
    pe = _tiny_pe(tmp_path / "app.exe")
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    r = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(pe),
            "profile": "code_static",
            "start": False,
        },
    )
    assert r.status_code == 400, r.text
    text = r.text.lower()
    assert "pe" in text or "source" in text or "binary" in text


def test_api_init_rejects_binary_re_profile(tmp_path: Path):
    src = tmp_path / "app.py"
    src.write_text("print(1)\n", encoding="utf-8")
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    r = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(src),
            "profile": "binary_re",
            "start": False,
        },
    )
    assert r.status_code == 400, r.text
    assert "binary_re" in r.text.lower() or "source" in r.text.lower()


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
