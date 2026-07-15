"""Regression: init-jobs must not be swallowed by /api/runs/{target_id}/{run_id}."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.init_progress import write_job
from vulnforge.ui.app import create_app


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
