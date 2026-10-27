"""Bench desk shell pages (/benchmarks) — top-level peer to Dev/Settings."""

from __future__ import annotations

from fastapi.testclient import TestClient

from vulnforge.ui.app import create_app


def test_benchmarks_pages_and_home_dock(tmp_path):
    app = create_app(runs_root=tmp_path / "runs", bench_results=tmp_path / "bench-results")
    with TestClient(app) as client:
        r = client.get("/benchmarks", follow_redirects=False)
        assert r.status_code == 200
        assert 'data-page="benchmarks"' in r.text
        assert 'data-bench-desk="scorecard"' in r.text
        assert 'href="/dev/benchmarks' not in r.text
        assert 'aria-current="page"' in r.text
        for path in ("/benchmarks/run", "/benchmarks/poc", "/benchmarks/results", "/benchmarks/library"):
            old = client.get(path, follow_redirects=False)
            assert old.status_code == 307, path
            assert old.headers["location"] == "/benchmarks"

        home = client.get("/")
        assert home.status_code == 200
        assert 'href="/benchmarks"' in home.text
        assert 'id="btn-open-benchmarks"' in home.text
