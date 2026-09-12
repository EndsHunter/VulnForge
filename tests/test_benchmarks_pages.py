"""Bench desk shell pages (/benchmarks) — top-level peer to Dev/Settings."""

from __future__ import annotations

from fastapi.testclient import TestClient

from vulnforge.ui.app import create_app


def test_benchmarks_pages_and_home_dock(tmp_path):
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as client:
        # Hub redirects to Run (top-level, not under /dev)
        r = client.get("/benchmarks", follow_redirects=False)
        assert r.status_code in (307, 302)
        assert r.headers["location"] == "/benchmarks/run"

        labels = ("Run", "POC workshop", "Results", "Library")
        paths = {
            "/benchmarks/run": "run",
            "/benchmarks/poc": "poc",
            "/benchmarks/results": "results",
            "/benchmarks/library": "library",
        }
        for path, active in paths.items():
            resp = client.get(path)
            assert resp.status_code == 200, path
            body = resp.text
            assert 'data-page="benchmarks"' in body
            assert f'data-bench-page="{active}"' in body
            assert 'href="/benchmarks/run"' in body
            assert 'href="/benchmarks/poc"' in body
            assert 'href="/benchmarks/results"' in body
            assert 'href="/benchmarks/library"' in body
            for label in labels:
                assert label in body
            # Not nested under /dev
            assert 'href="/dev/benchmarks' not in body
            assert path.startswith("/benchmarks")
            assert f'data-bench-panel="{active}"' in body
            assert 'aria-current="page"' in body

        home = client.get("/")
        assert home.status_code == 200
        assert 'href="/benchmarks"' in home.text
        assert 'id="btn-open-benchmarks"' in home.text
