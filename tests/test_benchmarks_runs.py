"""Benchmark hunt runs — mechanical path prove bar (ticket 3)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.benchmarks import TERMINAL_STATUSES, get_run, list_runs, run_hunt
from vulnforge.ui.app import create_app


def test_toy_sqli_mechanical_run_terminal_with_metrics():
    """Prove: toy_sqli mechanical → terminal status + metrics; no live LLM."""
    run = run_hunt(def_id="toy_sqli", mode="mechanical")
    assert run["def_id"] == "toy_sqli"
    assert run["types_run"] == ["hunt"]
    assert run["mode"] == "mechanical"
    assert run["status"] in TERMINAL_STATUSES
    assert run["status"] == "passed"
    assert run["finished_at"]
    metrics = run["metrics"]
    assert isinstance(metrics, dict)
    assert "recall" in metrics
    assert "hit_count" in metrics
    assert "oracle_count" in metrics
    assert metrics["oracle_count"] >= 1
    assert metrics["recall"] > 0
    assert metrics.get("confirmed") is False
    # Persisted + listable
    assert get_run(run["id"])["status"] == "passed"
    ids = [r["id"] for r in list_runs()]
    assert run["id"] in ids


def test_api_post_run_and_list_results():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["ok"]
        run = body["run"]
        assert run["status"] == "passed"
        assert run["metrics"]["recall"] > 0
        assert run["metrics"]["hit_count"] >= 1
        rid = run["id"]

        listed = client.get("/api/benchmarks/runs")
        assert listed.status_code == 200, listed.text
        rows = listed.json()["runs"]
        assert any(r["id"] == rid for r in rows)
        match = next(r for r in rows if r["id"] == rid)
        assert match["def_id"] == "toy_sqli"
        assert match["status"] == "passed"
        assert "recall" in (match.get("metrics") or {})

        detail = client.get(f"/api/benchmarks/runs/{rid}")
        assert detail.status_code == 200
        assert detail.json()["run"]["id"] == rid
        assert detail.json()["run"]["metrics"]["oracle_count"] >= 1


def test_api_live_mode_errors_without_llm():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        r = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "mode": "live"},
        )
        assert r.status_code == 200, r.text
        run = r.json()["run"]
        assert run["status"] == "error"
        assert "live" in (run.get("error") or "").lower()


def test_api_unknown_def_400():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        r = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "no_such_bench_xyz", "mode": "mechanical"},
        )
        assert r.status_code in (400, 404)


def test_run_and_results_page_hooks():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        run_page = client.get("/benchmarks/run")
        assert run_page.status_code == 200
        assert 'id="bench-run-mechanical"' in run_page.text
        assert 'id="bench-run-def"' in run_page.text
        assert "/api/benchmarks/runs" in run_page.text

        results = client.get("/benchmarks/results")
        assert results.status_code == 200
        assert 'id="bench-results-table"' in results.text
        assert "/api/benchmarks/runs" in results.text
