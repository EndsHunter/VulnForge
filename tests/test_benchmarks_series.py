"""Benchmark series + version compare (ticket 6 prove bar)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.benchmarks import (
    build_series,
    compare_versions,
    create_run,
    empty_side,
    extract_score,
    run_benchmark,
    summarize_version,
    update_def,
    update_run,
)
from vulnforge.paths import PROJECT_ROOT
from vulnforge.ui.app import create_app

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "bench_results_helpers.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "bench_results_helpers.test.js"


def _run(
    *,
    rid: str,
    def_id: str = "toy",
    version: int = 1,
    started_at: str = "2026-01-01T00:00:00Z",
    types_run: list[str] | None = None,
    metrics: dict | None = None,
    status: str = "passed",
) -> dict:
    return {
        "id": rid,
        "def_id": def_id,
        "version": version,
        "types_run": types_run or ["hunt"],
        "status": status,
        "started_at": started_at,
        "metrics": metrics
        or {"recall": 0.5, "score": 0.5, "hit_count": 1, "oracle_count": 2},
    }


def test_extract_score_prefers_type_slice():
    run = _run(
        rid="br-aaaaaaaaaaaa",
        types_run=["hunt", "recon"],
        metrics={
            "recall": 0.2,
            "score": 0.4,
            "by_type": {
                "hunt": {"recall": 0.8, "score": 0.8, "hit_count": 2},
                "recon": {"score": 0.3},
            },
        },
    )
    assert extract_score(run) == 0.2
    assert extract_score(run, run_type="hunt") == 0.8
    assert extract_score(run, run_type="recon") == 0.3
    assert extract_score(run, run_type="finding_report") is None


def test_build_series_sorts_and_filters():
    runs = [
        _run(rid="br-bbbbbbbbbbbb", started_at="2026-01-03T00:00:00Z", metrics={"recall": 1.0}),
        _run(rid="br-aaaaaaaaaaaa", started_at="2026-01-01T00:00:00Z", metrics={"recall": 0.25}),
        _run(
            rid="br-cccccccccccc",
            def_id="other",
            started_at="2026-01-02T00:00:00Z",
            metrics={"recall": 0.9},
        ),
        _run(
            rid="br-dddddddddddd",
            started_at="2026-01-04T00:00:00Z",
            types_run=["recon"],
            metrics={"score": 0.6, "by_type": {"recon": {"score": 0.6}}},
        ),
    ]
    series = build_series(runs, def_id="toy")
    assert series["def_id"] == "toy"
    assert [p["run_id"] for p in series["points"]] == [
        "br-aaaaaaaaaaaa",
        "br-bbbbbbbbbbbb",
        "br-dddddddddddd",
    ]
    assert series["points"][0]["score"] == 0.25
    typed = build_series(runs, def_id="toy", run_type="recon")
    assert [p["run_id"] for p in typed["points"]] == ["br-dddddddddddd"]
    assert typed["points"][0]["score"] == 0.6


def test_compare_versions_latest_aggregate_and_empty_zeros():
    runs = [
        _run(
            rid="br-aaaaaaaaaaaa",
            version=1,
            started_at="2026-01-01T00:00:00Z",
            metrics={
                "recall": 0.5,
                "score": 0.5,
                "hit_count": 1,
                "oracle_count": 2,
                "by_type": {"hunt": {"recall": 0.5, "score": 0.5, "hit_count": 1}},
            },
        ),
        _run(
            rid="br-bbbbbbbbbbbb",
            version=1,
            started_at="2026-01-02T00:00:00Z",
            metrics={
                "recall": 1.0,
                "score": 1.0,
                "hit_count": 2,
                "oracle_count": 2,
                "by_type": {"hunt": {"recall": 1.0, "score": 1.0, "hit_count": 2}},
            },
        ),
        _run(
            rid="br-cccccccccccc",
            version=2,
            started_at="2026-01-03T00:00:00Z",
            metrics={
                "recall": 0.25,
                "score": 0.25,
                "hit_count": 0,
                "oracle_count": 2,
                "by_type": {"hunt": {"recall": 0.25, "score": 0.25, "hit_count": 0}},
            },
        ),
    ]
    cmp = compare_versions(runs, def_id="toy", version_a=1, version_b=2)
    assert cmp["def_id"] == "toy"
    a, b = cmp["version_a"], cmp["version_b"]
    assert a["run_count"] == 2
    assert b["run_count"] == 1
    assert a["latest"]["run_id"] == "br-bbbbbbbbbbbb"
    assert a["latest"]["recall"] == 1.0
    assert a["aggregate"]["recall"] == 0.75
    assert b["latest"]["recall"] == 0.25
    assert cmp["delta"]["recall"] == -0.75
    assert cmp["delta"]["run_count"] == -1
    assert "hunt" in a["latest"]["by_type"]

    empty = summarize_version(runs, 99, def_id="toy")
    assert empty == empty_side(99)
    assert empty["run_count"] == 0
    assert empty["latest"] is None
    assert empty["aggregate"]["recall"] == 0.0
    assert empty["aggregate"]["hit_count"] == 0

    vs_missing = compare_versions(runs, def_id="toy", version_a=1, version_b=99)
    assert vs_missing["version_b"]["run_count"] == 0
    assert vs_missing["version_b"]["latest"] is None
    assert vs_missing["delta"]["recall"] == -1.0


def _write_scored_run(*, def_id: str, version: int, recall: float, hit_count: int) -> dict:
    row = create_run(
        def_id=def_id,
        version=version,
        types_run=["hunt"],
        mode="mechanical",
        status="running",
    )
    return update_run(
        row["id"],
        status="passed",
        metrics={
            "recall": recall,
            "score": recall,
            "hit_count": hit_count,
            "oracle_count": 2,
            "bench_type": "hunt",
            "by_type": {
                "hunt": {
                    "recall": recall,
                    "score": recall,
                    "hit_count": hit_count,
                    "oracle_count": 2,
                }
            },
            "confirmed": False,
        },
    )


def test_api_series_and_compare_two_versions_fixtures():
    """Prove: two versions of same def, compare API returns both sides + deltas."""
    a = _write_scored_run(def_id="toy_sqli", version=1, recall=0.5, hit_count=1)
    b = _write_scored_run(def_id="toy_sqli", version=2, recall=1.0, hit_count=2)
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        series = client.get(
            "/api/benchmarks/runs/series",
            params={"def_id": "toy_sqli", "type": "hunt"},
        )
        assert series.status_code == 200, series.text
        body = series.json()
        assert body["ok"]
        assert body["def_id"] == "toy_sqli"
        assert body["type"] == "hunt"
        ids = [p["run_id"] for p in body["points"]]
        assert a["id"] in ids and b["id"] in ids
        started = [p["started_at"] for p in body["points"]]
        assert started == sorted(started)
        scores = {p["run_id"]: p["score"] for p in body["points"]}
        assert scores[a["id"]] == 0.5
        assert scores[b["id"]] == 1.0

        cmp = client.get(
            "/api/benchmarks/compare",
            params={
                "def_id": "toy_sqli",
                "version_a": 1,
                "version_b": 2,
                "type": "hunt",
            },
        )
        assert cmp.status_code == 200, cmp.text
        data = cmp.json()
        assert data["ok"]
        assert data["def_id"] == "toy_sqli"
        assert data["version_a"]["version"] == 1
        assert data["version_b"]["version"] == 2
        assert data["version_a"]["run_count"] >= 1
        assert data["version_b"]["run_count"] >= 1
        assert data["version_a"]["latest"]["recall"] == 0.5
        assert data["version_b"]["latest"]["recall"] == 1.0
        assert data["delta"]["recall"] == 0.5
        assert data["delta"]["hit_count"] == 1
        assert data["version_a"]["latest"]["by_type"]["hunt"]["recall"] == 0.5

        empty = client.get(
            "/api/benchmarks/compare",
            params={"def_id": "toy_sqli", "version_a": 1, "version_b": 99},
        )
        assert empty.status_code == 200
        miss = empty.json()["version_b"]
        assert miss["run_count"] == 0
        assert miss["latest"] is None
        assert miss["aggregate"]["recall"] == 0.0
        assert miss["aggregate"]["hit_count"] == 0


def test_api_compare_two_mechanical_versions():
    """Prove: bump def version, run mechanical scores, compare both sides."""
    r1 = run_benchmark(def_id="toy_sqli", version=1, types=["hunt"], mode="mechanical")
    assert r1["status"] == "passed"
    assert r1["version"] == 1
    bumped = update_def("toy_sqli", name="toy_sqli v2 compare")
    assert int(bumped["head_version"]) == 2
    r2 = run_benchmark(def_id="toy_sqli", version=2, types=["hunt"], mode="mechanical")
    assert r2["status"] == "passed"
    assert r2["version"] == 2

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        cmp = client.get(
            "/api/benchmarks/compare",
            params={"def_id": "toy_sqli", "version_a": 1, "version_b": 2},
        )
        assert cmp.status_code == 200, cmp.text
        data = cmp.json()
        assert data["version_a"]["run_count"] >= 1
        assert data["version_b"]["run_count"] >= 1
        assert data["version_a"]["latest"]["run_id"]
        assert data["version_b"]["latest"]["run_id"]
        assert "recall" in data["delta"]
        assert "score" in data["delta"]

        series = client.get(
            "/api/benchmarks/runs/series", params={"def_id": "toy_sqli"}
        )
        assert series.status_code == 200
        ids = {p["run_id"] for p in series.json()["points"]}
        assert r1["id"] in ids
        assert r2["id"] in ids


def test_api_series_compare_validation():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        assert client.get("/api/benchmarks/runs/series").status_code == 400
        assert client.get(
            "/api/benchmarks/runs/series", params={"def_id": "no_such_bench_xyz"}
        ).status_code == 404
        assert client.get("/api/benchmarks/compare").status_code == 400
        assert client.get(
            "/api/benchmarks/compare",
            params={"def_id": "toy_sqli", "version_a": 1},
        ).status_code == 400
        assert client.get(
            "/api/benchmarks/compare",
            params={"def_id": "no_such_bench_xyz", "version_a": 1, "version_b": 2},
        ).status_code == 404


def test_results_page_chart_and_compare_hooks():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        page = client.get("/benchmarks/results")
        assert page.status_code == 200
        body = page.text
        assert 'id="bench-chart"' in body
        assert 'data-bench-chart="1"' in body
        assert 'id="bench-chart-svg"' in body
        assert 'data-bench-chart-svg="1"' in body
        assert 'id="bench-chart-line"' in body
        assert 'id="bench-chart-def"' in body
        assert 'id="bench-chart-type"' in body
        assert 'id="bench-compare"' in body
        assert 'data-bench-compare="1"' in body
        assert 'id="bench-compare-def"' in body
        assert 'id="bench-compare-a"' in body
        assert 'id="bench-compare-b"' in body
        assert 'id="bench-compare-apply"' in body
        assert 'data-bench-compare-side="a"' in body
        assert 'data-bench-compare-delta="1"' in body
        assert "/api/benchmarks/runs/series" in body
        assert "/api/benchmarks/compare" in body
        assert "bench_results_helpers.js" in body
        # Existing table/detail hooks stay
        assert 'id="bench-results-table"' in body
        assert 'data-bench-results-filters="1"' in body

        detail = client.get("/benchmarks/results/br-notarealid00")
        assert detail.status_code == 200
        assert 'data-bench-results-detail="1"' in detail.text
        assert 'id="bench-chart"' not in detail.text


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_bench_results_helpers_js():
    assert HELPERS.is_file()
    assert TEST_JS.is_file()
    proc = subprocess.run(
        ["node", "--test", str(TEST_JS)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"node --test failed (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
