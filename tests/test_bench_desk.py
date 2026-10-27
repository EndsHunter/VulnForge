"""Benchmarks desk reads python -m bench scorecards, including failed runs."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.paths import PROJECT_ROOT
from vulnforge.ui.app import create_app
from vulnforge.ui.bench_runs import get_run, list_runs

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "bench_desk"


def test_fixture_runs_keep_scorecard_field_names():
    runs = {run["id"]: run for run in list_runs(FIXTURE)}
    assert list(runs) == [
        "20261027T120000Z",
        "20261027T110000Z",
        "20261027T100000Z-failed",
        "20261027T090000Z-unscored",
    ]
    scored = runs["20261027T120000Z"]
    assert scored["status"] == "scored"
    assert scored["partial"] is False
    assert scored["cache_coverage"] == 1.0
    assert scored["stored_failure_count"] == 2
    assert scored["infra_error_row_count"] == 1
    assert scored["headline_metric"] == "recall_at_fpr_le_0.5pct"
    assert scored["headline_recall"] == 0.75
    sharp = scored["rows"][0]
    assert sharp["precision"] == 1.0
    assert sharp["recall"] == 0.875
    assert sharp["recall_at_fpr_le_0.5pct"] == 0.75
    assert sharp["vd_s"] == 0.75
    assert sharp["vd_s"] == sharp["recall_at_fpr_le_0.5pct"]
    assert sharp["fpr"] == 0.0
    assert sharp["youden"] == "equals VD-S (fewer than 200 negatives)"
    assert sharp["youden_in_ranking"] is False
    ranked = scored["rows"][1]
    assert ranked["youden"] == 0.496 or abs(ranked["youden"] - 0.496) < 1e-9
    assert ranked["youden"] != ranked["vd_s"]
    assert ranked["youden_in_ranking"] is True
    excluded = scored["rows"][2]
    assert excluded["excluded"] is True
    assert excluded["vd_s"] is None
    assert excluded["recall_at_fpr_le_0.5pct"] is None
    kinds = {row["error_kind"] for row in scored["error_rows"]}
    assert kinds == {"hunt_error", "infra_errors"}

    partial = runs["20261027T110000Z"]
    assert partial["status"] == "partial"
    assert partial["partial"] is True
    assert partial["cache_coverage"] == 0.85
    assert partial["stored_failure_count"] == 4
    assert partial["rows"][0]["recall"] == 0.4
    assert partial["rows"][0]["vd_s"] == partial["rows"][0]["recall_at_fpr_le_0.5pct"]

    failed = runs["20261027T100000Z-failed"]
    assert failed["status"] == "failed"
    assert failed["rows"] == []
    assert failed["partial"] is True
    assert failed["cache_coverage"] == 0.15
    assert failed["stored_failure_count"] == 11
    assert [row["task_id"] for row in failed["error_rows"]] == ["pair-ssrf", "pair-xss"]
    assert "connection refused" in failed["error"]

    unscored = runs["20261027T090000Z-unscored"]
    assert unscored["status"] == "unscored"
    assert unscored["rows"] == []
    assert unscored["error_rows"][0]["task_id"] == "pair-path"
    assert unscored["error_rows"][0]["error_kind"] == "cache_miss"


def test_page_renders_metrics_and_drops_the_old_desk(tmp_path):
    app = create_app(runs_root=tmp_path / "runs", bench_results=FIXTURE)
    with TestClient(app) as client:
        page = client.get("/benchmarks")
        assert page.status_code == 200
        body = page.text
        assert 'data-bench-desk="scorecard"' in body
        assert "POC workshop" not in body
        assert "Run mechanical" not in body
        assert "finding_report" not in body
        for field in (
            "precision",
            "recall",
            "recall_at_fpr_le_0.5pct",
            "vd_s",
            "fpr",
            "youden",
            "cache_coverage",
            "stored_failure_count",
            "infra_error_row_count",
            "partial",
        ):
            assert field in body
        assert "equals VD-S (fewer than 200 negatives)" in body
        assert "youden_in_ranking false" in body
        assert "youden_in_ranking true" in body
        assert "0.875" in body
        assert "0.75" in body
        assert "0.496" in body
        assert "pair-ssrf" in body
        assert "pair-path" in body
        assert "live run stopped before a scorecard" in body
        assert "no scorecard was written" in body
        assert 'data-status="failed"' in body
        assert 'data-status="unscored"' in body
        assert 'data-status="partial"' in body

        listed = client.get("/api/bench/runs")
        assert listed.status_code == 200
        payload = listed.json()
        assert payload["count"] == 4
        assert payload["results_root"] == str(FIXTURE.resolve())

        one = client.get("/api/bench/runs/20261027T120000Z")
        assert one.status_code == 200
        assert one.json()["run"]["infra_error_row_count"] == 1
        missing = client.get("/api/bench/runs/../secret")
        assert missing.status_code == 404

        for path in (
            "/benchmarks/run",
            "/benchmarks/poc",
            "/benchmarks/library",
            "/benchmarks/results",
            "/benchmarks/results/br-old",
        ):
            old = client.get(path, follow_redirects=False)
            assert old.status_code == 307
            assert old.headers["location"] == "/benchmarks"


def test_broken_scorecard_and_empty_dir_stay_visible(tmp_path):
    root = tmp_path / "results"
    broken = root / "broken"
    broken.mkdir(parents=True)
    (broken / "scorecard.json").write_text("{", encoding="utf-8")
    empty = root / "empty-run"
    empty.mkdir()
    runs = {run["id"]: run for run in list_runs(root)}
    assert runs["broken"]["status"] == "failed"
    assert "scorecard.json" in runs["broken"]["error"]
    assert runs["empty-run"]["status"] == "unscored"
    assert runs["empty-run"]["error"] == "no scorecard.json"
    assert get_run(root, "missing") is None
    assert get_run(root, "..") is None


def test_results_root_resolution(tmp_path, monkeypatch):
    monkeypatch.delenv("VF_BENCH_RESULTS", raising=False)
    app = create_app(runs_root=tmp_path / "runs")
    assert app.state.bench_results == (PROJECT_ROOT / "bench" / "results").resolve()
    chosen = tmp_path / "elsewhere"
    monkeypatch.setenv("VF_BENCH_RESULTS", str(chosen))
    from_env = create_app(runs_root=tmp_path / "runs")
    assert from_env.state.bench_results == chosen.resolve()
    flag = tmp_path / "flagged"
    forced = create_app(runs_root=tmp_path / "runs", bench_results=flag)
    assert forced.state.bench_results == flag.resolve()
