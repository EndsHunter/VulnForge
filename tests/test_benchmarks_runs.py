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


def test_api_live_mode_errors_without_llm(monkeypatch):
    monkeypatch.setattr(
        "vulnforge.benchmarks.live.load_config",
        lambda: {"llm": {"base_url": "", "model": ""}},
    )
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        r = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "mode": "live"},
        )
        assert r.status_code == 200, r.text
        run = r.json()["run"]
        assert run["status"] == "error"
        err = (run.get("error") or "").lower()
        assert "live bench is not enabled" not in err
        assert any(
            token in err for token in ("settings", "endpoint", "model", "base_url", "llm")
        )


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
        assert 'id="bench-run-live"' in run_page.text
        assert 'mode: "live"' in run_page.text
        assert 'id="bench-run-def"' in run_page.text
        assert "/api/benchmarks/runs" in run_page.text
        assert "all-hunt" in run_page.text
        assert "all-recon" in run_page.text
        assert "all-finding_report" in run_page.text
        assert "all-runnable" in run_page.text
        assert 'data-suite' in run_page.text

        results = client.get("/benchmarks/results")
        assert results.status_code == 200
        assert 'id="bench-results-table"' in results.text
        assert 'data-bench-results-filters="1"' in results.text
        assert 'id="bench-filter-kind"' in results.text
        assert 'id="bench-filter-def"' in results.text
        assert 'id="bench-filter-status"' in results.text
        assert 'id="bench-filter-type"' in results.text
        assert "All hunts" in results.text
        assert "all-hunt" in results.text
        assert 'data-bench-sort="1"' in results.text
        assert 'data-bench-order="1"' in results.text
        assert 'id="bench-results-apply"' in results.text
        assert "/api/benchmarks/runs" in results.text
        assert "/benchmarks/results/" in results.text


def test_api_runs_filter_and_sort():
    """GET /api/benchmarks/runs supports def_id/status/type + sort/order."""
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        run = created.json()["run"]
        rid = run["id"]
        assert run["status"] == "passed"

        by_def = client.get("/api/benchmarks/runs", params={"def_id": "toy_sqli"})
        assert by_def.status_code == 200
        assert any(r["id"] == rid for r in by_def.json()["runs"])

        by_status = client.get(
            "/api/benchmarks/runs",
            params={"status": "passed", "def_id": "toy_sqli"},
        )
        assert by_status.status_code == 200
        assert any(r["id"] == rid for r in by_status.json()["runs"])

        miss_status = client.get(
            "/api/benchmarks/runs",
            params={"status": "cancelled", "def_id": "toy_sqli"},
        )
        assert miss_status.status_code == 200
        assert not any(r["id"] == rid for r in miss_status.json()["runs"])

        by_type = client.get(
            "/api/benchmarks/runs",
            params={"type": "hunt", "def_id": "toy_sqli"},
        )
        assert by_type.status_code == 200
        assert any(r["id"] == rid for r in by_type.json()["runs"])

        sorted_desc = client.get(
            "/api/benchmarks/runs",
            params={"sort": "started_at", "order": "desc", "def_id": "toy_sqli"},
        )
        assert sorted_desc.status_code == 200
        rows_desc = sorted_desc.json()["runs"]
        assert rows_desc
        started = [r.get("started_at") or "" for r in rows_desc]
        assert started == sorted(started, reverse=True)

        sorted_recall = client.get(
            "/api/benchmarks/runs",
            params={"sort": "recall", "order": "desc", "def_id": "toy_sqli"},
        )
        assert sorted_recall.status_code == 200
        recalls = [
            float((r.get("metrics") or {}).get("recall") or 0)
            for r in sorted_recall.json()["runs"]
        ]
        assert recalls == sorted(recalls, reverse=True)

        # Full detail payload
        detail = client.get(f"/api/benchmarks/runs/{rid}")
        assert detail.status_code == 200
        d = detail.json()["run"]
        assert d["id"] == rid
        assert "metrics" in d
        assert "error" in d
        assert "harness_run_dir" in d
        assert d["metrics"]["hit_count"] >= 1


def test_results_detail_route_and_list_prove():
    """Prove: mechanical toy_sqli run appears in Results; detail route opens."""
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        rid = created.json()["run"]["id"]

        listed = client.get(
            "/api/benchmarks/runs",
            params={"def_id": "toy_sqli", "sort": "started_at", "order": "desc"},
        )
        assert listed.status_code == 200
        assert any(r["id"] == rid for r in listed.json()["runs"])

        page = client.get(f"/benchmarks/results/{rid}")
        assert page.status_code == 200
        assert 'data-bench-page="results"' in page.text
        assert f'data-detail-run-id="{rid}"' in page.text
        assert 'data-bench-results-detail="1"' in page.text
        assert 'id="bench-detail-body"' in page.text
        assert f"/api/benchmarks/runs/{rid}" in page.text or "/api/benchmarks/runs/" in page.text
        assert 'id="bench-results-back"' in page.text
        assert 'id="bench-detail-suite"' in page.text
        assert 'id="bench-detail-members"' in page.text


def test_defs_for_suite_excludes_poc_dev():
    from vulnforge.benchmarks import defs_for_suite, list_defs

    hunts = defs_for_suite(["hunt"])
    recons = defs_for_suite(["recon"])
    reports = defs_for_suite(["finding_report"])
    runnable = defs_for_suite(["hunt", "recon", "finding_report"])
    hunt_ids = [d["id"] for d, _ in hunts]
    recon_ids = [d["id"] for d, _ in recons]
    report_ids = [d["id"] for d, _ in reports]
    assert "toy_sqli" in hunt_ids
    assert "toy_sqli_recon" in recon_ids
    assert "toy_sqli_finding_report" in report_ids
    assert "toy_poc_dev" not in hunt_ids
    assert "toy_poc_dev" not in recon_ids
    assert "toy_poc_dev" not in report_ids
    by_id = {d["id"]: d for d in list_defs()}
    for bid in hunt_ids:
        assert "hunt" in (by_id[bid].get("types") or [])
    assert {d["id"] for d, _ in runnable} == (
        set(hunt_ids) | set(recon_ids) | set(report_ids)
    )


def test_api_suite_all_recon_one_parent_plus_children():
    """All recons is one parent run; each recon def is a child."""
    from vulnforge.benchmarks import defs_for_suite

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "all-recon", "types": ["recon"], "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["ok"]
        assert body.get("suite") is True
        run = body["run"]
        assert run["def_id"] == "all-recon"
        assert run["types_run"] == ["recon"]
        metrics = run["metrics"]
        assert metrics.get("suite") is True
        expect = [d["id"] for d, _ in defs_for_suite(["recon"])]
        assert metrics["count"] == len(expect)
        members = metrics.get("members") or []
        got = [m["def_id"] for m in members]
        assert got == sorted(expect)
        assert "toy_sqli_recon" in got
        assert run["status"] == "passed"
        assert metrics["passed_count"] == len(expect)
        assert metrics.get("confirmed") is False
        child_ids = metrics.get("member_run_ids") or []
        assert len(child_ids) == len(expect)
        listed = client.get("/api/benchmarks/runs").json()["runs"]
        listed_ids = {r["id"] for r in listed}
        assert run["id"] in listed_ids
        for cid in child_ids:
            assert cid in listed_ids
            detail = client.get(f"/api/benchmarks/runs/{cid}")
            assert detail.status_code == 200
            child = detail.json()["run"]
            assert child["status"] == "passed"
            assert "recon" in child["types_run"]

        parents = client.get("/api/benchmarks/runs", params={"suite": "true"})
        assert parents.status_code == 200
        parent_ids = [r["id"] for r in parents.json()["runs"]]
        assert run["id"] in parent_ids
        assert not any(cid in parent_ids for cid in child_ids)
        kids = client.get("/api/benchmarks/runs", params={"suite": "false"})
        kid_ids = [r["id"] for r in kids.json()["runs"]]
        assert run["id"] not in kid_ids
        assert all(cid in kid_ids for cid in child_ids)
        mixed = client.get("/api/benchmarks/runs", params={"sort": "started_at", "order": "desc"})
        mixed_ids = [r["id"] for r in mixed.json()["runs"]]
        assert mixed_ids.index(run["id"]) < min(mixed_ids.index(cid) for cid in child_ids)

        series = client.get(
            "/api/benchmarks/runs/series",
            params={"def_id": "all-recon", "type": "recon"},
        )
        assert series.status_code == 200, series.text
        points = series.json()["points"]
        assert any(p["run_id"] == run["id"] for p in points)

        detail_page = client.get(f"/benchmarks/results/{run['id']}")
        assert detail_page.status_code == 200
        assert 'id="bench-detail-members"' in detail_page.text
        assert 'data-bench-detail-suite="1"' in detail_page.text


def test_api_suite_all_hunt_includes_toy_and_flag():
    from vulnforge.benchmarks import defs_for_suite

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "all-hunt", "suite": True, "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        run = created.json()["run"]
        assert run["def_id"] == "all-hunt"
        metrics = run["metrics"]
        expect = {d["id"] for d, _ in defs_for_suite(["hunt"])}
        got = {m["def_id"] for m in (metrics.get("members") or [])}
        assert got == expect
        assert "toy_sqli" in got
        toy = metrics["by_def"]["toy_sqli"]
        assert toy["status"] == "passed"
        assert toy.get("recall") is not None and toy["recall"] > 0
        assert metrics.get("confirmed") is False


def test_api_suite_true_without_def_id():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"suite": True, "types": ["finding_report"], "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        run = created.json()["run"]
        assert run["def_id"] == "all-finding_report"
        assert run["metrics"].get("suite") is True
        ids = [m["def_id"] for m in run["metrics"]["members"]]
        assert "toy_sqli_finding_report" in ids
