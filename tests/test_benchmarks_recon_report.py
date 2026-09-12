"""Benchmark recon + finding_report scorers / runs (ticket 5 prove bar)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.benchmarks import (
    TERMINAL_STATUSES,
    create_def,
    get_run,
    list_defs,
    run_benchmark,
    score_finding_report,
    score_recon,
    seed_from_ground_truth,
)
from vulnforge.paths import PROJECT_ROOT
from vulnforge.ui.app import create_app


def test_seed_includes_recon_and_finding_report_defs():
    ids = {d["id"] for d in list_defs()}
    assert "toy_sqli_recon" in ids
    assert "toy_sqli_finding_report" in ids
    recon = next(d for d in list_defs() if d["id"] == "toy_sqli_recon")
    report = next(d for d in list_defs() if d["id"] == "toy_sqli_finding_report")
    assert recon["types"] == ["recon"]
    assert report["types"] == ["finding_report"]
    # missing-only re-seed does not clobber
    result = seed_from_ground_truth(missing_only=True)
    assert "toy_sqli_recon" in result["skipped"]
    assert "toy_sqli_finding_report" in result["skipped"]


def test_score_recon_mechanical_toy_sqli():
    target = PROJECT_ROOT / "fixtures" / "toy_sqli"
    oracle = {
        "type": "recon",
        "id": "toy_sqli_recon",
        "components": [{"name": "app", "path_hints": ["app.py"]}],
        "require_relations": True,
        "require_trust_boundaries": True,
        "architecture_ref": "fixtures/benchmarks/architecture/toy_sqli.json",
    }
    m = score_recon(target, oracle)
    assert m["mode"] == "mechanical"
    assert m["bench_type"] == "recon"
    assert m["component_recall"] == 1.0
    assert m["path_hint_recall"] == 1.0
    assert m["relations_ok"] is True
    assert m["trust_boundaries_ok"] is True
    assert m["score"] > 0
    assert m["passed"] is True
    assert m.get("confirmed") is False


def test_score_finding_report_mechanical_fixture():
    oracle = {
        "type": "finding_report",
        "required_fields": [
            "title",
            "summary",
            "weakness_class",
            "threat_model",
            "citations",
            "severity_claim",
        ],
        "min_citation_density": 1.0,
        "honesty_labels": ["severity_claim", "needs_human"],
        "fixture_report_ref": "fixtures/benchmarks/reports/toy_sqli_report.json",
    }
    m = score_finding_report(None, oracle)
    assert m["mode"] == "mechanical"
    assert m["bench_type"] == "finding_report"
    assert m["required_fields_recall"] == 1.0
    assert m["citation_density"] >= 1.0
    assert m["honesty_labels_recall"] == 1.0
    assert m["score"] > 0
    assert m["passed"] is True
    assert m.get("confirmed") is False


def test_run_recon_bench_terminal_with_metrics():
    run = run_benchmark(def_id="toy_sqli_recon", types=["recon"], mode="mechanical")
    assert run["def_id"] == "toy_sqli_recon"
    assert run["types_run"] == ["recon"]
    assert run["mode"] == "mechanical"
    assert run["status"] in TERMINAL_STATUSES
    assert run["status"] == "passed"
    assert run["finished_at"]
    metrics = run["metrics"]
    assert metrics.get("bench_type") == "recon"
    assert metrics.get("mode") == "mechanical"
    assert metrics.get("component_recall", 0) > 0
    assert metrics.get("relations_ok") is True
    assert metrics.get("trust_boundaries_ok") is True
    assert metrics.get("score", 0) > 0
    assert "recon" in (metrics.get("by_type") or {})
    assert get_run(run["id"])["status"] == "passed"


def test_run_finding_report_bench_terminal_with_metrics():
    run = run_benchmark(
        def_id="toy_sqli_finding_report",
        types=["finding_report"],
        mode="mechanical",
    )
    assert run["def_id"] == "toy_sqli_finding_report"
    assert run["types_run"] == ["finding_report"]
    assert run["status"] == "passed"
    metrics = run["metrics"]
    assert metrics.get("bench_type") == "finding_report"
    assert metrics.get("required_fields_recall") == 1.0
    assert metrics.get("citation_density", 0) >= 1.0
    assert metrics.get("honesty_labels_hit", 0) >= 1
    assert metrics.get("score", 0) > 0
    assert "finding_report" in (metrics.get("by_type") or {})


def test_api_recon_and_report_runs_and_refuse_poc_dev():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        recon = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli_recon", "types": ["recon"], "mode": "mechanical"},
        )
        assert recon.status_code == 200, recon.text
        rbody = recon.json()["run"]
        assert rbody["status"] == "passed"
        assert rbody["metrics"]["bench_type"] == "recon"
        assert rbody["metrics"]["score"] > 0

        report = client.post(
            "/api/benchmarks/runs",
            json={
                "def_id": "toy_sqli_finding_report",
                "types": ["finding_report"],
                "mode": "mechanical",
            },
        )
        assert report.status_code == 200, report.text
        pbody = report.json()["run"]
        assert pbody["status"] == "passed"
        assert pbody["metrics"]["bench_type"] == "finding_report"

        refuse = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["poc_dev"], "mode": "mechanical"},
        )
        assert refuse.status_code == 400
        assert "poc_dev" in refuse.text.lower()


def test_create_multi_type_def_and_run_page_lists_types():
    create_def(
        "multi_type_toy",
        name="Multi type toy",
        types=["recon", "hunt"],
        target_ref="fixtures/toy_sqli",
        oracle={
            "type": "recon",
            "components": [{"name": "app", "path_hints": ["app.py"]}],
            "require_relations": True,
            "require_trust_boundaries": True,
            "architecture_ref": "fixtures/benchmarks/architecture/toy_sqli.json",
        },
        tags=["custom"],
    )
    defs = {d["id"]: d for d in list_defs()}
    assert set(defs["multi_type_toy"]["types"]) == {"recon", "hunt"}

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        page = client.get("/benchmarks/run")
        assert page.status_code == 200
        assert "bench-run-type-filter" in page.text
        assert "finding_report" in page.text
        assert "recon" in page.text
        assert "poc_dev" not in page.text.split("bench-run-type-filter")[1].split("</select>")[0]

        lib = client.get("/api/benchmarks")
        assert lib.status_code == 200
        row = next(b for b in lib.json()["benchmarks"] if b["id"] == "multi_type_toy")
        assert "recon" in row["types"] and "hunt" in row["types"]

        # Run only recon slice
        run = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "multi_type_toy", "types": ["recon"], "mode": "mechanical"},
        )
        assert run.status_code == 200, run.text
        assert run.json()["run"]["types_run"] == ["recon"]
        assert run.json()["run"]["status"] == "passed"
