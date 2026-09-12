"""POC workshop (poc_dev) — ticket 7 prove bar."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.benchmarks import (
    TERMINAL_STATUSES,
    get_run,
    list_defs,
    run_poc_workshop,
    seed_from_ground_truth,
)
from vulnforge.paths import PROJECT_ROOT
from vulnforge.ui.app import create_app

RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"
REPORT_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report.js"


def test_seed_includes_toy_poc_dev():
    ids = {d["id"] for d in list_defs()}
    assert "toy_poc_dev" in ids
    row = next(d for d in list_defs() if d["id"] == "toy_poc_dev")
    assert row["types"] == ["poc_dev"]
    result = seed_from_ground_truth(missing_only=True)
    assert "toy_poc_dev" in result["skipped"]


def test_workshop_run_writes_benchmark_run_terminal():
    """Prove: workshop run → BenchmarkRun with poc_dev, terminal status, metrics."""
    run = run_poc_workshop(def_id="toy_poc_dev", mode="mechanical")
    assert run["def_id"] == "toy_poc_dev"
    assert run["types_run"] == ["poc_dev"]
    assert run["mode"] == "mechanical"
    assert run["status"] in TERMINAL_STATUSES
    assert run["status"] == "passed"
    assert run["finished_at"]
    metrics = run["metrics"]
    assert isinstance(metrics, dict)
    assert metrics.get("bench_type") == "poc_dev"
    assert metrics.get("confirmed") is False
    assert metrics.get("network") == "none"
    assert metrics.get("network_enforced") is True
    assert metrics.get("pack_recall") == 1.0
    assert metrics.get("poc_run_recall") == 1.0
    assert metrics.get("score", 0) > 0
    assert metrics.get("passed") is True
    assert "poc_dev" in (metrics.get("by_type") or {})
    assert run.get("harness_run_dir")
    sandbox = Path(run["harness_run_dir"])
    assert (sandbox / "poc.py").is_file()
    assert (sandbox / "poc_meta.json").is_file()
    assert (sandbox / "poc_run.json").is_file()
    # Persisted
    assert get_run(run["id"])["types_run"] == ["poc_dev"]
    assert get_run(run["id"])["status"] == "passed"


def test_api_poc_workshop_and_run_path_still_refuses():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/poc/runs",
            json={"def_id": "toy_poc_dev", "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["ok"]
        run = body["run"]
        assert run["types_run"] == ["poc_dev"]
        assert run["status"] == "passed"
        assert run["metrics"]["network"] == "none"
        assert run["metrics"]["confirmed"] is False

        refuse = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_poc_dev", "types": ["poc_dev"], "mode": "mechanical"},
        )
        assert refuse.status_code == 400
        assert "poc_dev" in refuse.text.lower()


def test_poc_workshop_page_hooks():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        page = client.get("/benchmarks/poc")
        assert page.status_code == 200
        assert 'data-bench-page="poc"' in page.text
        assert 'id="bench-poc-run"' in page.text
        assert 'id="bench-poc-def"' in page.text
        assert "/api/benchmarks/poc/runs" in page.text
        # Must not absorb Report Develop POC modal
        assert 'id="poc-modal"' not in page.text
        assert "poc-modal" not in page.text


def test_run_html_poc_modal_untouched():
    """Prove: run.html / report.js Develop POC modal markup not edited this ticket."""
    assert RUN_HTML.is_file()
    text = RUN_HTML.read_text(encoding="utf-8")
    assert 'id="poc-modal"' in text
    assert "Develop POC" in text
    # Stable fingerprint of the modal opening block (must remain present)
    assert 'role="dialog"' in text
    assert 'aria-labelledby="poc-title"' in text
    assert REPORT_JS.is_file()
    rjs = REPORT_JS.read_text(encoding="utf-8")
    assert '$("#poc-modal")' in rjs or "$('#poc-modal')" in rjs
    assert "closeDevelopPoc" in rjs or "DevelopPoc" in rjs or "poc-modal" in rjs


def test_no_live_network_contract_in_artifact():
    run = run_poc_workshop(def_id="toy_poc_dev")
    sandbox = Path(run["harness_run_dir"])
    import json

    poc_run = json.loads((sandbox / "poc_run.json").read_text(encoding="utf-8"))
    assert poc_run.get("network") == "none"
    assert poc_run.get("ok") is True
    assert run["metrics"]["poc_run_actual"]["network"] == "none"
