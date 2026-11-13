"""Benchmark runs: single-case L0, fixture checks suite, listing and routes."""

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

        page = client.get(f"/benchmarks/runs/{rid}")
        assert page.status_code == 200
        assert 'data-bench-view="run"' in page.text
        assert f'data-run-id="{rid}"' in page.text

        old = client.get(f"/benchmarks/results/{rid}", follow_redirects=False)
        assert old.status_code == 308
        assert old.headers["location"] == f"/benchmarks/runs/{rid}"

        detail = client.get(f"/api/benchmarks/runs/{rid}").json()["run"]
        assert detail["tier"] == "l0"
        assert detail["suite_id"] is None


def test_suite_members_partition_library():
    from vulnforge.benchmarks import list_defs, suite_members, suite_of

    defs = list_defs()
    real = {d["id"] for d in suite_members("realworld", "directed", defs)}
    synth = {d["id"] for d in suite_members("synthetic", "directed", defs)}
    checks = {d["id"] for d in suite_members("fixtures", "l0", defs)}
    assert "toy_sqli" in synth and "mono_synth" in synth
    assert all(i.startswith("entry-") for i in real) and len(real) == 16
    assert not real & synth
    # Fixture checks cover every vendored case, never the un-vendored OSS trees.
    assert synth <= checks
    assert not real & checks
    assert {"toy_sqli_recon", "toy_sqli_finding_report"} <= checks
    # Directed is hunt-only; poc_dev is retired.
    by_id = {d["id"]: d for d in defs}
    for bid in real | synth:
        assert "hunt" in by_id[bid]["types"]
    assert all("poc_dev" not in d["types"] for d in defs)
    assert suite_of({"types": ["hunt"], "tags": ["suite:realworld"], "target_ref": "fixtures/x"}) == "realworld"


def test_api_fixture_checks_one_parent_plus_children():
    """Fixture checks are one suite-fixtures parent (tier l0); each case is a child."""
    from vulnforge.benchmarks import list_defs, suite_members

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post("/api/benchmarks/runs", json={"suite": "fixtures", "tier": "l0", "note": "ci"})
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["ok"] and body.get("suite") is True
        run = body["run"]
        assert run["def_id"] == "suite-fixtures"
        assert run["suite_id"] == "fixtures"
        assert run["tier"] == "l0"
        assert run["note"] == "ci"
        assert run["status"] in TERMINAL_STATUSES
        metrics = run["metrics"]
        assert metrics.get("suite") is True
        assert metrics.get("confirmed") is False
        expect = [d["id"] for d in suite_members("fixtures", "l0", list_defs())]
        members = metrics.get("members") or []
        assert [m["def_id"] for m in members] == expect
        by = {m["def_id"]: m for m in members}
        assert by["toy_sqli_recon"]["status"] == "passed"
        assert by["toy_sqli"]["status"] == "passed"
        assert metrics["count"] == len(expect)
        child_ids = metrics.get("member_run_ids") or []
        assert len(child_ids) == len(expect)
        child = client.get(f"/api/benchmarks/runs/{child_ids[0]}").json()["run"]
        assert child["parent_id"] == run["id"]
        assert child["tier"] == "l0"

        parents = client.get("/api/benchmarks/runs", params={"suite": "true"})
        parent_ids = [r["id"] for r in parents.json()["runs"]]
        assert run["id"] in parent_ids
        assert not any(cid in parent_ids for cid in child_ids)
        kids = client.get("/api/benchmarks/runs", params={"suite": "false"})
        kid_ids = [r["id"] for r in kids.json()["runs"]]
        assert run["id"] not in kid_ids
        assert all(cid in kid_ids for cid in child_ids)
        by_suite = client.get("/api/benchmarks/runs", params={"suite_id": "fixtures", "tier": "l0"})
        assert [r["id"] for r in by_suite.json()["runs"]] == [run["id"]]
        mixed = client.get("/api/benchmarks/runs", params={"sort": "started_at", "order": "desc"})
        mixed_ids = [r["id"] for r in mixed.json()["runs"]]
        assert mixed_ids.index(run["id"]) < min(mixed_ids.index(cid) for cid in child_ids)

        suites = client.get("/api/benchmarks/suites").json()
        fx = next(s for s in suites["suites"] if s["id"] == "fixtures")
        assert fx["runs"]["l0"]["latest"]["id"] == run["id"]


def test_api_suite_run_refusals():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        bad_tier = client.post("/api/benchmarks/runs", json={"suite": "synthetic", "tier": "l0"})
        assert bad_tier.status_code == 400
        missing = client.post("/api/benchmarks/runs", json={})
        assert missing.status_code == 400
        # Retired type-based suites are no longer accepted as def ids.
        legacy = client.post("/api/benchmarks/runs", json={"def_id": "all-recon", "mode": "mechanical"})
        assert legacy.status_code in (400, 404)


def test_list_runs_started_at_parent_before_later_children():
    """Child started_at one second later still lists after the suite parent."""
    import json

    from vulnforge.benchmarks import create_run, runs_root, update_run

    parent = create_run(
        def_id="all-recon", version=1, types_run=["recon"], status="passed"
    )
    early_child = create_run(
        def_id="toy_a", version=1, types_run=["recon"], status="passed"
    )
    late_child = create_run(
        def_id="toy_b", version=1, types_run=["recon"], status="passed"
    )
    between = create_run(
        def_id="toy_mid", version=1, types_run=["hunt"], status="passed"
    )
    newer = create_run(
        def_id="toy_sqli", version=1, types_run=["hunt"], status="passed"
    )
    update_run(
        parent["id"],
        metrics={
            "suite": True,
            "member_run_ids": [early_child["id"], late_child["id"]],
        },
    )
    stamps = {
        parent["id"]: "2026-01-01T00:00:00Z",
        early_child["id"]: "2026-01-01T00:00:01Z",
        between["id"]: "2026-01-01T00:00:03Z",
        late_child["id"]: "2026-01-01T00:00:05Z",
        newer["id"]: "2026-01-02T00:00:00Z",
    }
    root = runs_root()
    for rid, ts in stamps.items():
        path = root / rid / "result.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["started_at"] = ts
        path.write_text(json.dumps(raw), encoding="utf-8")

    children_asc = sorted([early_child["id"], late_child["id"]])
    children_desc = list(reversed(children_asc))
    asc_ids = [
        parent["id"],
        *children_asc,
        between["id"],
        newer["id"],
    ]
    desc_ids = [
        newer["id"],
        between["id"],
        parent["id"],
        *children_desc,
    ]
    assert [r["id"] for r in list_runs(sort="started_at", order="asc")] == asc_ids
    assert [r["id"] for r in list_runs(sort="started_at", order="desc")] == desc_ids

    # suite filter still drops the parent or the children; ungrouped children
    # fall back to their own started_at.
    assert [r["id"] for r in list_runs(suite=True, sort="started_at", order="asc")] == [
        parent["id"]
    ]
    assert [r["id"] for r in list_runs(suite=False, sort="started_at", order="asc")] == [
        early_child["id"],
        between["id"],
        late_child["id"],
        newer["id"],
    ]

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        listed = client.get(
            "/api/benchmarks/runs",
            params={"sort": "started_at", "order": "desc"},
        )
        assert listed.status_code == 200
        assert [r["id"] for r in listed.json()["runs"]] == desc_ids
