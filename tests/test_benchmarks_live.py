"""Live hunt evals on the BenchmarkRun contract (no real LLM / Ralph)."""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from vulnforge.benchmarks import (
    TERMINAL_STATUSES,
    HuntHint,
    defs_for_suite,
    eval_runs_root_for,
    live_refusal,
    reconcile_live_run,
    start_live_run,
    start_live_suite,
)
from vulnforge.benchmarks.live import (
    enqueue_eval_hunt,
    hunt_hints_from_oracle,
    packet_leaks_oracle,
    score_live_hunt,
)
from vulnforge.benchmarks.runner import run_benchmark, run_benchmark_suite
from vulnforge.benchmarks.runs import BenchmarkRunError, create_run, get_run, update_run
from vulnforge.benchmarks.store import get_version
from vulnforge.paths import PROJECT_ROOT
from vulnforge.ui.app import create_app


def _llm_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulnforge.benchmarks.live.load_config",
        lambda: {"llm": {"base_url": "http://127.0.0.1:9/v1", "model": "test-model"}},
    )


def _hold_live(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject a no-op worker so POST returns running without Ralph."""
    orig = start_live_run
    orig_suite = start_live_suite

    def wrapped_run(*, def_id, version=None, types=None, worker=None):
        return orig(
            def_id=def_id,
            version=version,
            types=types,
            worker=worker or (lambda _rid: None),
        )

    def wrapped_suite(*, types=None, only=None, worker=None):
        return orig_suite(
            types=types,
            only=only,
            worker=worker or (lambda _rid: None),
        )

    monkeypatch.setattr("vulnforge.benchmarks.api.start_live_run", wrapped_run)
    monkeypatch.setattr("vulnforge.benchmarks.api.start_live_suite", wrapped_suite)


def test_run_benchmark_live_mode_raises():
    with pytest.raises(BenchmarkRunError, match="start_live_run"):
        run_benchmark(def_id="toy_sqli", types=["hunt"], mode="live")
    with pytest.raises(BenchmarkRunError, match="start_live_run"):
        run_benchmark_suite(types=["hunt"], mode="live")


def test_api_live_recon_errors_without_ralph(monkeypatch):
    _llm_ok(monkeypatch)
    spawned: list[str] = []
    monkeypatch.setattr(
        "vulnforge.benchmarks.live._spawn_daemon",
        lambda fn, rid: spawned.append(rid),
    )
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        r = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli_recon", "types": ["recon"], "mode": "live"},
        )
        assert r.status_code == 200, r.text
        run = r.json()["run"]
        assert run["status"] == "error"
        assert "hunt" in (run.get("error") or "").lower()
        assert run.get("harness_run_dir") in (None, "")
        assert spawned == []


def test_api_live_hunt_injected_worker_then_get_terminal(monkeypatch):
    _llm_ok(monkeypatch)

    def write_passed(run_id: str) -> None:
        update_run(
            run_id,
            status="passed",
            metrics={
                "mode": "live",
                "confirmed": False,
                "recall": 1.0,
                "passed": True,
                "hit_count": 1,
                "oracle_count": 1,
            },
        )

    orig = start_live_run

    def wrapped(*, def_id, version=None, types=None, worker=None):
        return orig(
            def_id=def_id,
            version=version,
            types=types,
            worker=worker or write_passed,
        )

    monkeypatch.setattr("vulnforge.benchmarks.api.start_live_run", wrapped)

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "live"},
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body.get("ok") is True
        assert body.get("async") is True
        run = body["run"]
        assert run["mode"] == "live"
        assert run["status"] in {"queued", "running", "passed"}
        assert (run.get("metrics") or {}).get("confirmed") is False
        rid = run["id"]
        detail = client.get(f"/api/benchmarks/runs/{rid}")
        assert detail.status_code == 200, detail.text
        got = detail.json()["run"]
        assert got["status"] in TERMINAL_STATUSES
        assert got["status"] == "passed"
        assert got["metrics"]["confirmed"] is False


def test_api_second_live_post_conflicts(monkeypatch):
    _llm_ok(monkeypatch)
    _hold_live(monkeypatch)
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        first = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "live"},
        )
        assert first.status_code == 200, first.text
        run = first.json()["run"]
        assert run["status"] in {"queued", "running"}
        second = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "live"},
        )
        assert second.status_code == 409
        detail = second.json()["detail"]
        assert detail["run_id"] == run["id"]


def test_api_active_lists_held_live_run(monkeypatch):
    _llm_ok(monkeypatch)
    _hold_live(monkeypatch)
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        empty = client.get("/api/benchmarks/runs/active")
        assert empty.status_code == 200, empty.text
        assert empty.json()["runs"] == []
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "live"},
        )
        assert created.status_code == 200, created.text
        rid = created.json()["run"]["id"]
        active = client.get("/api/benchmarks/runs/active")
        assert active.status_code == 200, active.text
        ids = [r["id"] for r in active.json()["runs"]]
        assert rid in ids
        assert all(r["status"] in {"queued", "running"} for r in active.json()["runs"])


def test_live_refusal_and_hunt_hint_leak():
    assert live_refusal(types=["recon"], suite=False, def_id="toy_sqli_recon")
    assert "hunt" in (live_refusal(types=["recon"], suite=False, def_id="toy_sqli_recon") or "")
    assert live_refusal(types=["hunt"], suite=True, def_id="all-recon")
    assert live_refusal(types=["hunt"], suite=False, def_id="toy_sqli") is None

    snap = get_version("entry-00080", 1)
    oracle = snap.get("oracle") if isinstance(snap.get("oracle"), dict) else {}
    hints = hunt_hints_from_oracle(oracle)
    assert hints
    hint = hints[0]
    assert isinstance(hint, HuntHint)
    finding = (oracle.get("findings") or [None])[0]
    assert isinstance(finding, dict)
    payload = {
        "area": "eval",
        "class": hint.attack_class,
        "path_hints": [hint.path],
        "selection": {"path": hint.path, "start_line": None, "end_line": None},
    }
    assert packet_leaks_oracle(payload) is None
    leaked = dict(payload)
    leaked["report_id"] = finding.get("report_id")
    assert packet_leaks_oracle(leaked)
    ghsa = dict(payload)
    ghsa["notes"] = str(finding.get("report_id") or "GHSA-78H3-63C4-5FQC")
    assert packet_leaks_oracle(ghsa)


def test_enqueue_eval_hunt_rejects_oracle_payload(monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    def fake_hunt(run_dir, **kwargs):
        captured.update(kwargs)
        captured["run_dir"] = run_dir
        return {
            "ok": True,
            "payload": {
                "area": kwargs.get("area"),
                "class": kwargs.get("attack_class"),
                "path_hints": [kwargs.get("path")],
                "selection": {
                    "path": kwargs.get("path"),
                    "start_line": kwargs.get("start_line"),
                },
            },
        }

    monkeypatch.setattr("vulnforge.control.ops.hunt_from_selection", fake_hunt)
    hint = HuntHint(path="app.py", attack_class="injection")
    r = enqueue_eval_hunt(tmp_path, hint)
    assert r.get("ok") is True
    assert captured.get("area") == "eval"
    assert "operator_notes" not in captured or not captured.get("operator_notes")
    assert captured.get("start_line") is None
    payload = r.get("payload") or {}
    assert payload.get("selection", {}).get("start_line") is None
    assert "report_id" not in payload
    assert "GHSA-" not in str(payload)
    assert "operator_notes" not in payload

    def leak_hunt(run_dir, **kwargs):
        return {
            "ok": True,
            "payload": {
                "class": kwargs.get("attack_class"),
                "path_hints": [kwargs.get("path")],
                "report_id": "GHSA-AAAA-BBBB-CCCC",
                "title": "secret",
            },
        }

    monkeypatch.setattr("vulnforge.control.ops.hunt_from_selection", leak_hunt)
    bad = enqueue_eval_hunt(tmp_path, hint)
    assert bad.get("ok") is False
    assert "GHSA" in (bad.get("error") or "") or "oracle" in (bad.get("error") or "")


def test_eval_runs_root_for_is_isolated():
    root = eval_runs_root_for("br-aaaaaaaaaaaa")
    assert "eval_runs" in root.parts
    operator_runs = (PROJECT_ROOT / "runs").resolve()
    assert root != operator_runs
    assert operator_runs not in root.parents
    assert "runs_root" not in inspect.signature(eval_runs_root_for).parameters


def test_score_live_hunt_counts_rejected_mech(monkeypatch, tmp_path):
    class FakeDB:
        def __init__(self, *args, **kwargs):
            pass

        def list_findings(self, states=None):
            assert states is None
            return [
                SimpleNamespace(
                    id=1,
                    stable_key="k",
                    state="rejected_mech",
                    body={
                        "sink_path": "app.py",
                        "sink_symbol": "search_users",
                        "citations": [
                            {
                                "path": "app.py",
                                "start_line": 12,
                                "symbol": "search_users",
                            }
                        ],
                    },
                )
            ]

        def close(self):
            pass

    monkeypatch.setattr("vulnforge.db.Database", FakeDB)
    snap = get_version("toy_sqli", 1)
    oracle = snap.get("oracle") if isinstance(snap.get("oracle"), dict) else {}
    findings = [f for f in (oracle.get("findings") or []) if isinstance(f, dict)]
    sc = score_live_hunt(tmp_path / "run-001", findings)
    assert sc["confirmed"] is False
    assert sc["mode"] == "live"
    assert sc["hit_count"] >= 1
    assert sc["passed"] is True


def test_reconcile_live_run_terminal_is_noop(monkeypatch):
    _llm_ok(monkeypatch)
    run = start_live_run(
        def_id="toy_sqli",
        types=["hunt"],
        worker=lambda rid: update_run(
            rid,
            status="passed",
            metrics={"mode": "live", "confirmed": False, "passed": True},
        ),
    )
    assert run["status"] == "passed"
    again = reconcile_live_run(run["id"])
    assert again["status"] == "passed"
    assert again["finished_at"] == run["finished_at"]
    assert again["metrics"]["confirmed"] is False


def test_reconcile_dead_ralph_scores_and_closes(monkeypatch, tmp_path):
    harness = tmp_path / "eval" / "tgt" / "run-001"
    harness.mkdir(parents=True)
    (harness / "harness.db").write_text("", encoding="utf-8")
    row = create_run(
        def_id="toy_sqli",
        version=1,
        types_run=["hunt"],
        mode="live",
        status="running",
    )
    update_run(
        row["id"],
        harness_run_dir=str(harness),
        metrics={"mode": "live", "confirmed": False, "live": {"phase": "ralph"}},
    )
    monkeypatch.setattr(
        "vulnforge.benchmarks.live.runner_status",
        lambda _p: {"alive": False},
    )

    class FakeDB:
        def __init__(self, *args, **kwargs):
            pass

        def has_queued_or_leased(self):
            return False

        def list_findings(self, states=None):
            return [
                SimpleNamespace(
                    id=1,
                    stable_key="k",
                    state="needs_human",
                    body={
                        "sink_path": "app.py",
                        "sink_symbol": "search_users",
                        "citations": [{"path": "app.py", "symbol": "search_users"}],
                    },
                )
            ]

        def close(self):
            pass

    monkeypatch.setattr("vulnforge.db.Database", FakeDB)
    closed = reconcile_live_run(row["id"])
    assert closed["status"] in {"passed", "failed"}
    assert closed["metrics"]["confirmed"] is False
    assert closed["metrics"]["live"]["phase"] == "done"


def test_start_live_suite_hold_worker_has_members(monkeypatch):
    _llm_ok(monkeypatch)
    driven: list[str] = []
    parent = start_live_suite(types=["hunt"], worker=lambda rid: driven.append(rid))
    assert parent["def_id"] == "all-hunt"
    assert parent["status"] == "running"
    ids = parent["metrics"]["member_run_ids"]
    expect = [d["id"] for d, _ in defs_for_suite(["hunt"])]
    assert len(ids) == len(expect)
    assert driven == [parent["id"]]
    child = get_run(ids[0])
    assert child["mode"] == "live"
    assert child["status"] == "queued"


def test_live_all_recon_errors_without_children(monkeypatch):
    _llm_ok(monkeypatch)
    driven: list[str] = []
    parent = start_live_suite(
        types=["recon"],
        worker=lambda rid: driven.append(rid),
    )
    assert parent["status"] == "error"
    assert "hunt" in (parent.get("error") or "").lower()
    assert not (parent.get("metrics") or {}).get("member_run_ids")
    assert driven == []


def test_mechanical_post_still_blocking_passed():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "mechanical"},
        )
        assert created.status_code == 200, created.text
        run = created.json()["run"]
        assert run["status"] == "passed"
        assert created.json().get("async") is not True


def test_run_page_has_live_button():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        page = client.get("/benchmarks/run")
        assert page.status_code == 200
        assert 'id="bench-run-live"' in page.text
        assert 'mode: "live"' in page.text


def test_cancel_live_run_via_stop(monkeypatch):
    _llm_ok(monkeypatch)
    _hold_live(monkeypatch)
    stopped: list[str] = []
    monkeypatch.setattr(
        "vulnforge.benchmarks.live.stop_run_hard",
        lambda path: stopped.append(str(path)),
    )
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks/runs",
            json={"def_id": "toy_sqli", "types": ["hunt"], "mode": "live"},
        )
        rid = created.json()["run"]["id"]
        update_run(rid, harness_run_dir=str(Path("/tmp/vf-eval-fake")))
        stopped_resp = client.post(f"/api/benchmarks/runs/{rid}/stop")
        assert stopped_resp.status_code == 200, stopped_resp.text
        run = stopped_resp.json()["run"]
        assert run["status"] == "cancelled"
        assert stopped


def test_write_live_overlay_pins_settings_api_mode(tmp_path, monkeypatch):
    from vulnforge.benchmarks.live import live_config_from_settings, write_live_overlay
    from vulnforge.benchmarks import runs as runs_mod
    import yaml

    monkeypatch.setattr(runs_mod, "runs_root", lambda: tmp_path)
    monkeypatch.setattr(
        "vulnforge.benchmarks.live.runs_root", lambda: tmp_path
    )
    cfg = {
        "llm": {
            "base_url": "http://127.0.0.1:9/v1",
            "model": "bench-model",
            "api_mode": "Responses",
            "api_key": "k",
        },
        "run": {},
        "stages": {"validate_llm": True},
        "packet": {},
        "tools": {},
    }
    live = live_config_from_settings("br-testoverlay01", cfg)
    assert live.api_mode == "responses"
    path = write_live_overlay("br-testoverlay01", cfg)
    assert path.is_file()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["llm"]["api_mode"] == "responses"
    assert data["llm"]["model"] == "bench-model"
    assert data["stages"]["validate_llm"] is False
