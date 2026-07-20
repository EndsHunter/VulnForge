"""Operator AI chat tools + loop (FakeLLM, no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.db import Database
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
from vulnforge.operator_chat import handle_turn, confirm_pending
from vulnforge.operator_chat.tools_common import (
    enqueue_hunt_impl,
    list_findings_all_impl,
    list_hunts_impl,
    list_runs_impl,
    rollup_results_impl,
)
from vulnforge.operator_chat import tools_home, tools_run
from vulnforge.ui.store import RunRef


def _make_run(runs_root: Path, target_id: str, run_id: str, *, target_path: Path) -> RunRef:
    run = runs_root / target_id / run_id
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    (run / "project").mkdir()
    (run / "transcripts").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run(
        run_id,
        target_path=str(target_path),
        profile="code_static",
        prompt_pin="test",
        config={},
    )
    db.close()
    return RunRef(target_id=target_id, run_id=run_id, path=run.resolve())


def test_list_runs_and_findings_fleet(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    r1 = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    r2 = _make_run(runs_root, "app-b", "run-001", target_path=toy_sqli)

    db = Database.open(r1.path / "harness.db")
    db.insert_finding(
        stable_key="k1",
        state="needs_human",
        body={"title": "SQLi", "summary": "bad query", "weakness_class": "injection"},
        evidence_id="e1",
    )
    db.close()
    db = Database.open(r2.path / "harness.db")
    db.insert_finding(
        stable_key="k2",
        state="confirmed",
        body={"title": "XSS", "summary": "reflected", "weakness_class": "client-side"},
        evidence_id=None,
    )
    db.close()

    listed = list_runs_impl(runs_root, {"filter": "all"})
    assert listed["ok"]
    assert listed["count"] >= 2

    all_f = list_findings_all_impl(runs_root, {"state": "needs_human"})
    assert all_f["ok"]
    assert all_f["count"] == 1
    assert all_f["findings"][0]["title"] == "SQLi"
    assert all_f["findings"][0]["target_id"] == "app-a"

    roll = rollup_results_impl(runs_root, {})
    assert roll["ok"]
    assert roll["count"] >= 2


def test_enqueue_and_list_hunts(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    r = enqueue_hunt_impl(
        run,
        {
            "class": "injection",
            "area": "app",
            "paths": ["app.py"],
            "notes": "from test",
        },
    )
    assert r.get("ok"), r
    assert r.get("task_id")
    hunts = list_hunts_impl(run, {"class": "injection"})
    assert hunts["ok"]
    assert hunts["count"] >= 1
    assert hunts["hunts"][0]["class"] == "injection"


def test_home_mutate_requires_confirm_flag(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    out = tools_home.dispatch(
        "enqueue_hunt",
        {
            "target_id": "app-a",
            "run_id": "run-001",
            "class": "injection",
            "area": "app",
        },
        runs_root=runs_root,
        project_root=tmp_path,
        execute_mutations=False,
    )
    assert out.get("pending_confirm") is True

    out2 = tools_home.dispatch(
        "enqueue_hunt",
        {
            "target_id": "app-a",
            "run_id": "run-001",
            "class": "injection",
            "area": "app",
        },
        runs_root=runs_root,
        project_root=tmp_path,
        execute_mutations=True,
    )
    assert out2.get("ok") is True
    assert out2.get("task_id")


def test_run_dispatch_list_hunts(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    db = Database.open(run.path / "harness.db")
    db.enqueue_task("hunt", {"area": "x", "class": "wildcard"}, priority=40)
    db.close()
    out = tools_run.dispatch("list_hunts", {}, run=run, execute_mutations=False)
    assert out["ok"]
    assert out["count"] == 1


def test_handle_turn_fake_llm_tool_loop(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    project_root = tmp_path
    (project_root / "config").mkdir(exist_ok=True)

    fake = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[
                    {
                        "id": "c1",
                        "name": "list_runs",
                        "arguments": {"filter": "all"},
                    }
                ],
                raw=None,
                model_id="fake",
            ),
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="You have at least one run listed.",
                tool_calls=[],
                raw=None,
                model_id="fake",
            ),
        ]
    )
    cfg = {"llm": {"model": "fake", "base_url": "http://127.0.0.1:9/v1"}}
    r = handle_turn(
        scope="home",
        message="List my runs",
        project_root=project_root,
        runs_root=runs_root,
        cfg=cfg,
        client=fake,
    )
    assert r["ok"]
    assert r["session_id"]
    roles = [m["role"] for m in r["messages"]]
    assert "tool" in roles
    assert any(m.get("role") == "assistant" and "run" in (m.get("content") or "").lower() for m in r["messages"])


def test_confirm_enqueue_flow(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    project_root = tmp_path
    (project_root / "config").mkdir(exist_ok=True)

    fake = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="I'll enqueue that.",
                tool_calls=[
                    {
                        "id": "c1",
                        "name": "enqueue_hunt",
                        "arguments": {
                            "target_id": "app-a",
                            "run_id": "run-001",
                            "class": "injection",
                            "area": "app",
                        },
                    }
                ],
                raw=None,
                model_id="fake",
            ),
        ]
    )
    cfg = {"llm": {"model": "fake"}}
    r = handle_turn(
        scope="home",
        message="Hunt injection on app-a/run-001",
        project_root=project_root,
        runs_root=runs_root,
        cfg=cfg,
        client=fake,
    )
    assert r.get("pending_confirm")
    token = r["pending_confirm"]["token"]
    sid = r["session_id"]

    # no hunt yet (confirm pending)
    hunts = list_hunts_impl(run, {})
    assert hunts["count"] == 0

    conf = confirm_pending(
        token=token,
        session_id=sid,
        scope="home",
        project_root=project_root,
        runs_root=runs_root,
        cfg=cfg,
        client=FakeLLMClient(
            responses=[
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="Hunt enqueued.",
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                )
            ]
        ),
    )
    assert conf["ok"]
    hunts2 = list_hunts_impl(run, {})
    assert hunts2["count"] == 1


def test_api_chat_routes_smoke(tmp_path: Path, toy_sqli: Path, monkeypatch):
    from fastapi.testclient import TestClient
    from vulnforge.ui.app import create_app
    from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass

    runs_root = tmp_path / "runs"
    _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    app = create_app(runs_root=runs_root)
    app.state.project_root = tmp_path
    (tmp_path / "config").mkdir(exist_ok=True)

    fake = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="hi",
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )

    import vulnforge.operator_chat.service as svc

    real_handle = svc.handle_turn

    def _wrapped(**kwargs):
        kwargs["client"] = fake
        return real_handle(**kwargs)

    monkeypatch.setattr(svc, "handle_turn", _wrapped)
    # re-import path used by app is package level
    import vulnforge.operator_chat as oc

    monkeypatch.setattr(oc, "handle_turn", _wrapped)

    client = TestClient(app)
    res = client.get("/chat")
    assert res.status_code == 200
    res = client.post("/api/chat", json={"message": "hello"})
    assert res.status_code == 200
    body = res.json()
    assert body.get("session_id")
    assert body.get("messages")
