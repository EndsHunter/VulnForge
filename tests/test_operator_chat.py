"""Operator AI chat tools + loop (FakeLLM, no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.db import Database
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
from vulnforge.operator_chat import handle_turn, confirm_pending
from vulnforge.operator_chat.tools_common import (
    enqueue_hunt_impl,
    get_finding_impl,
    list_findings_all_impl,
    list_findings_impl,
    list_hunts_impl,
    list_runs_impl,
    read_evidence_impl,
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


def test_handle_turn_many_tool_rounds_unlimited(tmp_path: Path, toy_sqli: Path):
    """Operator chat is not clamped by llm.max_tool_rounds (was min 4 / max 12)."""
    runs_root = tmp_path / "runs"
    _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    project_root = tmp_path
    (project_root / "config").mkdir(exist_ok=True)

    n_tools = 15  # exceeds old hard cap of 12
    responses = []
    for i in range(n_tools):
        responses.append(
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[
                    {
                        "id": f"c{i}",
                        "name": "list_runs",
                        "arguments": {"filter": "all"},
                    }
                ],
                raw=None,
                model_id="fake",
            )
        )
    responses.append(
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="Done after many tool rounds.",
            tool_calls=[],
            raw=None,
            model_id="fake",
        )
    )
    fake = FakeLLMClient(responses=responses)
    # Intentionally low agent max_tool_rounds — must not apply to operator chat
    cfg = {"llm": {"model": "fake", "max_tool_rounds": 4}}
    r = handle_turn(
        scope="home",
        message="Do many tools then answer",
        project_root=project_root,
        runs_root=runs_root,
        cfg=cfg,
        client=fake,
    )
    assert r["ok"]
    texts = [m.get("content") or "" for m in r["messages"] if m.get("role") == "assistant"]
    joined = " ".join(str(t) for t in texts)
    assert "Done after many tool rounds" in joined
    assert "Stopped after max tool rounds" not in joined


def test_run_operator_loop_respects_explicit_max_rounds(tmp_path: Path, toy_sqli: Path):
    from vulnforge.operator_chat.loop import run_operator_loop

    responses = [
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="",
            tool_calls=[
                {"id": "c1", "name": "list_runs", "arguments": {"filter": "all"}}
            ],
            raw=None,
            model_id="fake",
        ),
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="",
            tool_calls=[
                {"id": "c2", "name": "list_runs", "arguments": {"filter": "all"}}
            ],
            raw=None,
            model_id="fake",
        ),
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="should not reach",
            tool_calls=[],
            raw=None,
            model_id="fake",
        ),
    ]
    fake = FakeLLMClient(responses=responses)
    result = run_operator_loop(
        client=fake,
        system="test",
        history=[],
        user_message="go",
        tools=[],
        dispatch=lambda name, args: {"ok": True, "count": 0},
        max_rounds=2,
        session_id="s1",
        scope="home",
    )
    texts = [m.get("content") or "" for m in result["messages"] if m.get("role") == "assistant"]
    assert any("Stopped after max tool rounds" in str(t) for t in texts)
    assert not any("should not reach" in str(t) for t in texts)


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


def _seed_finding_with_evidence(run: RunRef) -> int:
    pack = run.path / "evidence" / "2"
    pack.mkdir(parents=True)
    (pack / "xml_buffer_overflow.md").write_text("# overflow notes\n", encoding="utf-8")
    (pack / "poc.c").write_text("int main(){}\n", encoding="utf-8")
    db = Database.open(run.path / "harness.db")
    fid = db.insert_finding(
        stable_key="k-eap",
        state="needs_human",
        body={
            "title": "Stack buffer overflow in EAP XML parsing",
            "summary": "unbounded CopyMemory",
            "weakness_class": "memory-safety",
            "evidence_id": "2",
            "poc_relpath": "xml_buffer_overflow.md",
        },
        evidence_id="2",
    )
    db.close()
    return fid


def test_read_evidence_without_relpath_reads_pack_not_evidence_md(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    _seed_finding_with_evidence(run)

    out = read_evidence_impl(run, {"pack_id": "2"})
    assert out.get("ok") is True, out
    assert out.get("error") != "file not found"
    assert "evidence.md" not in str(out.get("path") or "")
    files = out.get("files") or []
    assert "xml_buffer_overflow.md" in files
    assert "poc.c" in files
    assert "overflow notes" in (out.get("content") or "")


def test_list_evidence_lists_pack_files(tmp_path: Path, toy_sqli: Path):
    from vulnforge.operator_chat.tools_common import list_evidence_impl

    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    _seed_finding_with_evidence(run)

    listed = list_evidence_impl(run, {"pack_id": "2"})
    assert listed.get("ok") is True, listed
    names = listed.get("files") or []
    assert "xml_buffer_overflow.md" in names
    assert "poc.c" in names

    all_packs = list_evidence_impl(run, {})
    assert all_packs.get("ok") is True
    pack_ids = [p.get("pack_id") for p in (all_packs.get("packs") or [])]
    assert "2" in pack_ids


def test_run_chat_has_list_evidence_tool():
    names = [s["function"]["name"] for s in tools_run.schemas()]
    assert "list_evidence" in names
    assert "list_findings" in names
    assert "read_evidence" in names


def test_list_findings_includes_poc_and_evidence_files(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    _seed_finding_with_evidence(run)

    out = list_findings_impl(run, {})
    assert out["count"] == 1
    row = out["findings"][0]
    assert row["evidence_id"] == "2"
    assert row.get("poc_relpath") == "xml_buffer_overflow.md"
    assert "xml_buffer_overflow.md" in (row.get("evidence_files") or [])


def test_get_finding_accepts_hash_prefixed_id(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    fid = _seed_finding_with_evidence(run)

    hashed = get_finding_impl(run, {"finding_id": f"#{fid}"})
    assert hashed.get("ok") is True, hashed
    assert hashed["finding_id"] == fid
    assert "xml_buffer_overflow.md" in (hashed.get("evidence_files") or [])

    labeled = get_finding_impl(run, {"finding_id": f"finding-{fid}"})
    assert labeled.get("ok") is True, labeled


def test_home_list_findings_alias_does_not_require_run_ids(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    _seed_finding_with_evidence(run)

    missing = tools_home.dispatch(
        "list_findings",
        {},
        runs_root=runs_root,
        project_root=tmp_path,
    )
    assert missing.get("ok") is True, missing
    assert missing.get("count") >= 1
    assert missing["findings"][0]["title"]

    scoped = tools_home.dispatch(
        "list_findings",
        {"target_id": "app-a", "run_id": "run-001"},
        runs_root=runs_root,
        project_root=tmp_path,
    )
    assert scoped.get("ok") is True, scoped
    assert scoped["count"] == 1


def test_persisted_chat_history_keeps_tool_call_ids(tmp_path: Path, toy_sqli: Path):
    from vulnforge.agent_runtime.transcript import openaiish_to_strands_messages
    from vulnforge.operator_chat.loop import run_operator_loop

    runs_root = tmp_path / "runs"
    run = _make_run(runs_root, "app-a", "run-001", target_path=toy_sqli)
    _seed_finding_with_evidence(run)

    fake = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[
                    {
                        "id": "c1",
                        "name": "list_findings",
                        "arguments": {"state": "needs_human"},
                    }
                ],
                raw=None,
                model_id="fake",
            ),
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="One finding needs review.",
                tool_calls=[],
                raw=None,
                model_id="fake",
            ),
        ]
    )
    result = run_operator_loop(
        client=fake,
        system="sys",
        history=[],
        user_message="What findings need human review?",
        tools=tools_run.schemas(),
        dispatch=lambda n, a: tools_run.dispatch(n, a, run=run),
        session_id="s1",
        scope="run",
    )
    stored = list(result["messages"] or [])
    tool_msgs = [m for m in stored if m.get("role") == "tool"]
    assert tool_msgs, stored
    assert tool_msgs[0].get("tool_call_id") == "c1"
    asst_with_calls = [
        m
        for m in stored
        if m.get("role") == "assistant" and m.get("tool_calls")
    ]
    assert asst_with_calls, stored

    strands = openaiish_to_strands_messages(stored)
    uses = []
    results = []
    for m in strands:
        for b in m.get("content") or []:
            if isinstance(b, dict) and "toolUse" in b:
                uses.append(b["toolUse"].get("toolUseId"))
            if isinstance(b, dict) and "toolResult" in b:
                results.append(b["toolResult"].get("toolUseId"))
    assert uses == ["c1"]
    assert results == ["c1"]
