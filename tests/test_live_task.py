"""Live task pane progress + bounded mid-task steer (issue #47)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.agent_runtime import run_tool_loop
from vulnforge.agent_runtime.strands_loop import apply_steer_before_model
from vulnforge.db import Database
from vulnforge.live_task import (
    add_operator_note,
    apply_round_boundary,
    bind_task,
    operator_force_active,
    read_live_view,
    record_tool_call,
    request_abort,
    request_force_submit_none,
    summarize_args,
    unbind_task,
)
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
from vulnforge.packet import Packet
from vulnforge.stages.hunt import shallow_none_should_requeue
from vulnforge.ui.app import create_app


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "toy" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run(
        "run-001",
        str(tmp_path),
        "code_static",
        "pin",
        {"run": {"profile": "code_static"}, "llm": {"max_tool_rounds": 8}},
    )
    db.enqueue_task(
        "hunt",
        {"area": "api", "class": "injection", "path_hints": ["app.py"]},
        priority=40,
    )
    db.enqueue_task("recon", {"agent": "default-map"}, priority=10)
    db.insert_finding(
        {
            "title": "keep me",
            "sink_path": "app.py",
            "sink_symbol": "query",
            "class": "injection",
        },
        state="needs_human",
    )
    db.conn.execute(
        """
        UPDATE tasks
        SET state='leased', lease_owner='operator-test', lease_until='2099-01-01T00:00:00Z',
            attempt=1
        WHERE id=1
        """
    )
    db.conn.commit()
    db.close()
    return run


def _finding_state(run: Path) -> list[tuple[int, str]]:
    db = Database.open(run / "harness.db")
    try:
        rows = db.conn.execute("SELECT id, state FROM findings ORDER BY id").fetchall()
        return [(int(r["id"]), str(r["state"])) for r in rows]
    finally:
        db.close()


def test_summarize_args_is_one_line_and_bounded():
    text = summarize_args({"path": "app.py", "pattern": "SELECT " + ("x" * 200), "operator_forced": True})
    assert "\n" not in text
    assert "operator_forced" not in text
    assert "path=app.py" in text
    assert len(text) <= 180


def test_record_tool_round_and_event(tmp_path: Path):
    run = _run(tmp_path)
    token = bind_task(run, 1, "hunt", 8)
    try:
        record_tool_call("grep", {"pattern": "SELECT", "path": "app.py"}, {"ok": True})
        record_tool_call("read_file", {"path": "app.py"}, {"ok": True, "content": "secret"})
    finally:
        unbind_task(token)
    view = read_live_view(run, 1)
    assert view["round"] == 1
    assert view["max_rounds"] == 8
    assert [s["tool"] for s in view["steps"]] == ["grep", "read_file"]
    assert "secret" not in json.dumps(view)
    assert "SELECT" in view["steps"][0]["args_summary"]
    events = (run / "events.jsonl").read_text(encoding="utf-8")
    assert "task_step" in events
    assert "grep" in events


def test_note_is_injected_once_and_does_not_touch_findings(tmp_path: Path):
    run = _run(tmp_path)
    before = _finding_state(run)
    added = add_operator_note(run, 1, "  focus the login query  ")
    assert added["ok"] is True
    assert _finding_state(run) == before
    schema = [{"type": "function", "function": {"name": "read_file"}}]
    seen: list[str] = []

    def handler(name, args):
        seen.append(name)
        return {"ok": True}

    token = bind_task(run, 1, "hunt", 4)
    try:
        first = apply_round_boundary(handler, schema)
        second = apply_round_boundary(handler, schema)
    finally:
        unbind_task(token)
    assert first["action"] == "note"
    assert "focus the login query" in first["note_text"]
    assert "does not confirm" in first["note_text"]
    assert second["action"] == "none"
    assert seen == []
    assert _finding_state(run) == before


def test_force_submit_none_at_boundary_skips_model_tool(tmp_path: Path):
    run = _run(tmp_path)
    before = _finding_state(run)
    queued = request_force_submit_none(run, 1, "operator says stop with none")
    assert queued["ok"] is True
    called: list[tuple[str, bool]] = []

    def handler(name, args):
        called.append((name, operator_force_active()))
        assert name == "submit_none"
        assert "stop with none" in args["reason"]
        return {"ok": True, "stored": "none"}

    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[{"id": "1", "name": "read_file", "arguments": {"path": "app.py"}}],
                raw=None,
                model_id="fake",
            )
        ]
    )
    packet = Packet(
        system="sys",
        user="hunt",
        tools_schema=[
            {"type": "function", "function": {"name": "read_file"}},
            {"type": "function", "function": {"name": "submit_none"}},
        ],
    )
    token = bind_task(run, 1, "hunt", 6)
    try:
        result = run_tool_loop(client, packet, handler, max_rounds=4, temperature=0.1)
    finally:
        unbind_task(token)
    assert result.ok is True
    assert result.raw.get("operator_forced_submit_none") is True
    assert called == [("submit_none", True)]
    assert "read_file" not in [name for name, _ in called]
    view = read_live_view(run, 1)
    assert view["steps"][-1]["tool"] == "submit_none"
    assert _finding_state(run) == before


def test_abort_beats_force_and_does_not_call_tools(tmp_path: Path):
    run = _run(tmp_path)
    request_force_submit_none(run, 1, "should not run")
    request_abort(run, 1, "operator_abort")
    called: list[str] = []

    def handler(name, args):
        called.append(name)
        return {"ok": True, "stored": "none"}

    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[{"id": "1", "name": "submit_candidate", "arguments": {"title": "x"}}],
                raw=None,
                model_id="fake",
            )
        ]
    )
    packet = Packet(
        system="sys",
        user="hunt",
        tools_schema=[{"type": "function", "function": {"name": "submit_none"}}],
    )
    token = bind_task(run, 1, "hunt", 4)
    try:
        result = run_tool_loop(client, packet, handler, max_rounds=3, temperature=0)
    finally:
        unbind_task(token)
    assert result.ok is False
    assert result.error == "operator_abort"
    assert called == []
    blob = json.dumps(result.transcript)
    assert "submit_candidate" not in blob


def test_shallow_requeue_skipped_when_operator_forced_none():
    session = {"operator_forced_submit_none": True}
    assert shallow_none_should_requeue(session, {}, True) is False
    assert shallow_none_should_requeue({}, {}, True) is True
    assert shallow_none_should_requeue({}, {"force_depth": True}, True) is False


def test_strands_hook_force_cancels_without_rewriting_a_chosen_tool(tmp_path: Path):
    run = _run(tmp_path)
    request_force_submit_none(run, 1, "boundary none")

    class Agent:
        def __init__(self) -> None:
            self.messages: list[dict] = []
            self.cancelled = False

        def cancel(self) -> None:
            self.cancelled = True

    agent = Agent()
    session: dict = {}
    called: list[str] = []

    def handler(name, args):
        called.append(name)
        return {"ok": True, "stored": "none"}

    token = bind_task(run, 1, "hunt", 5)
    try:
        apply_steer_before_model(
            agent,
            session,
            handler,
            [{"type": "function", "function": {"name": "submit_none"}}],
        )
    finally:
        unbind_task(token)
    assert agent.cancelled is True
    assert called == ["submit_none"]
    assert session.get("terminal_ok") is True
    assert session.get("terminal_tool") == "submit_none"
    assert agent.messages == []


def test_api_steer_never_changes_findings(tmp_path: Path):
    run = _run(tmp_path)
    before = _finding_state(run)
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as client:
        live = client.get("/api/runs/toy/run-001/tasks/1/live")
        assert live.status_code == 200
        body = live.json()
        assert body["state"] == "leased"
        assert body["kind"] == "hunt"
        assert body["steps"] == []

        queued = client.post(
            "/api/runs/toy/run-001/tasks/2/steer/note",
            json={"note": "nope"},
        )
        assert queued.status_code == 400

        note = client.post(
            "/api/runs/toy/run-001/tasks/1/steer/note",
            json={"note": "check the binder"},
        )
        assert note.status_code == 200
        assert note.json()["ok"] is True

        recon = client.post(
            "/api/runs/toy/run-001/tasks/2/steer/submit_none",
            json={"reason": "no"},
        )
        assert recon.status_code == 400

        # Recon is queued; lease it and confirm hunt-only.
        db = Database.open(run / "harness.db")
        db.conn.execute(
            """
            UPDATE tasks SET state='leased', lease_owner='operator-test',
                lease_until='2099-01-01T00:00:00Z' WHERE id=2
            """
        )
        db.conn.commit()
        db.close()
        recon_leased = client.post(
            "/api/runs/toy/run-001/tasks/2/steer/submit_none",
            json={"reason": "no"},
        )
        assert recon_leased.status_code == 400
        assert "hunt-only" in recon_leased.json()["detail"]

        forced = client.post(
            "/api/runs/toy/run-001/tasks/1/steer/submit_none",
            json={"reason": "operator stop"},
        )
        assert forced.status_code == 200
        assert forced.json()["confirms_findings"] is False

        aborted = client.post(
            "/api/runs/toy/run-001/tasks/1/steer/abort",
            json={"reason": "operator_abort"},
        )
        assert aborted.status_code == 200
        assert aborted.json()["state"] == "cancelled"
        assert aborted.json()["confirms_findings"] is False

    assert _finding_state(run) == before
    db = Database.open(run / "harness.db")
    try:
        task = db.get_task(1)
        assert task is not None
        assert task.state == "cancelled"
        assert db.conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"] == 1
    finally:
        db.close()


def test_live_pane_markup_present():
    root = Path(__file__).resolve().parents[1]
    html = (root / "vulnforge/ui/templates/run.html").read_text(encoding="utf-8")
    js = (root / "vulnforge/ui/static/app.js").read_text(encoding="utf-8")
    assert 'id="live-task-modal"' in html
    assert "task-live-btn" in js
    assert "openLiveTask" in js
    assert "does not confirm" in js
    assert "Force task #" in js
    assert "Abort task #" in js
