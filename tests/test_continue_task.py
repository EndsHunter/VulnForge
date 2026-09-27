"""Context-window continuation: continue_hunt / continue_recon + mechanical fallback."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from vulnforge.agent_runtime.context_watch import (
    continue_tool_from_schema,
    estimate_messages_tokens,
    is_context_overflow_error,
    next_nudge_level,
    nudge_text,
    pressure_level,
)
from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass, TokenUsage
from vulnforge.packet import pack_hunt
from vulnforge.paths import system_prompts_root
from vulnforge.stages import hunt, recon
from vulnforge.tools import build_tool_handler
from vulnforge.tools.continue_task import enqueue_continuation, max_continue_depth
from vulnforge.tools.registry import clear_registry_cache


def _run(tmp_path: Path, toy: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy), "code_static", "pin", {})
    return run_dir, db


def test_context_watch_pressure_and_nudge():
    assert pressure_level(1000, 32768, 0.7) == "none"
    assert pressure_level(23000, 32768, 0.7) == "warn"
    assert pressure_level(30000, 32768, 0.7) == "must"
    assert next_nudge_level(None, "none") is None
    assert next_nudge_level(None, "warn") == "warn"
    assert next_nudge_level("warn", "warn") is None
    assert next_nudge_level("warn", "must") == "must"
    text = nudge_text("continue_hunt", used_tokens=30000, window_tokens=32768, level="must")
    assert "continue_hunt" in text
    assert "MUST" in text
    assert is_context_overflow_error("context_length")
    assert is_context_overflow_error("prompt is too long for the context window")
    assert not is_context_overflow_error("max_tool_rounds")
    schema = [
        {
            "type": "function",
            "function": {"name": "continue_hunt", "parameters": {}},
        }
    ]
    assert continue_tool_from_schema(schema) == "continue_hunt"
    assert estimate_messages_tokens([{"role": "user", "content": "abcd" * 20}]) >= 1


def test_continue_hunt_tool_enqueues_child(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _run(tmp_path, toy_sqli)
    parent = db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
    )
    ctx = {
        "db": db,
        "run_dir": run_dir,
        "task_id": parent,
        "task_payload": {
            "area": "app",
            "class": "injection",
            "path_hints": ["app.py"],
        },
        "cfg": {"run": {"max_continue_depth": 3}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    r = h(
        "continue_hunt",
        {
            "handoff": "Read app.py search_users; still need to check other.py sinks.",
            "explored_paths": ["app.py"],
            "remaining_paths": ["other.py"],
        },
    )
    assert r.get("ok") is True, r
    child_id = r.get("task_id")
    child = next(t for t in db.list_tasks() if t.id == child_id)
    assert child.kind == "hunt"
    assert child.state == "queued"
    assert child.payload.get("continue_from_task_id") == parent
    assert child.payload.get("continue_generation") == 1
    assert "search_users" in (child.payload.get("continue_handoff") or "")
    assert child.payload.get("path_hints") == ["other.py"]
    assert ctx["session"].get("continued") is True
    # Second call is idempotent
    r2 = h("continue_hunt", {"handoff": "again"})
    assert r2.get("ok") is True
    assert r2.get("task_id") == child_id
    hunts = [t for t in db.list_tasks() if t.kind == "hunt"]
    assert len(hunts) == 2
    db.close()


def test_continue_recon_tool_enqueues_child(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _run(tmp_path, toy_sqli)
    parent = db.enqueue_task("recon", {"enqueue_hunts": True})
    ctx = {
        "db": db,
        "run_dir": run_dir,
        "task_id": parent,
        "task_payload": {"enqueue_hunts": True},
        "cfg": {"run": {"max_continue_depth": 3}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    r = h(
        "continue_recon",
        {"handoff": "Mapped app.py; still need workers/ and auth/."},
    )
    assert r.get("ok") is True, r
    child = next(t for t in db.list_tasks() if t.id == r["task_id"])
    assert child.kind == "recon"
    assert child.payload.get("include_prior_architecture") is True
    assert child.payload.get("merge_with_existing") is True
    assert child.payload.get("continue_generation") == 1
    db.close()


def test_owner_connection_rejects_other_thread(tmp_path: Path, toy_sqli: Path):
    """The owner connection keeps SQLite's same-thread check.

    Sharing ``db.conn`` with the tool worker must fail this test. Disabling
    ``check_same_thread`` makes the foreign-thread ``execute`` succeed, so the
    assertion below fails.
    """
    _run_dir, db = _run(tmp_path, toy_sqli)
    box: dict = {}

    def worker() -> None:
        try:
            db.conn.execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            box["error"] = exc
        else:
            box["error"] = None

    thread = threading.Thread(target=worker, name="vf-conn-guard")
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert isinstance(box.get("error"), sqlite3.ProgrammingError)
    db.close()


def test_continue_tools_enqueue_from_worker_thread(tmp_path: Path, toy_sqli: Path):
    """continue_hunt and continue_recon enqueue on the thread that runs the tool."""
    run_dir, db = _run(tmp_path, toy_sqli)
    hunt_parent = db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
    )
    recon_parent = db.enqueue_task("recon", {"enqueue_hunts": True})
    hunt_ctx = {
        "db": db,
        "run_dir": run_dir,
        "task_id": hunt_parent,
        "task_payload": {
            "area": "app",
            "class": "injection",
            "path_hints": ["app.py"],
        },
        "cfg": {"run": {"max_continue_depth": 3}},
        "session": {},
    }
    recon_ctx = {
        "db": db,
        "run_dir": run_dir,
        "task_id": recon_parent,
        "task_payload": {"enqueue_hunts": True},
        "cfg": {"run": {"max_continue_depth": 3}},
        "session": {},
    }
    box: dict = {}

    def worker() -> None:
        try:
            db.conn.execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            box["guard"] = exc
        else:
            box["guard"] = None
        hunt_h = build_tool_handler(hunt_ctx)
        recon_h = build_tool_handler(recon_ctx)
        box["hunt"] = hunt_h(
            "continue_hunt",
            {"handoff": "Read app.py; child should finish other.py."},
        )
        box["recon"] = recon_h(
            "continue_recon",
            {"handoff": "Mapped app.py; still need workers/."},
        )
        # Empty session: idempotent lookup must also run on this thread.
        again = dict(hunt_ctx)
        again["session"] = {}
        box["hunt_again"] = build_tool_handler(again)(
            "continue_hunt",
            {"handoff": "should reuse the child"},
        )

    thread = threading.Thread(target=worker, name="vf-tool-worker")
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert isinstance(box.get("guard"), sqlite3.ProgrammingError)
    hunt_r = box["hunt"]
    recon_r = box["recon"]
    assert hunt_r.get("ok") is True, hunt_r
    assert recon_r.get("ok") is True, recon_r
    assert box["hunt_again"].get("ok") is True
    assert box["hunt_again"].get("already") is True
    assert box["hunt_again"].get("task_id") == hunt_r.get("task_id")

    tasks = db.list_tasks()
    hunt_child = next(t for t in tasks if t.id == hunt_r["task_id"])
    recon_child = next(t for t in tasks if t.id == recon_r["task_id"])
    assert hunt_child.kind == "hunt" and hunt_child.state == "queued"
    assert hunt_child.payload.get("continue_from_task_id") == hunt_parent
    assert recon_child.kind == "recon" and recon_child.state == "queued"
    assert recon_child.payload.get("continue_from_task_id") == recon_parent
    assert sum(1 for t in tasks if t.kind == "hunt") == 2
    db.close()


def test_continue_depth_cap(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _run(tmp_path, toy_sqli)
    parent = db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "injection",
            "continue_generation": 3,
        },
    )
    ctx = {
        "db": db,
        "run_dir": run_dir,
        "task_id": parent,
        "task_payload": {
            "area": "app",
            "class": "injection",
            "continue_generation": 3,
        },
        "cfg": {"run": {"max_continue_depth": 3}},
        "session": {},
    }
    r = enqueue_continuation(ctx, kind="hunt", handoff="more work")
    assert r.get("ok") is False
    assert r.get("code") == "continue_depth"
    assert max_continue_depth(ctx["cfg"]) == 3
    db.close()


def test_pack_hunt_includes_continue_handoff(tmp_path: Path):
    pkt = pack_hunt(
        {"llm": {"context_tokens": 32768, "max_context_fraction": 0.25}, "run": {}, "packet": {}},
        system_prompts_root(),
        {
            "area": "app",
            "class": "wildcard",
            "path_hints": ["a.py"],
            "continue_handoff": "Parent read a.py; check b.py next.",
            "explored_paths": ["a.py"],
        },
        "{}",
        [],
        [],
    )
    assert "continue_hunt" in pkt.user
    assert "Parent read a.py" in pkt.user
    names = {
        (t.get("function") or {}).get("name")
        for t in pkt.tools_schema
    }
    assert "continue_hunt" in names


def test_hunt_stage_continue_is_success(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _run(tmp_path, toy_sqli)
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
    )
    task = db.lease_next_task("w", 60)
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "1",
                            "name": "continue_hunt",
                            "arguments": {
                                "handoff": "Need more file reads on helpers.py",
                                "explored_paths": ["app.py"],
                            },
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": [], "max_continue_depth": 3},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert r.get("continued") is True
    assert r.get("child_task_id")
    child = next(t for t in db.list_tasks() if t.id == r["child_task_id"])
    assert child.kind == "hunt"
    assert child.payload.get("continue_from_task_id") == task.id
    facts = db.list_coverage_facts()
    assert any(f.get("last_depth") == "continued" for f in facts)
    db.close()


def test_hunt_context_length_auto_continues(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _run(tmp_path, toy_sqli)
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
    )
    task = db.lease_next_task("w", 60)
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=False,
                    classification=ResponseClass.CONTEXT_LENGTH,
                    content=None,
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                    error="context_length",
                    usage=TokenUsage(
                        prompt_tokens=32000,
                        completion_tokens=0,
                        total_tokens=32000,
                        source="provider",
                    ),
                )
            ],
            "max_tool_rounds": 4,
            "force_submit_on_round_limit": False,
            "context_tokens": 32768,
            "continue_on_context": True,
        },
        "run": {"ignore_globs": [], "max_continue_depth": 3},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert r.get("continued") is True
    assert r.get("child_task_id")
    db.close()


def test_recon_stage_continue_is_success(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _run(tmp_path, toy_sqli)
    db.enqueue_task("recon", {"enqueue_hunts": False})
    task = db.lease_next_task("w", 60)
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "1",
                            "name": "continue_recon",
                            "arguments": {
                                "handoff": "Inventory done; still mapping auth/",
                            },
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": [], "max_continue_depth": 3, "max_recon_auto_retries": 2},
        "packet": {},
        "tools": {},
    }
    r = recon.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert r.get("continued") is True
    assert r.get("child_task_id")
    child = next(t for t in db.list_tasks() if t.id == r["child_task_id"])
    assert child.kind == "recon"
    assert child.payload.get("include_prior_architecture") is True
    db.close()


def test_fake_loop_injects_context_nudge():
    from vulnforge.agent_runtime import run_tool_loop
    from vulnforge.llm import FakeLLMClient
    from vulnforge.packet import Packet

    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[
                    {
                        "id": "0",
                        "name": "list_dir",
                        "arguments": {"path": "."},
                    }
                ],
                raw=None,
                model_id="fake",
                usage=TokenUsage(
                    prompt_tokens=30000,
                    completion_tokens=10,
                    total_tokens=30010,
                    source="provider",
                ),
            ),
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[
                    {
                        "id": "1",
                        "name": "continue_hunt",
                        "arguments": {"handoff": "child should keep going"},
                    }
                ],
                raw=None,
                model_id="fake",
            ),
        ]
    )
    packet = Packet(
        system="sys",
        user="user",
        tools_schema=[
            {
                "type": "function",
                "function": {"name": "continue_hunt", "parameters": {}},
            }
        ],
    )
    seen: list[str] = []

    def handler(name, args):
        seen.append(name)
        return {"ok": True, "task_id": 99, "message": "queued"}

    result = run_tool_loop(
        client,
        packet,
        handler,
        max_rounds=4,
        temperature=0.1,
        cfg={"llm": {"context_tokens": 32768, "continue_context_fraction": 0.7}},
    )
    assert result.ok
    assert "continue_hunt" in seen
    blob = " ".join(
        str(m.get("content") or "")
        for m in (result.transcript or [])
        if isinstance(m, dict)
    )
    assert "CONTEXT" in blob or "context" in blob.lower()


def test_recon_context_length_auto_continues(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _run(tmp_path, toy_sqli)
    db.enqueue_task("recon", {"enqueue_hunts": False})
    task = db.lease_next_task("w", 60)
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=False,
                    classification=ResponseClass.CONTEXT_LENGTH,
                    content=None,
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                    error="context_length",
                    usage=TokenUsage(
                        prompt_tokens=32000,
                        completion_tokens=0,
                        total_tokens=32000,
                        source="provider",
                    ),
                )
            ],
            "max_tool_rounds": 4,
            "force_submit_on_round_limit": False,
            "context_tokens": 32768,
            "continue_on_context": True,
        },
        "run": {
            "ignore_globs": [],
            "max_continue_depth": 3,
            "max_recon_auto_retries": 2,
        },
        "packet": {},
        "tools": {},
    }
    r = recon.run(task, db, run_dir, cfg)
    assert r.get("continued") or r.get("recon_requeued"), r
    assert r.get("child_task_id")
    child = next(t for t in db.list_tasks() if t.id == r["child_task_id"])
    assert child.kind == "recon"
    db.close()


def test_registry_discovers_continue_tools():
    clear_registry_cache()
    from vulnforge.tools.registry import agent_tool_names

    names = agent_tool_names()
    assert "continue_hunt" in names
    assert "continue_recon" in names


def _on_tool_worker(handler, calls: list[dict]):
    """Run the stage tool handler on another thread, as Strands does."""

    def wrapped(name, args):
        box: dict = {}

        def worker() -> None:
            box["thread"] = threading.get_ident()
            try:
                box["out"] = handler(name, args if isinstance(args, dict) else {})
            except Exception as exc:
                box["exc"] = exc

        thread = threading.Thread(target=worker, name="vf-tool-worker")
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert box.get("thread") != threading.get_ident()
        if "exc" in box:
            raise box["exc"]
        out = box.get("out")
        calls.append(out if isinstance(out, dict) else {"ok": False, "result": out})
        return out

    return wrapped


def _require_queued_handoff_child(
    db: Database,
    *,
    kind: str,
    parent_id: int,
    handoff: str,
    child_id: int | None,
):
    """Fail the test when the queued continuation child is missing."""
    children = []
    for task in db.list_tasks():
        payload = task.payload if isinstance(task.payload, dict) else {}
        if task.kind != kind or task.state != "queued":
            continue
        if payload.get("continue_from_task_id") != parent_id:
            continue
        if payload.get("continue_handoff") != handoff:
            continue
        if payload.get("continue_generation") != 1:
            continue
        children.append(task)
    assert children, (
        f"queued {kind} continuation child missing for parent #{parent_id} "
        f"(handoff {handoff!r})"
    )
    ids = [task.id for task in children]
    assert len(children) == 1, (
        f"expected one queued {kind} handoff child for parent #{parent_id}, found {ids}"
    )
    assert child_id == children[0].id, (
        f"{kind} parent result child id {child_id!r} is not the queued handoff child {ids}"
    )
    return children[0]


def _stage_cfg(tool_name: str, handoff: str, *, recon: bool = False) -> dict:
    run = {"ignore_globs": [], "max_continue_depth": 3}
    if recon:
        run["max_recon_auto_retries"] = 2
    return {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "1",
                            "name": tool_name,
                            "arguments": {"handoff": handoff},
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": run,
        "packet": {},
        "tools": {},
    }


def _assert_parent_result_names_child(db: Database, task_id: int, result: dict, child_id: int) -> None:
    assert result.get("status") == "succeeded", result
    assert result.get("continued") is True
    assert result.get("child_task_id") == child_id
    assert db.complete_task(task_id, result, state="succeeded") is True
    stored = db.get_task(task_id)
    assert stored is not None
    assert stored.state == "succeeded"
    parent_result = stored.result if isinstance(stored.result, dict) else {}
    assert parent_result.get("child_task_id") == child_id, parent_result


def test_hunt_and_recon_worker_handoff_is_parent_result(tmp_path: Path, toy_sqli: Path, monkeypatch):
    """continue_hunt and continue_recon queue a child the parent result names.

    The tool runs on a worker thread. The test fails if that child is missing.
    """
    from vulnforge.stages import hunt as hunt_stage
    from vulnforge.stages import recon as recon_stage

    hunt_handoff = "Read app.py search_users; child should check helpers.py sinks."
    recon_handoff = "Mapped app.py routes; child should map workers/ and auth/."
    tool_calls: list[dict] = []

    def _wrap_builder(real):
        def builder(ctx):
            return _on_tool_worker(real(ctx), tool_calls)

        return builder

    monkeypatch.setattr(
        hunt_stage,
        "build_tool_handler",
        _wrap_builder(hunt_stage.build_tool_handler),
    )
    monkeypatch.setattr(
        recon_stage,
        "build_tool_handler",
        _wrap_builder(recon_stage.build_tool_handler),
    )

    hunt_root = tmp_path / "hunt"
    hunt_root.mkdir()
    run_dir, db = _run(hunt_root, toy_sqli)
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
    )
    hunt_task = db.lease_next_task("w", 60)
    assert hunt_task is not None
    hunt_result = hunt.run(hunt_task, db, run_dir, _stage_cfg("continue_hunt", hunt_handoff))
    hunt_child = _require_queued_handoff_child(
        db,
        kind="hunt",
        parent_id=hunt_task.id,
        handoff=hunt_handoff,
        child_id=hunt_result.get("child_task_id"),
    )
    _assert_parent_result_names_child(db, hunt_task.id, hunt_result, hunt_child.id)
    assert tool_calls and tool_calls[-1].get("ok") is True
    assert "stop" in str(tool_calls[-1].get("message") or "").lower()
    assert tool_calls[-1].get("task_id") == hunt_child.id
    db.close()

    recon_root = tmp_path / "recon"
    recon_root.mkdir()
    run_dir, db = _run(recon_root, toy_sqli)
    db.enqueue_task("recon", {"enqueue_hunts": False})
    recon_task = db.lease_next_task("w", 60)
    assert recon_task is not None
    recon_result = recon.run(
        recon_task,
        db,
        run_dir,
        _stage_cfg("continue_recon", recon_handoff, recon=True),
    )
    recon_child = _require_queued_handoff_child(
        db,
        kind="recon",
        parent_id=recon_task.id,
        handoff=recon_handoff,
        child_id=recon_result.get("child_task_id"),
    )
    assert recon_child.payload.get("include_prior_architecture") is True
    assert recon_child.payload.get("merge_with_existing") is True
    _assert_parent_result_names_child(db, recon_task.id, recon_result, recon_child.id)
    assert tool_calls[-1].get("ok") is True
    assert "stop" in str(tool_calls[-1].get("message") or "").lower()
    assert tool_calls[-1].get("task_id") == recon_child.id
    db.close()
