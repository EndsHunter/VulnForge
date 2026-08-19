"""Context-window continuation: continue_hunt / continue_recon + mechanical fallback."""

from __future__ import annotations

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
