"""End-to-end reconâ†’huntâ†’validate with FakeLLMClient via cfg."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.cli import EXIT_IDLE, EXIT_INFRA, EXIT_PROGRESS, main
from vulnforge.db import Database
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass, make_client
from vulnforge.stages import hunt, recon
from vulnforge.util import append_event


def test_make_client_fake():
    cfg = {"llm": {"fake": True, "fake_responses": []}}
    c = make_client(cfg)
    assert isinstance(c, FakeLLMClient)


def test_recon_enqueues_hunts(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    tid = db.enqueue_task("recon", {})
    task = db.lease_next_task("w", 60)
    assert task and task.id == tid

    arch_args = {
        "summary": "Tiny vulnerable SQLi toy app",
        "trust_boundaries": ["user input"],
        "components": [{"name": "app", "path_hints": ["app.py"]}],
        "input_surfaces": ["search q param"],
        "hunt_focus": [
            {"area": "app", "class": "injection", "path_hints": ["app.py"]}
        ],
    }
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
                            "name": "submit_architecture",
                            "arguments": arch_args,
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": [], "max_tasks": 10},
        "packet": {},
        "tools": {},
    }
    result = recon.run(task, db, run_dir, cfg)
    assert result["status"] == "succeeded", result
    assert result["hunt_enqueued"] >= 1
    s = db.summary()
    assert s["tasks"].get("queued", 0) >= 1
    db.close()


def test_hunt_submit_none(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    tid = db.enqueue_task("hunt", {"area": "app", "class": "injection", "path_hints": ["app.py"]})
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
                            "name": "submit_none",
                            "arguments": {"reason": "no issue after review of app.py"},
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": []},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r.get("none_found")
    db.close()


def test_cli_init_and_idle_after_empty_queue(tmp_path: Path, toy_sqli: Path):
    runs = tmp_path / "runs"
    code = main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    assert code == EXIT_PROGRESS
    run_dir = next(next(runs.iterdir()).iterdir())
    db = Database.open(run_dir / "harness.db")
    # clear recon so idle
    db.conn.execute("UPDATE tasks SET state='succeeded'")
    db.conn.commit()
    db.close()
    code = main(["run-once", "--run-dir", str(run_dir)])
    assert code == EXIT_IDLE
    assert (run_dir / "project" / "findings.json").is_file()


def _tool_ok(name: str, arguments: dict) -> LLMResult:
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[{"id": "1", "name": name, "arguments": arguments}],
        raw=None,
        model_id="fake",
    )


def _read_noise() -> LLMResult:
    """Non-terminal tool call so the loop can thrash until max_tool_rounds."""
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[
            {
                "id": "n",
                "name": "list_dir",
                "arguments": {"path": "."},
            }
        ],
        raw=None,
        model_id="fake",
    )


def test_hunt_max_tool_rounds_is_failed_task(tmp_path: Path, toy_sqli: Path):
    """P0.1: model thrash (max_tool_rounds) must not be failed_infra."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt", {"area": "app", "class": "injection", "path_hints": ["app.py"]}
    )
    task = db.lease_next_task("w", 60)
    assert task is not None
    # 3 read-noise rounds with max_rounds=2 â†’ max_tool_rounds
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [_read_noise(), _read_noise(), _read_noise()],
            "max_tool_rounds": 2,
        },
        "run": {"ignore_globs": []},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "failed_task", r
    assert r.get("error") == "max_tool_rounds"
    db.close()


def test_recon_max_tool_rounds_is_failed_task(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.enqueue_task("recon", {})
    task = db.lease_next_task("w", 60)
    assert task is not None
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [_read_noise(), _read_noise(), _read_noise()],
            "max_tool_rounds": 2,
        },
        "run": {"ignore_globs": [], "max_recon_auto_retries": 2},
        "packet": {},
        "tools": {},
    }
    r = recon.run(task, db, run_dir, cfg)
    assert r["status"] == "failed_task", r
    assert r.get("error") == "max_tool_rounds"
    # Recoverable: child recon enqueued so Ralph keeps looping
    assert r.get("recon_requeued") is True
    assert r.get("child_task_id")
    child = next(t for t in db.list_tasks() if t.id == r["child_task_id"])
    assert child.kind == "recon"
    assert child.state == "queued"
    assert child.payload.get("recon_generation") == 2
    assert child.payload.get("parent_task_id") == task.id
    db.close()


def test_recon_auto_retry_respects_cap(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    # Already at generation cap (gen 1 + max_auto 1 => max gen 2; start as gen 2)
    db.enqueue_task(
        "recon",
        {"recon_generation": 2, "recon_auto_retry": True, "parent_task_id": 0},
    )
    task = db.lease_next_task("w", 60)
    assert task is not None
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [_read_noise(), _read_noise(), _read_noise()],
            "max_tool_rounds": 2,
        },
        "run": {"ignore_globs": [], "max_recon_auto_retries": 1},
        "packet": {},
        "tools": {},
    }
    r = recon.run(task, db, run_dir, cfg)
    assert r["status"] == "failed_task"
    assert r.get("error") == "max_tool_rounds"
    assert not r.get("recon_requeued")
    assert r.get("child_task_id") is None
    # Only the one recon task (no new child)
    recons = [t for t in db.list_tasks() if t.kind == "recon"]
    assert len(recons) == 1
    db.close()


def test_poison_hunt_does_not_block_sibling(tmp_path: Path, toy_sqli: Path):
    """P0.1+P0.5: poison A (max_tool_rounds) â†’ failed_task; good B still leases."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    (run_dir / "project").mkdir()
    db = Database.create(run_dir / "harness.db")
    # Store fake LLM script on disk via config file path is hard; drive stages directly
    # then assert CLI failure path leaves sibling queued.
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    id_a = db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"], "tag": "poison"},
        priority=10,
    )
    id_b = db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "access-control",
            "path_hints": ["app.py"],
            "tag": "good",
        },
        priority=50,
    )
    db.close()

    # Monkey-patch via rewriting harness config is awkward; use stage+cli fail path:
    # First lease poison A via hunt.run with thrash, mark failed_task via db, then
    # run good B.
    db = Database.open(run_dir / "harness.db")
    task_a = db.lease_next_task("w", 60)
    assert task_a is not None and task_a.id == id_a
    cfg_poison = {
        "llm": {
            "fake": True,
            "fake_responses": [_read_noise(), _read_noise(), _read_noise()],
            "max_tool_rounds": 2,
        },
        "run": {"ignore_globs": [], "max_task_attempts": 3},
        "packet": {},
        "tools": {},
    }
    ra = hunt.run(task_a, db, run_dir, cfg_poison)
    assert ra["status"] == "failed_task"
    db.fail_task(task_a.id, "failed_task", ra.get("error", "max_tool_rounds"))
    append_event(
        run_dir,
        {
            "source": "vf",
            "event": "failed_task",
            "task_id": task_a.id,
            "error": ra.get("error"),
        },
    )

    task_b = db.lease_next_task("w", 60)
    assert task_b is not None and task_b.id == id_b
    cfg_good = {
        "llm": {
            "fake": True,
            "fake_responses": [
                _tool_ok(
                    "submit_none",
                    {"reason": "reviewed access control surfaces; none found"},
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": []},
        "packet": {},
        "tools": {},
    }
    rb = hunt.run(task_b, db, run_dir, cfg_good)
    assert rb["status"] == "succeeded", rb
    assert rb.get("none_found")
    db.complete_task(task_b.id, rb)
    s = db.summary()
    assert s["tasks"].get("failed_task", 0) >= 1
    assert s["tasks"].get("succeeded", 0) >= 1
    # poison terminal; good done; no infinite requeue of A
    ta = db.get_task(id_a)
    tb = db.get_task(id_b)
    assert ta is not None and ta.state == "failed_task"
    assert tb is not None and tb.state == "succeeded"
    db.close()


def test_cli_max_tool_rounds_exit_progress_not_infra(
    tmp_path: Path, toy_sqli: Path, monkeypatch
):
    """run-once treats max_tool_rounds as EXIT_PROGRESS so Ralph does not streak EXIT 20."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    (run_dir / "project").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt", {"area": "app", "class": "injection", "path_hints": ["app.py"]}
    )
    db.close()

    from vulnforge import stages as stages_pkg
    from vulnforge.stages import hunt as hunt_mod

    def _fake_run(task, db, run_dir, cfg):
        return {
            "status": "failed_task",
            "error": "max_tool_rounds",
            "model_id": "fake",
        }

    monkeypatch.setattr(hunt_mod, "run", _fake_run)
    # dispatch imports hunt module dynamically; patch package path used by cli
    monkeypatch.setattr(
        "vulnforge.stages.hunt.run",
        _fake_run,
    )

    code = main(["run-once", "--run-dir", str(run_dir)])
    assert code == EXIT_PROGRESS
    db = Database.open(run_dir / "harness.db")
    tasks = db.list_tasks()
    assert any(t.state == "failed_task" for t in tasks)
    # sibling can still be leased if present
    db.enqueue_task(
        "hunt", {"area": "app", "class": "wildcard", "path_hints": ["app.py"]}
    )
    db.close()
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "failed_task" in events
    assert "max_tool_rounds" in events


def test_infra_attempt_cap_deadletters(tmp_path: Path, toy_sqli: Path, monkeypatch):
    """P0.2: N infra failures â†’ deadletter + EXIT_PROGRESS; no eternal requeue."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    (run_dir / "project").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    tid = db.enqueue_task(
        "hunt", {"area": "app", "class": "injection", "path_hints": ["app.py"]}
    )
    db.close()

    def _infra_run(task, db, run_dir, cfg):
        return {"status": "failed_infra", "error": "connection refused"}

    monkeypatch.setattr("vulnforge.stages.hunt.run", _infra_run)

    # max_task_attempts=2: two leases then deadletter
    # Patch load_config to inject max_task_attempts without rewriting default.yaml.
    import vulnforge.cli as cli_mod

    real_load = cli_mod.load_config

    def _cfg(path=None):
        c = real_load(path)
        c.setdefault("run", {})["max_task_attempts"] = 2
        return c

    monkeypatch.setattr(cli_mod, "load_config", _cfg)

    codes = []
    for _ in range(3):
        codes.append(main(["run-once", "--run-dir", str(run_dir)]))

    # max_task_attempts=2: lease1 requeue (INFRA), lease2 deadletter (PROGRESS), then idle
    assert codes[:2] == [EXIT_INFRA, EXIT_PROGRESS]
    assert codes[2] == EXIT_IDLE
    db = Database.open(run_dir / "harness.db")
    t = db.get_task(tid)
    assert t is not None
    assert t.state == "deadletter"
    assert t.attempt == 2
    # No queued work for the poison task
    assert not any(x.state == "queued" and x.id == tid for x in db.list_tasks())
    db.close()
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "failed_infra" in events
    assert "deadletter" in events


def test_poison_then_sibling_via_cli(tmp_path: Path, toy_sqli: Path, monkeypatch):
    """Integration: poison A terminal + good B succeeds through run-once."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    (run_dir / "project").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    id_a = db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
        priority=10,
    )
    id_b = db.enqueue_task(
        "hunt",
        {"area": "app", "class": "access-control", "path_hints": ["app.py"]},
        priority=50,
    )
    db.close()

    calls = {"n": 0}

    def _scripted(task, db, run_dir, cfg):
        calls["n"] += 1
        if task.id == id_a:
            return {"status": "failed_task", "error": "max_tool_rounds"}
        return {
            "status": "succeeded",
            "none_found": True,
            "reason": "ok",
        }

    monkeypatch.setattr("vulnforge.stages.hunt.run", _scripted)

    c1 = main(["run-once", "--run-dir", str(run_dir)])
    c2 = main(["run-once", "--run-dir", str(run_dir)])
    assert c1 == EXIT_PROGRESS
    assert c2 == EXIT_PROGRESS

    db = Database.open(run_dir / "harness.db")
    ta = db.get_task(id_a)
    tb = db.get_task(id_b)
    assert ta is not None and ta.state == "failed_task"
    assert tb is not None and tb.state == "succeeded"
    db.close()
