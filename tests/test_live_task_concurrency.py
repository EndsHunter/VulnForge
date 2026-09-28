"""Concurrent live-snapshot writers must not drop tool steps (issue #112)."""

from __future__ import annotations

import contextvars
import json
import multiprocessing
import threading
import time
from collections import defaultdict
from pathlib import Path

from vulnforge.live_task import (
    _MAX_STEPS,
    _live_lock,
    bind_task,
    note_round_start,
    read_live_view,
    record_tool_call,
    unbind_task,
)


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    run.mkdir()
    return run


def _thread(fn) -> threading.Thread:
    ctx = contextvars.copy_context()
    thread = threading.Thread(target=ctx.run, args=(fn,), daemon=True)
    thread.start()
    return thread


def _join(threads: list[threading.Thread], timeout: float = 20) -> None:
    for thread in threads:
        thread.join(timeout)
        assert not thread.is_alive(), "live snapshot writer did not finish (lock deadlock?)"


def _calls_by_round(steps: list[dict]) -> dict[int, list[int]]:
    grouped: dict[int, list[int]] = defaultdict(list)
    for step in steps:
        grouped[int(step["round"])].append(int(step["call"]))
    return grouped


def _assert_unique_monotonic_calls(steps: list[dict]) -> None:
    grouped = _calls_by_round(steps)
    assert grouped, "expected at least one step"
    for calls in grouped.values():
        assert calls == sorted(calls)
        assert len(calls) == len(set(calls))
        assert calls == list(range(calls[0], calls[0] + len(calls)))


def test_concurrent_threads_keep_every_tool_call(tmp_path: Path):
    run = _run(tmp_path)
    n = 16
    token = bind_task(run, 2, "recon", 12)
    try:
        assert note_round_start() == 1
        barrier = threading.Barrier(n)

        def worker(index: int):
            def run_one() -> None:
                barrier.wait(timeout=10)
                record_tool_call(f"tool_{index:02d}", {"i": index}, {"ok": True})

            return run_one

        threads = [_thread(worker(i)) for i in range(n)]
        _join(threads)
    finally:
        unbind_task(token)

    view = read_live_view(run, 2)
    assert len(view["steps"]) == n
    assert sorted(s["tool"] for s in view["steps"]) == [f"tool_{i:02d}" for i in range(n)]
    assert {s["round"] for s in view["steps"]} == {1}
    assert [s["call"] for s in view["steps"]] == list(range(1, n + 1))
    _assert_unique_monotonic_calls(view["steps"])
    events = [
        json.loads(line)
        for line in (run / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    task_steps = [e for e in events if e.get("event") == "task_step"]
    assert len(task_steps) == n
    assert sorted(e["call"] for e in task_steps) == list(range(1, n + 1))
    assert (run / "steer" / "task-2.lock").is_file()
    assert not (run / "live" / "task-2.lock").exists()


def test_concurrent_threads_cap_at_max_steps(tmp_path: Path):
    run = _run(tmp_path)
    n = _MAX_STEPS + 7
    token = bind_task(run, 2, "recon", 12)
    try:
        note_round_start()
        barrier = threading.Barrier(n)
        threads = []
        for index in range(n):

            def worker(index: int = index):
                def run_one() -> None:
                    barrier.wait(timeout=10)
                    record_tool_call(f"tool_{index:02d}", {"i": index}, {"ok": index % 2 == 0})

                return run_one

            threads.append(_thread(worker()))
        _join(threads, timeout=30)
    finally:
        unbind_task(token)

    view = read_live_view(run, 2)
    assert len(view["steps"]) == _MAX_STEPS
    tools = [s["tool"] for s in view["steps"]]
    assert len(tools) == len(set(tools))
    assert set(tools) <= {f"tool_{i:02d}" for i in range(n)}
    assert [s["call"] for s in view["steps"]] == list(range(n - _MAX_STEPS + 1, n + 1))
    _assert_unique_monotonic_calls(view["steps"])
    events = (run / "events.jsonl").read_text(encoding="utf-8")
    assert events.count('"event": "task_step"') == n


def test_round_start_does_not_drop_concurrent_steps(tmp_path: Path):
    run = _run(tmp_path)
    n = 20
    token = bind_task(run, 3, "hunt", 30)
    try:
        note_round_start()
        stop = threading.Event()

        def bump() -> None:
            while not stop.is_set():
                note_round_start()
                time.sleep(0.002)

        bumper = _thread(bump)
        barrier = threading.Barrier(n)
        workers = []
        for index in range(n):

            def worker(index: int = index):
                def run_one() -> None:
                    barrier.wait(timeout=10)
                    record_tool_call(f"mix_{index:02d}", {"i": index}, {"ok": True})

                return run_one

            workers.append(_thread(worker()))
        _join(workers)
        stop.set()
        _join([bumper])
    finally:
        unbind_task(token)

    view = read_live_view(run, 3)
    assert sorted(s["tool"] for s in view["steps"]) == [f"mix_{i:02d}" for i in range(n)]
    _assert_unique_monotonic_calls(view["steps"])
    raw = json.loads((run / "live" / "task-3.json").read_text(encoding="utf-8"))
    assert isinstance(raw.get("steps"), list)
    assert len(raw["steps"]) == n


def test_record_tool_call_reenters_live_lock(tmp_path: Path):
    """Steer holds this lock while calling submit_none, which records a step."""
    run = _run(tmp_path)
    token = bind_task(run, 1, "hunt", 4)
    try:
        note_round_start()

        def inner() -> None:
            with _live_lock(run, 1):
                record_tool_call("submit_none", {"reason": "boundary"}, {"ok": True})

        thread = _thread(inner)
        _join([thread], timeout=5)
    finally:
        unbind_task(token)
    view = read_live_view(run, 1)
    assert [s["tool"] for s in view["steps"]] == ["submit_none"]
    assert view["steps"][0]["call"] == 1


def _proc_record(repo: str, run_dir: str, task_id: int, index: int, barrier) -> None:
    import sys

    root = str(Path(repo))
    if root not in sys.path:
        sys.path.insert(0, root)
    from vulnforge.live_task import LiveBind, _bind, record_tool_call

    bind = LiveBind(Path(run_dir), task_id, "recon", 12)
    bind.round_n = 1
    token = _bind.set(bind)
    try:
        barrier.wait(timeout=20)
        record_tool_call(f"proc_{index:02d}", {"i": index}, {"ok": True})
    finally:
        _bind.reset(token)


def test_concurrent_processes_keep_every_tool_call(tmp_path: Path):
    run = _run(tmp_path)
    token = bind_task(run, 4, "recon", 12)
    unbind_task(token)
    # Re-open a running snapshot without each child calling bind_task (that
    # would blank the file). Children only append under the shared flock.
    snap = json.loads((run / "live" / "task-4.json").read_text(encoding="utf-8"))
    snap["phase"] = "running"
    snap["round"] = 1
    (run / "live" / "task-4.json").write_text(
        json.dumps(snap, indent=2) + "\n", encoding="utf-8"
    )

    n = 8
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(n)
    repo = str(Path(__file__).resolve().parents[1])
    procs = [
        ctx.Process(
            target=_proc_record,
            args=(repo, str(run), 4, index, barrier),
        )
        for index in range(n)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(30)
        assert proc.exitcode == 0, f"child {proc.pid} exit {proc.exitcode}"

    view = read_live_view(run, 4)
    assert len(view["steps"]) == n
    assert sorted(s["tool"] for s in view["steps"]) == [f"proc_{i:02d}" for i in range(n)]
    assert {s["round"] for s in view["steps"]} == {1}
    assert [s["call"] for s in view["steps"]] == list(range(1, n + 1))
    _assert_unique_monotonic_calls(view["steps"])
