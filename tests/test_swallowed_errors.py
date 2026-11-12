"""note_swallowed helper + per-run counter (issue #173)."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

import pytest

from vulnforge import errors
from vulnforge.errors import (
    SWALLOWED_LOG_NAME,
    note_swallowed,
    read_swallowed_summary,
    reset_swallowed_counts,
    swallowed_count,
    swallowed_counts,
)


@pytest.fixture(autouse=True)
def _reset_counts():
    reset_swallowed_counts()
    yield
    reset_swallowed_counts()


def _lines(run_dir: Path) -> list[dict]:
    path = run_dir / SWALLOWED_LOG_NAME
    if not path.is_file():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_counts_per_run_and_unattributed(tmp_path: Path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    note_swallowed(ValueError("x"), context="t.a", run_dir=a)
    note_swallowed(ValueError("y"), context="t.a", run_dir=a)
    note_swallowed(KeyError("z"), context="t.b", run_dir=b)
    note_swallowed(RuntimeError("none"), context="t.none")
    assert swallowed_count(a) == 2
    assert swallowed_count(b) == 1
    assert swallowed_count() == 1
    assert swallowed_counts() == {str(a): 2, str(b): 1, "": 1}


def test_writes_jsonl_line_with_context(tmp_path: Path):
    note_swallowed(OSError("disk gone"), context="hunt.merge_codemap_annotations", run_dir=tmp_path)
    rows = _lines(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["context"] == "hunt.merge_codemap_annotations"
    assert row["type"] == "OSError"
    assert row["message"] == "disk gone"
    assert row["ts"].endswith("Z")
    assert isinstance(row["pid"], int)


def test_unattributed_writes_nothing(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    note_swallowed(ValueError("x"), context="t")
    assert list(tmp_path.iterdir()) == []


def test_never_raises_on_bad_inputs(tmp_path: Path):
    class BadStr(Exception):
        def __str__(self) -> str:  # pragma: no cover - exercised via helper
            raise RuntimeError("str exploded")

    # Missing run dir: open() fails, helper must swallow it and not create the dir.
    missing = tmp_path / "does-not-exist"
    note_swallowed(ValueError("x"), context="t", run_dir=missing)
    assert not missing.exists()
    assert swallowed_count(missing) == 1
    # __str__ that raises.
    note_swallowed(BadStr(), context="t", run_dir=tmp_path)
    # Odd context / run_dir types.
    note_swallowed(ValueError("x"), context=None, run_dir=tmp_path)  # type: ignore[arg-type]
    note_swallowed(ValueError("x"), context="t", run_dir=object())  # type: ignore[arg-type]
    assert swallowed_count(tmp_path) == 2


def test_never_raises_when_logger_breaks(tmp_path: Path, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("logging down")

    monkeypatch.setattr(errors.logger, "log", boom)
    note_swallowed(ValueError("x"), context="t", run_dir=tmp_path)
    assert swallowed_count(tmp_path) == 1


def test_first_occurrence_warns_then_debug(tmp_path: Path, caplog):
    caplog.set_level(logging.DEBUG, logger="vulnforge.swallowed")
    note_swallowed(ValueError("one"), context="t.ctx", run_dir=tmp_path)
    note_swallowed(ValueError("two"), context="t.ctx", run_dir=tmp_path)
    recs = [r for r in caplog.records if r.name == "vulnforge.swallowed"]
    assert [r.levelno for r in recs] == [logging.WARNING, logging.DEBUG]
    assert "t.ctx" in recs[0].getMessage() and "ValueError" in recs[0].getMessage()
    assert recs[1].exc_info is not None  # traceback only at debug


def test_level_debug_for_expected_failures(tmp_path: Path, caplog):
    caplog.set_level(logging.DEBUG, logger="vulnforge.swallowed")
    note_swallowed(OSError("closed"), context="t.close", run_dir=tmp_path, level=logging.DEBUG)
    recs = [r for r in caplog.records if r.name == "vulnforge.swallowed"]
    assert [r.levelno for r in recs] == [logging.DEBUG]


def test_line_cap_keeps_counting(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(errors, "_MAX_LINES_PER_RUN", 2)
    for i in range(5):
        note_swallowed(ValueError(str(i)), context="t", run_dir=tmp_path)
    assert swallowed_count(tmp_path) == 5
    assert len(_lines(tmp_path)) == 2


def test_message_truncated(tmp_path: Path):
    note_swallowed(ValueError("x" * 5000), context="t", run_dir=tmp_path)
    assert len(_lines(tmp_path)[0]["message"]) == errors._MSG_MAX


def test_thread_safe_counter(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(errors, "_MAX_LINES_PER_RUN", 0)  # count only, no file IO

    def worker():
        for _ in range(200):
            note_swallowed(ValueError("x"), context="t.thread", run_dir=tmp_path)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert swallowed_count(tmp_path) == 1600


def test_attributes_to_bound_live_task(tmp_path: Path):
    from vulnforge.live_task import bind_task, unbind_task

    token = bind_task(tmp_path, 7, "hunt", 3)
    try:
        note_swallowed(ValueError("in task"), context="t.bound")
    finally:
        unbind_task(token)
    note_swallowed(ValueError("after"), context="t.bound")
    assert swallowed_count(tmp_path) == 1
    assert swallowed_count() == 1
    assert [r["context"] for r in _lines(tmp_path)] == ["t.bound"]


def test_read_summary_missing_and_malformed(tmp_path: Path):
    assert read_swallowed_summary(tmp_path) == {
        "count": 0,
        "by_context": [],
        "last_ts": None,
        "truncated": False,
    }
    note_swallowed(ValueError("a"), context="c.one", run_dir=tmp_path)
    note_swallowed(ValueError("b"), context="c.one", run_dir=tmp_path)
    note_swallowed(ValueError("c"), context="c.two", run_dir=tmp_path)
    with (tmp_path / SWALLOWED_LOG_NAME).open("a", encoding="utf-8") as f:
        f.write("not json\n\n[1, 2]\n")
    s = read_swallowed_summary(tmp_path, top=2)
    assert s["count"] == 5  # malformed lines still count; blank lines do not
    assert s["by_context"] == [{"context": "c.one", "count": 2}, {"context": "?", "count": 2}]
    assert s["last_ts"]
    assert s["truncated"] is False


def test_read_summary_truncates_large_file(tmp_path: Path, monkeypatch):
    for _ in range(3):
        note_swallowed(ValueError("x"), context="c", run_dir=tmp_path)
    size = (tmp_path / SWALLOWED_LOG_NAME).stat().st_size
    monkeypatch.setattr(errors, "_READ_MAX_BYTES", size - 1)
    s = read_swallowed_summary(tmp_path)
    assert s["truncated"] is True
    assert s["count"] >= 2


def test_call_site_keeps_control_flow(tmp_path: Path):
    """A raising progress callback is counted but the manifest still builds."""
    from vulnforge.util import build_single_file_manifest

    target = tmp_path / "x.py"
    target.write_text("print(1)\n", encoding="utf-8")

    def bad_progress(_kw):
        raise RuntimeError("ui gone")

    man = build_single_file_manifest(target, progress=bad_progress)
    assert man["files"]
    assert swallowed_count() >= 1


def test_aggregate_tool_gaps_surfaces_count(tmp_path: Path):
    from vulnforge.tool_gaps import aggregate_tool_gaps

    rd = tmp_path / "runs" / "tgt" / "run-001"
    rd.mkdir(parents=True)
    (rd / "harness.db").write_bytes(b"")
    note_swallowed(ValueError("x"), context="hunt.client_close", run_dir=rd)
    note_swallowed(ValueError("y"), context="hunt.client_close", run_dir=rd)
    rollup = aggregate_tool_gaps(tmp_path / "runs")
    rows = [r for r in rollup["per_run"] if r["run_id"] == "run-001"]
    assert rows, rollup["per_run"]
    sw = rows[0]["swallowed_errors"]
    assert sw["count"] == 2
    assert sw["by_context"][0] == {"context": "hunt.client_close", "count": 2}
    assert rollup["total_swallowed_errors"] == 2
