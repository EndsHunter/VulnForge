"""Campaign yield curve (#211): gated findings per million tokens."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.control import campaign as campaign_ctl
from vulnforge.control.yield_curve import (
    compute_yield_series,
    format_tokens,
    run_yield,
    yield_sentence,
)
from vulnforge.db import Database
from vulnforge.ui import store
from vulnforge.usage import record_usage


def _hunt(tid: int, *, finding_id=None, state="succeeded", at=None) -> dict:
    result = {"status": state}
    if finding_id is not None:
        result["finding_id"] = finding_id
    else:
        result["none_found"] = True
    return {
        "id": tid,
        "kind": "hunt",
        "state": state,
        "payload": {"area": "api", "class": "injection"},
        "result": result,
        "updated_at": at or f"2026-11-13T10:{tid:02d}:00Z",
    }


def _validate(tid: int, finding_id: int, kind="validate_llm") -> dict:
    return {
        "id": tid,
        "kind": kind,
        "state": "succeeded",
        "payload": {"finding_id": finding_id},
        "result": {},
        "updated_at": f"2026-11-13T11:{tid % 60:02d}:00Z",
    }


def _finding(fid: int, state: str, *, path="app.py", symbol=None, **extra) -> dict:
    body = {"title": f"F{fid}", "sink_path": path, "weakness_class": "injection"}
    if symbol:
        body["sink_symbol"] = symbol
    body.update(extra)
    return {"id": fid, "state": state, "body": body}


def test_empty_run_has_no_curve():
    out = compute_yield_series([], [], {})
    assert out["available"] is False
    assert out["reason"] == "no_hunts"
    assert out["latest"] is None
    assert out["series"] == []
    assert out["advisory"] is True
    assert out["sentence"] == "No finished hunts yet."


def test_no_usage_data_is_unavailable_not_zero():
    tasks = [_hunt(i) for i in range(1, 6)]
    out = compute_yield_series(tasks, [], {})
    assert out["available"] is False
    assert out["reason"] == "no_usage"
    assert out["series"], "points exist so the UI can say why"
    for pt in out["series"]:
        assert pt["available"] is False
        assert pt["rate_per_mtok"] is None  # never drawn as zero
    assert out["latest"]["hunts"] == 5
    assert out["sentence"].startswith("Yield unavailable")


def test_partial_usage_in_window_is_unavailable():
    tasks = [_hunt(1), _hunt(2)]
    out = compute_yield_series(tasks, [], {1: {"total_tokens": 1000}})
    assert out["latest"]["available"] is False
    assert out["latest"]["reason"] == "usage_incomplete"
    assert out["latest"]["hunts_without_usage"] == 1
    assert out["latest"]["rate_per_mtok"] is None


def test_failed_hunt_without_usage_does_not_blank_the_window():
    tasks = [_hunt(1), _hunt(2, state="failed_task")]
    out = compute_yield_series(tasks, [], {1: {"total_tokens": 1000}})
    assert out["latest"]["available"] is True
    assert out["latest"]["rate_per_mtok"] == 0.0


def test_gate_rejected_and_candidates_not_counted():
    tasks = [_hunt(1, finding_id=1), _hunt(2, finding_id=2), _hunt(3, finding_id=3),
             _hunt(4, finding_id=4), _hunt(5, finding_id=5)]
    findings = [
        _finding(1, "candidate", path="a.py"),
        _finding(2, "rejected_mech", path="b.py"),
        _finding(3, "rejected_llm", path="c.py"),
        _finding(4, "needs_human", path="d.py"),
        _finding(5, "superseded", path="e.py"),
    ]
    usage = {i: {"total_tokens": 200_000} for i in range(1, 6)}
    out = compute_yield_series(tasks, findings, usage)
    latest = out["latest"]
    assert latest["gated"] == 1
    assert latest["tokens"] == 1_000_000
    assert latest["rate_per_mtok"] == 1.0
    assert out["totals"]["gated_findings"] == 1


def test_near_dups_counted_once():
    # Two rows on the same sink path+symbol (merge_key), both past the gates,
    # filed by different hunts: one finding, at the earlier hunt.
    tasks = [_hunt(1, finding_id=1), _hunt(2, finding_id=2), _hunt(3, finding_id=1)]
    findings = [
        _finding(1, "needs_human", path="srv/db.py", symbol="run_query"),
        _finding(2, "confirmed", path="srv/db.py", symbol="run_query",
                 weakness_class="wildcard"),
    ]
    usage = {i: {"total_tokens": 100_000} for i in (1, 2, 3)}
    out = compute_yield_series(tasks, findings, usage, window=1)
    gated = [pt["gated"] for pt in out["series"]]
    assert gated == [1, 0, 0]
    assert out["totals"]["gated_findings"] == 1


def test_near_dup_link_and_superseded_twin_count_once():
    tasks = [_hunt(1, finding_id=1), _hunt(2, finding_id=2)]
    findings = [
        _finding(1, "needs_human", path="x.py"),
        _finding(2, "needs_human", path="y.py", near_dup_of=1),
        _finding(3, "superseded", path="x.py", superseded_by=1),
    ]
    usage = {1: {"total_tokens": 500}, 2: {"total_tokens": 500}}
    out = compute_yield_series(tasks, findings, usage)
    assert out["latest"]["gated"] == 1


def test_sliding_window_and_validation_tokens():
    tasks = [_hunt(i, finding_id=(1 if i == 1 else None)) for i in range(1, 5)]
    tasks.append(_validate(10, 1))
    findings = [_finding(1, "needs_human")]
    usage = {i: {"total_tokens": 100_000} for i in range(1, 5)}
    usage[10] = {"prompt_tokens": 40_000, "completion_tokens": 10_000}
    out = compute_yield_series(tasks, findings, usage, window=2)
    series = out["series"]
    assert [pt["hunts"] for pt in series] == [1, 2, 2, 2]
    # Validation tokens for F1 belong to hunt 1's slot.
    assert series[0]["tokens"] == 150_000
    assert series[1]["tokens"] == 250_000
    assert [pt["gated"] for pt in series] == [1, 1, 0, 0]
    assert out["latest"]["start_task_id"] == 3
    assert out["latest"]["end_task_id"] == 4
    assert out["latest"]["rate_per_mtok"] == 0.0
    assert out["window"] == {"basis": "hunts", "size": 2}


def test_unfinished_hunts_ignored():
    tasks = [_hunt(1), _hunt(2, state="queued"), _hunt(3, state="leased"),
             _hunt(4, state="cancelled")]
    out = compute_yield_series(tasks, [], {1: {"total_tokens": 10}})
    assert out["totals"]["finished_hunts"] == 1


def test_series_is_downsampled_but_keeps_latest():
    tasks = [_hunt(i, at=f"2026-11-13T{i // 60:02d}:{i % 60:02d}:00Z") for i in range(1, 301)]
    usage = {i: {"total_tokens": 1000} for i in range(1, 301)}
    out = compute_yield_series(tasks, [], usage, max_points=50)
    assert len(out["series"]) <= 50
    assert out["series"][-1]["end_task_id"] == 300


def test_sentence_and_token_format():
    assert format_tokens(1_400_000) == "1.4M"
    assert format_tokens(12_400) == "12k"
    assert format_tokens(1_200) == "1.2k"
    assert format_tokens(980) == "980"
    s = yield_sentence({"hunts": 20, "tokens": 1_400_000, "gated": 0, "available": True})
    assert s == "0 new gated findings in the last 1.4M tokens (20 hunts)"
    s1 = yield_sentence({"hunts": 1, "tokens": 900, "gated": 1, "available": True})
    assert s1 == "1 new gated finding in the last 900 tokens (1 hunt)"


# ---------- Read path + campaign/status ----------


def _make_run(tmp_path: Path) -> store.RunRef:
    runs = tmp_path / "runs"
    run_dir = runs / "toy" / "run-001"
    run_dir.mkdir(parents=True)
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(tmp_path / "target"), "code_static", "pin", {})
    db.close()
    return store.resolve_run(runs, "toy", "run-001")


def _finish_hunt(db: Database, result: dict) -> int:
    tid = db.enqueue_task("hunt", {"area": "api", "class": "injection"})
    db.conn.execute(
        "UPDATE tasks SET state='succeeded', result_json=? WHERE id=?",
        (json.dumps(result), tid),
    )
    db.conn.commit()
    return tid


def test_run_yield_reads_db_and_ledger(tmp_path: Path):
    ref = _make_run(tmp_path)
    db = Database.open(ref.path / "harness.db")
    try:
        fid = db.insert_finding(
            {"title": "sqli", "sink_path": "a.py", "weakness_class": "injection"},
            state="needs_human",
        )
        t1 = _finish_hunt(db, {"status": "succeeded", "finding_id": fid})
        t2 = _finish_hunt(db, {"status": "succeeded", "none_found": True})
    finally:
        db.close()
    record_usage(ref.path, task_id=t1, kind="hunt:injection",
                 usage={"prompt_tokens": 600_000, "completion_tokens": 100_000,
                        "total_tokens": 700_000})
    record_usage(ref.path, task_id=t2, kind="hunt:injection",
                 usage={"total_tokens": 700_000})
    out = run_yield(ref.path)
    assert out["available"] is True
    assert out["latest"]["gated"] == 1
    assert out["latest"]["tokens"] == 1_400_000
    assert out["sentence"] == "1 new gated finding in the last 1.4M tokens (2 hunts)"


def test_run_yield_falls_back_to_summary_by_task(tmp_path: Path):
    ref = _make_run(tmp_path)
    db = Database.open(ref.path / "harness.db")
    try:
        t1 = _finish_hunt(db, {"status": "succeeded", "none_found": True})
    finally:
        db.close()
    (ref.path / "llm_usage_summary.json").write_text(
        json.dumps({"by_task": {str(t1): {"total_tokens": 5000}}}), encoding="utf-8"
    )
    out = run_yield(ref.path)
    assert out["available"] is True
    assert out["latest"]["tokens"] == 5000


def test_campaign_status_returns_yield_and_never_stops(tmp_path: Path, monkeypatch):
    from vulnforge.ui import runner as runctl

    def boom(*_a, **_k):  # advisory read must not touch the runner
        raise AssertionError("yield must not pause or stop Ralph")

    monkeypatch.setattr(runctl, "pause_run", boom)
    monkeypatch.setattr(runctl, "stop_run_hard", boom)
    ref = _make_run(tmp_path)
    out = campaign_ctl.apply(ref, "status")
    assert out["ok"] is True
    y = out["yield"]
    assert y["schema"] == "vulnforge.yield@1"
    assert y["advisory"] is True
    assert y["available"] is False
    assert y["reason"] == "no_hunts"
    assert not (ref.path / "STOP").exists()
