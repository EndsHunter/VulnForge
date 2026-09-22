"""Hunt MoA wiring (#71). Flag off stays single-pass. Flag on never confirms."""

from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.packet import pack_hunt
from vulnforge.paths import system_prompts_root
from vulnforge.stages import hunt
from vulnforge.stages.hunt_moa import result_emits_confirmed
from vulnforge.transcript import list_transcript_passes, load_transcript


def _tool(name: str, arguments: dict) -> LLMResult:
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[{"id": "1", "name": name, "arguments": arguments}],
        raw=None,
        model_id="fake",
    )


def _read_noise() -> LLMResult:
    return _tool("list_dir", {"path": "."})


def _write() -> LLMResult:
    return _tool(
        "write_evidence",
        {
            "relpath": "notes.md",
            "content": "Evidence notes for this hunt perspective slot.",
        },
    )


def _read() -> LLMResult:
    return _tool("read_file", {"path": "app.py"})


def _candidate(**overrides) -> dict:
    body = {
        "title": "SQL injection in search",
        "summary": "User input is concatenated into a SQL query in search_users.",
        "weakness_class": "injection",
        "sink_path": "app.py",
        "sink_symbol": "search_users",
        "citations": [
            {
                "path": "app.py",
                "start_line": 10,
                "end_line": 14,
                "symbol": "search_users",
            }
        ],
        "threat_model": {
            "attacker": "remote unauthenticated user",
            "boundary": "HTTP request into the database",
            "impact": "read or modify application rows",
        },
    }
    body.update(overrides)
    return body


def _cfg(responses: list, *, moa: bool, rounds: int = 12, force_submit: bool = True) -> dict:
    return {
        "llm": {
            "fake": True,
            "fake_responses": responses,
            "max_tool_rounds": rounds,
            "force_submit_on_round_limit": force_submit,
        },
        "run": {"ignore_globs": [], "profile": "code_static"},
        "packet": {},
        "tools": {},
        "stages": {"hunt_moa": moa},
    }


def _lease(tmp_path: Path, toy_sqli: Path, payload: dict | None = None):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    body = payload or {
        "area": "app",
        "class": "injection",
        "path_hints": ["app.py"],
    }
    tid = db.enqueue_task("hunt", body)
    task = db.lease_next_task("w", 60)
    assert task is not None and task.id == tid
    return run_dir, db, task


def _validate_tasks(db) -> list:
    return [t for t in db.list_tasks() if t.kind == "validate_mech"]


def _assert_contract(obj: dict, *, n: int, cell: str) -> None:
    assert set(obj) == {
        "perspectives",
        "agree_count",
        "label",
        "cell_outcome",
        "requeue_note",
        "none_perspectives",
    }
    assert obj["cell_outcome"] == cell
    assert obj["cell_outcome"] != "confirmed"
    assert isinstance(obj["agree_count"], int)
    assert obj["label"] == f"{obj['agree_count']}/{n} hunt agree"
    assert obj["requeue_note"] in (None, "all_perspectives_none", "partial_none")
    assert isinstance(obj["none_perspectives"], list)
    assert len(obj["perspectives"]) == n
    for entry in obj["perspectives"]:
        assert set(entry) <= {"id", "outcome", "title", "reason"}
        assert entry["outcome"] in ("candidate", "none")
    none_ids = [e["id"] for e in obj["perspectives"] if e["outcome"] == "none"]
    assert obj["none_perspectives"] == none_ids
    assert result_emits_confirmed(obj) is False


def test_pack_hunt_perspective_hook():
    prompts = system_prompts_root()
    cfg = {"llm": {"context_tokens": 32768, "max_context_fraction": 0.25}, "packet": {}}
    pkt = pack_hunt(
        cfg,
        prompts,
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
        "{}",
        [],
        [],
        perspective="hunt_sink.md",
        perspective_id="sink_driven",
    )
    assert "seed sinks" in pkt.user.lower()
    assert pkt.meta.get("perspective_id") == "sink_driven"
    assert pkt.meta.get("perspective") == "hunt_sink.md"
    plain = pack_hunt(
        cfg,
        prompts,
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
        "{}",
        [],
        [],
    )
    assert "perspective_id" not in plain.meta
    assert "Perspective: sink-driven" not in plain.user


def test_flag_off_single_pass_unchanged(tmp_path: Path, toy_sqli: Path):
    run_dir, db, task = _lease(tmp_path, toy_sqli)
    cfg = _cfg([_read(), _tool("submit_none", {"reason": "no issue in app.py"})], moa=False)
    result = hunt.run(task, db, run_dir, cfg)
    assert result["status"] == "succeeded", result
    assert result.get("none_found") is True
    assert "hunt_moa" not in result
    assert db.list_findings() == []
    assert db.list_notes("hunt_moa") == []
    assert _validate_tasks(db) == []
    facts = db.list_coverage_facts()
    assert len(facts) == 1
    assert facts[0]["visit_count"] == 1
    assert facts[0]["last_depth"] == "none"
    passes = list_transcript_passes(run_dir, task.id)
    assert len(passes) == 1
    data = load_transcript(run_dir, task.id)
    assert data is not None
    assert "perspective_id" not in (data.get("meta") or {})
    blob = "\n".join(
        str(m.get("content") or "")
        for m in (data.get("messages") or [])
        if isinstance(m, dict)
    )
    assert "Perspective: sink-driven" not in blob
    db.close()


def test_moa_merges_one_candidate_and_writes_body(tmp_path: Path, toy_sqli: Path):
    run_dir, db, task = _lease(tmp_path, toy_sqli)
    poisoned = _candidate(state="confirmed")
    other = _candidate(state="confirmed", summary="Richer writeup " + ("x" * 80))
    responses = [
        _write(),
        _tool("submit_candidate", poisoned),
        _write(),
        _tool("submit_candidate", other),
        _tool("submit_none", {"reason": "authz boundary is enforced here"}),
    ]
    result = hunt.run(task, db, run_dir, _cfg(responses, moa=True, rounds=12))
    assert result["status"] == "succeeded", result
    findings = db.list_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.state == "candidate"
    assert finding.state != "confirmed"
    assert finding.body.get("state") != "confirmed"
    assert result_emits_confirmed(finding.body) is False
    moa = finding.body.get("hunt_moa")
    assert isinstance(moa, dict)
    _assert_contract(moa, n=3, cell="candidate")
    assert moa["agree_count"] == 2
    assert moa["label"] == "2/3 hunt agree"
    assert moa["requeue_note"] == "partial_none"
    assert moa["none_perspectives"] == ["authz"]
    assert moa["perspectives"][0]["outcome"] == "candidate"
    assert "authz boundary" in moa["perspectives"][2]["reason"]
    validates = _validate_tasks(db)
    assert len(validates) == 1
    assert validates[0].payload.get("finding_id") == finding.id
    facts = db.list_coverage_facts()
    assert len(facts) == 1
    assert facts[0]["visit_count"] == 1
    assert facts[0]["last_depth"] == "candidate"
    passes = list_transcript_passes(run_dir, task.id)
    ids = []
    for row in passes:
        data = load_transcript(run_dir, task.id, pass_key=row.get("pass_key"))
        assert data is not None
        meta = data.get("meta") or {}
        ids.append(meta.get("perspective_id"))
        assert meta.get("perspective_id")
    assert ids == ["sink_driven", "dataflow", "authz"]
    sink_pass = load_transcript(run_dir, task.id, pass_key="sink_driven")
    blob = "\n".join(
        str(m.get("content") or "")
        for m in (sink_pass.get("messages") or [])
        if isinstance(m, dict)
    )
    assert "seed sinks" in blob.lower()
    db.close()


def test_moa_two_clusters_inserts_only_top(tmp_path: Path, toy_sqli: Path):
    run_dir, db, task = _lease(tmp_path, toy_sqli)
    agree_a = _candidate(title="SQLi A")
    agree_b = _candidate(
        title="SQLi B richer",
        summary="Longer evidence summary " + ("detail " * 20),
        citations=[
            {"path": "app.py", "start_line": 10, "end_line": 12, "symbol": "search_users"},
            {"path": "app.py", "start_line": 20, "end_line": 22, "symbol": "search_users"},
            {"path": "app.py", "start_line": 30, "end_line": 32, "symbol": "search_users"},
        ],
    )
    other = _candidate(
        title="Missing owner check",
        sink_path="other.py",
        sink_symbol="load_row",
        weakness_class="access-control",
        citations=[
            {"path": "other.py", "start_line": 4, "end_line": 8, "symbol": "load_row"}
        ],
    )
    responses = [
        _write(),
        _tool("submit_candidate", agree_a),
        _write(),
        _tool("submit_candidate", agree_b),
        _write(),
        _tool("submit_candidate", other),
    ]
    result = hunt.run(task, db, run_dir, _cfg(responses, moa=True, rounds=12))
    assert result["status"] == "succeeded", result
    findings = db.list_findings()
    assert len(findings) == 1
    assert findings[0].state == "candidate"
    assert findings[0].body.get("title") == "SQLi B richer"
    assert findings[0].body.get("sink_symbol") == "search_users"
    moa = findings[0].body["hunt_moa"]
    _assert_contract(moa, n=3, cell="candidate")
    assert moa["agree_count"] == 2
    assert moa["label"] == "2/3 hunt agree"
    assert moa["requeue_note"] is None
    assert moa["none_perspectives"] == []
    assert len(_validate_tasks(db)) == 1
    facts = db.list_coverage_facts()
    assert len(facts) == 1 and facts[0]["visit_count"] == 1
    db.close()


def test_moa_all_none_one_coverage_and_note(tmp_path: Path, toy_sqli: Path):
    run_dir, db, task = _lease(tmp_path, toy_sqli)
    responses = [
        _read(),
        _tool("submit_none", {"reason": "no sink in app.py"}),
        _tool("submit_none", {"reason": "no untrusted flow"}),
        _tool("submit_none", {"reason": "authz check holds"}),
    ]
    result = hunt.run(task, db, run_dir, _cfg(responses, moa=True, rounds=12))
    assert result["status"] == "succeeded", result
    assert result.get("none_found") is True
    assert db.list_findings() == []
    assert _validate_tasks(db) == []
    facts = db.list_coverage_facts()
    assert len(facts) == 1
    assert facts[0]["visit_count"] == 1
    assert facts[0]["last_depth"] == "none"
    notes = db.list_notes("hunt_moa")
    assert len(notes) == 1
    moa = notes[0]["payload"]["hunt_moa"]
    _assert_contract(moa, n=3, cell="none")
    assert moa["agree_count"] == 0
    assert moa["label"] == "0/3 hunt agree"
    assert moa["requeue_note"] == "all_perspectives_none"
    assert moa["none_perspectives"] == ["sink_driven", "dataflow", "authz"]
    assert result["hunt_moa"]["requeue_note"] == "all_perspectives_none"
    assert result_emits_confirmed(moa) is False
    db.close()


def test_moa_shared_round_budget_does_not_triple(tmp_path: Path, toy_sqli: Path):
    run_dir, db, task = _lease(tmp_path, toy_sqli)
    responses = [_read_noise() for _ in range(6)]
    result = hunt.run(
        task,
        db,
        run_dir,
        _cfg(responses, moa=True, rounds=2, force_submit=False),
    )
    assert result["status"] == "failed_task", result
    assert result.get("error") == "max_tool_rounds"
    assert db.list_findings() == []
    assert _validate_tasks(db) == []
    facts = db.list_coverage_facts()
    assert len(facts) == 1
    assert facts[0]["visit_count"] == 1
    assert facts[0]["last_depth"] == "aborted"
    passes = list_transcript_passes(run_dir, task.id)
    assert len(passes) == 1
    data = load_transcript(run_dir, task.id, pass_key=passes[0].get("pass_key"))
    assert (data or {}).get("meta", {}).get("perspective_id") == "sink_driven"
    db.close()
