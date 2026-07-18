"""validate_llm: flag-off safety, full disprove path with FakeLLM, demote-only."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace

import yaml

from vulnforge.cli import (
    DEFERRED_TASK_KINDS,
    EXIT_CONFIG,
    EXIT_PROGRESS,
    cmd_apply_candidate,
    cmd_run_once,
    dispatch_task,
    load_config,
)
from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.stages import validate_llm
from vulnforge.stages.validate_mech import run as validate_mech_run
from vulnforge.util import build_target_manifest, write_json


def _setup_run(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    man = build_target_manifest(toy_sqli, [])
    write_json(run_dir / "target_manifest.json", man)
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    return run_dir, db


def _good_body(toy_sqli: Path, evidence_id: str = "e1") -> dict:
    body = {
        "title": "SQL injection in search_users",
        "summary": "User input is concatenated into SQL.",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "unauthenticated user",
            "boundary": "HTTP query parameter to SQL engine",
            "impact": "read or modify arbitrary user rows",
        },
        "citations": [{"path": "app.py", "start_line": 10, "symbol": "search_users"}],
        "evidence_id": evidence_id,
        "severity_claim": "HIGH",
    }
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break
    return body


def _write_evidence(run_dir: Path, eid: str = "e1") -> None:
    (run_dir / "evidence" / eid).mkdir(parents=True, exist_ok=True)
    (run_dir / "evidence" / eid / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )


class T:
    def __init__(self, fid, task_id: int = 1, payload: dict | None = None):
        self.payload = payload if payload is not None else {"finding_id": fid}
        self.id = task_id


def test_flag_off_skips_without_mutating_bare_candidate(tmp_path: Path, toy_sqli: Path):
    """Flag off without pending_llm stamp must not promote arbitrary candidates."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    r = validate_llm.run(T(fid), db, run_dir, {"stages": {"validate_llm": False}})
    assert r["status"] == "succeeded"
    assert r.get("skipped") is True
    assert r.get("promoted") is not True
    assert db.get_finding(fid).state == "candidate"
    assert "needs_human" not in (db.get_finding(fid).body or {})
    db.close()


def _fake_cfg(*verdict_contents: str) -> dict:
    """Config with FakeLLM scripted disprove responses (one chat each)."""
    responses = [
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content=c,
            tool_calls=[],
            raw=None,
            model_id="fake-disprove",
        )
        for c in verdict_contents
    ]
    return {
        "stages": {"validate_llm": True},
        "llm": {
            "fake": True,
            "model": "fake-disprove",
            "fake_responses": responses,
        },
        "packet": {"max_file_slice_chars": 4000},
    }


_REJECT = (
    "Claim restated.\nAlternative: mitigated.\nReachable: no.\n"
    "VERDICT=reject\nFramework binds parameters."
)
_STAND = (
    "Claim holds. Alternative fails: no parameterization on path.\n"
    "Reachable: yes.\nVERDICT=stand"
)
_NEEDS = "VERDICT=needs_human\nUnclear host binding."
_PARSE_FAIL = "I would reject this finding but forgot the tag."


def test_flag_on_disprove_reject(tmp_path: Path, toy_sqli: Path):
    """Both dual verifiers must reject for rejected_llm."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    cfg = _fake_cfg(_REJECT, _REJECT)
    r = validate_llm.run(T(fid), db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r.get("verdict") == "reject"
    assert r.get("rejected") is True
    assert r.get("stood") == 0
    assert r.get("total") == 2
    assert r.get("label") == "0/2"
    f = db.get_finding(fid)
    assert f.state == "rejected_llm"
    assert f.state != "confirmed"
    vl = f.body.get("validation_llm") or {}
    assert vl.get("verdict") == "reject"
    assert vl.get("stood") == 0
    assert vl.get("label") == "0/2"
    assert len(vl.get("verifiers") or []) == 2
    assert all(v.get("verdict") == "reject" for v in vl["verifiers"])
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "validate_llm_done" in events
    assert '"stood": 0' in events or '"stood":0' in events
    db.close()


def test_flag_on_disprove_single_reject_not_enough(tmp_path: Path, toy_sqli: Path):
    """One reject + one stand → needs_human, 1/2 llm verified."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    cfg = _fake_cfg(_REJECT, _STAND)
    r = validate_llm.run(T(fid), db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r.get("rejected") is False
    assert r.get("stood") == 1
    assert r.get("label") == "1/2"
    f = db.get_finding(fid)
    assert f.state == "needs_human"
    assert f.state != "rejected_llm"
    vl = f.body.get("validation_llm") or {}
    assert vl.get("stood") == 1
    assert vl.get("total") == 2
    assert {v["verdict"] for v in vl["verifiers"]} == {"reject", "stand"}
    db.close()


def test_flag_on_disprove_stand_needs_human(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    cfg = _fake_cfg(_STAND, _STAND)
    r = validate_llm.run(T(fid), db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r.get("verdict") == "stand"
    assert r.get("confirmed") is False
    assert r.get("stood") == 2
    assert r.get("label") == "2/2"
    f = db.get_finding(fid)
    assert f.state == "needs_human"
    assert f.body.get("needs_human") is True
    assert (f.body.get("validation_llm") or {}).get("label") == "2/2"
    db.close()


def test_flag_on_disprove_parse_fail_needs_human_never_confirms(
    tmp_path: Path, toy_sqli: Path
):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    cfg = _fake_cfg(_PARSE_FAIL, _PARSE_FAIL)
    r = validate_llm.run(T(fid), db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r.get("verdict") == "needs_human"
    assert r.get("stood") == 0
    f = db.get_finding(fid)
    assert f.state == "needs_human"
    assert f.state != "confirmed"
    assert f.body.get("needs_human") is True
    db.close()


def test_mech_with_validate_llm_enqueues_then_disprove(
    tmp_path: Path, toy_sqli: Path
):
    """Mech must not confirm when validate_llm is on; disprove decides."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    cfg = _fake_cfg(_NEEDS, _NEEDS)
    r = validate_mech_run(T(fid), db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r["verdict"] == "pending_llm"
    f = db.get_finding(fid)
    assert f.state == "needs_human"
    assert (f.body.get("validation_mech") or {}).get("pending_llm") is True
    row = db.conn.execute(
        "SELECT kind, state FROM tasks WHERE kind='validate_llm' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["kind"] == "validate_llm"

    r2 = validate_llm.run(T(fid), db, run_dir, cfg)
    assert r2["status"] == "succeeded"
    assert db.get_finding(fid).state == "needs_human"
    assert db.get_finding(fid).body.get("needs_human") is True
    assert (db.get_finding(fid).body.get("validation_llm") or {}).get("total") == 2
    db.close()


def test_flag_off_after_pending_llm_promotes_needs_human(
    tmp_path: Path, toy_sqli: Path
):
    """Flag flipped off after mech enqueue must not leave stuck pending_llm forever."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    r = validate_mech_run(T(fid), db, run_dir, {"stages": {"validate_llm": True}})
    assert r["verdict"] == "pending_llm"
    assert db.get_finding(fid).state == "needs_human"

    # Operator turns flag off; stale validate_llm task runs.
    r2 = validate_llm.run(
        T(fid), db, run_dir, {"stages": {"validate_llm": False}}
    )
    assert r2["status"] == "succeeded"
    assert r2.get("promoted") is True
    assert r2.get("verdict") == "needs_human"
    f = db.get_finding(fid)
    assert f.state == "needs_human"
    assert f.body.get("needs_human") is True
    assert (f.body.get("validation_llm") or {}).get("status") == "disabled_after_enqueue"
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "validate_llm_disabled" in events
    db.close()


def test_flag_false_mech_needs_human_zero_validate_llm_enqueue(
    tmp_path: Path, toy_sqli: Path
):
    """Flag false → needs_human and zero validate_llm tasks (no auto-confirm)."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    cfg = {"stages": {"validate_llm": False}}
    r = validate_mech_run(T(fid), db, run_dir, cfg)
    assert r["verdict"] == "needs_human"
    assert db.get_finding(fid).state == "needs_human"
    n = db.conn.execute(
        "SELECT COUNT(*) AS c FROM tasks WHERE kind='validate_llm'"
    ).fetchone()["c"]
    assert n == 0
    db.close()


def test_default_yaml_validate_llm_false_zero_enqueue(
    tmp_path: Path, toy_sqli: Path
):
    """Load real default.yaml stages → no validate_llm enqueue after mech pass."""
    root = Path(__file__).resolve().parents[1]
    default_yaml = root / "config" / "default.yaml"
    assert default_yaml.is_file()
    raw = yaml.safe_load(default_yaml.read_text(encoding="utf-8"))
    assert raw["stages"]["validate_llm"] is False

    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    r = validate_mech_run(T(fid), db, run_dir, {"stages": raw["stages"]})
    assert r["verdict"] == "needs_human"
    n = db.conn.execute(
        "SELECT COUNT(*) AS c FROM tasks WHERE kind='validate_llm'"
    ).fetchone()["c"]
    assert n == 0
    db.close()


def test_flag_on_missing_finding_failed_task(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    r = validate_llm.run(
        T(None, payload={}), db, run_dir, {"stages": {"validate_llm": True}}
    )
    assert r["status"] == "failed_task"
    assert r.get("error") in ("missing_finding_id", "invalid_finding_id")
    r2 = validate_llm.run(
        T(99999), db, run_dir, {"stages": {"validate_llm": True}}
    )
    assert r2["status"] == "failed_task"
    assert r2.get("error") == "finding_not_found"
    db.close()


def test_flag_on_invalid_finding_id_no_raise(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    r = validate_llm.run(
        T(None, payload={"finding_id": "not-an-int"}),
        db,
        run_dir,
        {"stages": {"validate_llm": True}},
    )
    assert r["status"] == "failed_task"
    assert r.get("error") == "invalid_finding_id"
    db.close()


def test_parse_disprove_verdict_defaults_needs_human():
    assert validate_llm.parse_disprove_verdict("")["verdict"] == "needs_human"
    assert validate_llm.parse_disprove_verdict("garbage")["verdict"] == "needs_human"
    assert (
        validate_llm.parse_disprove_verdict("VERDICT=reject\nreason=mitigated")[
            "verdict"
        ]
        == "reject"
    )
    assert (
        validate_llm.parse_disprove_verdict('{"verdict": "stand"}')["verdict"]
        == "stand"
    )
    # Untagged free-text reject intentionally ignored
    assert (
        validate_llm.parse_disprove_verdict("I would reject this finding")["verdict"]
        == "needs_human"
    )


def test_aggregate_disprove_verdicts():
    a = validate_llm.aggregate_disprove_verdicts(
        [{"verdict": "reject"}, {"verdict": "reject"}]
    )
    assert a["all_reject"] is True
    assert a["stood"] == 0
    assert a["label"] == "0/2"
    assert a["aggregate"] == "rejected_llm"

    b = validate_llm.aggregate_disprove_verdicts(
        [{"verdict": "reject"}, {"verdict": "stand"}]
    )
    assert b["all_reject"] is False
    assert b["stood"] == 1
    assert b["label"] == "1/2"
    assert b["aggregate"] == "needs_human"

    c = validate_llm.aggregate_disprove_verdicts(
        [{"verdict": "stand"}, {"verdict": "stand"}]
    )
    assert c["stood"] == 2
    assert c["verdict"] == "stand"

    d = validate_llm.aggregate_disprove_verdicts(
        [{"verdict": "reject"}, {"verdict": "needs_human"}]
    )
    assert d["stood"] == 0
    assert d["all_reject"] is False
    assert d["aggregate"] == "needs_human"


def test_resolve_disprove_verifiers_defaults():
    v = validate_llm.resolve_disprove_verifiers({})
    assert len(v) == 2
    assert v[0]["id"] == "threat_model"
    assert v[1]["prompt"] == "disprove_code.md"
    custom = validate_llm.resolve_disprove_verifiers(
        {
            "llm": {
                "disprove_verifiers": [
                    {"id": "a", "prompt": "disprove_threat.md"},
                    {"id": "b", "prompt": "disprove_code.md", "model": "other"},
                ]
            }
        }
    )
    assert custom[1]["model"] == "other"


def test_pack_disprove_includes_perspective():
    from vulnforge.packet import pack_disprove

    root = Path(__file__).resolve().parents[1] / "prompts" / "v1"
    pkt = pack_disprove(
        {"packet": {}},
        root,
        {"title": "t", "summary": "s"},
        [],
        perspective="disprove_threat.md",
        verifier_id="threat_model",
    )
    assert "threat-model skeptic" in pkt.user.lower() or "threat-model" in pkt.user.lower()
    assert "Finding JSON" in pkt.user
    pkt2 = pack_disprove(
        {"packet": {}},
        root,
        {"title": "t"},
        [],
        perspective="disprove_code.md",
        verifier_id="code_mitigation",
    )
    assert "mitigation" in pkt2.user.lower() or "code" in pkt2.user.lower()


def test_dispatch_validate_llm_no_crash(tmp_path: Path, toy_sqli: Path):
    """cli.dispatch_task runs full dual disprove without raising."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="candidate")
    task_id = db.enqueue_task("validate_llm", {"finding_id": fid}, priority=25)
    row = db.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    task = db._row_to_task(row)
    r = dispatch_task(task, db, run_dir, _fake_cfg(_REJECT, _REJECT))
    assert r["status"] == "succeeded"
    assert db.get_finding(fid).state == "rejected_llm"
    assert (db.get_finding(fid).body.get("validation_llm") or {}).get("label") == "0/2"
    db.close()


def test_implementation_complete_flag():
    assert validate_llm.IMPLEMENTATION_COMPLETE is True


def test_example_inbox_fixture_shape():
    root = Path(__file__).resolve().parents[1]
    path = root / "fixtures" / "inbox_candidate.example.json"
    assert path.is_file()
    body = json.loads(path.read_text(encoding="utf-8"))
    from vulnforge.stages.hunt import validate_candidate_shape

    assert validate_candidate_shape(body) == []


def test_apply_candidate_happy_path(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    _write_evidence(run_dir)
    cand = tmp_path / "cand.json"
    cand.write_text(json.dumps(body), encoding="utf-8")
    db.close()

    args = SimpleNamespace(file=str(cand), run_dir=str(run_dir))
    code = cmd_apply_candidate(args, {})
    assert code == EXIT_PROGRESS
    db = Database.open(run_dir / "harness.db")
    rows = db.conn.execute("SELECT id, state FROM findings").fetchall()
    assert len(rows) == 1
    assert rows[0]["state"] == "candidate"
    trow = db.conn.execute(
        "SELECT kind FROM tasks WHERE kind='validate_mech'"
    ).fetchone()
    assert trow is not None
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "apply_candidate" in events
    assert "has_evidence_id" in events
    db.close()


def test_apply_candidate_shape_reject(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.close()
    cand = tmp_path / "bad.json"
    cand.write_text(json.dumps({"title": "x"}), encoding="utf-8")

    args = SimpleNamespace(file=str(cand), run_dir=str(run_dir))
    err = io.StringIO()
    with redirect_stderr(err):
        code = cmd_apply_candidate(args, {})
    assert code == EXIT_CONFIG
    assert "shape" in err.getvalue().lower() or "candidate" in err.getvalue().lower()
    db = Database.open(run_dir / "harness.db")
    n = db.conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]
    assert n == 0
    db.close()


def test_apply_candidate_warning_missing_evidence(tmp_path: Path, toy_sqli: Path):
    """Missing evidence is warning-only; still inserts if shape OK."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    del body["evidence_id"]
    cand = tmp_path / "warn.json"
    cand.write_text(json.dumps(body), encoding="utf-8")
    db.close()

    args = SimpleNamespace(file=str(cand), run_dir=str(run_dir))
    err = io.StringIO()
    with redirect_stderr(err):
        code = cmd_apply_candidate(args, {})
    assert code == EXIT_PROGRESS
    assert "rejected_mech" in err.getvalue()
    assert "warning" in err.getvalue().lower()
    db = Database.open(run_dir / "harness.db")
    assert db.conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"] == 1
    db.close()


def test_gapfill_not_implemented_exit_progress(tmp_path: Path, toy_sqli: Path):
    """Deferred gapfill stub â†’ failed_task + EXIT_PROGRESS (not CONFIG)."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    tid = db.enqueue_task("gapfill", {"note": "synthetic"}, priority=90)
    # Only this task should be leased (recon not inserted)
    db.conn.execute("DELETE FROM tasks WHERE kind != 'gapfill'")
    db.conn.commit()
    db.close()

    args = SimpleNamespace(run_dir=str(run_dir))
    err = io.StringIO()
    with redirect_stderr(err):
        code = cmd_run_once(args, {"run": {"lease_ttl_seconds": 1800}})
    assert code == EXIT_PROGRESS
    db = Database.open(run_dir / "harness.db")
    row = db.conn.execute(
        "SELECT state, result_json FROM tasks WHERE id=?", (tid,)
    ).fetchone()
    assert row["state"] == "failed_task"
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "not_implemented" in events
    assert "gapfill" in DEFERRED_TASK_KINDS
    db.close()


def test_unknown_task_kind_exit_config(tmp_path: Path, toy_sqli: Path):
    """Truly unknown kind â†’ EXIT_CONFIG + unknown_task_kind event."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    tid = db.enqueue_task("not_a_real_stage", {}, priority=90)
    db.conn.execute("DELETE FROM tasks WHERE kind != 'not_a_real_stage'")
    db.conn.commit()
    db.close()

    args = SimpleNamespace(run_dir=str(run_dir))
    err = io.StringIO()
    with redirect_stderr(err):
        code = cmd_run_once(args, {"run": {"lease_ttl_seconds": 1800}})
    assert code == EXIT_CONFIG
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "unknown_task_kind" in events
    db = Database.open(run_dir / "harness.db")
    row = db.conn.execute("SELECT state FROM tasks WHERE id=?", (tid,)).fetchone()
    assert row["state"] == "failed_task"
    db.close()


def test_load_config_default_validate_llm_false():
    cfg = load_config()
    assert (cfg.get("stages") or {}).get("validate_llm") is False
