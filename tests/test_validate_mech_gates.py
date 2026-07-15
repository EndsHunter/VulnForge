from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.stages.validate_mech import run as validate_run
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


def _good_body(evidence_id="e1"):
    return {
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


class T:
    def __init__(self, fid):
        self.payload = {"finding_id": fid}
        self.id = 1


def test_missing_citation_rejected(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["citations"] = [{"path": "nope.py"}]
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "n.txt").write_text("x")
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert db.get_finding(fid).state == "rejected_mech"
    db.close()


def test_missing_poc_rejected(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    del body["evidence_id"]
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    db.close()


def test_good_candidate_needs_human(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    (run_dir / "evidence" / "e1").mkdir()
    # min non-vacuous pack size (MIN_EVIDENCE_FILE_BYTES)
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    # fix line number to real file
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    f = db.get_finding(fid)
    assert f.state == "needs_human"
    assert f.body.get("needs_human") is True
    db.close()


def test_vacuous_empty_evidence_rejected(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    (run_dir / "evidence" / "e1").mkdir()
    # empty dir or tiny file only
    (run_dir / "evidence" / "e1" / "tiny.txt").write_text("x")
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("missing_evidence" in x for x in r.get("reasons") or [])
    db.close()


def _fix_citation_line(body: dict, toy_sqli: Path) -> None:
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break


def test_poc_relpath_missing_rejected_no_pack_fallback(tmp_path: Path, toy_sqli: Path):
    """M2: if poc_relpath set, that file must exist â€” other pack files do not count."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["poc_relpath"] = "poc.md"
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "other.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("missing_poc" in x for x in r.get("reasons") or []), r
    db.close()


def test_poc_relpath_present_needs_human(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["poc_relpath"] = "poc.md"
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "poc.md").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    assert db.get_finding(fid).state == "needs_human"
    db.close()
