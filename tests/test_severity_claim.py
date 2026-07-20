"""Unit tests for severity_claim normalize / soft-drop."""

from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.findings.severity import (
    ALLOWED_SEVERITY_CLAIMS,
    apply_severity_claim,
    normalize_severity_claim,
)
from vulnforge.stages.hunt import prepare_candidate_submission
from vulnforge.stages.validate_mech import run as validate_run
from vulnforge.tools.evidence_write import MIN_EVIDENCE_FILE_BYTES
from vulnforge.util import build_target_manifest, write_json


def test_normalize_canonical_and_aliases():
    assert normalize_severity_claim("HIGH") == "HIGH"
    assert normalize_severity_claim("high") == "HIGH"
    assert normalize_severity_claim("  medium ") == "MEDIUM"
    assert normalize_severity_claim("info") == "INFORMATIONAL"
    assert normalize_severity_claim("CRIT") == "CRITICAL"
    assert normalize_severity_claim("moderate") == "MEDIUM"
    assert normalize_severity_claim(None) is None
    assert normalize_severity_claim("") is None
    assert normalize_severity_claim("attacker can RCE the host") is None
    assert normalize_severity_claim("security_claim") is None
    for a in ALLOWED_SEVERITY_CLAIMS:
        assert normalize_severity_claim(a) == a


def test_apply_normalize_and_drop():
    body, action = apply_severity_claim({"severity_claim": "high", "title": "t"})
    assert action == "normalized"
    assert body["severity_claim"] == "HIGH"

    body2, action2 = apply_severity_claim(
        {"severity_claim": "HIGH", "title": "t"}
    )
    assert action2 is None
    assert body2["severity_claim"] == "HIGH"

    body3, action3 = apply_severity_claim(
        {
            "severity_claim": "successful exploit would show data leak",
            "title": "t",
        }
    )
    assert action3 == "dropped"
    assert "severity_claim" not in body3
    assert body3["severity_claim_dropped"] == (
        "successful exploit would show data leak"
    )

    body4, action4 = apply_severity_claim({"title": "t"})
    assert action4 is None
    assert "severity_claim" not in body4


def _setup_run(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    man = build_target_manifest(toy_sqli, [])
    write_json(run_dir / "target_manifest.json", man)
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    return run_dir, db


def _good_body(evidence_id="e1", severity="HIGH"):
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
        "severity_claim": severity,
    }


def _fix_citation_line(body: dict, toy_sqli: Path) -> None:
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break


def _write_evidence(run_dir: Path, eid: str = "e1") -> None:
    d = run_dir / "evidence" / eid
    d.mkdir(parents=True, exist_ok=True)
    pad = "x" * max(MIN_EVIDENCE_FILE_BYTES, 40)
    (d / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n" + pad + "\n",
        encoding="utf-8",
    )


class T:
    def __init__(self, fid):
        self.payload = {"finding_id": fid}
        self.id = 1


def test_mech_alias_high_lower_needs_human(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(severity="high")
    _write_evidence(run_dir)
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    f = db.get_finding(fid)
    assert f.body.get("severity_claim") == "HIGH"
    db.close()


def test_mech_info_alias_needs_human(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(severity="info")
    _write_evidence(run_dir)
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    assert db.get_finding(fid).body.get("severity_claim") == "INFORMATIONAL"
    db.close()


def test_mech_free_text_soft_dropped_not_bad_severity(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    free = "successful exploit would show full DB dump"
    body = _good_body(severity=free)
    _write_evidence(run_dir)
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    reasons = r.get("reasons") or []
    assert not any("bad_severity" in str(x) for x in reasons), r
    f = db.get_finding(fid)
    assert "severity_claim" not in (f.body or {}) or f.body.get("severity_claim") in (
        None,
        "",
    )
    assert f.body.get("severity_claim_dropped") == free
    db.close()


def test_prepare_candidate_soft_drops_free_text(tmp_path: Path):
    evidence_root = tmp_path / "evidence"
    eid = "pack1"
    d = evidence_root / eid
    d.mkdir(parents=True)
    (d / "n.txt").write_text("x" * max(MIN_EVIDENCE_FILE_BYTES, 40), encoding="utf-8")
    session = {
        "evidence_ids_written": [eid],
        "evidence_id": eid,
    }
    body = {
        "title": "SQL injection in search_users",
        "summary": "User input is concatenated into SQL.",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "unauthenticated user",
            "boundary": "HTTP query parameter to SQL engine",
            "impact": "read or modify arbitrary user rows",
        },
        "citations": [{"path": "app.py", "start_line": 10}],
        "evidence_id": eid,
        "severity_claim": "Optional brief claim of what a successful exploit would show.",
    }
    prepared, err = prepare_candidate_submission(body, session, evidence_root)
    assert err is None, err
    assert prepared is not None
    assert "severity_claim" not in prepared
    assert prepared.get("severity_claim_dropped")
