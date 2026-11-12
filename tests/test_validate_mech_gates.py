from __future__ import annotations

import json
from pathlib import Path

from vulnforge.db import Database
from vulnforge.stages.validate_mech import run as validate_run
from vulnforge.util import build_target_manifest, meta_fingerprint, write_json


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


def test_validate_mech_skips_terminal_human_states(tmp_path: Path, toy_sqli: Path):
    """confirmed / rejected_human must not be rewritten by validate_mech."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break
    for i, terminal in enumerate(("confirmed", "rejected_human")):
        # Unique stable_key per state so inserts do not collide
        b = {
            **body,
            "title": terminal,
            "citations": [
                {
                    **body["citations"][0],
                    "path": f"app.py",
                    "symbol": f"search_users_{i}",
                }
            ],
        }
        fid = db.insert_finding(b, state=terminal, stable_key=f"term-{terminal}")
        r = validate_run(T(fid), db, run_dir, {"stages": {}})
        assert r.get("skipped") is True, r
        assert r.get("reason") == "already_terminal"
        assert db.get_finding(fid).state == terminal
    db.close()


def test_validate_mech_skips_needs_human_after_mech_pass(tmp_path: Path, toy_sqli: Path):
    """needs_human with validation_mech.passed must not be demoted by re-run."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["validation_mech"] = {"status": "passed", "pending_llm": False}
    body["needs_human"] = True
    # Broken citation would reject if gates re-ran
    body["citations"] = [{"path": "nope_missing.py"}]
    fid = db.insert_finding(body, state="needs_human", stable_key="nh-protect")
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r.get("skipped") is True, r
    assert r.get("reason") == "already_needs_human"
    assert db.get_finding(fid).state == "needs_human"
    db.close()


def test_validate_mech_rearms_after_deadlettered(tmp_path: Path, toy_sqli: Path):
    """deadlettered + validate_llm on → re-arm pending_llm and enqueue disprove."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["validation_mech"] = {
        "status": "passed",
        "pending_llm": False,
        "deadlettered": True,
    }
    body["needs_human"] = True
    # Broken citation would demote if gates re-ran — must not re-run gates
    body["citations"] = [{"path": "nope_missing.py"}]
    fid = db.insert_finding(body, state="needs_human", stable_key="nh-rearm")
    r = validate_run(T(fid), db, run_dir, {"stages": {"validate_llm": True}})
    assert r.get("verdict") == "pending_llm", r
    assert r.get("rearmed") is True
    f = db.get_finding(fid)
    assert f is not None and f.state == "needs_human"
    assert (f.body.get("validation_mech") or {}).get("pending_llm") is True
    assert not (f.body.get("validation_mech") or {}).get("deadlettered")
    n = db.conn.execute(
        "SELECT COUNT(*) AS c FROM tasks WHERE kind='validate_llm'"
    ).fetchone()["c"]
    assert n == 1
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


def test_citation_missing_line_rejected(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["citations"] = [{"path": "app.py", "symbol": "search_users"}]
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("citation_missing_line" in x for x in r.get("reasons") or [])
    db.close()


def test_citation_content_mismatch_rejected(tmp_path: Path, toy_sqli: Path):
    """Cite a blank/comment line that does not mention the claim tokens."""
    # Deliberate comment-only line with no claim tokens (fixture is a tmp copy).
    # Written before _setup_run so the manifest fingerprint includes it.
    app = toy_sqli / "app.py"
    app.write_text(
        app.read_text(encoding="utf-8") + "\n# unrelated filler comment\n",
        encoding="utf-8",
    )
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["sink_symbol"] = "search_users"
    text = app.read_text(encoding="utf-8")
    wrong = None
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip() == "# unrelated filler comment":
            wrong = i
            break
    assert wrong is not None
    body["citations"] = [
        {"path": "app.py", "start_line": wrong, "symbol": "search_users"}
    ]
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("citation_content_mismatch" in x for x in r.get("reasons") or [])
    db.close()


def test_citation_content_match_passes(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["sink_symbol"] = "search_users"
    _fix_citation_line(body, toy_sqli)
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    db.close()


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


def test_meta_fingerprint_not_false_mutated(tmp_path: Path, toy_sqli: Path):
    """Large-tree manifests store meta:size:mtime — must not SHA-compare those."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    man_path = run_dir / "target_manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    app = toy_sqli / "app.py"
    man["files"]["app.py"] = meta_fingerprint(app)
    write_json(man_path, man)

    body = _good_body()
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    assert not any("target_mutated" in x for x in r.get("reasons") or []), r
    db.close()


def test_severity_alias_info_needs_human(tmp_path: Path, toy_sqli: Path):
    """Aliases like info canonicalize to INFORMATIONAL."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["severity_claim"] = "info"
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    assert db.get_finding(fid).body.get("severity_claim") == "INFORMATIONAL"
    db.close()


def test_severity_free_text_soft_drop_needs_human(tmp_path: Path, toy_sqli: Path):
    """Free-text severity_claim is soft-dropped; no bad_severity reject."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    free = "what a successful exploit would show"
    body["severity_claim"] = free
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    assert not any("bad_severity" in str(x) for x in (r.get("reasons") or [])), r
    f = db.get_finding(fid)
    assert f.body.get("severity_claim_dropped") == free
    assert not f.body.get("severity_claim")
    db.close()


def test_vacuous_impact_hedge_rejected(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["threat_model"]["impact"] = "could potentially be a security risk"
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("vacuous_impact" in x for x in r.get("reasons") or []), r
    db.close()


def test_vacuous_boundary_token_rejected(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["threat_model"]["boundary"] = "unknown"
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("vacuous_boundary" in x for x in r.get("reasons") or []), r
    db.close()


def test_high_severity_without_concrete_impact_rejected(tmp_path: Path, toy_sqli: Path):
    """HIGH/CRITICAL need concrete impact hints (authz, data, RCE, …)."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["severity_claim"] = "CRITICAL"
    body["threat_model"]["impact"] = "bad outcome for the application runtime"
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any(
        "vacuous_impact_for_severity" in x for x in r.get("reasons") or []
    ), r
    db.close()


def test_summary_too_short_rejected(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body()
    body["summary"] = "SQL bug"
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("summary_too_short" in x for x in r.get("reasons") or []), r
    db.close()


def test_meta_fingerprint_detects_real_mutation(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    man_path = run_dir / "target_manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    app = toy_sqli / "app.py"
    man["files"]["app.py"] = meta_fingerprint(app)
    write_json(man_path, man)

    # Mutate size (and typically mtime) after inventory
    app.write_text(app.read_text(encoding="utf-8") + "\n# mutated\n", encoding="utf-8")

    body = _good_body()
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert any("target_mutated:app.py" in x for x in r.get("reasons") or []), r
    db.close()


# ---------------------------------------------------------------------------
# Operator security policy exclusion gate + severity rubric (#183)
# ---------------------------------------------------------------------------


def _passing_body(run_dir: Path, toy_sqli: Path) -> dict:
    body = _good_body()
    (run_dir / "evidence" / "e1").mkdir(exist_ok=True)
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    _fix_citation_line(body, toy_sqli)
    return body


def test_policy_exclusion_rejects_with_rule_cited(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    rev = db.set_security_policy(
        {
            "exclusions": [
                {
                    "id": "ex-app",
                    "paths": ["app.py"],
                    "weakness_class": "injection",
                    "reason": "toy app accepted risk",
                }
            ]
        }
    )
    fid = db.insert_finding(_passing_body(run_dir, toy_sqli))
    r = validate_run(T(fid), db, run_dir, {"stages": {"validate_llm": True}})
    assert r["verdict"] == "rejected_mech", r
    assert r["reasons"] == ["policy_excluded:ex-app"]
    f = db.get_finding(fid)
    assert f.state == "rejected_mech"
    m = f.body["policy_match"]
    assert m["rule_id"] == "ex-app"
    assert m["kind"] == "excluded"
    assert m["reason"] == "toy app accepted risk"
    assert m["matched_paths"] == ["app.py"]
    assert m["policy_revision"] == rev
    # Demote-only: no validate_llm enqueued, never confirmed.
    assert not [t for t in db.list_tasks() if t.kind == "validate_llm"]
    db.close()


def test_policy_out_of_scope_rejects(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {"out_of_scope": [{"id": "oos-1", "paths": ["*.py"], "reason": "demo only"}]}
    )
    fid = db.insert_finding(_passing_body(run_dir, toy_sqli))
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert r["reasons"] == ["policy_out_of_scope:oos-1"]
    assert db.get_finding(fid).body["policy_match"]["kind"] == "out_of_scope"
    db.close()


def test_policy_exclusion_class_mismatch_passes(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {
            "exclusions": [
                {"id": "ex-1", "paths": ["app.py"], "weakness_class": "xss", "reason": "r"}
            ]
        }
    )
    fid = db.insert_finding(_passing_body(run_dir, toy_sqli))
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    assert "policy_match" not in db.get_finding(fid).body
    db.close()


def test_policy_exclusion_needs_every_cited_path(tmp_path: Path, toy_sqli: Path):
    """One citation outside the rule keeps the finding in scope."""
    (toy_sqli / "lib").mkdir()
    (toy_sqli / "lib" / "helper.py").write_text(
        "def helper():\n    return search_users('x')\n", encoding="utf-8"
    )
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {"exclusions": [{"id": "ex-lib", "paths": ["lib/**"], "reason": "vendored"}]}
    )
    body = _passing_body(run_dir, toy_sqli)
    body["citations"].append({"path": "lib/helper.py", "start_line": 2, "symbol": "helper"})
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    db.close()


def test_policy_exclusion_reported_alongside_other_reasons(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {"exclusions": [{"id": "ex-1", "paths": ["app.py"], "reason": "accepted"}]}
    )
    body = _good_body()
    _fix_citation_line(body, toy_sqli)
    del body["evidence_id"]  # also fails evidence gate
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    assert "missing_evidence_id" in r["reasons"]
    assert "policy_excluded:ex-1" in r["reasons"]
    assert db.get_finding(fid).body["policy_match"]["rule_id"] == "ex-1"
    db.close()


def test_no_policy_leaves_gates_unchanged(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    fid = db.insert_finding(_passing_body(run_dir, toy_sqli))
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human"
    b = db.get_finding(fid).body
    assert "policy_match" not in b and "severity_rubric" not in b
    db.close()


def test_policy_does_not_regate_mech_passed_finding(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {"exclusions": [{"id": "ex-1", "paths": ["app.py"], "reason": "accepted"}]}
    )
    body = _passing_body(run_dir, toy_sqli)
    body["validation_mech"] = {"status": "passed", "pending_llm": False}
    fid = db.insert_finding(body, state="needs_human", stable_key="nh-pol")
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r.get("reason") == "already_needs_human"
    f = db.get_finding(fid)
    assert f.state == "needs_human" and "policy_match" not in f.body
    db.close()


def test_policy_rubric_caps_severity_and_records_rule(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {
            "severity_rubric": [
                {"id": "sev-loose", "max_severity": "HIGH", "paths": ["**"]},
                {"id": "sev-app", "max_severity": "LOW", "paths": ["app.py"],
                 "criteria": "toy app"},
            ]
        }
    )
    body = _passing_body(run_dir, toy_sqli)
    body["severity_claim"] = "CRITICAL"
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    b = db.get_finding(fid).body
    assert b["severity_claim"] == "LOW"
    assert b["severity_claim_original"] == "CRITICAL"
    assert b["severity_rubric"]["rule_id"] == "sev-app"
    assert b["severity_rubric"]["action"] == "capped"
    db.close()


def test_policy_rubric_never_raises_severity(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy({"severity_rubric": [{"id": "sev-1", "max_severity": "CRITICAL"}]})
    body = _passing_body(run_dir, toy_sqli)
    body["severity_claim"] = "LOW"
    fid = db.insert_finding(body)
    validate_run(T(fid), db, run_dir, {"stages": {}})
    b = db.get_finding(fid).body
    assert b["severity_claim"] == "LOW"
    assert "severity_claim_original" not in b
    assert b["severity_rubric"]["action"] == "within"
    db.close()


def test_policy_cap_does_not_loosen_non_vacuous_gate(tmp_path: Path, toy_sqli: Path):
    """CRITICAL with a soft impact is rejected even if the rubric caps it to LOW."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy({"severity_rubric": [{"id": "sev-1", "max_severity": "LOW"}]})
    body = _passing_body(run_dir, toy_sqli)
    body["severity_claim"] = "CRITICAL"
    body["threat_model"]["impact"] = "something unpleasant happens to the system overall"
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech", r
    assert "vacuous_impact_for_severity" in r["reasons"]
    db.close()


def test_candidate_supplied_policy_keys_are_stripped(tmp_path: Path, toy_sqli: Path):
    """A hunt cannot disable the cap or fake an exclusion via harness-owned keys."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy({"severity_rubric": [{"id": "sev-1", "max_severity": "LOW"}]})
    body = _passing_body(run_dir, toy_sqli)
    body["severity_claim"] = "CRITICAL"
    body["severity_claim_original"] = "CRITICAL"
    body["severity_rubric"] = {"rule_id": "fake", "action": "capped"}
    body["policy_match"] = {"kind": "excluded", "rule_id": "fake", "matched_paths": ["x"]}
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    b = db.get_finding(fid).body
    assert b["severity_claim"] == "LOW"
    assert b["severity_rubric"]["rule_id"] == "sev-1"
    assert "policy_match" not in b
    assert set(b["harness_keys_dropped"]) == {
        "policy_match",
        "severity_rubric",
        "severity_claim_original",
    }
    db.close()


def test_policy_matches_citation_as_gate_resolves_it(tmp_path: Path, toy_sqli: Path):
    """``../<target>/vendor/x`` and symlinks are judged by the file the gate accepted."""
    import os

    (toy_sqli / "vendor").mkdir()
    (toy_sqli / "vendor" / "lib.py").write_text(
        "def search_users(q):\n    return q\n", encoding="utf-8"
    )
    os.symlink(toy_sqli / "vendor" / "lib.py", toy_sqli / "alias.py")
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {"exclusions": [{"id": "ex-v", "paths": ["vendor/**"], "reason": "vendored"}]}
    )
    for i, cite in enumerate((f"../{toy_sqli.name}/vendor/lib.py", "alias.py")):
        body = _passing_body(run_dir, toy_sqli)
        body["title"] = f"SQL injection in search_users {i}"
        body["citations"] = [{"path": cite, "start_line": 1, "symbol": "search_users"}]
        fid = db.insert_finding(body, stable_key=f"pol-resolve-{i}")
        r = validate_run(T(fid), db, run_dir, {"stages": {}})
        assert r["verdict"] == "rejected_mech", (cite, r)
        assert r["reasons"] == ["policy_excluded:ex-v"], (cite, r)
        assert db.get_finding(fid).body["policy_match"]["matched_paths"] == ["vendor/lib.py"]
    db.close()


def test_garbage_harness_keys_dropped_does_not_crash(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _passing_body(run_dir, toy_sqli)
    body["severity_claim_original"] = "CRITICAL"
    body["harness_keys_dropped"] = [{"x": 1}]
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human", r
    b = db.get_finding(fid).body
    assert "severity_claim_original" not in b
    assert b["harness_keys_dropped"] == ["severity_claim_original"]
    db.close()
