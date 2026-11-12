"""Report → Reject → Promote to policy (#184)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.db import Database
from vulnforge.hitl import approval_block_id, finding_report_id, notes_block_id
from vulnforge.policy_promote import draft_rule_from_finding, promote_rule
from vulnforge.security_policy import PolicyError, normalize_policy
from vulnforge.stages.validate_mech import run as validate_run
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest, write_json

REJECT_NOTE = "search_users is only reachable from the admin console (trusted operator)."


def _body(toy_sqli: Path, *, evidence_id: str = "e1", wc: str = "injection") -> dict:
    body = {
        "title": "SQL injection in search_users",
        "summary": "User input is concatenated into SQL.",
        "weakness_class": wc,
        "threat_model": {
            "attacker": "unauthenticated user",
            "boundary": "HTTP query parameter to SQL engine",
            "impact": "read or modify arbitrary user rows",
        },
        "citations": [{"path": "app.py", "start_line": 1, "symbol": "search_users"}],
        "evidence_id": evidence_id,
        "severity_claim": "HIGH",
    }
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break
    return body


class T:
    def __init__(self, fid):
        self.payload = {"finding_id": fid}
        self.id = 1


def _run(root: Path, toy_sqli: Path) -> Path:
    run_dir = root / "run-001"
    run_dir.mkdir(parents=True)
    (run_dir / "evidence").mkdir()
    write_json(run_dir / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli.resolve()), "code_static", "pin", {})
    db.close()
    return run_dir


def _needs_human(run_dir: Path, toy_sqli: Path, *, evidence_id: str = "e1", wc="injection") -> int:
    pack = run_dir / "evidence" / evidence_id
    pack.mkdir(exist_ok=True)
    (pack / "note.txt").write_text("repro notes for SQL injection PoC steps\n")
    db = Database.open(run_dir / "harness.db")
    try:
        fid = db.insert_finding(
            _body(toy_sqli, evidence_id=evidence_id, wc=wc), stable_key=f"k-{evidence_id}"
        )
        assert validate_run(T(fid), db, run_dir, {"stages": {}})["verdict"] == "needs_human"
    finally:
        db.close()
    return fid


def _rejected(run_dir: Path, toy_sqli: Path, note: str = REJECT_NOTE, **kw) -> int:
    fid = _needs_human(run_dir, toy_sqli, **kw)
    r = dashops.review_finding(run_dir, fid, action="reject", notes=note)
    assert r["ok"] and r["to_state"] == "rejected_human"
    return fid


@pytest.fixture
def run_dir(tmp_path: Path, toy_sqli: Path) -> Path:
    return _run(tmp_path, toy_sqli)


def _db(run_dir: Path) -> Database:
    return Database.open(run_dir / "harness.db")


# --- draft -----------------------------------------------------------------


def test_draft_prefills_location_class_and_reject_note(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        assert d["ok"] and d["saved"] is False
        assert d["rule"] == {
            "id": f"ex-hr-{fid}",
            "paths": ["app.py"],
            "weakness_class": "injection",
            "reason": REJECT_NOTE,
        }
        assert d["base_revision"] is None
        assert d["hitl"]["report_id"] == finding_report_id(fid)
        assert d["hitl"]["block_id"] == approval_block_id(fid)
        assert d["hitl"]["value"] == "changes-requested"
        assert d["would_match"]["matches_source"] is True
        assert db.get_security_policy() is None  # draft stores nothing
        oos = draft_rule_from_finding(db, fid, target_list="out_of_scope")
        assert oos["rule"]["id"] == f"oos-hr-{fid}" and "weakness_class" not in oos["rule"]
        assert draft_rule_from_finding(db, fid, target_list="trusted_inputs")["error"] == (
            "bad_target_list"
        )
    finally:
        db.close()


def test_draft_refuses_without_human_reject(run_dir: Path, toy_sqli: Path):
    fid = _needs_human(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        assert draft_rule_from_finding(db, fid)["error"] == "not_human_rejected"
        assert draft_rule_from_finding(db, 9999)["error"] == "finding_not_found"
        # rejected_human state without the durable HITL row → refused (never invented)
        db.conn.execute("UPDATE findings SET state='rejected_human' WHERE id=?", (fid,))
        db.conn.commit()
        assert draft_rule_from_finding(db, fid)["error"] == "no_hitl_reject_response"
    finally:
        db.close()


def test_draft_reason_uses_current_reject_note_only(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli, note="old note from first reject")
    dashops.review_finding(run_dir, fid, action="needs_human")
    dashops.review_finding(run_dir, fid, action="reject", notes="")
    db = _db(run_dir)
    try:
        # stale finding-N-notes row from the first reject must not leak in
        rows = {r["block_id"]: r for r in db.list_hitl_responses(finding_report_id(fid))}
        assert rows[notes_block_id(fid)]["value"] == "old note from first reject"
        d = draft_rule_from_finding(db, fid)
        assert d["rule"]["reason"] == ""
        assert any("no note" in w for w in d["warnings"])
    finally:
        db.close()


# --- save --------------------------------------------------------------------


def test_promote_saves_rule_with_provenance_and_no_state_change(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    other = _needs_human(run_dir, toy_sqli, evidence_id="e2")
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        assert [h["finding_id"] for h in d["would_match"]["needs_human"]] == [other]
        rule = dict(d["rule"], paths=["app.py"], reason="Admin-only console input")
        rule["provenance"] = {"kind": "human_reject", "finding_id": 777}  # client-supplied: dropped
        r = promote_rule(db, run_dir, fid, rule, base_revision=d["base_revision"], operator="alice")
        assert r["ok"] and r["saved"], r
        cur = db.get_security_policy()
        assert cur["revision"] == r["revision"] and cur["source"] == "human_reject"
        assert f"finding #{fid}" in cur["note"]
        saved = cur["policy"]["exclusions"][0]
        assert saved["reason"] == "Admin-only console input"
        prov = saved["provenance"]
        hitl_row = next(
            x for x in db.list_hitl_responses(finding_report_id(fid))
            if x["block_id"] == approval_block_id(fid)
        )
        assert prov["finding_id"] == fid
        assert prov["hitl_report_id"] == finding_report_id(fid)
        assert prov["hitl_block_id"] == approval_block_id(fid)
        assert prov["hitl_response_value"] == "changes-requested"
        assert prov["hitl_response_at"] == hitl_row["at"]
        assert prov["hitl_note"] == REJECT_NOTE
        assert prov["operator"] == "alice"
        assert prov["origin_paths"] == ["app.py"]
        assert prov["origin_weakness_class"] == "injection"
        # nothing re-gated, nothing promoted
        assert db.get_finding(fid).state == "rejected_human"
        assert db.get_finding(other).state == "needs_human"
        hist = db.list_security_policy_revisions()
        assert hist[0]["promoted_rules"] == [
            {
                "list": "exclusions",
                "rule_id": saved["id"],
                "finding_id": fid,
                "hitl_report_id": finding_report_id(fid),
                "hitl_block_id": approval_block_id(fid),
                "hitl_response_at": hitl_row["at"],
                "operator": "alice",
            }
        ]
    finally:
        db.close()
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert '"source": "human_reject"' in events


def test_saved_rule_rejects_later_candidates_mechanically(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        assert promote_rule(db, run_dir, fid, d["rule"], base_revision=None)["ok"]
        (run_dir / "evidence" / "e3").mkdir()
        (run_dir / "evidence" / "e3" / "note.txt").write_text("repro notes for SQL injection\n")
        new = db.insert_finding(_body(toy_sqli, evidence_id="e3"), stable_key="k-e3")
        assert validate_run(T(new), db, run_dir, {"stages": {}})["verdict"] == "rejected_mech"
        f = db.get_finding(new)
        assert f.body["policy_match"]["rule_id"] == d["rule"]["id"]
        # other weakness class on the same file is not covered
        (run_dir / "evidence" / "e4").mkdir()
        (run_dir / "evidence" / "e4" / "note.txt").write_text("repro notes for path traversal\n")
        xss = db.insert_finding(
            _body(toy_sqli, evidence_id="e4", wc="path_traversal"), stable_key="k-e4"
        )
        assert validate_run(T(xss), db, run_dir, {"stages": {}})["verdict"] == "needs_human"
    finally:
        db.close()


def test_dry_run_stores_nothing(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        r = promote_rule(db, run_dir, fid, d["rule"], base_revision=None, dry_run=True)
        assert r["ok"] and r["saved"] is False and r["rule"]["provenance"]["finding_id"] == fid
        assert db.get_security_policy() is None
    finally:
        db.close()


def test_blank_or_star_class_needs_explicit_all_classes(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        for wc in ("", "*", None):
            rule = dict(d["rule"], weakness_class=wc)
            r = promote_rule(db, run_dir, fid, rule, base_revision=None)
            assert r["error"] == "invalid_rule", wc
        assert db.get_security_policy() is None
        r = promote_rule(
            db, run_dir, fid, dict(d["rule"], weakness_class=""), base_revision=None, all_classes=True
        )
        assert r["ok"] and r["rule"]["weakness_class"] == "*"
    finally:
        db.close()


def test_invalid_rule_and_empty_reason_store_nothing(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        assert promote_rule(db, run_dir, fid, dict(d["rule"], reason=""), base_revision=None)[
            "error"
        ] == "invalid_rule"
        assert promote_rule(db, run_dir, fid, dict(d["rule"], paths=[]), base_revision=None)[
            "error"
        ] == "invalid_rule"
        assert promote_rule(db, run_dir, fid, "nope", base_revision=None)["error"] == "invalid_rule"
        assert db.get_security_policy() is None
    finally:
        db.close()


def test_stale_base_revision_conflicts(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        db.set_security_policy({"notes": "someone else saved"})
        r = promote_rule(db, run_dir, fid, d["rule"], base_revision=d["base_revision"])
        assert r["error"] == "policy_changed"
        assert db.get_security_policy()["policy"]["exclusions"] == []
    finally:
        db.close()


def test_two_saves_from_same_base_cannot_both_land(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        first = promote_rule(db, run_dir, fid, d["rule"], base_revision=None)
        assert first["ok"]
        second = promote_rule(
            db, run_dir, fid, dict(d["rule"], id="ex-other"), base_revision=None
        )
        assert second["error"] == "policy_changed"
        # db-level check is atomic too
        with pytest.raises(PolicyError):
            db.set_security_policy({"notes": "x"}, expected_revision=None)
        assert len(db.get_security_policy()["policy"]["exclusions"]) == 1
    finally:
        db.close()


def test_reopened_finding_cannot_be_promoted(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
    finally:
        db.close()
    dashops.review_finding(run_dir, fid, action="needs_human")
    db = _db(run_dir)
    try:
        r = promote_rule(db, run_dir, fid, d["rule"], base_revision=None)
        assert r["error"] == "not_human_rejected"
        assert db.get_security_policy() is None
    finally:
        db.close()


def test_precheck_aborts_inside_transaction(run_dir: Path, toy_sqli: Path):
    db = _db(run_dir)
    try:
        with pytest.raises(PolicyError):
            db.set_security_policy({"notes": "x"}, precheck=lambda: "no_hitl_reject_response")
        assert db.get_security_policy() is None
        assert not db.conn.in_transaction
    finally:
        db.close()


# --- provenance is harness-owned and durable ---------------------------------


def _promoted(run_dir: Path, toy_sqli: Path) -> tuple[int, dict]:
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        assert promote_rule(db, run_dir, fid, d["rule"], base_revision=None)["ok"]
        return fid, db.get_security_policy()
    finally:
        db.close()


def test_manual_save_cannot_fabricate_provenance(run_dir: Path, toy_sqli: Path):
    fid, cur = _promoted(run_dir, toy_sqli)
    prov = cur["policy"]["exclusions"][0]["provenance"]
    db = _db(run_dir)
    try:
        forged = dict(prov, finding_id=fid + 41)
        pol = dict(cur["policy"])
        pol["exclusions"] = pol["exclusions"] + [
            {"id": "ex-forged", "paths": ["**"], "weakness_class": "*", "reason": "x",
             "provenance": forged}
        ]
        with pytest.raises(PolicyError, match="harness-owned"):
            db.set_security_policy(pol)
        # pasting a real provenance object onto another rule id is also refused
        pol["exclusions"][-1]["provenance"] = prov
        with pytest.raises(PolicyError, match="harness-owned"):
            db.set_security_policy(pol)
        assert db.get_security_policy()["revision"] == cur["revision"]
    finally:
        db.close()


def test_provenance_survives_manual_edit_and_restore(run_dir: Path, toy_sqli: Path):
    fid, cur = _promoted(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        pol = json.loads(json.dumps(cur["policy"]))
        pol["exclusions"][0]["paths"] = ["app.py", "admin/**"]  # widen by hand
        pol["notes"] = "edited"
        rev2 = db.set_security_policy(pol, note="widened")
        rule = db.get_security_policy()["policy"]["exclusions"][0]
        assert rule["provenance"] == cur["policy"]["exclusions"][0]["provenance"]
        assert rule["provenance"]["origin_paths"] == ["app.py"]
        db.set_security_policy({"notes": "wiped"})
        rev4 = db.restore_security_policy_revision(rev2)
        restored = db.get_security_policy()["policy"]["exclusions"][0]
        assert restored["provenance"]["finding_id"] == fid
        hist = {h["revision"]: h for h in db.list_security_policy_revisions()}
        assert hist[rev2]["promoted_rules"] == []  # carried, not new
        assert hist[rev4]["promoted_rules"][0]["finding_id"] == fid  # reappears after restore
        assert hist[cur["revision"]]["promoted_rules"][0]["finding_id"] == fid
    finally:
        db.close()


def test_normalize_provenance_shape():
    base = {
        "kind": "human_reject",
        "finding_id": 3,
        "hitl_report_id": "finding-3",
        "hitl_block_id": "finding-3-review",
        "hitl_response_value": "changes-requested",
        "hitl_response_at": "2026-01-01T00:00:00Z",
        "hitl_note": " n ",
        "operator": "op",
        "promoted_at": "2026-01-01T00:00:01Z",
        "origin_paths": ["app.py"],
        "origin_weakness_class": "injection",
    }
    rule = {"id": "ex-1", "paths": ["app.py"], "weakness_class": "injection", "reason": "r"}
    pol, errs = normalize_policy({"exclusions": [dict(rule, provenance=base)]})
    assert not errs and pol["exclusions"][0]["provenance"]["hitl_note"] == "n"
    for bad in (
        dict(base, extra=1),
        dict(base, kind="auto"),
        dict(base, finding_id="3"),
        dict(base, finding_id=True),
        dict(base, hitl_response_value="approved"),
        dict(base, hitl_response_at=""),
        "x",
    ):
        _, errs = normalize_policy({"exclusions": [dict(rule, provenance=bad)]})
        assert errs, bad
    # only exclusions / out_of_scope may carry provenance
    _, errs = normalize_policy(
        {"trusted_inputs": [{"id": "t", "description": "d", "paths": [], "provenance": base}]}
    )
    assert errs


# --- API ---------------------------------------------------------------------


def _client(tmp_path: Path, toy_sqli: Path):
    from vulnforge.ui.app import create_app

    runs_root = tmp_path / "runs"
    run_dir = _run(runs_root / "toy", toy_sqli)
    (run_dir / "project").mkdir(exist_ok=True)
    return TestClient(create_app(runs_root=runs_root)), run_dir, "/api/runs/toy/run-001"


def test_api_draft_and_promote(tmp_path: Path, toy_sqli: Path):
    client, run_dir, base = _client(tmp_path, toy_sqli)
    fid = _needs_human(run_dir, toy_sqli)
    assert client.get(f"{base}/findings/{fid}/policy-draft").status_code == 400
    rv = client.post(
        f"{base}/findings/{fid}/review", json={"action": "reject", "notes": REJECT_NOTE}
    )
    assert rv.status_code == 200, rv.text
    d = client.get(f"{base}/findings/{fid}/policy-draft").json()
    assert d["rule"]["reason"] == REJECT_NOTE and d["saved"] is False
    assert client.get(f"{base}/findings/999/policy-draft").status_code == 404
    pv = client.post(
        f"{base}/findings/{fid}/promote-to-policy",
        json={"rule": d["rule"], "base_revision": d["base_revision"], "dry_run": True},
    )
    assert pv.status_code == 200 and pv.json()["saved"] is False
    assert client.get(f"{base}/security-policy").json()["revision"] is None
    bad = client.post(
        f"{base}/findings/{fid}/promote-to-policy",
        json={"rule": d["rule"], "target_list": "attacker_controlled"},
    )
    assert bad.status_code == 400
    ok = client.post(
        f"{base}/findings/{fid}/promote-to-policy",
        json={"rule": d["rule"], "base_revision": d["base_revision"]},
    )
    assert ok.status_code == 200, ok.text
    again = client.post(
        f"{base}/findings/{fid}/promote-to-policy",
        json={"rule": dict(d["rule"], id="ex-2"), "base_revision": d["base_revision"]},
    )
    assert again.status_code == 409
    hist = client.get(f"{base}/security-policy/history").json()["revisions"]
    assert hist[0]["source"] == "human_reject"
    assert hist[0]["promoted_rules"][0]["finding_id"] == fid
    # manual PUT round-trip keeps provenance (carried forward)
    cur = client.get(f"{base}/security-policy").json()
    put = client.put(f"{base}/security-policy", json={"policy": cur["policy"], "note": "re-save"})
    assert put.status_code == 200, put.text
    assert put.json()["policy"]["exclusions"][0]["provenance"]["finding_id"] == fid


# --- UI ----------------------------------------------------------------------

STATIC = Path(__file__).resolve().parents[1] / "vulnforge" / "ui" / "static"
RUN_HTML = Path(__file__).resolve().parents[1] / "vulnforge" / "ui" / "templates" / "run.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_report_policy_promote_js():
    test_js = Path(__file__).resolve().parent / "js" / "report_policy_promote.test.js"
    proc = subprocess.run(
        ["node", "--test", str(test_js)], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_report_ui_wires_promote_modal():
    html = RUN_HTML.read_text(encoding="utf-8")
    report = (STATIC / "report.js").read_text(encoding="utf-8")
    policy = (STATIC / "security_policy.js").read_text(encoding="utf-8")
    assert html.index('src="/static/report_policy_promote.js"') < html.index(
        'src="/static/report.js"'
    )
    assert 'id="policy-promote-modal"' in html and 'id="policy-promote-save"' in html
    assert "report-promote-policy-btn" in report and "ReportPolicyPromote.canPromote(f)" in report
    assert "/promote-to-policy" in report and "/policy-draft" in report
    assert "historyProvenanceHtml(rev.promoted_rules" in policy


# --- interleavings inside the save transaction (Grok diff review) -------------


def _wrap_precheck(db: Database, before):
    """Run ``before(db)`` inside set_security_policy's transaction, then the real precheck."""
    orig = db.set_security_policy
    seen: dict = {}

    def wrapped(policy, **kw):
        real = kw.get("precheck")

        def pc():
            before(db)
            err = real() if real else None
            seen["in_tx_after_precheck"] = db.conn.in_transaction
            return err

        kw["precheck"] = pc
        return orig(policy, **kw)

    db.set_security_policy = wrapped  # type: ignore[method-assign]
    return seen


def test_promote_holds_write_lock_through_precheck(run_dir: Path, toy_sqli: Path):
    import sqlite3

    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)
        locked: dict = {}

        def other_writer(_db):
            other = sqlite3.connect(str(run_dir / "harness.db"), timeout=0.2)
            try:
                other.execute(
                    "INSERT INTO security_policy_revisions(created_at, source, note, policy_json)"
                    " VALUES ('x', 'manual', '', '{}')"
                )
                other.commit()
                locked["blocked"] = False
            except sqlite3.OperationalError as e:
                locked["blocked"] = "locked" in str(e)
            finally:
                other.close()

        seen = _wrap_precheck(db, other_writer)
        r = promote_rule(db, run_dir, fid, d["rule"], base_revision=None)
        assert r["ok"], r
        assert locked["blocked"] is True
        assert seen["in_tx_after_precheck"] is True
        hist = db.list_security_policy_revisions()
        assert len(hist) == 1 and hist[0]["source"] == "human_reject"
    finally:
        db.close()


def test_reopen_inside_save_window_stores_nothing(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)

        def reopen(_db):
            _db.conn.execute(
                "DELETE FROM hitl_responses WHERE report_id=? AND block_id=?",
                (finding_report_id(fid), approval_block_id(fid)),
            )

        _wrap_precheck(db, reopen)
        r = promote_rule(db, run_dir, fid, d["rule"], base_revision=None)
        assert r["error"] == "no_hitl_reject_response", r
        assert db.get_security_policy() is None
        assert not db.conn.in_transaction
    finally:
        db.close()


def test_same_second_note_rewrite_is_detected(run_dir: Path, toy_sqli: Path):
    fid = _rejected(run_dir, toy_sqli)
    db = _db(run_dir)
    try:
        d = draft_rule_from_finding(db, fid)

        def rewrite(_db):
            _db.conn.execute(
                "UPDATE hitl_responses SET note='different' WHERE report_id=? AND block_id=?",
                (finding_report_id(fid), approval_block_id(fid)),
            )

        _wrap_precheck(db, rewrite)
        r = promote_rule(db, run_dir, fid, d["rule"], base_revision=None)
        assert r["error"] == "hitl_response_changed", r
        assert db.get_security_policy() is None
    finally:
        db.close()


def test_precheck_that_commits_cannot_insert(run_dir: Path, toy_sqli: Path):
    db = _db(run_dir)
    try:
        with pytest.raises(RuntimeError, match="ended the transaction"):
            db.set_security_policy({"notes": "x"}, precheck=lambda: db.conn.commit())
        assert db.get_security_policy() is None
    finally:
        db.close()
