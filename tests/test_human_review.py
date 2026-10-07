"""Human review / reclassify findings after mech gates."""

from __future__ import annotations

import inspect
from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.control.ops import ACCEPT_BLOCKED_WHILE_PENDING_LLM
from vulnforge.db import Database
from vulnforge.hitl import approval_block_id, publish_finding, respond, responses_document
from vulnforge.stages.validate_mech import run as validate_run
from vulnforge.ui.app import create_app
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest, write_json


def _setup(tmp_path: Path, toy_sqli: Path):
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


class T:
    def __init__(self, fid):
        self.payload = {"finding_id": fid}
        self.id = 1


def test_mech_then_human_confirm_and_reclassify(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n"
    )
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "needs_human"
    assert db.get_finding(fid).state == "needs_human"
    db.close()

    acc = dashops.review_finding(
        run_dir, fid, action="confirm", notes="Looks real; accepted after manual check."
    )
    assert acc["ok"] is True
    assert acc["to_state"] == "confirmed"
    assert acc["note_relpath"]
    note_path = run_dir / "evidence" / "e1" / acc["note_relpath"]
    assert note_path.is_file()
    assert "Looks real" in note_path.read_text(encoding="utf-8")

    # Human can reclassify confirmed → rejected
    rej = dashops.review_finding(
        run_dir, fid, action="reject", notes="False positive on second look."
    )
    assert rej["ok"] is True
    assert rej["to_state"] == "rejected_human"
    assert rej["from_state"] == "confirmed"

    # And reopen for more review
    reopen = dashops.review_finding(run_dir, fid, action="needs_human", notes="")
    assert reopen["ok"] is True
    assert reopen["to_state"] == "needs_human"


def test_human_reject_from_mech_rejected(tmp_path: Path, toy_sqli: Path):
    """Operator can override a mech reject if they disagree (realign)."""
    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    body["citations"] = [{"path": "nope.py"}]
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "n.txt").write_text("x" * 40)
    fid = db.insert_finding(body)
    r = validate_run(T(fid), db, run_dir, {"stages": {}})
    assert r["verdict"] == "rejected_mech"
    db.close()

    # Realign: mark needs human then confirm
    r1 = dashops.review_finding(run_dir, fid, action="needs_human", notes="citation ok offline")
    assert r1["ok"] and r1["to_state"] == "needs_human"
    r2 = dashops.review_finding(run_dir, fid, action="confirm", notes="accepted with caveats")
    assert r2["ok"] and r2["to_state"] == "confirmed"


def _stamp_pending(run_dir: Path, db: Database, toy_sqli: Path, *, pending: bool) -> int:
    body = _good_body(toy_sqli)
    body["needs_human"] = True
    body["validation_mech"] = {"status": "passed", "pending_llm": pending}
    (run_dir / "evidence" / "e1").mkdir(exist_ok=True)
    (run_dir / "evidence" / "e1" / "note.txt").write_text("repro notes\n")
    return db.insert_finding(body, state="needs_human")


def test_confirm_refused_while_pending_llm_reject_still_allowed(
    tmp_path: Path, toy_sqli: Path
):
    """Accept is a hard block while dual disprove is pending. Reject is not."""
    assert "force" not in inspect.signature(dashops.review_finding).parameters
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _stamp_pending(run_dir, db, toy_sqli, pending=True)
    publish_finding(db, run_dir, fid)

    refused = dashops.review_finding(
        run_dir, fid, action="confirm", notes="too early"
    )
    assert refused["ok"] is False
    assert refused["code"] == "pending_llm"
    assert refused["error"] == ACCEPT_BLOCKED_WHILE_PENDING_LLM
    assert "force" not in refused
    assert db.get_finding(fid).state == "needs_human"

    alias = dashops.review_finding(run_dir, fid, action="accept", notes="too early")
    assert alias["ok"] is False
    assert alias["code"] == "pending_llm"
    assert db.get_finding(fid).state == "needs_human"

    hitl = respond(
        db,
        run_dir,
        f"finding-{fid}",
        block_id=approval_block_id(fid),
        value="approved",
        note="inbox accept",
    )
    assert hitl["ok"] is False
    assert hitl["code"] == "pending_llm"
    assert db.get_finding(fid).state == "needs_human"
    doc = responses_document(db, run_dir)
    assert approval_block_id(fid) not in (doc.get("responses") or {})

    rejected = dashops.review_finding(
        run_dir, fid, action="reject", notes="Noise while disprove is still running."
    )
    assert rejected["ok"] is True
    assert rejected["to_state"] == "rejected_human"
    assert db.get_finding(fid).state == "rejected_human"
    db.close()


def test_confirm_allowed_after_pending_llm_clears(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _stamp_pending(run_dir, db, toy_sqli, pending=False)
    db.close()
    acc = dashops.review_finding(
        run_dir, fid, action="confirm", notes="Disprove settled; accepting."
    )
    assert acc["ok"] is True
    assert acc["to_state"] == "confirmed"


def test_review_api_refuses_confirm_while_pending_llm_even_with_force(
    tmp_path: Path, toy_sqli: Path
):
    runs_root = tmp_path / "runs"
    run_dir = runs_root / "toy" / "run-001"
    run_dir.mkdir(parents=True)
    (run_dir / "evidence").mkdir()
    write_json(run_dir / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    fid = _stamp_pending(run_dir, db, toy_sqli, pending=True)
    db.close()

    app = create_app(runs_root=runs_root)
    client = TestClient(app)
    url = f"/api/runs/toy/run-001/findings/{fid}/review"
    forced = client.post(url, json={"action": "confirm", "notes": "now", "force": True})
    assert forced.status_code == 400, forced.text
    assert forced.json()["detail"] == ACCEPT_BLOCKED_WHILE_PENDING_LLM

    db2 = Database.open(run_dir / "harness.db")
    assert db2.get_finding(fid).state == "needs_human"
    db2.close()

    rejected = client.post(url, json={"action": "reject", "notes": "drop it"})
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["to_state"] == "rejected_human"
