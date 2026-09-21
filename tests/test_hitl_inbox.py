"""Durable HITL report↔responses inbox. Confirm requires explicit human review."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.cli import main as vf_main
from vulnforge.db import Database
from vulnforge.hitl import (
    SCHEMA_ID,
    RESPONSES_SCHEMA_ID,
    approval_block_id,
    emit_packet,
    list_inbox,
    notes_block_id,
    publish_finding,
    respond,
    responses_document,
    sync_findings,
)
from vulnforge.stages.validate_mech import run as validate_run
from vulnforge.ui.app import create_app
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest, utc_now_iso, write_json


def _setup(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "toy" / "run-001"
    run_dir.mkdir(parents=True)
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


def _pass_mech(run_dir: Path, db: Database, toy_sqli: Path, cfg: dict | None = None) -> int:
    body = _good_body(toy_sqli)
    (run_dir / "evidence" / "e1").mkdir()
    (run_dir / "evidence" / "e1" / "note.txt").write_text("repro notes for SQL injection\n")
    fid = db.insert_finding(body)
    out = validate_run(T(fid), db, run_dir, cfg or {"stages": {}})
    assert out["finding_state"] == "needs_human"
    assert db.get_finding(fid).state == "needs_human"
    return fid


def _approval_absent(doc: dict, fid: int) -> None:
    key = approval_block_id(fid)
    assert key not in (doc.get("responses") or {})


def test_mech_publishes_awaiting_review_and_does_not_confirm(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    report_id = f"finding-{fid}"
    stored = db.get_hitl_report(report_id)
    assert stored is not None
    packet = stored["packet"]
    assert packet["schema"] == SCHEMA_ID
    assert packet["status"] == "awaiting-review"
    assert packet["harness"] == "vulnforge"
    assert packet["source"]["state"] == "needs_human"
    block_ids = {b.get("id") for b in packet["blocks"] if b.get("type") in ("ask", "decision", "approval")}
    assert approval_block_id(fid) in block_ids
    assert notes_block_id(fid) in block_ids

    doc = responses_document(db, run_dir)
    assert doc["schema"] == RESPONSES_SCHEMA_ID
    assert doc["responses"] == {}
    _approval_absent(doc, fid)
    on_disk = json.loads((run_dir / "hitl" / "responses.json").read_text(encoding="utf-8"))
    assert on_disk["responses"] == {}
    assert (run_dir / "hitl" / "reports" / f"{report_id}.json").is_file()

    inbox = list_inbox(db, run_dir)
    assert inbox["count"] == 1
    assert inbox["items"][0]["id"] == report_id
    assert inbox["items"][0]["status"] == "awaiting-review"
    assert db.get_finding(fid).state == "needs_human"
    db.close()


def test_pending_llm_still_needs_human_with_empty_responses(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli, {"stages": {"validate_llm": True}})
    assert db.get_finding(fid).state == "needs_human"
    packet = db.get_hitl_report(f"finding-{fid}")["packet"]
    assert packet["status"] == "awaiting-review"
    _approval_absent(responses_document(db, run_dir), fid)
    db.close()


def test_inbox_survives_reopen(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    db.close()
    db2 = Database.open(run_dir / "harness.db")
    inbox = list_inbox(db2, run_dir)
    assert inbox["count"] == 1
    assert inbox["items"][0]["source"]["id"] == str(fid)
    assert db2.get_finding(fid).state == "needs_human"
    db2.close()


def test_confirm_requires_explicit_review_and_round_trips(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    report_id = f"finding-{fid}"

    notes = respond(
        db,
        run_dir,
        report_id,
        block_id=notes_block_id(fid),
        value="looks plausible, still not accepted",
        operator="ada",
    )
    assert notes["ok"] is True
    assert notes["confirmed"] is False
    assert db.get_finding(fid).state == "needs_human"
    assert db.get_hitl_report(report_id)["status"] == "awaiting-review"

    bogus = respond(
        db,
        run_dir,
        report_id,
        block_id=approval_block_id(fid),
        value="confirmed",
    )
    assert bogus["ok"] is False
    assert db.get_finding(fid).state == "needs_human"

    # A response row written outside review must not promote the finding.
    db.upsert_hitl_response(
        report_id,
        approval_block_id(fid),
        value="approved",
        note="forged",
        at=utc_now_iso(),
        operator="forged",
    )
    sync_findings(db, run_dir)
    assert db.get_finding(fid).state == "needs_human"
    assert list_inbox(db, run_dir)["count"] == 1
    db.close()

    acc = dashops.review_finding(
        run_dir, fid, action="confirm", notes="Looks real after manual check."
    )
    assert acc["ok"] is True
    assert acc["to_state"] == "confirmed"
    assert acc["hitl"]["ok"] is True
    assert acc["hitl"]["status"] == "done"
    assert acc["hitl"]["response"]["value"] == "approved"
    assert acc["hitl"]["response"]["note"] == "Looks real after manual check."
    assert set(acc["hitl"]["response"]) == {"block", "value", "note", "at"}

    db3 = Database.open(run_dir / "harness.db")
    assert db3.get_finding(fid).state == "confirmed"
    doc = json.loads((run_dir / "hitl" / "responses.json").read_text(encoding="utf-8"))
    saved = doc["responses"][approval_block_id(fid)]
    assert saved["value"] == "approved"
    assert saved["block"] == approval_block_id(fid)
    assert set(saved) == {"block", "value", "note", "at"}
    assert list_inbox(db3, run_dir)["count"] == 0
    assert db3.get_hitl_report(report_id)["status"] == "done"
    db3.close()


def test_reject_and_reopen(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    db.close()
    rej = dashops.review_finding(run_dir, fid, action="reject", notes="False positive.")
    assert rej["to_state"] == "rejected_human"
    assert rej["hitl"]["response"]["value"] == "changes-requested"
    reopen = dashops.review_finding(run_dir, fid, action="needs_human", notes="")
    assert reopen["to_state"] == "needs_human"
    db2 = Database.open(run_dir / "harness.db")
    doc = responses_document(db2, run_dir)
    assert approval_block_id(fid) not in doc["responses"]
    assert db2.get_finding(fid).state == "needs_human"
    assert db2.get_hitl_report(f"finding-{fid}")["status"] == "awaiting-review"
    db2.close()


def test_rejected_llm_closes_packet_without_inventing_an_answer(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    db.update_finding_state(fid, "rejected_llm", reason="validate_llm:rejected:test")
    out = publish_finding(db, run_dir, fid)
    assert out["status"] == "done"
    assert db.get_finding(fid).state == "rejected_llm"
    _approval_absent(responses_document(db, run_dir), fid)
    assert list_inbox(db, run_dir)["count"] == 0
    db.close()


def test_explicit_packet_round_trip_does_not_confirm(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    packet = {
        "schema": SCHEMA_ID,
        "id": "gate-export",
        "title": "Export gate",
        "status": "awaiting-review",
        "blocks": [
            {
                "type": "decision",
                "id": "gate-export-choice",
                "prompt": "Include transcripts?",
                "a": {"tag": "include", "title": "Include"},
                "b": {"tag": "omit", "title": "Omit"},
            },
            {
                "type": "approval",
                "id": "gate-export-ok",
                "prompt": "Sign off on the export gate?",
            },
        ],
    }
    emitted = emit_packet(db, run_dir, packet)
    assert emitted["ok"] is True
    assert emitted["report"]["schema"] == SCHEMA_ID
    inbox = list_inbox(db, run_dir)
    ids = {item["id"] for item in inbox["items"]}
    assert "gate-export" in ids
    assert f"finding-{fid}" in ids

    partial = respond(
        db,
        run_dir,
        "gate-export",
        block_id="gate-export-choice",
        value="omit",
        note="keep the pack small",
    )
    assert partial["ok"] is True
    assert partial["status"] == "awaiting-review"
    assert partial["confirmed"] is False
    assert db.get_finding(fid).state == "needs_human"

    done = respond(
        db,
        run_dir,
        "gate-export",
        block_id="gate-export-ok",
        value="approved",
        note="gate only",
    )
    assert done["ok"] is True
    assert done["status"] == "answered"
    assert done["confirmed"] is False
    assert db.get_finding(fid).state == "needs_human"
    db.close()

    db2 = Database.open(run_dir / "harness.db")
    doc = responses_document(db2, run_dir)
    assert doc["responses"]["gate-export-choice"]["value"] == "omit"
    assert doc["responses"]["gate-export-choice"]["note"] == "keep the pack small"
    assert doc["responses"]["gate-export-ok"]["value"] == "approved"
    inbox2 = list_inbox(db2, run_dir)
    assert "gate-export" not in {item["id"] for item in inbox2["items"]}
    assert f"finding-{fid}" in {item["id"] for item in inbox2["items"]}
    assert db2.get_finding(fid).state == "needs_human"
    db2.close()


def test_explicit_packet_cannot_spoof_finding_or_bad_schema(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    bad_schema = emit_packet(
        db,
        run_dir,
        {
            "schema": "harness-deck/report@1",
            "id": "gate-x",
            "status": "awaiting-review",
            "blocks": [{"type": "approval", "id": "gate-x-ok", "prompt": "Go?"}],
        },
    )
    assert bad_schema["ok"] is False
    spoof = emit_packet(
        db,
        run_dir,
        {
            "schema": SCHEMA_ID,
            "id": "finding-1",
            "status": "awaiting-review",
            "blocks": [{"type": "approval", "id": "gate-x-ok", "prompt": "Go?"}],
        },
    )
    assert spoof["ok"] is False
    reserved = emit_packet(
        db,
        run_dir,
        {
            "schema": SCHEMA_ID,
            "id": "gate-y",
            "status": "draft",
            "blocks": [
                {"type": "approval", "id": "finding-1-review", "prompt": "Steal the finding block?"}
            ],
        },
    )
    assert reserved["ok"] is False
    assert db.list_findings() == []
    db.close()


def test_inbox_backfills_needs_human_and_confirm_is_still_explicit(
    tmp_path: Path, toy_sqli: Path
):
    """A needs_human row with no packet yet still appears, and stays unconfirmed."""
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_good_body(toy_sqli), state="needs_human")
    assert db.get_hitl_report(f"finding-{fid}") is None
    inbox = list_inbox(db, run_dir)
    assert inbox["count"] == 1
    assert db.get_finding(fid).state == "needs_human"
    _approval_absent(responses_document(db, run_dir), fid)
    out = respond(
        db,
        run_dir,
        f"finding-{fid}",
        block_id=approval_block_id(fid),
        value="approved",
        note="explicit accept of a backfilled packet",
    )
    assert out["ok"] is True
    assert out["to_state"] == "confirmed"
    assert db.get_finding(fid).state == "confirmed"
    db.close()


def test_soft_migrate_adds_hitl_tables(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    db.conn.execute("DROP TABLE hitl_responses")
    db.conn.execute("DROP TABLE hitl_reports")
    db.conn.commit()
    db.close()
    reopened = Database.open(run_dir / "harness.db")
    assert reopened.list_hitl_reports() == []
    assert reopened.list_hitl_responses() == []
    reopened.close()


def test_cli_inbox_and_respond(tmp_path: Path, toy_sqli: Path, capsys):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    db.close()
    code = vf_main(["hitl", "inbox", "--run-dir", str(run_dir)])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    payload = json.loads(captured.out)
    assert payload["count"] == 1
    assert payload["items"][0]["schema"] == SCHEMA_ID

    code = vf_main(
        [
            "hitl",
            "respond",
            "--run-dir",
            str(run_dir),
            "--id",
            f"finding-{fid}",
            "--block",
            approval_block_id(fid),
            "--value",
            "approved",
            "--note",
            "cli accept",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0, captured.err
    body = json.loads(captured.out)
    assert body["to_state"] == "confirmed"
    db2 = Database.open(run_dir / "harness.db")
    assert db2.get_finding(fid).state == "confirmed"
    doc = responses_document(db2, run_dir)
    assert doc["responses"][approval_block_id(fid)]["value"] == "approved"
    assert doc["responses"][approval_block_id(fid)]["note"] == "cli accept"
    db2.close()


def test_api_inbox_page_and_respond(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    run_dir, db = _setup(runs_root, toy_sqli)
    fid = _pass_mech(run_dir, db, toy_sqli)
    db.close()
    app = create_app(runs_root=runs_root)
    with TestClient(app) as client:
        page = client.get("/runs/toy/run-001")
        assert page.status_code == 200
        assert 'id="hitl-inbox"' in page.text
        assert 'id="hitl-inbox-report"' in page.text
        assert "/static/hitl_inbox.js" in page.text

        base = "/api/runs/toy/run-001"
        inbox = client.get(f"{base}/hitl/inbox")
        assert inbox.status_code == 200, inbox.text
        body = inbox.json()
        assert body["count"] == 1
        assert body["items"][0]["id"] == f"finding-{fid}"

        notes = client.post(
            f"{base}/hitl/reports/finding-{fid}/respond",
            json={"block_id": notes_block_id(fid), "value": "note only", "operator": "ada"},
        )
        assert notes.status_code == 200, notes.text
        assert notes.json()["finding_state"] == "needs_human"

        missing = client.post(
            f"{base}/hitl/reports/finding-{fid}/respond",
            json={"block_id": approval_block_id(fid), "value": "confirmed"},
        )
        assert missing.status_code == 400

        still = client.get(f"{base}/hitl/inbox")
        assert still.json()["count"] == 1

        acc = client.post(
            f"{base}/hitl/reports/finding-{fid}/respond",
            json={
                "block_id": approval_block_id(fid),
                "value": "approved",
                "note": "api accept",
                "operator": "ada",
            },
        )
        assert acc.status_code == 200, acc.text
        assert acc.json()["to_state"] == "confirmed"
        after = client.get(f"{base}/hitl/inbox")
        assert after.json()["count"] == 0
        doc = client.get(f"{base}/hitl/responses")
        assert doc.status_code == 200
        saved = doc.json()["responses"][approval_block_id(fid)]
        assert saved["value"] == "approved"
        assert saved["note"] == "api accept"

    db2 = Database.open(run_dir / "harness.db")
    assert db2.get_finding(fid).state == "confirmed"
    db2.close()
