"""Derived evidence tier (issue #210). Label only: never state, never severity."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from vulnforge.db import Database
from vulnforge.evidence_tier import (
    TIER_RANK,
    TIERS,
    evidence_tier,
    evidence_tier_for_finding,
)
from vulnforge.export_findings import export_json, export_markdown, findings_to_rows
from vulnforge.hitl import list_inbox, publish_finding
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest, write_json

MECH_OK = {"status": "passed", "pending_llm": False}


def _stand(models=("m-a", "m-b")):
    return {
        "status": "needs_human",
        "verdict": "stand",
        "stood": len(models),
        "total": len(models),
        "label": f"{len(models)}/{len(models)}",
        "verifiers": [
            {"id": f"p{i}", "verdict": "stand", "model_id": m} for i, m in enumerate(models)
        ],
    }


def _poc(verdict):
    return {"at": "2026-11-01T00:00:00Z", "verdict": verdict, "label": verdict}


# ---- tier function ---------------------------------------------------------


def test_tiers_are_ordered_weakest_first_with_room_for_a_tool_tier():
    ranks = [TIER_RANK[t] for t in TIERS]
    assert ranks == sorted(ranks)
    assert TIERS == ("ungated", "gated", "stood", "reproduced")
    # Room between stood and reproduced for a future deterministic-tool tier.
    assert TIER_RANK["reproduced"] - TIER_RANK["stood"] > 10


def test_gated_when_only_mech_passed():
    t = evidence_tier({"validation_mech": dict(MECH_OK)}, "needs_human")
    assert t["tier"] == "gated"
    assert t["disprove"]["status"] == "not_run"
    assert t["poc"] is None


def test_stood_when_every_slot_stands_and_records_model_spread():
    multi = evidence_tier({"validation_mech": MECH_OK, "validation_llm": _stand()}, "needs_human")
    assert multi["tier"] == "stood"
    assert multi["disprove"]["models"] == 2
    assert multi["disprove"]["same_model"] is False

    same = evidence_tier(
        {"validation_mech": MECH_OK, "validation_llm": _stand(("m-a", "m-a"))}, "needs_human"
    )
    assert same["tier"] == "stood"
    assert same["disprove"]["same_model"] is True
    assert "weaker" in same["summary"]
    assert "weak signal" in same["summary"].lower()


def test_reproduced_when_sandbox_observed_signal():
    t = evidence_tier(
        {"validation_mech": MECH_OK, "validation_llm": _stand(), "poc_validation_latest": _poc("signal_observed")},
        "needs_human",
    )
    assert t["tier"] == "reproduced"
    assert t["poc"]["raises_tier"] is True
    # Reproduced does not need a stand: PoC evidence is separate from disprove.
    t2 = evidence_tier(
        {"validation_mech": MECH_OK, "poc_validation_latest": _poc("signal_observed")}, "needs_human"
    )
    assert t2["tier"] == "reproduced"


def test_ungated_without_mech_pass():
    assert evidence_tier({}, "candidate")["tier"] == "ungated"
    assert evidence_tier({"validation_mech": {"status": "failed"}}, "rejected_mech")["tier"] == "ungated"
    # A PoC signal does not lift a finding that never passed the gates.
    assert (
        evidence_tier({"poc_validation_latest": _poc("signal_observed")}, "rejected_mech")["tier"]
        == "ungated"
    )


def test_disprove_off_pending_or_skipped_stays_gated():
    off = {"validation_mech": MECH_OK, "validation_llm": {"status": "disabled_after_enqueue"}}
    assert evidence_tier(off, "needs_human")["tier"] == "gated"
    assert evidence_tier(off, "needs_human")["disprove"]["status"] == "off"

    pending = {"validation_mech": {"status": "passed", "pending_llm": True}}
    assert evidence_tier(pending, "needs_human")["disprove"]["status"] == "pending"

    # Re-armed disprove: an old stand is stale while the new pass is pending.
    rearmed = {"validation_mech": {"status": "passed", "pending_llm": True}, "validation_llm": _stand()}
    assert evidence_tier(rearmed, "needs_human")["tier"] == "gated"

    partial = {"validation_mech": MECH_OK, "validation_llm": {"status": "partial", "verdict": "pending"}}
    assert evidence_tier(partial, "needs_human")["disprove"]["status"] == "pending"

    skipped = {"validation_mech": MECH_OK, "validation_llm": {"status": "skipped_incomplete"}}
    assert evidence_tier(skipped, "needs_human")["tier"] == "gated"
    assert evidence_tier(skipped, "needs_human")["disprove"]["status"] == "skipped"


def test_split_or_unparsed_disprove_is_not_stood():
    split = {
        "validation_mech": MECH_OK,
        "validation_llm": {
            "verdict": "needs_human",
            "verifiers": [{"verdict": "stand", "model_id": "a"}, {"verdict": "reject", "model_id": "b"}],
        },
    }
    t = evidence_tier(split, "needs_human")
    assert t["tier"] == "gated" and t["disprove"]["status"] == "split"

    unparsed = {
        "validation_mech": MECH_OK,
        "validation_llm": {"verdict": "needs_human", "verifiers": [{"verdict": "needs_human"}]},
    }
    assert evidence_tier(unparsed, "needs_human")["disprove"]["status"] == "inconclusive"

    rejected = {"validation_mech": MECH_OK, "validation_llm": {"verdict": "reject"}}
    assert evidence_tier(rejected, "rejected_llm")["tier"] == "gated"
    assert evidence_tier(rejected, "rejected_llm")["disprove"]["status"] == "rejected"


def test_failed_or_inconclusive_poc_does_not_raise_but_stays_visible():
    for verdict in ("signal_absent", "poc_broken", "inconclusive", "build_failed", "sandbox_unavailable"):
        t = evidence_tier(
            {"validation_mech": MECH_OK, "validation_llm": _stand(), "poc_validation_latest": _poc(verdict)},
            "needs_human",
        )
        assert t["tier"] == "stood", verdict
        assert t["poc"]["verdict"] == verdict
        assert t["poc"]["raises_tier"] is False
        assert verdict in t["summary"]
        assert "does not raise" in t["summary"]


def test_later_failed_run_replaces_an_earlier_signal():
    body = {
        "validation_mech": MECH_OK,
        "poc_validation": [_poc("signal_observed"), _poc("signal_absent")],
        "poc_validation_latest": _poc("signal_absent"),
    }
    assert evidence_tier(body, "needs_human")["tier"] == "gated"


def test_queued_rerun_does_not_erase_last_finished_run():
    # enqueue_validate overwrites poc_validation_latest with a verdict-less marker.
    body = {
        "validation_mech": MECH_OK,
        "poc_validation": [_poc("signal_observed"), {"action": "enqueue_validate", "task_id": 9}],
        "poc_validation_latest": {"action": "enqueue_validate", "task_id": 9},
    }
    t = evidence_tier(body, "needs_human")
    assert t["tier"] == "reproduced"
    assert t["poc"]["pending"] is True

    only_queued = {"validation_mech": MECH_OK, "poc_validation_latest": {"action": "enqueue_validate"}}
    t2 = evidence_tier(only_queued, "needs_human")
    assert t2["tier"] == "gated"
    assert t2["poc"] == {"verdict": None, "at": None, "pending": True, "raises_tier": False}
    assert "queued" in t2["summary"]


def test_older_findings_with_missing_fields():
    # No validation_mech stamp at all: infer from a post-mech state.
    for st in ("needs_human", "confirmed", "rejected_human", "rejected_llm"):
        assert evidence_tier({"title": "old"}, st)["tier"] == "gated", st
    assert evidence_tier(None, None)["tier"] == "ungated"
    assert evidence_tier({"validation_llm": "garbage", "poc_validation_latest": [1]}, "needs_human")["tier"] == "gated"
    # Old verifiers without model ids: same_model unknown, not guessed.
    t = evidence_tier(
        {"validation_llm": {"verdict": "stand", "verifiers": [{"verdict": "stand"}, {"verdict": "stand"}]}},
        "needs_human",
    )
    assert t["tier"] == "stood"
    assert t["disprove"]["same_model"] is None


def test_pure_and_label_only():
    body = {
        "validation_mech": MECH_OK,
        "validation_llm": _stand(),
        "poc_validation_latest": _poc("signal_observed"),
        "severity_claim": "LOW",
    }
    before = copy.deepcopy(body)
    t = evidence_tier(body, "needs_human")
    assert body == before
    assert evidence_tier(body, "needs_human") == t
    assert "state" not in t and "severity" not in t and "confirmed" not in json.dumps(t)
    text = json.dumps(t).lower()
    assert "proven" not in text and "verified" not in text
    assert evidence_tier_for_finding({"state": "needs_human", "body": body}) == t


# ---- readers: HITL packet, exports, human_review ---------------------------


def _good_body(toy_sqli: Path) -> dict:
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
        "evidence_id": "e1",
        "severity_claim": "HIGH",
    }
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break
    return body


def _needs_human(tmp_path: Path, toy_sqli: Path, extra: dict):
    run_dir = tmp_path / "toy" / "run-001"
    (run_dir / "evidence" / "e1").mkdir(parents=True)
    write_json(run_dir / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    body = _good_body(toy_sqli)
    body.update({"validation_mech": dict(MECH_OK), "needs_human": True})
    body.update(extra)
    fid = db.insert_finding(body)
    db.conn.execute("UPDATE findings SET state='needs_human' WHERE id=?", (fid,))
    db.conn.commit()
    return run_dir, db, fid


def test_hitl_packet_and_inbox_carry_tier(tmp_path: Path, toy_sqli: Path):
    run_dir, db, fid = _needs_human(tmp_path, toy_sqli, {"validation_llm": _stand()})
    try:
        pub = publish_finding(db, run_dir, fid)
        assert pub["report"]["evidence_tier"]["tier"] == "stood"
        assert "Evidence tier:** `stood`" in pub["report"]["blocks"][0]["markdown"]
        inbox = list_inbox(db, run_dir)
        assert inbox["items"][0]["evidence_tier"]["tier"] == "stood"
        assert db.get_finding(fid).state == "needs_human"
    finally:
        db.close()


def test_exports_read_tier(tmp_path: Path, toy_sqli: Path):
    run_dir, db, fid = _needs_human(
        tmp_path, toy_sqli, {"poc_validation_latest": _poc("signal_observed")}
    )
    try:
        rows = findings_to_rows(db)
        assert rows[0]["evidence_tier"] == "reproduced"
        data = json.loads(export_json(run_dir, db))
        assert data["rows"][0]["evidence_tier"] == "reproduced"
        assert data["findings"][0]["evidence_tier"]["tier"] == "reproduced"
        assert "**evidence_tier:** `reproduced`" in export_markdown(run_dir, db)
    finally:
        db.close()


def test_human_review_records_tier_at_verdict_time(tmp_path: Path, toy_sqli: Path):
    run_dir, db, fid = _needs_human(
        tmp_path,
        toy_sqli,
        {"validation_llm": _stand(("m", "m")), "poc_validation_latest": _poc("poc_broken")},
    )
    db.close()
    r = dashops.review_finding(run_dir, fid, action="reject", notes="not reachable")
    assert r["ok"] is True
    db = Database.open(run_dir / "harness.db")
    try:
        f = db.get_finding(fid)
        entry = f.body["human_review"][-1]
        assert entry["evidence_tier"] == "stood"
        assert entry["evidence_tier_detail"] == {
            "disprove": "stand",
            "same_model": True,
            "poc_verdict": "poc_broken",
        }
        assert f.body["human_review_latest"]["evidence_tier"] == "stood"
        assert f.state == "rejected_human"
        # Severity untouched by the tier.
        assert f.body["severity_claim"] == "HIGH"
    finally:
        db.close()

    acc = dashops.review_finding(run_dir, fid, action="confirm")
    assert acc["ok"] is True
    # Accept from rejected_human: tier is still computed from the body, not the state.
    db = Database.open(run_dir / "harness.db")
    try:
        assert db.get_finding(fid).body["human_review"][-1]["evidence_tier"] == "stood"
    finally:
        db.close()


def test_snapshot_findings_carry_tier(tmp_path: Path, toy_sqli: Path):
    from vulnforge.cli import main
    from vulnforge.ui import store

    runs = tmp_path / "runs"
    main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    ref = store.discover_runs(runs)[0]
    db = Database.open(ref.path / "harness.db")
    try:
        body = _good_body(toy_sqli)
        body.update({"validation_mech": dict(MECH_OK), "validation_llm": _stand()})
        fid = db.insert_finding(body)
        db.conn.execute("UPDATE findings SET state='needs_human' WHERE id=?", (fid,))
        db.conn.commit()
    finally:
        db.close()
    snap = store.run_snapshot(ref)
    row = next(f for f in snap["findings"] if f["id"] == fid)
    assert row["evidence_tier"]["tier"] == "stood"
    assert row["state"] == "needs_human"
    assert row["severity"] == "high"
