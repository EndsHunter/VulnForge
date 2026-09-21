"""Durable HITL report ↔ responses contract.

Schema: ``vulnforge/hitl-report@1`` (report packets) and
``vulnforge/hitl-responses@1`` (answers keyed by interactive block id).

Pattern adapted from harness-deck's report + ``responses.json`` contract:
versioned schema id, status ``draft | awaiting-review | answered | done``,
and interactive blocks ``ask`` / ``decision`` / ``approval``. VulnForge stores
the pair in ``harness.db`` (``hitl_reports`` / ``hitl_responses``) and projects
``hitl/responses.json`` plus ``hitl/reports/<id>.json`` for harness re-reads.

Finding packets are owned by finding state. ``needs_human`` publishes
``awaiting-review``. ``confirmed`` is written only by explicit human review
(``review_finding`` / an approval response that delegates to it). Publishing,
syncing, or reading responses never invents an approval and never sets
``confirmed``.

Ralph / loop state (``run.lock``, Ralph pid) is separate from this inbox.

See ``docs/harness/validate/HITL.md``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.db import Database
from vulnforge.util import utc_now_iso, write_json

SCHEMA_ID = "vulnforge/hitl-report@1"
RESPONSES_SCHEMA_ID = "vulnforge/hitl-responses@1"
HARNESS_NAME = "vulnforge"

STATUSES = frozenset({"draft", "awaiting-review", "answered", "done"})
INTERACTIVE_TYPES = frozenset({"ask", "decision", "approval"})
BLOCK_TYPES = frozenset({"prose", "ask", "decision", "approval"})
ASK_MODES = frozenset({"choice", "yesno", "text"})
APPROVAL_VALUES = frozenset({"approved", "changes-requested"})

# Finding-owned ids. Explicit packets must not use these.
_FINDING_REPORT_RE = re.compile(r"^finding-(\d+)$")
_FINDING_BLOCK_RE = re.compile(r"^finding-\d+-")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$")

_NOTE_MAX = 20000
_DONE_FINDING_STATES = frozenset(
    {"confirmed", "rejected_human", "rejected_llm", "rejected_mech", "superseded"}
)


def finding_report_id(finding_id: int) -> str:
    return f"finding-{int(finding_id)}"


def approval_block_id(finding_id: int) -> str:
    return f"finding-{int(finding_id)}-review"


def notes_block_id(finding_id: int) -> str:
    return f"finding-{int(finding_id)}-notes"


def parse_finding_report_id(report_id: str) -> Optional[int]:
    m = _FINDING_REPORT_RE.fullmatch(str(report_id or ""))
    if not m:
        return None
    return int(m.group(1))


def status_for_finding_state(state: str) -> Optional[str]:
    """Map a finding state onto a report status. ``None`` means no packet."""
    if state == "needs_human":
        return "awaiting-review"
    if state in _DONE_FINDING_STATES:
        return "done"
    return None


def _fail(error: str) -> dict[str, Any]:
    return {"ok": False, "error": error}


def _run_identity(db: Database, run_dir: Path) -> tuple[str, str]:
    row = None
    try:
        row = db.get_run()
    except Exception:
        row = None
    run_id = run_dir.name
    if row is not None:
        try:
            if row["id"]:
                run_id = str(row["id"])
        except (KeyError, IndexError, TypeError):
            pass
    project = run_dir.parent.name or run_id
    return run_id, project


def _check_id(value: str, *, what: str) -> Optional[str]:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        return f"invalid {what}: {value!r}"
    return None


def _option_values(options: Any) -> list[str]:
    if not isinstance(options, list):
        return []
    out: list[str] = []
    for opt in options:
        if isinstance(opt, str) and opt.strip():
            out.append(opt.strip())
        elif isinstance(opt, dict):
            raw = opt.get("value") or opt.get("id") or opt.get("label") or opt.get("text")
            if raw is not None and str(raw).strip():
                out.append(str(raw).strip())
    return out


def _validate_blocks(blocks: Any, *, allow_finding_ids: bool) -> Optional[str]:
    if not isinstance(blocks, list) or not blocks:
        return "blocks must be a non-empty list"
    seen: set[str] = set()
    interactive = 0
    for block in blocks:
        if not isinstance(block, dict):
            return "block must be an object"
        btype = str(block.get("type") or "")
        if btype not in BLOCK_TYPES:
            return f"unsupported block type: {btype!r}"
        if btype == "prose":
            if not isinstance(block.get("markdown"), str):
                return "prose block requires markdown"
            continue
        interactive += 1
        bid = block.get("id")
        err = _check_id(str(bid or ""), what="block id")
        if err:
            return err
        bid_s = str(bid)
        if bid_s in seen:
            return f"duplicate block id: {bid_s}"
        seen.add(bid_s)
        if not allow_finding_ids and _FINDING_BLOCK_RE.match(bid_s):
            return f"block id {bid_s} is reserved for finding review"
        prompt = block.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            return f"block {bid_s} requires prompt"
        if btype == "ask":
            mode = str(block.get("mode") or "")
            if mode not in ASK_MODES:
                return f"ask block {bid_s} mode must be choice|yesno|text"
            if mode == "choice" and not _option_values(block.get("options")):
                return f"ask block {bid_s} requires options"
        elif btype == "decision":
            for side in ("a", "b"):
                arm = block.get(side)
                if not isinstance(arm, dict):
                    return f"decision block {bid_s} requires {side}"
                tag = arm.get("tag")
                if not isinstance(tag, str) or not tag.strip():
                    return f"decision block {bid_s} {side}.tag is required"
            if str(block["a"]["tag"]).strip() == str(block["b"]["tag"]).strip():
                return f"decision block {bid_s} tags must differ"
        elif btype == "approval":
            pass
    if interactive < 1:
        return "packet requires at least one ask, decision, or approval block"
    return None


def _validate_value(block: dict, value: str) -> Optional[str]:
    raw = value if isinstance(value, str) else ""
    text = raw.strip()
    if not text:
        return "value is required"
    if len(text) > _NOTE_MAX:
        return "value is too long"
    btype = block.get("type")
    if btype == "approval":
        if text not in APPROVAL_VALUES:
            return "approval value must be approved or changes-requested"
        return None
    if btype == "decision":
        tags = {
            str(block["a"]["tag"]).strip(),
            str(block["b"]["tag"]).strip(),
        }
        if text not in tags:
            return "decision value must be one of the side tags"
        return None
    if btype == "ask":
        mode = str(block.get("mode") or "")
        if mode == "yesno" and text not in ("yes", "no"):
            return "yesno value must be yes or no"
        if mode == "choice" and text not in _option_values(block.get("options")):
            return "choice value must be one of the options"
        return None
    return "block is not interactive"


def _public_response(row: Optional[dict]) -> Optional[dict[str, str]]:
    if not row:
        return None
    return {
        "block": str(row.get("block") or row.get("block_id") or ""),
        "value": str(row.get("value") or ""),
        "note": str(row.get("note") or ""),
        "at": str(row.get("at") or ""),
    }


def _clip(text: str, limit: int = _NOTE_MAX) -> str:
    s = (text or "").strip()
    if len(s) > limit:
        return s[:limit] + "\n...[truncated]"
    return s


def build_finding_packet(
    finding,
    *,
    run_id: str,
    project: str,
    status: str,
    created: str,
    updated: str,
) -> dict[str, Any]:
    """Versioned report for one finding. Does not include a human answer."""
    body = dict(getattr(finding, "body", None) or {})
    fid = int(finding.id)
    title = str(body.get("title") or finding.stable_key or f"Finding {fid}")[:300]
    tm = body.get("threat_model") if isinstance(body.get("threat_model"), dict) else {}
    summary = str(body.get("summary") or "_No summary._")
    markdown = "\n".join(
        [
            f"**State:** `{finding.state}`",
            "",
            summary,
            "",
            f"- Attacker: {tm.get('attacker') or '-'}",
            f"- Boundary: {tm.get('boundary') or '-'}",
            f"- Impact: {tm.get('impact') or '-'}",
            "",
            "`needs_human` means mechanical gates passed. "
            "`confirmed` is an explicit human accept and is not exploit proof.",
        ]
    )
    return {
        "schema": SCHEMA_ID,
        "id": finding_report_id(fid),
        "project": project,
        "harness": HARNESS_NAME,
        "title": title,
        "kind": "finding-review",
        "status": status,
        "created": created,
        "updated": updated,
        "source": {
            "kind": "finding",
            "id": str(fid),
            "state": str(finding.state or ""),
        },
        "blocks": [
            {"type": "prose", "title": "Finding", "markdown": markdown},
            {
                "type": "approval",
                "id": approval_block_id(fid),
                "prompt": (
                    "Accept this finding? "
                    "approved records an explicit human accept (confirmed). "
                    "changes-requested records an explicit human reject. "
                    "Neither value is exploit proof."
                ),
            },
            {
                "type": "ask",
                "id": notes_block_id(fid),
                "prompt": "Reviewer notes. A note alone does not accept the finding.",
                "mode": "text",
            },
        ],
    }


def responses_document(db: Database, run_dir: Path) -> dict[str, Any]:
    """Flat responses map keyed by block id. Missing keys are unanswered."""
    run_id, project = _run_identity(db, run_dir)
    rows = db.list_hitl_responses()
    responses: dict[str, dict[str, str]] = {}
    latest = ""
    for row in rows:
        pub = _public_response(row)
        if not pub or not pub["block"]:
            continue
        responses[pub["block"]] = pub
        if pub["at"] > latest:
            latest = pub["at"]
    return {
        "schema": RESPONSES_SCHEMA_ID,
        "run": run_id,
        "project": project,
        "updated": latest or utc_now_iso(),
        "responses": responses,
    }


def write_projections(db: Database, run_dir: Path) -> dict[str, Any]:
    """Rewrite ``hitl/responses.json`` and per-report JSON from the DB."""
    doc = responses_document(db, run_dir)
    write_json(run_dir / "hitl" / "responses.json", doc)
    dest = run_dir / "hitl" / "reports"
    dest.mkdir(parents=True, exist_ok=True)
    keep: set[str] = set()
    for rep in db.list_hitl_reports():
        name = f"{rep['id']}.json"
        keep.add(name)
        packet = rep.get("packet") if isinstance(rep.get("packet"), dict) else {}
        write_json(dest / name, packet)
    for path in dest.glob("*.json"):
        if path.name not in keep:
            try:
                path.unlink()
            except OSError:
                pass
    return doc


def publish_finding(db: Database, run_dir: Path, finding_id: int) -> dict[str, Any]:
    """Upsert the finding's report from its current state.

    Never writes a response and never changes finding.state.
    """
    finding = db.get_finding(int(finding_id))
    if not finding:
        return _fail("finding_not_found")
    before = finding.state
    report_id = finding_report_id(finding.id)
    existing = db.get_hitl_report(report_id)
    status = status_for_finding_state(str(finding.state or ""))
    if status is None:
        return {"ok": True, "skipped": True, "reason": "no_hitl_packet"}
    if finding.state in ("rejected_mech", "superseded") and not existing:
        return {"ok": True, "skipped": True, "reason": "no_existing_packet"}
    if finding.state == "candidate":
        return {"ok": True, "skipped": True, "reason": "candidate"}

    now = utc_now_iso()
    created = now
    if existing:
        packet0 = existing.get("packet") if isinstance(existing.get("packet"), dict) else {}
        created = str(packet0.get("created") or existing.get("created_at") or now)
    run_id, project = _run_identity(db, run_dir)
    packet = build_finding_packet(
        finding,
        run_id=run_id,
        project=project,
        status=status,
        created=created,
        updated=now,
    )
    db.upsert_hitl_report(packet)
    # Re-read finding to prove publish did not mutate it.
    again = db.get_finding(int(finding_id))
    if again is None or again.state != before:
        return _fail("publish_mutated_finding_state")
    doc = write_projections(db, run_dir)
    return {
        "ok": True,
        "schema": SCHEMA_ID,
        "report_id": report_id,
        "status": status,
        "report": packet,
        "responses": doc.get("responses") or {},
    }


def sync_findings(db: Database, run_dir: Path) -> dict[str, Any]:
    """Publish a packet for every finding that belongs in the contract.

    Reads finding rows and writes reports only. Does not invent responses
    and does not set ``confirmed``.
    """
    published = 0
    for finding in db.list_findings():
        out = publish_finding(db, run_dir, finding.id)
        if out.get("ok") and not out.get("skipped"):
            published += 1
    return {"ok": True, "published": published}


def record_human_review(
    db: Database,
    run_dir: Path,
    *,
    finding_id: int,
    action: str,
    notes: str = "",
    operator: str = "operator",
    at: Optional[str] = None,
) -> dict[str, Any]:
    """Persist the explicit review action onto the responses store.

    Caller has already changed finding state. This function does not set
    ``confirmed`` itself. Reopen clears the approval answer so a previous
    accept is not still treated as the current response.
    """
    act = str(action or "").strip().lower()
    published = publish_finding(db, run_dir, int(finding_id))
    if not published.get("ok"):
        return published
    if published.get("skipped"):
        return _fail("finding_has_no_hitl_report")
    report_id = str(published["report_id"])
    stamp = at or utc_now_iso()
    note = _clip(notes)
    stored: Optional[dict] = None
    if act in ("confirm", "accept", "reject"):
        value = "approved" if act in ("confirm", "accept") else "changes-requested"
        stored = db.upsert_hitl_response(
            report_id,
            approval_block_id(finding_id),
            value=value,
            note=note,
            at=stamp,
            operator=operator or "operator",
        )
        if note:
            db.upsert_hitl_response(
                report_id,
                notes_block_id(finding_id),
                value=note,
                note="",
                at=stamp,
                operator=operator or "operator",
            )
    elif act in ("needs_human", "reopen"):
        db.delete_hitl_response(report_id, approval_block_id(finding_id))
        if note:
            stored = db.upsert_hitl_response(
                report_id,
                notes_block_id(finding_id),
                value=note,
                note="",
                at=stamp,
                operator=operator or "operator",
            )
    else:
        return _fail(f"invalid action: {action!r}")
    doc = write_projections(db, run_dir)
    fresh = db.get_hitl_report(report_id)
    status = (fresh or {}).get("status") or published.get("status")
    return {
        "ok": True,
        "schema": SCHEMA_ID,
        "responses_schema": RESPONSES_SCHEMA_ID,
        "report_id": report_id,
        "status": status,
        "response": _public_response(stored),
        "responses": doc.get("responses") or {},
    }


def _normalize_explicit_packet(packet: dict, run_dir: Path, db: Database) -> dict[str, Any]:
    run_id, project = _run_identity(db, run_dir)
    now = utc_now_iso()
    out = dict(packet)
    out["schema"] = SCHEMA_ID
    out["harness"] = str(out.get("harness") or HARNESS_NAME)
    out["project"] = str(out.get("project") or project)
    out["id"] = str(out.get("id") or "")
    out["title"] = str(out.get("title") or out["id"])[:300]
    out["status"] = str(out.get("status") or "")
    out["created"] = str(out.get("created") or now)
    out["updated"] = now
    if "kind" not in out:
        out["kind"] = "gate"
    source = out.get("source") if isinstance(out.get("source"), dict) else {}
    kind = str(source.get("kind") or "gate")
    out["source"] = {
        "kind": kind,
        "id": str(source.get("id") or out["id"]),
    }
    if out["source"]["kind"] == "finding":
        raise ValueError("explicit packets cannot use source.kind finding")
    # Keep run id available for projections without pretending it is the report id.
    out.setdefault("run", run_id)
    return out


def emit_packet(db: Database, run_dir: Path, packet: dict) -> dict[str, Any]:
    """Store an explicit HITL packet (a gate). Does not touch findings."""
    if not isinstance(packet, dict):
        return _fail("packet must be an object")
    schema = packet.get("schema")
    if schema != SCHEMA_ID:
        return _fail(f"schema must be {SCHEMA_ID}")
    report_id = str(packet.get("id") or "")
    err = _check_id(report_id, what="report id")
    if err:
        return _fail(err)
    if parse_finding_report_id(report_id) is not None:
        return _fail("finding report ids are owned by finding review")
    status = str(packet.get("status") or "")
    if status not in STATUSES:
        return _fail("status must be draft|awaiting-review|answered|done")
    source = packet.get("source") if isinstance(packet.get("source"), dict) else {}
    if str(source.get("kind") or "") == "finding":
        return _fail("explicit packets cannot use source.kind finding")
    block_err = _validate_blocks(packet.get("blocks"), allow_finding_ids=False)
    if block_err:
        return _fail(block_err)
    try:
        normalized = _normalize_explicit_packet(packet, run_dir, db)
    except ValueError as exc:
        return _fail(str(exc))
    before_states = {f.id: f.state for f in db.list_findings()}
    db.upsert_hitl_report(normalized)
    after = {f.id: f.state for f in db.list_findings()}
    if after != before_states:
        return _fail("emit_mutated_finding_state")
    doc = write_projections(db, run_dir)
    return {
        "ok": True,
        "schema": SCHEMA_ID,
        "report_id": normalized["id"],
        "status": normalized["status"],
        "report": normalized,
        "responses": doc.get("responses") or {},
    }


def _block_by_id(packet: dict, block_id: str) -> Optional[dict]:
    blocks = packet.get("blocks") if isinstance(packet.get("blocks"), list) else []
    for block in blocks:
        if isinstance(block, dict) and str(block.get("id") or "") == block_id:
            return block
    return None


def _interactive_ids(packet: dict) -> list[str]:
    blocks = packet.get("blocks") if isinstance(packet.get("blocks"), list) else []
    out: list[str] = []
    for block in blocks:
        if isinstance(block, dict) and block.get("type") in INTERACTIVE_TYPES:
            out.append(str(block.get("id") or ""))
    return [x for x in out if x]


def respond(
    db: Database,
    run_dir: Path,
    report_id: str,
    *,
    block_id: str,
    value: str,
    note: str = "",
    operator: str = "operator",
) -> dict[str, Any]:
    """Record one human answer.

    Finding approval blocks delegate to ``review_finding`` so ``confirmed``
    still requires that explicit review action. Any other write leaves
    finding states untouched.
    """
    fid_guess = parse_finding_report_id(str(report_id))
    if fid_guess is not None and db.get_hitl_report(str(report_id)) is None:
        # Older needs_human rows may predate the packet. Publishing does not
        # write an answer and does not change finding state.
        publish_finding(db, run_dir, fid_guess)
    report = db.get_hitl_report(str(report_id))
    if not report:
        return _fail("report_not_found")
    packet = report.get("packet") if isinstance(report.get("packet"), dict) else {}
    block = _block_by_id(packet, str(block_id))
    if not block:
        return _fail("block_not_found")
    if block.get("type") not in INTERACTIVE_TYPES:
        return _fail("block_not_interactive")
    value_s = str(value or "").strip()
    bad = _validate_value(block, value_s)
    if bad:
        return _fail(bad)
    note_s = _clip(note)

    fid = parse_finding_report_id(str(report_id))
    source = packet.get("source") if isinstance(packet.get("source"), dict) else {}
    if fid is not None or source.get("kind") == "finding":
        if fid is None or str(source.get("kind") or "") != "finding":
            return _fail("finding_report_mismatch")
        if str(source.get("id") or "") != str(fid):
            return _fail("finding_report_mismatch")
        if block.get("type") == "approval":
            action = "confirm" if value_s == "approved" else "reject"
            # End any read transaction on this connection before review opens another.
            try:
                db.conn.commit()
            except Exception:
                pass
            from vulnforge.control.ops import review_finding

            reviewed = review_finding(
                run_dir,
                fid,
                action=action,
                notes=note_s,
                operator=operator or "operator",
            )
            if not reviewed.get("ok"):
                return reviewed
            return {
                **reviewed,
                "schema": SCHEMA_ID,
                "report_id": finding_report_id(fid),
                "hitl_status": (reviewed.get("hitl") or {}).get("status"),
            }
        if block.get("type") == "ask" and block.get("mode") == "text":
            if str(packet.get("status") or "") != "awaiting-review":
                return _fail("report_not_awaiting_review")
            before = db.get_finding(fid)
            before_state = before.state if before else None
            stamp = utc_now_iso()
            stored = db.upsert_hitl_response(
                str(report_id),
                str(block_id),
                value=value_s,
                note=note_s,
                at=stamp,
                operator=operator or "operator",
            )
            after = db.get_finding(fid)
            if after is None or after.state != before_state:
                return _fail("respond_mutated_finding_state")
            doc = write_projections(db, run_dir)
            return {
                "ok": True,
                "schema": SCHEMA_ID,
                "report_id": str(report_id),
                "status": "awaiting-review",
                "finding_state": after.state,
                "to_state": after.state,
                "confirmed": False,
                "response": _public_response(stored),
                "responses": doc.get("responses") or {},
            }
        return _fail("unsupported_finding_block")

    status = str(packet.get("status") or "")
    if status not in ("awaiting-review", "answered"):
        return _fail("report_not_open")
    stamp = utc_now_iso()
    stored = db.upsert_hitl_response(
        str(report_id),
        str(block_id),
        value=value_s,
        note=note_s,
        at=stamp,
        operator=operator or "operator",
    )
    have = {row["block_id"] for row in db.list_hitl_responses(str(report_id))}
    needed = _interactive_ids(packet)
    new_status = "answered" if needed and all(bid in have for bid in needed) else "awaiting-review"
    packet = dict(packet)
    packet["status"] = new_status
    packet["updated"] = stamp
    before_states = {f.id: f.state for f in db.list_findings()}
    db.upsert_hitl_report(packet)
    after_states = {f.id: f.state for f in db.list_findings()}
    if after_states != before_states:
        return _fail("respond_mutated_finding_state")
    doc = write_projections(db, run_dir)
    return {
        "ok": True,
        "schema": SCHEMA_ID,
        "report_id": str(report_id),
        "status": new_status,
        "confirmed": False,
        "response": _public_response(stored),
        "responses": doc.get("responses") or {},
    }


def get_report(db: Database, run_dir: Path, report_id: str) -> dict[str, Any]:
    sync_findings(db, run_dir)
    report = db.get_hitl_report(str(report_id))
    if not report:
        return _fail("report_not_found")
    packet = report.get("packet") if isinstance(report.get("packet"), dict) else {}
    rows = db.list_hitl_responses(str(report_id))
    responses = {}
    for row in rows:
        pub = _public_response(row)
        if pub and pub["block"]:
            responses[pub["block"]] = pub
    return {
        "ok": True,
        "schema": packet.get("schema") or report.get("schema"),
        "report": packet,
        "responses": responses,
    }


def list_inbox(db: Database, run_dir: Path) -> dict[str, Any]:
    """Awaiting-review items for this run. Syncs finding packets first."""
    sync_findings(db, run_dir)
    doc = responses_document(db, run_dir)
    # sync already projected; refresh once more so the file matches the read.
    write_projections(db, run_dir)
    items: list[dict[str, Any]] = []
    for report in db.list_hitl_reports(status="awaiting-review"):
        packet = report.get("packet") if isinstance(report.get("packet"), dict) else {}
        if packet.get("schema") != SCHEMA_ID:
            continue
        if packet.get("status") != "awaiting-review":
            continue
        block_ids = _interactive_ids(packet)
        subset = {
            bid: doc["responses"][bid]
            for bid in block_ids
            if bid in (doc.get("responses") or {})
        }
        items.append(
            {
                "id": packet.get("id"),
                "schema": SCHEMA_ID,
                "status": "awaiting-review",
                "title": packet.get("title") or packet.get("id"),
                "kind": packet.get("kind") or "",
                "source": packet.get("source") or {},
                "created": packet.get("created"),
                "updated": packet.get("updated"),
                "blocks": packet.get("blocks") or [],
                "responses": subset,
            }
        )
    return {
        "ok": True,
        "schema": SCHEMA_ID,
        "responses_schema": RESPONSES_SCHEMA_ID,
        "status": "awaiting-review",
        "count": len(items),
        "items": items,
        "responses_path": "hitl/responses.json",
    }


def open_for_run(run_dir: Path) -> Database:
    return Database.open(Path(run_dir) / "harness.db")
