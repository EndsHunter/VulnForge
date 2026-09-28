"""Campaign sandbox one-shot phase.

When a run was started with the sandbox PoC toggle, queue one ``validate_poc``
per harness-ready ``needs_human`` finding. A missing sandbox fails closed
inside the task (``sandbox_unavailable``) and does not change finding state
or clear HITL.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.util import utc_now_iso


def sandbox_oneshot_enabled(cfg: dict | None) -> bool:
    data = cfg or {}
    run = data.get("run") if isinstance(data.get("run"), dict) else {}
    ph = data.get("poc_harness") if isinstance(data.get("poc_harness"), dict) else {}
    return bool(run.get("sandbox_poc_validate") or ph.get("sandbox_oneshot"))


def _pending_validate(db, finding_id: int) -> bool:
    try:
        tasks = db.list_tasks(limit=500)
    except Exception:
        return False
    for task in tasks:
        if getattr(task, "kind", None) != "validate_poc":
            continue
        if getattr(task, "state", None) not in ("queued", "leased", "paused"):
            continue
        payload = getattr(task, "payload", None) or {}
        try:
            if int(payload.get("finding_id") or 0) == int(finding_id):
                return True
        except (TypeError, ValueError):
            continue
    return False


def _already_attempted(body: dict, pack_dir: Path | None) -> bool:
    marker = body.get("poc_sandbox_oneshot")
    if isinstance(marker, dict) and marker.get("task_id"):
        return True
    latest = body.get("poc_validation_latest")
    if isinstance(latest, dict) and latest.get("verdict"):
        return True
    if pack_dir is not None and (pack_dir / "poc_run.json").is_file():
        return True
    return False


def enqueue_sandbox_oneshot_phase(
    db,
    run_dir: Path,
    *,
    only_finding_id: int | None = None,
    reason: str = "campaign",
) -> list[int]:
    """Enqueue validate_poc for due findings. Returns new task ids.

    Does not change finding state. No-op when the run toggle is off.
    """
    from vulnforge.control.ops import get_run_config
    from vulnforge.poc_handoff import POC_DEVELOP_RELPATH, assess_poc_readiness
    from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

    if not sandbox_oneshot_enabled(get_run_config(db)):
        return []

    findings = db.list_findings(states=["needs_human"])
    created: list[int] = []
    run_dir = Path(run_dir)
    for finding in findings:
        if only_finding_id is not None and int(finding.id) != int(only_finding_id):
            continue
        body = dict(finding.body or {})
        raw_eid = finding.evidence_id or body.get("evidence_id") or ""
        if not raw_eid:
            continue
        try:
            eid = sanitize_evidence_id(str(raw_eid))
        except InvalidEvidenceId:
            continue
        pack_dir = run_dir / "evidence" / eid
        if _already_attempted(body, pack_dir if pack_dir.is_dir() else None):
            continue
        if _pending_validate(db, finding.id):
            continue
        hub_text = ""
        hub_path = pack_dir / POC_DEVELOP_RELPATH
        if hub_path.is_file():
            try:
                hub_text = hub_path.read_text(encoding="utf-8")
            except OSError:
                hub_text = ""
        readiness = assess_poc_readiness(
            finding_body=body,
            pack_dir=pack_dir if pack_dir.is_dir() else None,
            hub_text=hub_text,
            finding_state=str(finding.state or ""),
        )
        if not readiness.get("ready"):
            continue
        payload: dict[str, Any] = {
            "finding_id": finding.id,
            "evidence_id": eid,
            "operator": "campaign",
            "sandbox_oneshot": True,
            "reason": reason,
        }
        task_id = db.enqueue_task("validate_poc", payload, priority=60)
        now = utc_now_iso()
        fresh = db.get_finding(finding.id)
        body2 = dict((fresh.body if fresh else body) or {})
        body2["poc_sandbox_oneshot"] = {
            "at": now,
            "task_id": task_id,
            "reason": reason,
            "evidence_id": eid,
        }
        hist = body2.get("poc_validation")
        if not isinstance(hist, list):
            hist = []
        hist.append(
            {
                "at": now,
                "action": "enqueue_sandbox_oneshot",
                "operator": "campaign",
                "task_id": task_id,
            }
        )
        body2["poc_validation"] = hist[-50:]
        # Keep an existing verdict if one is already recorded.
        latest = body2.get("poc_validation_latest")
        if not (isinstance(latest, dict) and latest.get("verdict")):
            body2["poc_validation_latest"] = hist[-1]
        db.conn.execute(
            "UPDATE findings SET body_json=?, updated_at=? WHERE id=?",
            (json.dumps(body2), now, finding.id),
        )
        db.conn.commit()
        created.append(int(task_id))
    return created
