"""Operator control for develop_fix / verify_fix (CLI + dashboard API).

Enqueue only. Ralph executes. Nothing here changes finding state or touches
the target tree.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.db import Database
from vulnforge.errors import note_swallowed
from vulnforge.fix_patch import (
    FIX_CHECK_RELPATH,
    FIX_NOTES_RELPATH,
    FIX_PATCH_RELPATH,
    VERIFY_FIX_RELPATH,
    PatchError,
    validate_git_rev,
)
from vulnforge.stages.fix_common import FIX_ELIGIBLE_STATES
from vulnforge.task_priority import PRIORITY_HIGH
from vulnforge.util import append_event


def _eid(finding) -> str:
    body = dict(finding.body or {})
    return str(finding.evidence_id or body.get("evidence_id") or f"human-{finding.id}")


def _gate(db: Database, finding_id: int, force: bool) -> tuple[Any, dict | None]:
    finding = db.get_finding(int(finding_id))
    if finding is None:
        return None, {"ok": False, "error": "finding_not_found"}
    if not force and str(finding.state or "") not in FIX_ELIGIBLE_STATES:
        return None, {
            "ok": False,
            "error": f"finding_state_not_eligible:{finding.state}",
            "hint": "develop_fix / verify_fix run on confirmed or needs_human findings (or pass force).",
        }
    return finding, None


def _enqueue(run_dir: Path, db: Database, kind: str, finding, payload: dict, event: str) -> dict:
    task_id = db.enqueue_task(kind, payload, priority=PRIORITY_HIGH)
    try:
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": event,
                "finding_id": finding.id,
                "task_id": task_id,
                "kind": kind,
            },
        )
    except OSError as exc:
        note_swallowed(exc, context=f"fix_ops.{kind}_event")
    return {
        "ok": True,
        "kind": kind,
        "task_id": task_id,
        "finding_id": finding.id,
        "evidence_id": payload.get("evidence_id"),
        "state": finding.state,
    }


def enqueue_develop_fix(
    run_dir: Path,
    finding_id: int,
    *,
    operator: str = "operator",
    operator_notes: str = "",
    force: bool = False,
) -> dict[str, Any]:
    """Queue a develop_fix agent task. Never applies the patch; never changes state."""
    db = Database.open(Path(run_dir) / "harness.db")
    try:
        finding, err = _gate(db, finding_id, force)
        if err:
            return err
        payload: dict[str, Any] = {
            "finding_id": finding.id,
            "evidence_id": _eid(finding),
            "operator": operator or "operator",
        }
        notes = (operator_notes or "").strip()
        if notes:
            payload["operator_notes"] = notes[:4000]
        if force:
            payload["force"] = True
        return _enqueue(Path(run_dir), db, "develop_fix", finding, payload, "fix_develop_enqueued")
    finally:
        db.close()


def build_verify_payload(
    finding,
    *,
    patched_path: str = "",
    git_rev: str = "",
    repo_path: str = "",
    subdir: str = "",
    use_fix_patch: bool = False,
    baseline: bool = True,
    target_url: str = "",
    operator: str = "operator",
    force: bool = False,
    keep_tree: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    picked = [x for x in (bool(patched_path), bool(git_rev), bool(use_fix_patch)) if x]
    if len(picked) != 1:
        return None, "need_exactly_one_source:patched_path|git_rev|use_fix_patch"
    payload: dict[str, Any] = {
        "finding_id": finding.id,
        "evidence_id": _eid(finding),
        "operator": operator or "operator",
        "baseline": bool(baseline),
    }
    if patched_path:
        p = Path(patched_path).expanduser()
        if not p.is_dir():
            return None, f"patched_path_not_dir:{patched_path}"
        payload["patched_path"] = str(p.resolve())
    if git_rev:
        try:
            payload["git_rev"] = validate_git_rev(git_rev)
        except PatchError as e:
            return None, str(e)
        if repo_path:
            payload["repo_path"] = str(Path(repo_path).expanduser().resolve())
        if subdir:
            payload["subdir"] = str(subdir)
    if use_fix_patch:
        payload["use_fix_patch"] = True
    if target_url:
        payload["TARGET_URL"] = str(target_url).strip()
    if force:
        payload["force"] = True
    if keep_tree:
        payload["keep_tree"] = True
    return payload, None


def enqueue_verify_fix(run_dir: Path, finding_id: int, **kwargs: Any) -> dict[str, Any]:
    """Queue an independent verify_fix task. Never changes finding state."""
    force = bool(kwargs.get("force"))
    db = Database.open(Path(run_dir) / "harness.db")
    try:
        finding, err = _gate(db, finding_id, force)
        if err:
            return err
        payload, perr = build_verify_payload(finding, **kwargs)
        if perr or payload is None:
            return {"ok": False, "error": perr}
        if payload.get("use_fix_patch"):
            pack = Path(run_dir) / "evidence" / payload["evidence_id"]
            if not (pack / FIX_PATCH_RELPATH).is_file():
                return {"ok": False, "error": "fix_patch_missing", "hint": "Run develop_fix first."}
        return _enqueue(Path(run_dir), db, "verify_fix", finding, payload, "fix_verify_enqueued")
    finally:
        db.close()


def _read_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None
    except (OSError, ValueError):
        return None


def _read_text(p: Path, limit: int = 200_000) -> str | None:
    try:
        return p.read_text(encoding="utf-8")[:limit] if p.is_file() else None
    except OSError:
        return None


def get_finding_fix(run_dir: Path, finding_id: int) -> dict[str, Any]:
    """Read-only view: fix.patch, fix_notes.md, fix_check.json, verify_fix.json."""
    db = Database.open(Path(run_dir) / "harness.db")
    try:
        finding = db.get_finding(int(finding_id))
        if finding is None:
            return {"ok": False, "error": "finding_not_found"}
        from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

        try:
            eid = sanitize_evidence_id(_eid(finding))
        except InvalidEvidenceId as e:
            return {"ok": False, "error": f"invalid_evidence_id:{e}"}
        pack = Path(run_dir) / "evidence" / eid
        body = dict(finding.body or {})
        return {
            "ok": True,
            "finding_id": finding.id,
            "state": finding.state,
            "evidence_id": eid,
            "fix_patch": _read_text(pack / FIX_PATCH_RELPATH),
            "fix_notes": _read_text(pack / FIX_NOTES_RELPATH),
            "fix_check": _read_json(pack / FIX_CHECK_RELPATH),
            "verify_fix": _read_json(pack / VERIFY_FIX_RELPATH),
            "fix_development_latest": body.get("fix_development_latest"),
            "fix_verification": body.get("fix_verification") or [],
        }
    finally:
        db.close()
