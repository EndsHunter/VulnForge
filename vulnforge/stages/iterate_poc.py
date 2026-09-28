"""
Stage: iterate_poc — rewrite/re-run a PoC inside one sandbox session.

Operator-queued (Report "Iterate in sandbox", ``vf validate-poc --iterate``).
Never creates findings. Never sets confirmed. Never clears needs_human.
Never writes a HITL response.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vulnforge.poc_handoff import POC_DEVELOP_RELPATH, POC_RUN_RELPATH
from vulnforge.poc_session import (
    SESSION_RELPATH,
    apply_pack_rewrite,
    run_iterate_session,
    session_to_poc_run,
)
from vulnforge.util import append_event, utc_now_iso

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


def _parse_finding_id(raw: Any) -> tuple[int | None, str | None]:
    if raw is None:
        return None, "missing_finding_id"
    try:
        return int(raw), None
    except (TypeError, ValueError):
        return None, "invalid_finding_id"


def parse_rewrite_payload(text: str | None) -> dict[str, Any] | None:
    """Pull ``{"files": {rel: source}}`` from a model reply. None if unusable."""
    raw = (text or "").strip()
    if not raw:
        return None
    fence = _FENCE_RE.search(raw)
    if fence:
        raw = fence.group(1)
    else:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            return None
        raw = raw[start : end + 1]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    files = data.get("files")
    if not isinstance(files, dict) or not files:
        return None
    clean = {str(k): str(v) for k, v in files.items() if isinstance(k, str)}
    if not clean:
        return None
    note = str(data.get("note") or "")[:500]
    return {"files": clean, "note": note}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def _llm_rewriter(cfg: dict, scripted: list[dict[str, Any]]):
    """File rewrite only. The harness re-execs inside the pinned guest."""

    def rewriter(ctx: dict[str, Any]) -> dict[str, Any] | None:
        if scripted:
            item = scripted.pop(0)
            return item if isinstance(item, dict) else None
        # Cycle 0 with no steer has no model call. Later cycles ask for files.
        if int(ctx.get("cycle_index") or 0) == 0 and not ctx.get("steers"):
            return None
        from vulnforge.llm import make_client

        last = ctx.get("last") if isinstance(ctx.get("last"), dict) else {}
        steers = ctx.get("steers") or []
        steer_text = "\n".join(
            f"- {s.get('operator')}: {s.get('text')}" for s in steers if isinstance(s, dict)
        )
        pack_dir = Path(ctx["pack_dir"])
        snippets = []
        for path in sorted(pack_dir.glob("poc.*")):
            if path.is_file() and path.stat().st_size < 20_000:
                snippets.append(f"--- {path.name}\n{path.read_text(encoding='utf-8', errors='replace')[:8000]}")
        prompt = (
            "You are editing a PoC that already runs inside a hard sandbox "
            "(microVM or gVisor). Do not suggest host execution.\n"
            "Return JSON only: {\"files\": {\"poc.py\": \"source\"}, \"note\": \"why\"}.\n"
            "Files must stay inside the evidence pack. The harness will copy them "
            "into the same guest and re-run the existing command.\n\n"
            f"Last verdict: {last.get('verdict')}\n"
            f"Last stdout:\n{last.get('stdout_excerpt') or ''}\n"
            f"Last stderr:\n{last.get('stderr_excerpt') or ''}\n"
            f"Human steer (same session):\n{steer_text or '(none)'}\n\n"
            + "\n".join(snippets)
        )
        client = make_client(cfg)
        try:
            result = client.chat(
                [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                tools=None,
                temperature=0.1,
            )
        finally:
            try:
                client.close()
            except Exception:
                pass
        if not getattr(result, "ok", False):
            return None
        return parse_rewrite_payload(getattr(result, "content", None))

    return rewriter


def _scripted_rewriter(scripted: list[dict[str, Any]]):
    def rewriter(ctx: dict[str, Any]) -> dict[str, Any] | None:
        del ctx
        if not scripted:
            return None
        item = scripted.pop(0)
        return item if isinstance(item, dict) else None

    return rewriter


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    payload = dict(task.payload or {})
    fid, fid_err = _parse_finding_id(payload.get("finding_id"))
    if fid is None:
        return {"status": "failed_task", "error": fid_err or "missing_finding_id"}

    finding = db.get_finding(fid)
    if finding is None:
        return {"status": "failed_task", "error": "finding_not_found", "finding_id": fid}

    state_before = finding.state
    from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

    body = dict(finding.body or {})
    raw_eid = (
        payload.get("evidence_id")
        or finding.evidence_id
        or body.get("evidence_id")
        or f"human-{fid}"
    )
    try:
        eid = sanitize_evidence_id(str(raw_eid))
    except InvalidEvidenceId as exc:
        return {"status": "failed_task", "error": f"invalid_evidence_id:{exc}", "finding_id": fid}

    pack_dir = run_dir / "evidence" / eid
    hub_path = pack_dir / POC_DEVELOP_RELPATH
    hub_text = ""
    if hub_path.is_file():
        try:
            hub_text = hub_path.read_text(encoding="utf-8")
        except OSError:
            hub_text = ""

    env_extra: dict[str, str] = {}
    for key in ("TARGET_URL", "target_url", "BASE_URL", "base_url"):
        if payload.get(key):
            env_extra["TARGET_URL"] = str(payload[key])
            break
    if isinstance(payload.get("env"), dict):
        env_extra.update({str(k): str(v) for k, v in payload["env"].items()})

    force_cmd = str(payload.get("command") or payload.get("run") or "").strip() or None
    run_row = db.get_run()
    target_path = None
    if run_row is not None:
        try:
            target_path = run_row["target_path"] or None
        except (KeyError, TypeError, IndexError):
            target_path = None

    scripted = [dict(x) for x in (payload.get("scripted_rewrites") or []) if isinstance(x, dict)]
    agent = payload.get("agent", True)
    if agent is False:
        rewriter = _scripted_rewriter(scripted) if scripted else None
    else:
        rewriter = _llm_rewriter(cfg, scripted)

    # Pre-apply an explicit rewrite list is the scripted path above.
    # A single payload.rewrite dict is applied before the session so cycle 1 sees it.
    preload = payload.get("rewrite")
    if isinstance(preload, dict) and preload.get("files"):
        try:
            apply_pack_rewrite(pack_dir, preload.get("files") or {})
        except ValueError as exc:
            return {
                "status": "failed_task",
                "error": str(exc),
                "finding_id": fid,
                "finding_state": state_before,
            }

    session = run_iterate_session(
        pack_dir,
        cfg=cfg,
        hub_text=hub_text,
        finding_body=body,
        finding_id=fid,
        force_command=force_cmd,
        target_path=target_path,
        env_extra=env_extra or None,
        rewriter=rewriter,
        operator=str(payload.get("operator") or "agent"),
        operator_notes=str(payload.get("operator_notes") or ""),
    )
    run_result = session_to_poc_run(session)
    run_result["evidence_id"] = eid
    run_result["task_id"] = getattr(task, "id", None)
    run_result["operator"] = payload.get("operator") or "agent"
    try:
        _write_json(pack_dir / POC_RUN_RELPATH, run_result)
    except OSError as exc:
        return {
            "status": "failed_task",
            "error": f"write_poc_run_failed:{exc}",
            "finding_id": fid,
            "finding_state": state_before,
        }

    now = utc_now_iso()
    latest = {
        "at": now,
        "mode": "iterate",
        "verdict": run_result.get("verdict"),
        "end_reason": session.get("end_reason"),
        "cycles_run": len(session.get("cycles") or []),
        "max_cycles": session.get("max_cycles"),
        "wall_ttl_min": session.get("wall_ttl_min"),
        "session_id": session.get("session_id"),
        "isolation": session.get("isolation"),
        "runtime": session.get("runtime"),
        "task_id": getattr(task, "id", None),
        "operator_hint": session.get("operator_hint"),
        "poc_run_relpath": POC_RUN_RELPATH,
        "poc_session_relpath": SESSION_RELPATH,
        "confirms_finding": False,
        "label": (
            "sandbox reproduced"
            if run_result.get("verdict") == "signal_observed"
            else run_result.get("verdict")
        ),
    }
    body2 = dict(body)
    body2["evidence_id"] = eid
    body2["poc_run_relpath"] = POC_RUN_RELPATH
    body2["poc_session_relpath"] = SESSION_RELPATH
    body2["poc_validation_latest"] = latest
    body2["poc_session_latest"] = latest
    hist = body2.get("poc_validation")
    if not isinstance(hist, list):
        hist = []
    hist.append(dict(latest))
    body2["poc_validation"] = hist[-50:]

    db.conn.execute(
        """
        UPDATE findings
        SET body_json=?, evidence_id=?, updated_at=?
        WHERE id=?
        """,
        (json.dumps(body2), eid, now, fid),
    )
    db.conn.commit()

    try:
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "poc_iterate_finished",
                "task_id": getattr(task, "id", None),
                "finding_id": fid,
                "evidence_id": eid,
                "verdict": run_result.get("verdict"),
                "end_reason": session.get("end_reason"),
                "cycles_run": len(session.get("cycles") or []),
                "isolation": session.get("isolation"),
                "confirms_finding": False,
            },
        )
    except OSError:
        pass

    return {
        "status": "succeeded",
        "finding_id": fid,
        "evidence_id": eid,
        "verdict": run_result.get("verdict"),
        "end_reason": session.get("end_reason"),
        "cycles_run": len(session.get("cycles") or []),
        "finding_state": state_before,
        "session": session,
        "poc_run": run_result,
    }
