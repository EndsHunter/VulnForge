"""
Stage: validate_llm (OPTIONAL â€” default off)

Adversarial disprove pass after validate_mech when stages.validate_llm is true.

Can only demote/reject. Never create findings. Never raise severity.
Same model as hunter is weak signal â€” residual risk is recorded on the finding.

When the flag is **off**, a leased validate_llm task (e.g. enqueued while the
flag was on, then config flipped) treats mech as terminal for automation:
promote still-open findings that already passed validate_mech to
``needs_human`` (never auto-``confirmed`` — that is a human decision).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vulnforge.llm import InfraError, classify_llm_failure, make_client, messages_from_packet
from vulnforge.packet import pack_disprove
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.util import append_event, utc_now_iso

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Full pack_disprove + LLM path is implemented.
IMPLEMENTATION_COMPLETE = True

# States that must not be reopened or "upgraded" by this stage.
# needs_human is open for re-disprove only if still pending_llm; once human
# confirmed/rejected, LLM must not override.
_TERMINAL_FINDING_STATES = frozenset(
    ("confirmed", "rejected_mech", "rejected_llm", "rejected_human", "superseded")
)


def _parse_finding_id(raw: Any) -> tuple[int | None, str | None]:
    """Return (fid, error). error set when payload present but not a valid int."""
    if raw is None:
        return None, "missing_finding_id"
    try:
        return int(raw), None
    except (TypeError, ValueError):
        return None, "invalid_finding_id"


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    """
    Adversarial disprove pass.

    Behavior:
      - flag off + open finding (mech already passed / pending_llm) -> needs_human
      - flag off + missing/terminal finding -> succeeded skip (no mutation)
      - flag on + missing/invalid finding -> failed_task (never raise / never confirm)
      - flag on + terminal finding -> succeeded skip
      - flag on + LLM: reject -> rejected_llm; stand | needs_human / parse fail ->
        needs_human (never auto-confirm; human is the confirm gate)
      - flag on + infra LLM failure -> failed_infra (retryable)
    """
    stages = cfg.get("stages") or {}
    flag_on = bool(stages.get("validate_llm"))
    fid_raw = (task.payload or {}).get("finding_id")
    fid, fid_err = _parse_finding_id(fid_raw)

    if not flag_on:
        return _flag_off_skip_or_confirm(task, db, run_dir, fid, fid_err)

    if fid is None:
        return _failed_invalid_payload(
            task, db, run_dir, fid, reason=fid_err or "missing_finding_id"
        )

    if not IMPLEMENTATION_COMPLETE:
        return _safe_hold_incomplete(
            task, db, run_dir, fid, reason="validate_llm_incomplete_stub"
        )

    return _run_disprove(task, db, run_dir, cfg, fid)


def _run_disprove(
    task,
    db,
    run_dir: Path,
    cfg: dict,
    fid: int,
) -> dict[str, Any]:
    """Full disprove: citation slices â†’ pack_disprove â†’ single chat â†’ verdict."""
    finding = db.get_finding(fid)
    if finding is None:
        return _failed_invalid_payload(
            task, db, run_dir, fid, reason="finding_not_found"
        )

    if finding.state in _TERMINAL_FINDING_STATES:
        _emit_event(
            run_dir,
            {
                "source": "vf",
                "event": "validate_llm_skipped",
                "task_id": getattr(task, "id", None),
                "finding_id": fid,
                "reason": "already_terminal",
                "finding_state": finding.state,
                "verdict": "skipped",
            },
        )
        return {
            "status": "succeeded",
            "skipped": True,
            "reason": "already_terminal",
            "finding_id": fid,
            "finding_state": finding.state,
        }

    run_row = db.get_run()
    if not run_row:
        return {
            "status": "failed_task",
            "error": "no_run",
            "finding_id": fid,
        }

    target = Path(run_row["target_path"])
    pkt_cfg = cfg.get("packet") or {}
    per_slice = int(pkt_cfg.get("max_file_slice_chars", 4000))
    # Cap total citation budget for the disprove packet
    max_chars = max(per_slice, min(per_slice * 4, 24_000))

    slices = load_citation_slices(finding, target, max_chars=max_chars)
    prompts_root = PROJECT_ROOT / "prompts" / "v1"
    body = dict(finding.body or {})
    try:
        packet = pack_disprove(cfg, prompts_root, body, slices)
    except FileNotFoundError as e:
        return _apply_verdict(
            task,
            db,
            run_dir,
            fid,
            verdict="needs_human",
            parse_reason="missing_prompts",
            content=None,
            model_id=None,
            extra={"error": str(e)},
        )

    client = make_client(cfg)
    model_id: str | None = None
    result_content: str | None = None
    try:
        try:
            model_id = client.fingerprint_model()
        except InfraError as e:
            return {
                "status": "failed_infra",
                "error": str(e),
                "finding_id": fid,
            }

        messages = messages_from_packet(packet)
        temp = float((cfg.get("llm") or {}).get("temperature_disprove", 0.2))
        result = client.chat(messages, tools=None, temperature=temp)
        if result.usage is None or result.usage.source == "none":
            from vulnforge.llm import estimate_usage_from_messages

            result.usage = estimate_usage_from_messages(
                messages, result.content, result.tool_calls
            )
        usage_fields = record_llm_result(
            run_dir,
            task_id=getattr(task, "id", 0) or 0,
            kind="validate_llm",
            model_id=model_id,
            result=result,
        )
        result_content = result.content
        try:
            save_transcript(
                run_dir,
                getattr(task, "id", 0) or 0,
                kind="validate_llm",
                model_id=model_id,
                messages=list(result.transcript or messages)
                + (
                    [{"role": "assistant", "content": result.content or ""}]
                    if result.content
                    else []
                ),
                result={
                    "ok": result.ok,
                    "classification": result.classification.value,
                    "error": result.error,
                    "content": result.content,
                    **usage_fields,
                },
                meta={"finding_id": fid, "stage": "disprove"},
            )
        except OSError:
            pass

        if not result.ok:
            status = classify_llm_failure(result)
            if status == "failed_infra":
                return {
                    "status": "failed_infra",
                    "error": result.error or result.classification.value,
                    "finding_id": fid,
                    "model_id": model_id,
                    **usage_fields,
                }
            # Model thrash / empty â†’ never confirm; hold for human
            return _apply_verdict(
                task,
                db,
                run_dir,
                fid,
                verdict="needs_human",
                parse_reason=result.error or result.classification.value,
                content=result.content,
                model_id=model_id,
                extra={"llm_failed": True},
            )

        parsed = parse_disprove_verdict(result.content or "")
        return _apply_verdict(
            task,
            db,
            run_dir,
            fid,
            verdict=parsed["verdict"],
            parse_reason=parsed.get("reason") or "ok",
            content=result.content,
            model_id=model_id,
            extra={"parse": parsed},
        )
    finally:
        try:
            client.close()
        except Exception:
            pass


def _apply_verdict(
    task,
    db,
    run_dir: Path,
    fid: int,
    *,
    verdict: str,
    parse_reason: str,
    content: str | None,
    model_id: str | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Map disprove verdict -> finding state.

    reject -> rejected_llm
    stand | needs_human -> needs_human (never auto-confirm; human is the gate)
    """
    finding = db.get_finding(fid)
    if finding is None:
        return _failed_invalid_payload(
            task, db, run_dir, fid, reason="finding_not_found"
        )
    if finding.state in _TERMINAL_FINDING_STATES:
        return {
            "status": "succeeded",
            "skipped": True,
            "reason": "already_terminal",
            "finding_id": fid,
            "finding_state": finding.state,
        }

    v = (verdict or "needs_human").lower()
    if v not in ("reject", "stand", "needs_human"):
        v = "needs_human"
        parse_reason = f"invalid_verdict:{verdict}"

    body = dict(finding.body or {})
    mech_meta = body.get("validation_mech")
    if isinstance(mech_meta, dict):
        mech_meta = dict(mech_meta)
        mech_meta["pending_llm"] = False
        body["validation_mech"] = mech_meta

    reasoning = (content or "").strip()
    if len(reasoning) > 8000:
        reasoning = reasoning[:8000] + "\nâ€¦[truncated]"

    llm_meta: dict[str, Any] = {
        "status": "completed",
        "verdict": v,
        "parse_reason": parse_reason,
        "model_id": model_id,
        "reasoning": reasoning,
        "at": utc_now_iso(),
        "residual_risk": (
            "Same-model or same-provider disprove is weak signal; "
            "prefer human review for HIGH/CRITICAL claims."
        ),
    }
    if extra:
        # Keep body compact â€” drop large parse raw if present
        safe_extra = {k: extra[k] for k in extra if k != "parse"}
        if "parse" in extra and isinstance(extra["parse"], dict):
            safe_extra["parse_reason_detail"] = extra["parse"].get("reason")
        llm_meta.update(safe_extra)
    body["validation_llm"] = llm_meta

    if v == "reject":
        new_state = "rejected_llm"
        body.pop("needs_human", None)
        reasons = body.get("validation_reasons")
        if not isinstance(reasons, list):
            reasons = []
        note = "validate_llm:rejected"
        if note not in reasons:
            reasons.append(note)
        body["validation_reasons"] = reasons
    else:
        # stand or needs_human — queue for operator; never auto-confirm
        new_state = "needs_human"
        body["needs_human"] = True
        if isinstance(body.get("validation_mech"), dict):
            body["validation_mech"]["resolved"] = (
                "stand_awaiting_human" if v == "stand" else "needs_human"
            )
        reasons = body.get("validation_reasons")
        if not isinstance(reasons, list):
            reasons = []
        if v == "stand":
            note = "validate_llm:stand_awaiting_human"
        else:
            note = f"validate_llm:needs_human:{parse_reason}"
        if note not in reasons:
            reasons.append(note)
        body["validation_reasons"] = reasons
        if v != "stand":
            llm_meta["status"] = "needs_human"

    db.conn.execute(
        "UPDATE findings SET state=?, body_json=?, updated_at=? WHERE id=?",
        (new_state, json.dumps(body), utc_now_iso(), fid),
    )
    db.conn.commit()

    _emit_event(
        run_dir,
        {
            "source": "vf",
            "event": "validate_llm_done",
            "task_id": getattr(task, "id", None),
            "finding_id": fid,
            "verdict": v,
            "finding_state": new_state,
            "parse_reason": parse_reason,
            "model_id": model_id,
        },
    )

    return {
        "status": "succeeded",
        "verdict": v,
        "finding_id": fid,
        "finding_state": new_state,
        "parse_reason": parse_reason,
        "model_id": model_id,
        "confirmed": False,
        "rejected": new_state == "rejected_llm",
        "needs_human": new_state == "needs_human",
    }


def _flag_off_skip_or_confirm(
    task,
    db,
    run_dir: Path,
    fid: int | None,
    fid_err: str | None,
) -> dict[str, Any]:
    """
    LLM stage disabled â†’ mech is terminal for findings that already passed mech.

    Stale validate_llm tasks (enqueued while flag was on) promote findings that
    carry ``validation_mech.pending_llm`` (set by validate_mech) so they are not
    stuck forever as candidate. Bare candidates without that stamp are not
    promoted (would bypass mech).
    """
    if fid is None:
        _emit_event(
            run_dir,
            {
                "source": "vf",
                "event": "validate_llm_skipped",
                "task_id": getattr(task, "id", None),
                "finding_id": None,
                "reason": "validate_llm_disabled",
                "detail": fid_err or "missing_finding_id",
                "finding_state": None,
                "verdict": "skipped",
            },
        )
        return {
            "status": "succeeded",
            "skipped": True,
            "reason": "validate_llm_disabled",
            "finding_id": None,
        }

    finding = db.get_finding(fid)
    if finding is None:
        _emit_event(
            run_dir,
            {
                "source": "vf",
                "event": "validate_llm_skipped",
                "task_id": getattr(task, "id", None),
                "finding_id": fid,
                "reason": "validate_llm_disabled",
                "detail": "finding_not_found",
                "finding_state": None,
                "verdict": "skipped",
            },
        )
        return {
            "status": "succeeded",
            "skipped": True,
            "reason": "validate_llm_disabled",
            "finding_id": fid,
            "detail": "finding_not_found",
        }

    if finding.state in _TERMINAL_FINDING_STATES:
        _emit_event(
            run_dir,
            {
                "source": "vf",
                "event": "validate_llm_skipped",
                "task_id": getattr(task, "id", None),
                "finding_id": fid,
                "reason": "validate_llm_disabled",
                "finding_state": finding.state,
                "verdict": "skipped",
            },
        )
        return {
            "status": "succeeded",
            "skipped": True,
            "reason": "validate_llm_disabled",
            "finding_id": fid,
            "finding_state": finding.state,
        }

    body = dict(finding.body)
    mech_meta = body.get("validation_mech")
    pending = (
        isinstance(mech_meta, dict) and bool(mech_meta.get("pending_llm"))
    )
    if not pending:
        # No mech-pass stamp: clean skip without confirming (avoids free-ride).
        _emit_event(
            run_dir,
            {
                "source": "vf",
                "event": "validate_llm_skipped",
                "task_id": getattr(task, "id", None),
                "finding_id": fid,
                "reason": "validate_llm_disabled",
                "finding_state": finding.state,
                "verdict": "skipped",
                "promoted": False,
            },
        )
        return {
            "status": "succeeded",
            "skipped": True,
            "reason": "validate_llm_disabled",
            "finding_id": fid,
            "finding_state": finding.state,
            "promoted": False,
        }

    # Mech already passed -> needs_human (LLM stage off; human is still the confirm gate).
    if isinstance(mech_meta, dict):
        mech_meta = dict(mech_meta)
        mech_meta["pending_llm"] = False
        mech_meta["resolved"] = "needs_human_llm_disabled"
        body["validation_mech"] = mech_meta
    body["validation_llm"] = {
        "status": "disabled_after_enqueue",
        "reason": "validate_llm_disabled",
        "note": "LLM stage off -> mech is terminal for automation; awaiting human review",
        "at": utc_now_iso(),
    }
    body["needs_human"] = True
    db.conn.execute(
        "UPDATE findings SET state=?, body_json=?, updated_at=? WHERE id=?",
        ("needs_human", json.dumps(body), utc_now_iso(), fid),
    )
    db.conn.commit()
    _emit_event(
        run_dir,
        {
            "source": "vf",
            "event": "validate_llm_skipped",
            "task_id": getattr(task, "id", None),
            "finding_id": fid,
            "reason": "validate_llm_disabled",
            "finding_state": "needs_human",
            "verdict": "needs_human",
            "promoted": True,
        },
    )
    return {
        "status": "succeeded",
        "skipped": True,
        "reason": "validate_llm_disabled",
        "verdict": "needs_human",
        "promoted": True,
        "finding_id": fid,
        "finding_state": "needs_human",
    }


def _failed_invalid_payload(
    task,
    db,
    run_dir: Path,
    fid: int | None,
    *,
    reason: str,
) -> dict[str, Any]:
    """Flag-on path: bad payload â†’ failed_task; never raise; never confirm."""
    _emit_event(
        run_dir,
        {
            "source": "vf",
            "event": "validate_llm_skipped",
            "task_id": getattr(task, "id", None),
            "finding_id": fid,
            "reason": reason,
            "finding_state": None,
            "verdict": "failed_task",
        },
    )
    return {
        "status": "failed_task",
        "error": reason,
        "reason": reason,
        "finding_id": fid,
    }


def _safe_hold_incomplete(
    task,
    db,
    run_dir: Path,
    fid: int | None,
    *,
    reason: str,
) -> dict[str, Any]:
    """
    Hold finding in a safe non-confirmed state and finish the task cleanly.

    Used for emergency CLI catch paths and IMPLEMENTATION_COMPLETE=False.
    Never raises. Never sets state to confirmed.
    """
    if fid is None:
        return _failed_invalid_payload(
            task, db, run_dir, None, reason="missing_finding_id"
        )

    finding = db.get_finding(fid)
    if finding is None:
        return _failed_invalid_payload(
            task, db, run_dir, fid, reason="finding_not_found"
        )

    finding_state: str | None = None
    if finding.state in _TERMINAL_FINDING_STATES:
        finding_state = finding.state
    else:
        body = dict(finding.body)
        body["needs_human"] = True
        body["validation_llm"] = {
            "status": "skipped_incomplete",
            "reason": reason,
            "at": utc_now_iso(),
        }
        reasons = body.get("validation_reasons")
        if not isinstance(reasons, list):
            reasons = []
        note = f"validate_llm:{reason}"
        if note not in reasons:
            reasons.append(note)
        body["validation_reasons"] = reasons
        hold_state = "needs_human"
        db.conn.execute(
            "UPDATE findings SET state=?, body_json=?, updated_at=? WHERE id=?",
            (hold_state, json.dumps(body), utc_now_iso(), fid),
        )
        db.conn.commit()
        finding_state = hold_state

    _emit_event(
        run_dir,
        {
            "source": "vf",
            "event": "validate_llm_skipped",
            "task_id": getattr(task, "id", None),
            "finding_id": fid,
            "reason": reason,
            "finding_state": finding_state,
            "verdict": "needs_human",
        },
    )

    return {
        "status": "succeeded",
        "verdict": "needs_human",
        "skipped": True,
        "incomplete": True,
        "reason": reason,
        "finding_id": fid,
        "finding_state": finding_state,
    }


def _emit_event(run_dir: Path, payload: dict[str, Any]) -> None:
    try:
        append_event(run_dir, payload)
    except Exception:
        pass


def load_citation_slices(
    finding, target_root: Path, max_chars: int
) -> list[dict]:
    """
    Read cited file/line ranges for the disprove packet.

    Safe best-effort helper (no raise on missing files).
    """
    body = getattr(finding, "body", None) or {}
    if isinstance(finding, dict):
        body = finding.get("body") or finding
    citations = body.get("citations") or []
    slices: list[dict] = []
    remaining = max(0, int(max_chars))
    root = target_root.resolve()
    for c in citations:
        if remaining <= 0:
            break
        if not isinstance(c, dict):
            continue
        rel = str(c.get("path") or "").replace("\\", "/").lstrip("/")
        if not rel or ".." in rel.split("/"):
            continue
        p = (root / rel).resolve()
        try:
            p.relative_to(root)
        except ValueError:
            continue
        if not p.is_file():
            slices.append({"path": rel, "error": "missing", "text": ""})
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            slices.append({"path": rel, "error": str(e), "text": ""})
            continue
        lines = text.splitlines()
        start = c.get("start_line")
        end = c.get("end_line")
        if start is not None:
            s = max(1, int(start))
            e = int(end) if end is not None else s
            e = max(s, e)
            # Pad a few lines of context around the citation
            pad = 3
            s0 = max(1, s - pad)
            e0 = min(len(lines), e + pad)
            chunk = "\n".join(lines[s0 - 1 : e0])
            meta_start, meta_end = s0, e0
        else:
            chunk = text
            meta_start, meta_end = 1, len(lines)
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
        remaining -= len(chunk)
        slices.append(
            {
                "path": rel,
                "start_line": meta_start,
                "end_line": meta_end,
                "symbol": c.get("symbol"),
                "text": chunk,
            }
        )
    return slices


def parse_disprove_verdict(content: str) -> dict:
    """
    Parse reject | stand | needs_human from model output.

    Default on parse failure: needs_human (never auto-confirm on garbage).
    Untagged free-text mentions of "reject" are intentionally ignored â€” only
    VERDICT= tags or JSON verdict fields count (demote-only safety).
    """
    text = (content or "").strip()
    if not text:
        return {"verdict": "needs_human", "reason": "empty_content"}

    m = re.search(
        r"VERDICT\s*=\s*(reject|stand|needs_human)\b",
        text,
        re.IGNORECASE,
    )
    if m:
        return {"verdict": m.group(1).lower(), "reason": "tag"}

    try:
        data = None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            brace = re.search(r"\{[^{}]*\}", text, re.DOTALL)
            if brace:
                data = json.loads(brace.group(0))
        if isinstance(data, dict):
            v = str(data.get("verdict") or data.get("VERDICT") or "").lower()
            if v in ("reject", "stand", "needs_human"):
                return {"verdict": v, "reason": "json", "raw": data}
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    return {"verdict": "needs_human", "reason": "parse_failure"}
