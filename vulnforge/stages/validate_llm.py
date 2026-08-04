"""
Stage: validate_llm (default ON via stages.validate_llm)

Adversarial dual-disprove pass after validate_mech when stages.validate_llm is true.

Two sequential LLM verifiers (threat-model + code/mitigation perspectives) each
try to kill the finding. Can only demote/reject. Never create findings. Never
raise severity. Never auto-confirm. Same-model dual disprove is weak signal.

Aggregation:
  - both reject → rejected_llm
  - any stand / needs_human / parse fail → needs_human
  - stood = count of VERDICT=stand; Report shows stood/total llm verified

When the flag is **off** (opt out for speed/debug), a leased validate_llm task
(e.g. enqueued while the flag was on, then config flipped) treats mech as
terminal for automation: promote still-open findings that already passed
validate_mech to ``needs_human`` (never auto-``confirmed`` — that is a human
decision).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vulnforge.llm import InfraError, classify_llm_failure, messages_from_packet
from vulnforge.packet import pack_disprove
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.paths import system_prompts_root
from vulnforge.util import append_event, utc_now_iso

# Full pack_disprove + dual LLM path is implemented.
IMPLEMENTATION_COMPLETE = True

# States that must not be reopened or "upgraded" by this stage.
# needs_human is open for re-disprove only if still pending_llm; once human
# confirmed/rejected, LLM must not override.
_TERMINAL_FINDING_STATES = frozenset(
    ("confirmed", "rejected_mech", "rejected_llm", "rejected_human", "superseded")
)

# Default dual verifiers when llm.disprove_verifiers is omitted.
_DEFAULT_DISPROVE_VERIFIERS: list[dict[str, str]] = [
    {"id": "threat_model", "prompt": "disprove_threat.md"},
    {"id": "code_mitigation", "prompt": "disprove_code.md"},
]


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
    Adversarial dual-disprove pass.

    Behavior:
      - flag off + open finding (mech already passed / pending_llm) -> needs_human
      - flag off + missing/terminal finding -> succeeded skip (no mutation)
      - flag on + missing/invalid finding -> failed_task (never raise / never confirm)
      - flag on + terminal finding -> succeeded skip
      - flag on + dual LLM: both reject -> rejected_llm; else -> needs_human
        (never auto-confirm; human is the confirm gate)
      - flag on + infra LLM failure before aggregate -> failed_infra (retryable)
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


def resolve_disprove_verifiers(cfg: dict) -> list[dict[str, Any]]:
    """Return ordered verifier slots from config or built-in defaults."""
    llm = cfg.get("llm") or {}
    raw = llm.get("disprove_verifiers")
    if not isinstance(raw, list) or not raw:
        return [dict(x) for x in _DEFAULT_DISPROVE_VERIFIERS]
    out: list[dict[str, Any]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        vid = str(item.get("id") or f"verifier_{i + 1}").strip() or f"verifier_{i + 1}"
        prompt = str(item.get("prompt") or "").strip()
        if not prompt:
            continue
        slot: dict[str, Any] = {"id": vid, "prompt": prompt}
        if item.get("model") is not None:
            slot["model"] = item.get("model")
        out.append(slot)
    return out if out else [dict(x) for x in _DEFAULT_DISPROVE_VERIFIERS]


def aggregate_disprove_verdicts(
    verifier_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Aggregate per-slot verdicts.

    stood = count of stand; rejected_llm only if every slot is reject.
    """
    total = len(verifier_results)
    if total == 0:
        return {
            "stood": 0,
            "total": 0,
            "label": "0/0",
            "aggregate": "needs_human",
            "verdict": "needs_human",
            "all_reject": False,
        }
    verdicts = []
    for vr in verifier_results:
        v = str(vr.get("verdict") or "needs_human").lower()
        if v not in ("reject", "stand", "needs_human"):
            v = "needs_human"
        verdicts.append(v)
    stood = sum(1 for v in verdicts if v == "stand")
    all_reject = all(v == "reject" for v in verdicts)
    aggregate = "rejected_llm" if all_reject else "needs_human"
    # Compatibility top-level verdict for older readers
    if all_reject:
        top = "reject"
    elif stood == total:
        top = "stand"
    else:
        top = "needs_human"
    return {
        "stood": stood,
        "total": total,
        "label": f"{stood}/{total}",
        "aggregate": aggregate,
        "verdict": top,
        "all_reject": all_reject,
    }


def _run_disprove(
    task,
    db,
    run_dir: Path,
    cfg: dict,
    fid: int,
) -> dict[str, Any]:
    """Full dual disprove: citation slices → sequential pack+chat → aggregate."""
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
    prompts_root = system_prompts_root()
    body = dict(finding.body or {})
    verifiers = resolve_disprove_verifiers(cfg)

    from vulnforge.llm_models import (
        make_client_for_model,
        multi_model_disprove_meta,
        resolve_validate_consensus,
        resolve_validate_models,
    )

    validate_models = resolve_validate_models(cfg)
    if not validate_models:
        validate_models = [str((cfg.get("llm") or {}).get("model") or "")]
    consensus_mode = resolve_validate_consensus(cfg)
    model_id: str | None = validate_models[0] if validate_models else None
    verifier_results: list[dict[str, Any]] = []
    open_clients: list[Any] = []
    try:
        temp = float((cfg.get("llm") or {}).get("temperature_disprove", 0.2))

        # Multi-model × dual perspectives: independent arguments; all must reject
        # to auto-reject_llm (low false-positive automation).
        for mid in validate_models:
            client = make_client_for_model(cfg, mid or None)
            open_clients.append(client)
            try:
                resolved = client.fingerprint_model()
            except InfraError as e:
                if verifier_results:
                    _stamp_partial_llm(
                        db,
                        fid,
                        verifier_results,
                        error=str(e),
                    )
                return {
                    "status": "failed_infra",
                    "error": str(e),
                    "finding_id": fid,
                    "model_id": mid,
                }
            model_id = resolved

            for slot in verifiers:
                slot_id = str(slot.get("id") or "verifier")
                perspective = str(slot.get("prompt") or "")
                # Per-verifier model override wins over validate_models entry
                slot_model = slot.get("model")
                recorded_model = str(slot_model) if slot_model else resolved
                active_client = client
                if slot_model and str(slot_model) != mid:
                    active_client = make_client_for_model(cfg, str(slot_model))
                    open_clients.append(active_client)
                    try:
                        recorded_model = active_client.fingerprint_model()
                    except InfraError as e:
                        if verifier_results:
                            _stamp_partial_llm(
                                db, fid, verifier_results, error=str(e)
                            )
                        return {
                            "status": "failed_infra",
                            "error": str(e),
                            "finding_id": fid,
                            "model_id": str(slot_model),
                            "verifier_id": slot_id,
                        }

                # Unique id when multiple models share perspective ids
                result_id = (
                    f"{slot_id}@{recorded_model}"
                    if len(validate_models) > 1
                    else slot_id
                )

                try:
                    packet = pack_disprove(
                        cfg,
                        prompts_root,
                        body,
                        slices,
                        perspective=perspective or None,
                        verifier_id=result_id,
                    )
                except FileNotFoundError as e:
                    verifier_results.append(
                        {
                            "id": result_id,
                            "prompt": perspective,
                            "verdict": "needs_human",
                            "parse_reason": "missing_prompts",
                            "model_id": recorded_model,
                            "reasoning": "",
                            "at": utc_now_iso(),
                            "error": str(e),
                        }
                    )
                    continue

                messages = messages_from_packet(packet)
                result = active_client.chat(
                    messages, tools=None, temperature=temp
                )
                if result.usage is None or result.usage.source == "none":
                    from vulnforge.llm import estimate_usage_from_messages

                    result.usage = estimate_usage_from_messages(
                        messages, result.content, result.tool_calls
                    )
                usage_fields = record_llm_result(
                    run_dir,
                    task_id=getattr(task, "id", 0) or 0,
                    kind="validate_llm",
                    model_id=recorded_model,
                    result=result,
                )
                try:
                    save_transcript(
                        run_dir,
                        getattr(task, "id", 0) or 0,
                        kind="validate_llm",
                        model_id=recorded_model,
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
                        meta={
                            "finding_id": fid,
                            "stage": "disprove",
                            "verifier_id": result_id,
                            "perspective": perspective,
                            "model_id": recorded_model,
                        },
                        pass_key=f"disprove-{result_id}",
                    )
                except OSError:
                    pass

                if not result.ok:
                    status = classify_llm_failure(result)
                    if status == "failed_infra":
                        if verifier_results:
                            _stamp_partial_llm(
                                db,
                                fid,
                                verifier_results,
                                error=result.error
                                or result.classification.value,
                            )
                        return {
                            "status": "failed_infra",
                            "error": result.error
                            or result.classification.value,
                            "finding_id": fid,
                            "model_id": recorded_model,
                            "verifier_id": result_id,
                            "partial_verifiers": len(verifier_results),
                            **usage_fields,
                        }
                    verifier_results.append(
                        {
                            "id": result_id,
                            "prompt": perspective,
                            "verdict": "needs_human",
                            "parse_reason": result.error
                            or result.classification.value,
                            "model_id": recorded_model,
                            "reasoning": (result.content or "")[:8000],
                            "at": utc_now_iso(),
                            "llm_failed": True,
                        }
                    )
                    continue

                parsed = parse_disprove_verdict(result.content or "")
                v = parsed["verdict"]
                reasoning = (result.content or "").strip()
                if len(reasoning) > 8000:
                    reasoning = reasoning[:8000] + "\n…[truncated]"
                verifier_results.append(
                    {
                        "id": result_id,
                        "prompt": perspective,
                        "verdict": v,
                        "parse_reason": parsed.get("reason") or "ok",
                        "model_id": recorded_model,
                        "reasoning": reasoning,
                        "at": utc_now_iso(),
                    }
                )

        multi = multi_model_disprove_meta(
            verifier_results, mode=consensus_mode
        )
        return _apply_dual_verdict(
            task,
            db,
            run_dir,
            fid,
            verifier_results=verifier_results,
            model_id=model_id,
            multi_model=multi,
        )
    finally:
        for c in open_clients:
            try:
                c.close()
            except Exception:
                pass


def _stamp_partial_llm(
    db,
    fid: int,
    verifier_results: list[dict[str, Any]],
    *,
    error: str,
) -> None:
    """Record partial dual results without changing finding state (infra retry)."""
    finding = db.get_finding(fid)
    if finding is None or finding.state in _TERMINAL_FINDING_STATES:
        return
    body = dict(finding.body or {})
    agg = aggregate_disprove_verdicts(verifier_results)
    body["validation_llm"] = {
        "status": "partial",
        "stood": agg["stood"],
        "total": agg["total"],
        "label": agg["label"],
        "aggregate": "pending",
        "verdict": "pending",
        "verifiers": verifier_results,
        "error": error,
        "at": utc_now_iso(),
        "residual_risk": (
            "Dual disprove interrupted by infrastructure failure; "
            "finding state not finalized."
        ),
    }
    db.conn.execute(
        "UPDATE findings SET body_json=?, updated_at=? WHERE id=?",
        (json.dumps(body), utc_now_iso(), fid),
    )
    db.conn.commit()


def _apply_dual_verdict(
    task,
    db,
    run_dir: Path,
    fid: int,
    *,
    verifier_results: list[dict[str, Any]],
    model_id: str | None,
    extra: dict[str, Any] | None = None,
    multi_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Map dual disprove results -> finding state.

    All slots reject -> rejected_llm
    Else -> needs_human (never auto-confirm; human is the gate)
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

    if not verifier_results:
        verifier_results = [
            {
                "id": "none",
                "prompt": "",
                "verdict": "needs_human",
                "parse_reason": "no_verifiers",
                "model_id": model_id,
                "reasoning": "",
                "at": utc_now_iso(),
            }
        ]

    agg = aggregate_disprove_verdicts(verifier_results)
    top_verdict = agg["verdict"]
    all_reject = bool(agg["all_reject"])
    stood = int(agg["stood"])
    total = int(agg["total"])
    label = str(agg["label"])

    body = dict(finding.body or {})
    mech_meta = body.get("validation_mech")
    if isinstance(mech_meta, dict):
        mech_meta = dict(mech_meta)
        mech_meta["pending_llm"] = False
        body["validation_mech"] = mech_meta

    # Compatibility reasoning: join truncated slot reasonings
    joined_parts = []
    for vr in verifier_results:
        rid = vr.get("id") or "?"
        vv = vr.get("verdict") or "?"
        rs = (vr.get("reasoning") or "").strip()
        if len(rs) > 2000:
            rs = rs[:2000] + "…"
        joined_parts.append(f"### {rid} ({vv})\n{rs}")
    reasoning = "\n\n".join(joined_parts)
    if len(reasoning) > 8000:
        reasoning = reasoning[:8000] + "\n…[truncated]"

    llm_meta: dict[str, Any] = {
        "status": "completed" if all_reject else "needs_human",
        "stood": stood,
        "total": total,
        "label": label,
        "aggregate": "rejected_llm" if all_reject else "needs_human",
        "verdict": top_verdict,
        "parse_reason": "aggregate",
        "model_id": model_id,
        "reasoning": reasoning,
        "verifiers": verifier_results,
        "at": utc_now_iso(),
        "residual_risk": (
            "Multi-model / dual-perspective disprove can only auto-reject when "
            "all slots reject. Agreement that a finding stands is not exploit "
            "proof — human is the confirm gate."
        ),
    }
    if multi_model:
        llm_meta["multi_model"] = multi_model
        if multi_model.get("multi_model_label"):
            llm_meta["multi_model_label"] = multi_model["multi_model_label"]
    if extra:
        safe_extra = {k: extra[k] for k in extra if k != "parse"}
        llm_meta.update(safe_extra)
    body["validation_llm"] = llm_meta

    if all_reject:
        new_state = "rejected_llm"
        body.pop("needs_human", None)
        reasons = body.get("validation_reasons")
        if not isinstance(reasons, list):
            reasons = []
        note = f"validate_llm:rejected:{label}"
        if note not in reasons:
            reasons.append(note)
        body["validation_reasons"] = reasons
        llm_meta["status"] = "completed"
    else:
        new_state = "needs_human"
        body["needs_human"] = True
        if isinstance(body.get("validation_mech"), dict):
            body["validation_mech"]["resolved"] = (
                "stand_awaiting_human"
                if top_verdict == "stand"
                else "needs_human"
            )
        reasons = body.get("validation_reasons")
        if not isinstance(reasons, list):
            reasons = []
        if top_verdict == "stand":
            note = f"validate_llm:stand_awaiting_human:{label}"
        else:
            note = f"validate_llm:needs_human:{label}"
        if note not in reasons:
            reasons.append(note)
        body["validation_reasons"] = reasons
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
            "verdict": top_verdict,
            "stood": stood,
            "total": total,
            "label": label,
            "finding_state": new_state,
            "parse_reason": "aggregate",
            "model_id": model_id,
            "verdicts": [
                {"id": vr.get("id"), "verdict": vr.get("verdict")}
                for vr in verifier_results
            ],
        },
    )

    return {
        "status": "succeeded",
        "verdict": top_verdict,
        "stood": stood,
        "total": total,
        "label": label,
        "finding_id": fid,
        "finding_state": new_state,
        "parse_reason": "aggregate",
        "model_id": model_id,
        "confirmed": False,
        "rejected": new_state == "rejected_llm",
        "needs_human": new_state == "needs_human",
    }


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
    """Single-slot fallback used by incomplete/error hold paths."""
    v = (verdict or "needs_human").lower()
    if v not in ("reject", "stand", "needs_human"):
        v = "needs_human"
        parse_reason = f"invalid_verdict:{verdict}"
    reasoning = (content or "").strip()
    if len(reasoning) > 8000:
        reasoning = reasoning[:8000] + "\n…[truncated]"
    single = [
        {
            "id": "single",
            "prompt": "",
            "verdict": v,
            "parse_reason": parse_reason,
            "model_id": model_id,
            "reasoning": reasoning,
            "at": utc_now_iso(),
        }
    ]
    # Single reject alone is not both-reject dual; map reject → needs_human
    # unless callers already used dual path. Hold paths should not reject.
    if v == "reject":
        single[0]["verdict"] = "needs_human"
        single[0]["parse_reason"] = f"hold_demote:{parse_reason}"
    return _apply_dual_verdict(
        task,
        db,
        run_dir,
        fid,
        verifier_results=single,
        model_id=model_id,
        extra=extra,
    )


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
