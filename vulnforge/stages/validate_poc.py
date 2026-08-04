"""
Stage: validate_poc — execute PoC under harness; write poc_run.json evidence.

Operator-queued (or CLI). Never creates findings. Never sets confirmed / reject.
Optional LLM referee when stages.validate_poc_referee is true (annotate only).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.llm import InfraError, classify_llm_failure, messages_from_packet
from vulnforge.packet import pack_poc_referee
from vulnforge.poc_handoff import POC_DEVELOP_RELPATH, POC_RUN_RELPATH
from vulnforge.poc_runner import execute_poc_for_pack, harness_config
from vulnforge.paths import system_prompts_root
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.util import append_event, utc_now_iso


def _parse_finding_id(raw: Any) -> tuple[int | None, str | None]:
    if raw is None:
        return None, "missing_finding_id"
    try:
        return int(raw), None
    except (TypeError, ValueError):
        return None, "invalid_finding_id"


def _parse_referee_verdict(content: str) -> dict[str, Any]:
    """Parse VERDICT=... lines from referee model output."""
    text = content or ""
    verdict = "inconclusive"
    confidence = "low"
    reasoning = ""
    for line in text.splitlines():
        s = line.strip()
        up = s.upper()
        if up.startswith("VERDICT="):
            v = s.split("=", 1)[1].strip().lower().strip("`\"'")
            if v in (
                "signal_observed",
                "signal_absent",
                "poc_broken",
                "inconclusive",
                "unsafe_skipped",
            ):
                verdict = v
        elif up.startswith("CONFIDENCE="):
            c = s.split("=", 1)[1].strip().lower().strip("`\"'")
            if c in ("low", "medium", "high"):
                confidence = c
        elif up.startswith("REASONING="):
            reasoning = s.split("=", 1)[1].strip()
    if not reasoning:
        reasoning = text[:1500]
    return {"verdict": verdict, "confidence": confidence, "reasoning": reasoning}


def _write_poc_run(pack_dir: Path, result: dict[str, Any]) -> Path:
    pack_dir.mkdir(parents=True, exist_ok=True)
    dest = pack_dir / POC_RUN_RELPATH
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(result, indent=2), encoding="utf-8")
    tmp.replace(dest)
    return dest


def _run_referee(
    *,
    task,
    db,
    run_dir: Path,
    cfg: dict,
    finding,
    body: dict,
    run_result: dict,
) -> dict[str, Any]:
    """Multi-model text-only referee; never mutates finding state."""
    from vulnforge.llm_models import (
        consensus_referee_slots,
        make_client_for_model,
        resolve_validate_consensus,
        resolve_validate_models,
    )
    from vulnforge.stages.validate_llm import load_citation_slices
    from vulnforge.util import target_tool_root

    run_row = db.get_run()
    target = Path(run_row["target_path"]) if run_row else Path(".")
    tool_root = target_tool_root(target)
    pkt_cfg = cfg.get("packet") or {}
    per_slice = int(pkt_cfg.get("max_file_slice_chars", 4000))
    max_chars = max(per_slice, min(per_slice * 4, 12_000))
    slices = load_citation_slices(finding, tool_root, max_chars=max_chars)
    prompts_root = system_prompts_root()
    try:
        packet = pack_poc_referee(
            cfg,
            prompts_root,
            body,
            slices,
            poc_run=run_result,
        )
    except FileNotFoundError as e:
        return {"ok": False, "error": f"missing_prompts:{e}"}

    models = resolve_validate_models(cfg)
    if not models:
        models = [str((cfg.get("llm") or {}).get("model") or "")]
    mode = resolve_validate_consensus(cfg)
    temp = float((cfg.get("llm") or {}).get("temperature_disprove", 0.1))
    messages = messages_from_packet(packet)
    slots: list[dict[str, Any]] = []
    open_clients: list[Any] = []
    try:
        for mid in models:
            client = make_client_for_model(cfg, mid or None)
            open_clients.append(client)
            try:
                model_id = client.fingerprint_model()
            except InfraError as e:
                return {
                    "ok": False,
                    "error": str(e),
                    "infra": True,
                    "slots": slots,
                    "model_id": mid,
                }
            result = client.chat(messages, tools=None, temperature=temp)
            usage_fields = record_llm_result(
                run_dir,
                task_id=getattr(task, "id", 0) or 0,
                kind="validate_poc_referee",
                model_id=model_id,
                result=result,
            )
            try:
                save_transcript(
                    run_dir,
                    getattr(task, "id", 0) or 0,
                    kind="validate_poc_referee",
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
                    meta={
                        "finding_id": finding.id,
                        "stage": "poc_referee",
                        "model_id": model_id,
                    },
                    pass_key=f"poc-ref-{model_id}",
                )
            except OSError:
                pass
            if not result.ok:
                status = classify_llm_failure(result)
                if status == "failed_infra":
                    return {
                        "ok": False,
                        "error": result.error or result.classification.value,
                        "infra": True,
                        "model_id": model_id,
                        "slots": slots,
                        **usage_fields,
                    }
                slots.append(
                    {
                        "ok": False,
                        "model_id": model_id,
                        "verdict": "inconclusive",
                        "confidence": "low",
                        "reasoning": result.error
                        or result.classification.value,
                        **usage_fields,
                    }
                )
                continue
            parsed = _parse_referee_verdict(result.content or "")
            slots.append(
                {
                    "ok": True,
                    "model_id": model_id,
                    **parsed,
                    **usage_fields,
                }
            )

        agg = consensus_referee_slots(slots, mode=mode)
        return {
            "ok": True,
            "model_id": (slots[0].get("model_id") if slots else None),
            "verdict": agg.get("verdict"),
            "confidence": agg.get("confidence"),
            "reasoning": agg.get("reason"),
            "consensus": agg.get("consensus"),
            "slots": slots,
            "multi_model": agg,
        }
    finally:
        for c in open_clients:
            try:
                c.close()
            except Exception:
                pass


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    payload = dict(task.payload or {})
    fid, fid_err = _parse_finding_id(payload.get("finding_id"))
    if fid is None:
        return {
            "status": "failed_task",
            "error": fid_err or "missing_finding_id",
        }

    finding = db.get_finding(fid)
    if finding is None:
        return {
            "status": "failed_task",
            "error": "finding_not_found",
            "finding_id": fid,
        }

    hc = harness_config(cfg)
    if not hc["enabled"] and not payload.get("force"):
        return {
            "status": "failed_task",
            "error": "poc_harness_disabled",
            "finding_id": fid,
            "hint": "Set poc_harness.enabled: true in config or pass force",
        }

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
    except InvalidEvidenceId as e:
        return {
            "status": "failed_task",
            "error": f"invalid_evidence_id:{e}",
            "finding_id": fid,
        }

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

    run_result = execute_poc_for_pack(
        pack_dir,
        cfg=cfg,
        hub_text=hub_text,
        env_extra=env_extra or None,
        finding_body=body,
        finding_id=fid,
        force_command=force_cmd,
    )
    run_result["evidence_id"] = eid
    run_result["task_id"] = getattr(task, "id", None)
    run_result["operator"] = payload.get("operator") or "agent"

    # Multi-model referee (default on via stages.validate_poc_referee / UI Settings)
    stages = cfg.get("stages") or {}
    # Default ON when key omitted (false-positive focus); explicit false disables
    if "validate_poc_referee" in stages:
        referee_on = bool(stages.get("validate_poc_referee"))
    else:
        referee_on = True
    if payload.get("referee") is True:
        referee_on = True
    if payload.get("referee") is False:
        referee_on = False
    referee_info: dict[str, Any] | None = None
    if referee_on and run_result.get("verdict") not in ("unsafe_skipped",):
        referee_info = _run_referee(
            task=task,
            db=db,
            run_dir=run_dir,
            cfg=cfg,
            finding=finding,
            body=body,
            run_result=run_result,
        )
        if referee_info.get("infra"):
            return {
                "status": "failed_infra",
                "error": referee_info.get("error") or "referee_infra",
                "finding_id": fid,
                "poc_run": run_result,
            }
        if referee_info.get("ok"):
            run_result["referee"] = {
                "verdict": referee_info.get("verdict"),
                "confidence": referee_info.get("confidence"),
                "reasoning": referee_info.get("reasoning"),
                "model_id": referee_info.get("model_id"),
                "slots": referee_info.get("slots"),
                "consensus": referee_info.get("consensus"),
                "multi_model": referee_info.get("multi_model"),
            }
            # Prefer multi-model consensus verdict (still evidence only — never confirm)
            if referee_info.get("verdict"):
                run_result["verdict_mechanical"] = run_result.get("verdict")
                run_result["verdict"] = referee_info["verdict"]
                if referee_info.get("confidence"):
                    run_result["confidence"] = referee_info["confidence"]
        else:
            run_result["referee"] = {
                "ok": False,
                "error": referee_info.get("error"),
                "slots": referee_info.get("slots"),
            }

    try:
        _write_poc_run(pack_dir, run_result)
    except OSError as e:
        return {
            "status": "failed_task",
            "error": f"write_poc_run_failed:{e}",
            "finding_id": fid,
            "poc_run": run_result,
        }

    # Link on finding body; never change state
    now = utc_now_iso()
    body2 = dict(body)
    body2["evidence_id"] = eid
    body2["poc_run_relpath"] = POC_RUN_RELPATH
    body2["poc_validation_latest"] = {
        "at": now,
        "verdict": run_result.get("verdict"),
        "confidence": run_result.get("confidence"),
        "exit_code": run_result.get("exit_code"),
        "signal_matched": run_result.get("signal_matched"),
        "task_id": getattr(task, "id", None),
        "runner": run_result.get("runner"),
        "poc_run_relpath": POC_RUN_RELPATH,
    }
    hist = body2.get("poc_validation")
    if not isinstance(hist, list):
        hist = []
    hist.append(dict(body2["poc_validation_latest"]))
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
                "event": "poc_validated",
                "task_id": getattr(task, "id", None),
                "finding_id": fid,
                "evidence_id": eid,
                "verdict": run_result.get("verdict"),
                "exit_code": run_result.get("exit_code"),
                "signal_matched": run_result.get("signal_matched"),
                "runner": run_result.get("runner"),
            },
        )
    except OSError:
        pass

    return {
        "status": "succeeded",
        "finding_id": fid,
        "evidence_id": eid,
        "poc_run_relpath": POC_RUN_RELPATH,
        "verdict": run_result.get("verdict"),
        "signal_matched": run_result.get("signal_matched"),
        "exit_code": run_result.get("exit_code"),
        "finding_state": finding.state,
        "poc_run": run_result,
        "referee": referee_info,
    }
