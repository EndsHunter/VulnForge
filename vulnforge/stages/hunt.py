"""Stage: hunt â€” one areaÃ—class investigation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.agent_runtime import run_tool_loop as run_agent_tool_loop
from vulnforge.llm import InfraError, classify_llm_failure
from vulnforge.packet import pack_hunt, refuse_if_over_budget
from vulnforge.stages.hunt_moa import (
    build_hunt_moa_body,
    hunt_moa_enabled,
    merge_hunt_candidates,
    resolve_hunt_perspectives,
    slot_evidence_id,
)
from vulnforge.tools import build_tool_handler
from vulnforge.tools.queue_note import flush_notes_to_db
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.paths import system_prompts_root
from vulnforge.tools.sink_preindex import filter_sinks_for_paths, record_sink_coverage
from vulnforge.util import append_event, normalize_relpath

# Abort errors that free the queue and may trigger auto-split (not infra).
ABORT_ERRORS = frozenset({"max_tool_rounds", "no_submit", "aborted_scope"})


def shallow_none_should_requeue(session: dict, payload: dict, shallow: bool) -> bool:
    """Shallow submit_none requeues once, unless the operator forced submit_none.

    Operator force finishes the hunt as none. It does not confirm a finding
    and it does not spawn a deeper child.
    """
    if session.get("operator_forced_submit_none"):
        return False
    return bool(
        shallow
        and not payload.get("force_depth")
        and not payload.get("shallow_requeued")
    )

MAX_SPLIT_DEPTH = 2
MAX_SPLIT_CHILDREN = 4
MIN_SPLIT_CHILDREN = 2
SPLIT_BUDGET_FRACTION = 0.30


def _resolve_task_seed_sinks(
    payload: dict,
    arch: dict,
    cfg: dict,
) -> list[dict[str, Any]]:
    """Sinks associated with this hunt (payload first, else path-filtered arch index)."""
    raw = payload.get("seed_sinks")
    if isinstance(raw, list) and raw:
        return [s for s in raw if isinstance(s, dict)]
    inv = arch.get("inventory") if isinstance(arch.get("inventory"), dict) else {}
    all_sinks = inv.get("seed_sinks") or arch.get("seed_sinks") or []
    if not isinstance(all_sinks, list) or not all_sinks:
        return []
    return filter_sinks_for_paths(
        [s for s in all_sinks if isinstance(s, dict)],
        payload.get("path_hints") or [],
        top_k=int((cfg.get("packet") or {}).get("max_seed_sinks", 12)),
    )


def _mark_sink_coverage(
    db,
    payload: dict,
    arch: dict,
    cfg: dict,
    *,
    area: str,
    attack_class: str,
    visit_delta: int,
    last_depth: str,
) -> None:
    """Update sink_coverage_facts for this hunt's seed sinks (best-effort)."""
    try:
        sinks = _resolve_task_seed_sinks(payload, arch, cfg)
        record_sink_coverage(
            db,
            sinks,
            area=area,
            attack_class=attack_class,
            visit_delta=visit_delta,
            last_depth=last_depth,
        )
    except Exception:
        pass


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    if hunt_moa_enabled(cfg if isinstance(cfg, dict) else {}):
        return _run_hunt_moa(task, db, run_dir, cfg if isinstance(cfg, dict) else {})
    run_row = db.get_run()
    if not run_row:
        return {"status": "failed_task", "error": "no_run"}
    target = Path(run_row["target_path"])
    arch = db.get_architecture() or {}
    payload = dict(task.payload or {})

    # Slim architecture slice for packet (area-focused, not full dump)
    codemap_struct = None
    try:
        codemap_struct = db.get_codemap()
    except Exception:
        codemap_struct = None
    architecture_txt = _architecture_slice(arch, payload, codemap=codemap_struct)

    # P2.6: human-readable known findings for packet
    known_findings = _known_findings_readable(db)
    known_keys = [f.stable_key for f in db.list_findings()]
    codemap_notes = [
        json.dumps(n["payload"])[:200]
        for n in db.list_notes(kind="codemap")
    ]

    seed_sinks = _resolve_task_seed_sinks(payload, arch, cfg)

    session: dict = {
        "candidate": None,
        "none_reason": None,
        "notes": [],
        "tools_used": [],
        "evidence_id": None,
        "evidence_ids_written": [],
    }

    def _submit_candidate(body: dict) -> dict:
        prepared, err = prepare_candidate_submission(
            body, session, Path(run_dir / "evidence")
        )
        if err is not None:
            return err
        session["candidate"] = prepared
        return {
            "ok": True,
            "stored": "candidate",
            "evidence_id": prepared.get("evidence_id"),
        }

    def _submit_none(args: dict) -> dict:
        reason = args.get("reason") if isinstance(args, dict) else str(args)
        if not reason or not str(reason).strip():
            return {"ok": False, "error": "reason required"}
        session["none_reason"] = str(reason).strip()
        from vulnforge.live_task import operator_force_active

        if operator_force_active():
            session["operator_forced_submit_none"] = True
        return {"ok": True, "stored": "none"}

    path_hints = list(payload.get("path_hints") or [])
    try:
        profile = str(run_row["profile"] or "")
    except (KeyError, IndexError, TypeError):
        profile = ""
    if not profile:
        profile = str((cfg.get("run") or {}).get("profile") or "code_static")
    target_root = str(target if target.is_dir() else target.parent)
    ctx = {
        "target_root": target_root,
        "evidence_root": str(run_dir / "evidence"),
        "run_dir": run_dir,
        "task_id": task.id,
        "task_payload": payload,
        "db": db,
        "cfg": cfg,
        "session": session,
        "submit_candidate": _submit_candidate,
        "submit_none": _submit_none,
        # P1.1 soft path jail — force_depth requires deeper tools before none,
        # but must NOT start widened (keep path_hints soft jail until one widen).
        "scope": {
            "enabled": True,
            "path_hints": path_hints,
            "path_prefix": payload.get("path_prefix") or "",
            "force_depth": bool(payload.get("force_depth")),
            "widened": False,
        },
    }
    # Ensure pack_hunt sees run profile for tool schemas
    if isinstance(cfg.get("run"), dict):
        cfg.setdefault("run", {})
        cfg["run"]["profile"] = profile
    else:
        cfg = dict(cfg)
        cfg["run"] = {**(cfg.get("run") or {}), "profile": profile}
    handler = build_tool_handler(ctx)
    prompts_root = system_prompts_root()
    from vulnforge.llm_models import cfg_for_stage, make_client_for_stage

    role_cfg = cfg_for_stage(cfg, "hunt")
    packet = pack_hunt(
        role_cfg,
        prompts_root,
        payload,
        architecture_txt,
        known_keys,
        codemap_notes,
        seed_sinks=seed_sinks or [],
        known_findings=known_findings,
        codemap=codemap_struct,
    )
    try:
        refuse_if_over_budget(packet)
    except Exception as e:
        return {"status": "failed_task", "error": f"over_budget: {e}"}

    client = make_client_for_stage(role_cfg, "hunt")
    try:
        try:
            model_id = client.fingerprint_model()
        except InfraError as e:
            return {"status": "failed_infra", "error": str(e)}
        max_rounds = int((role_cfg.get("llm") or {}).get("max_tool_rounds", 12))
        temp = float((role_cfg.get("llm") or {}).get("temperature_hunt", 0.4))
        result = run_agent_tool_loop(
            client,
            packet,
            handler,
            max_rounds=max_rounds,
            temperature=temp,
            cfg=role_cfg,
        )
        hunt_class = str(payload.get("class") or "wildcard").strip() or "wildcard"
        usage_fields = record_llm_result(
            run_dir,
            task_id=task.id,
            kind=f"hunt:{hunt_class}",
            model_id=model_id,
            result=result,
            extra={
                "class": hunt_class,
                "area": payload.get("area"),
            },
        )
        try:
            evidence_ids = list(session.get("evidence_ids_written") or [])
            if session.get("evidence_id") and session["evidence_id"] not in evidence_ids:
                evidence_ids.append(session["evidence_id"])
            files_created: list[str] = []
            for eid in evidence_ids:
                pack = Path(run_dir) / "evidence" / str(eid)
                if pack.is_dir():
                    for f in pack.rglob("*"):
                        if f.is_file():
                            try:
                                files_created.append(
                                    str(f.relative_to(run_dir)).replace("\\", "/")
                                )
                            except ValueError:
                                files_created.append(str(f))
                else:
                    files_created.append(f"evidence/{eid}/")
            save_transcript(
                run_dir,
                task.id,
                kind="hunt",
                model_id=model_id,
                messages=list(result.transcript or []),
                result={
                    "ok": result.ok,
                    "classification": result.classification.value,
                    "error": result.error,
                    "content": result.content,
                    "evidence_id": session.get("evidence_id"),
                    "evidence_ids": evidence_ids,
                    **usage_fields,
                },
                meta={
                    "payload": payload,
                    "tools_used": list(session.get("tools_used") or []),
                    "evidence_id": session.get("evidence_id"),
                    "evidence_ids_written": evidence_ids,
                    "files_created": files_created,
                    "temperature": temp,
                    "max_tool_rounds": max_rounds,
                    "agent_runtime": "strands",
                },
            )
        except OSError:
            pass
        area = payload.get("area", "app")
        cls = payload.get("class", "wildcard")

        if session.get("continued"):
            area = payload.get("area", "app")
            cls = payload.get("class", "wildcard")
            db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth="continued")
            _mark_sink_coverage(
                db,
                payload,
                arch,
                cfg,
                area=area,
                attack_class=cls,
                visit_delta=1,
                last_depth="continued",
            )
            flush_notes_to_db(ctx, db)
            return {
                "status": "succeeded",
                "continued": True,
                "auto_continued": bool(session.get("continue_auto")),
                "child_task_id": session.get("continue_child_task_id"),
                "spawned_hunts": list(session.get("spawned_hunts") or []),
                "model_id": model_id,
                "transcript": f"task-{task.id}",
                **usage_fields,
            }

        if not result.ok:
            status = classify_llm_failure(result)
            err = result.error or result.classification.value
            from vulnforge.agent_runtime.context_watch import is_context_overflow_error
            from vulnforge.tools.continue_task import maybe_auto_continue

            if is_context_overflow_error(err, result.classification):
                cont = maybe_auto_continue(
                    ctx,
                    kind="hunt",
                    error=err,
                    transcript=list(result.transcript or []),
                )
                if cont:
                    area = payload.get("area", "app")
                    cls = payload.get("class", "wildcard")
                    db.upsert_coverage_fact(
                        area, cls, visit_delta=1, last_depth="continued"
                    )
                    _mark_sink_coverage(
                        db,
                        payload,
                        arch,
                        cfg,
                        area=area,
                        attack_class=cls,
                        visit_delta=1,
                        last_depth="continued",
                    )
                    return {
                        "status": "succeeded",
                        "error": err,
                        "model_id": model_id,
                        "transcript": f"task-{task.id}",
                        **cont,
                        **usage_fields,
                    }
            out: dict[str, Any] = {
                "status": status,
                "error": err,
                "model_id": model_id,
                "transcript": f"task-{task.id}",
                **usage_fields,
            }
            # P1.4: abort taxonomy for thrash
            if status == "failed_task" and (
                err in ABORT_ERRORS or "max_tool_rounds" in str(err)
            ):
                out["error"] = "max_tool_rounds" if "max_tool_rounds" in str(err) else err
                out["aborted_scope"] = True
                db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth="aborted")
                _mark_sink_coverage(
                    db,
                    payload,
                    arch,
                    cfg,
                    area=area,
                    attack_class=cls,
                    visit_delta=1,
                    last_depth="aborted",
                )
                # P1.5 auto-split hook
                split_info = maybe_auto_split(task, db, cfg, run_dir)
                if split_info:
                    out["split"] = split_info
            return out

        flush_notes_to_db(ctx, db)
        # Merge agent codemap notes into stored structural map
        try:
            from vulnforge.tools.codemap import merge_annotations_into_codemap

            note_rows = [
                n
                for n in (session.get("notes") or [])
                if isinstance(n, dict) and n.get("kind") == "codemap"
            ]
            if note_rows:
                base_cm = db.get_codemap() or codemap_struct
                if base_cm:
                    db.set_codemap(
                        merge_annotations_into_codemap(base_cm, note_rows),
                        source="merge",
                    )
        except Exception:
            pass
        shallow = is_shallow(session, profile=profile)
        spawned_hunts = list(session.get("spawned_hunts") or [])

        if session.get("none_reason") is not None:
            # P1.3: shallow none → requeue once with force_depth; do not close cell as done.
            # Operator-forced submit_none finishes this task instead of spawning a child.
            if shallow_none_should_requeue(session, payload, shallow):
                db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth="shallow")
                _mark_sink_coverage(
                    db,
                    payload,
                    arch,
                    cfg,
                    area=area,
                    attack_class=cls,
                    visit_delta=1,
                    last_depth="shallow",
                )
                child_payload = {
                    **payload,
                    "force_depth": True,
                    "shallow_requeued": True,
                    "parent_task_id": task.id,
                }
                child_id = db.enqueue_task("hunt", child_payload, priority=45)
                try:
                    append_event(
                        run_dir,
                        {
                            "source": "vf",
                            "event": "shallow_requeue",
                            "task_id": task.id,
                            "child_task_id": child_id,
                            "area": area,
                            "class": cls,
                        },
                    )
                except OSError:
                    pass
                return {
                    "status": "succeeded",
                    "none_found": True,
                    "reason": session["none_reason"],
                    "shallow": True,
                    "shallow_requeued": True,
                    "child_task_id": child_id,
                    "spawned_hunts": spawned_hunts,
                    "model_id": model_id,
                    "transcript": f"task-{task.id}",
                    **usage_fields,
                }

            depth = "shallow" if shallow else "none"
            db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth=depth)
            _mark_sink_coverage(
                db,
                payload,
                arch,
                cfg,
                area=area,
                attack_class=cls,
                visit_delta=1,
                last_depth=depth,
            )
            return {
                "status": "succeeded",
                "none_found": True,
                "reason": session["none_reason"],
                "shallow": shallow,
                "spawned_hunts": spawned_hunts,
                "model_id": model_id,
                "transcript": f"task-{task.id}",
                **usage_fields,
            }

        if session.get("candidate"):
            body = dict(session["candidate"])
            if session.get("evidence_id") and not body.get("evidence_id"):
                body["evidence_id"] = session["evidence_id"]
            profile = run_row["profile"]
            # P2.5: mechanical near-dup merge before insert
            from vulnforge.findings.merge import merge_near_duplicate

            merge_info = merge_near_duplicate(db, body, profile=profile)
            if merge_info and merge_info.get("superseded_existing"):
                fid = merge_info["finding_id"]
                # Skip re-validation when merge only annotated a confirmed
                # (or otherwise non-material) keeper â€” never demote confirmed
                # via a flaky re-run of mech gates after annotation-only merge.
                need_validate = bool(merge_info.get("revalidate", False))
            else:
                fid = db.insert_finding(body, state="candidate", profile=profile)
                need_validate = True
            if need_validate:
                db.enqueue_task(
                    "validate_mech",
                    {"finding_id": fid, "parent_task_id": task.id},
                    priority=20,
                )
            db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth="candidate")
            _mark_sink_coverage(
                db,
                payload,
                arch,
                cfg,
                area=area,
                attack_class=cls,
                visit_delta=1,
                last_depth="candidate",
            )
            out_ok: dict[str, Any] = {
                "status": "succeeded",
                "finding_id": fid,
                "shallow": shallow,
                "spawned_hunts": spawned_hunts,
                "model_id": model_id,
                "transcript": f"task-{task.id}",
                **usage_fields,
            }
            if merge_info:
                out_ok["merge"] = merge_info
            return out_ok

        # P1.4 no_submit abort + optional split with enhanced diagnostics
        db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth="aborted")
        _mark_sink_coverage(
            db,
            payload,
            arch,
            cfg,
            area=area,
            attack_class=cls,
            visit_delta=1,
            last_depth="aborted",
        )

        # Diagnose why no_submit occurred
        diagnostics = _diagnose_no_submit(result, session)

        out_ns: dict[str, Any] = {
            "status": "failed_task",
            "error": "no_submit",
            "aborted_scope": True,
            "shallow": shallow,
            "model_id": model_id,
            "transcript": f"task-{task.id}",
            "diagnostics": diagnostics,  # Add diagnostic info for troubleshooting
            **usage_fields,
        }

        split_info = maybe_auto_split(task, db, cfg, run_dir)
        if split_info:
            out_ns["split"] = split_info

        # Log actionable suggestion for the user
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(
            f"Hunt task {task.id} ended without successful submit_candidate/submit_none. "
            f"Check max_tool_rounds ({cfg.get('llm', {}).get('max_tool_rounds', 12)}), "
            f"model compliance, and abort handling. Diagnostics: {diagnostics}"
        )

        return out_ns
    finally:
        client.close()


def _rounds_consumed(result: Any, allotted: int) -> int:
    """Tool rounds this slot spent, capped by the rounds it was given.

    The lease shares one ``llm.max_tool_rounds`` budget. A slot must not be
    charged more than its allotment, and a max_tool_rounds miss consumes the
    allotment even when usage is missing.
    """
    allotted_n = max(0, int(allotted))
    usage = getattr(result, "usage", None)
    calls = 0
    if usage is not None:
        raw = usage.get("llm_calls") if isinstance(usage, dict) else getattr(usage, "llm_calls", None)
        try:
            calls = int(raw or 0)
        except (TypeError, ValueError):
            calls = 0
    if calls <= 0:
        err = str(getattr(result, "error", "") or "")
        if "max_tool_rounds" in err:
            return allotted_n
        transcript = getattr(result, "transcript", None) or []
        calls = sum(
            1
            for message in transcript
            if isinstance(message, dict) and message.get("role") == "assistant"
        )
    if calls <= 0:
        calls = 1 if allotted_n else 0
    return max(0, min(calls, allotted_n))


def _merge_usage(acc: dict[str, Any], fields: dict[str, Any] | None) -> dict[str, Any]:
    if not fields:
        return acc
    if not acc:
        return dict(fields)
    out = dict(acc)
    for key in (
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "reasoning_tokens",
        "llm_calls",
    ):
        if key in out or key in fields:
            out[key] = int(out.get(key) or 0) + int(fields.get(key) or 0)
    if fields.get("usage_source"):
        out["usage_source"] = fields["usage_source"]
    return out


def _reset_perspective_session(session: dict) -> None:
    """Drop slot submit/evidence auth. Keep lease-level tools, notes, and spawns.

    Each perspective must ``write_evidence`` itself. Session membership does
    not carry a previous slot's pack.
    """
    session["candidate"] = None
    session["none_reason"] = None
    session["evidence_id"] = None
    session["evidence_ids_written"] = []
    for key in (
        "continued",
        "continue_auto",
        "continue_child_task_id",
        "continue_handoff",
        "operator_forced_submit_none",
    ):
        session.pop(key, None)


def _moa_coverage(db, payload, arch, cfg, *, area: str, cls: str, depth: str) -> None:
    db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth=depth)
    _mark_sink_coverage(
        db,
        payload,
        arch,
        cfg,
        area=area,
        attack_class=cls,
        visit_delta=1,
        last_depth=depth,
    )


def _perspective_model(value: Any) -> Any:
    """Blank, a legacy model id, or a ``{host_id, model_id}`` ref. Not ``str(dict)``."""
    if isinstance(value, dict):
        mid = str(value.get("model_id") or "").strip()
        hid = str(value.get("host_id") or "").strip()
        if not mid:
            return ""
        if hid:
            return {"host_id": hid, "model_id": mid}
        return mid
    return str(value or "").strip()


def _moa_base(task, model_id: str | None, usage: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "model_id": model_id,
        "transcript": f"task-{task.id}",
    }
    out.update(usage or {})
    return out


def _save_perspective_transcript(
    run_dir: Path,
    task,
    *,
    model_id: str | None,
    result,
    session: dict,
    usage_fields: dict[str, Any],
    payload: dict,
    temp: float,
    allotted: int,
    total_rounds: int,
    perspective_id: str,
    perspective: str,
    slot_tools: list[str],
) -> None:
    try:
        evidence_ids = list(session.get("evidence_ids_written") or [])
        if session.get("evidence_id") and session["evidence_id"] not in evidence_ids:
            evidence_ids.append(session["evidence_id"])
        files_created: list[str] = []
        for eid in evidence_ids:
            pack = Path(run_dir) / "evidence" / str(eid)
            if pack.is_dir():
                for f in pack.rglob("*"):
                    if f.is_file():
                        try:
                            files_created.append(
                                str(f.relative_to(run_dir)).replace("\\", "/")
                            )
                        except ValueError:
                            files_created.append(str(f))
            else:
                files_created.append(f"evidence/{eid}/")
        save_transcript(
            run_dir,
            task.id,
            kind="hunt",
            model_id=model_id,
            messages=list(result.transcript or []),
            result={
                "ok": result.ok,
                "classification": result.classification.value,
                "error": result.error,
                "content": result.content,
                "evidence_id": session.get("evidence_id"),
                "evidence_ids": evidence_ids,
                **usage_fields,
            },
            meta={
                "payload": payload,
                "tools_used": list(slot_tools),
                "evidence_id": session.get("evidence_id"),
                "evidence_ids_written": evidence_ids,
                "files_created": files_created,
                "temperature": temp,
                "max_tool_rounds": allotted,
                "max_tool_rounds_total": total_rounds,
                "agent_runtime": "strands",
                "perspective_id": perspective_id,
                "perspective": perspective,
            },
            pass_key=perspective_id,
        )
    except OSError:
        pass


def _flush_moa_notes(ctx, db, session: dict, codemap_struct) -> None:
    flush_notes_to_db(ctx, db)
    try:
        from vulnforge.tools.codemap import merge_annotations_into_codemap

        note_rows = [
            n
            for n in (session.get("notes") or [])
            if isinstance(n, dict) and n.get("kind") == "codemap"
        ]
        if note_rows:
            base_cm = db.get_codemap() or codemap_struct
            if base_cm:
                db.set_codemap(
                    merge_annotations_into_codemap(base_cm, note_rows),
                    source="merge",
                )
    except Exception:
        pass


def _run_hunt_moa(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    """Sequential perspectives inside the already-held hunt lease.

    Flag-off hunts never enter here. One shared ``max_tool_rounds`` budget,
    one merge, at most one candidate insert, one coverage upsert.
    ``validate_mech`` is enqueued only when that candidate exists.
    ``continue_hunt`` stops the panel; the child is a full hunt, not a resumed slot.
    """
    run_row = db.get_run()
    if not run_row:
        return {"status": "failed_task", "error": "no_run"}
    target = Path(run_row["target_path"])
    arch = db.get_architecture() or {}
    payload = dict(task.payload or {})
    codemap_struct = None
    try:
        codemap_struct = db.get_codemap()
    except Exception:
        codemap_struct = None
    architecture_txt = _architecture_slice(arch, payload, codemap=codemap_struct)
    known_findings = _known_findings_readable(db)
    known_keys = [f.stable_key for f in db.list_findings()]
    codemap_notes = [
        json.dumps(n["payload"])[:200]
        for n in db.list_notes(kind="codemap")
    ]
    seed_sinks = _resolve_task_seed_sinks(payload, arch, cfg)
    session: dict = {
        "candidate": None,
        "none_reason": None,
        "notes": [],
        "tools_used": [],
        "evidence_id": None,
        "evidence_ids_written": [],
    }

    def _submit_candidate(body: dict) -> dict:
        prepared, err = prepare_candidate_submission(
            body, session, Path(run_dir / "evidence")
        )
        if err is not None:
            return err
        session["candidate"] = prepared
        return {
            "ok": True,
            "stored": "candidate",
            "evidence_id": prepared.get("evidence_id"),
        }

    def _submit_none(args: dict) -> dict:
        reason = args.get("reason") if isinstance(args, dict) else str(args)
        if not reason or not str(reason).strip():
            return {"ok": False, "error": "reason required"}
        session["none_reason"] = str(reason).strip()
        from vulnforge.live_task import operator_force_active

        if operator_force_active():
            session["operator_forced_submit_none"] = True
        return {"ok": True, "stored": "none"}

    path_hints = list(payload.get("path_hints") or [])
    try:
        profile = str(run_row["profile"] or "")
    except (KeyError, IndexError, TypeError):
        profile = ""
    if not profile:
        profile = str((cfg.get("run") or {}).get("profile") or "code_static")
    target_root = str(target if target.is_dir() else target.parent)
    ctx = {
        "target_root": target_root,
        "evidence_root": str(run_dir / "evidence"),
        "run_dir": run_dir,
        "task_id": task.id,
        "task_payload": payload,
        "db": db,
        "cfg": cfg,
        "session": session,
        "submit_candidate": _submit_candidate,
        "submit_none": _submit_none,
        "scope": {
            "enabled": True,
            "path_hints": path_hints,
            "path_prefix": payload.get("path_prefix") or "",
            "force_depth": bool(payload.get("force_depth")),
            "widened": False,
        },
    }
    if isinstance(cfg.get("run"), dict):
        cfg.setdefault("run", {})
        cfg["run"]["profile"] = profile
    else:
        cfg = dict(cfg)
        cfg["run"] = {**(cfg.get("run") or {}), "profile": profile}
        ctx["cfg"] = cfg
    handler = build_tool_handler(ctx)
    prompts_root = system_prompts_root()
    perspectives = resolve_hunt_perspectives(cfg)
    area = payload.get("area", "app")
    cls = payload.get("class", "wildcard")
    hunt_class = str(payload.get("class") or "wildcard").strip() or "wildcard"
    total_rounds = int((cfg.get("llm") or {}).get("max_tool_rounds", 12))
    remaining = total_rounds
    temp = float((cfg.get("llm") or {}).get("temperature_hunt", 0.4))

    from vulnforge.llm_models import (
        bind_role_cfg,
        cfg_for_stage,
        make_client_for_model,
        make_client_for_stage,
    )

    role_cfg = cfg_for_stage(cfg, "hunt")
    client = make_client_for_stage(role_cfg, "hunt")
    try:
        try:
            model_id = client.fingerprint_model()
        except InfraError as e:
            return {"status": "failed_infra", "error": str(e)}

        slot_rows: list[dict[str, Any]] = []
        usage_acc: dict[str, Any] = {}
        last_abort_result = None
        fake = bool((cfg.get("llm") or {}).get("fake"))

        for index, slot in enumerate(perspectives):
            pid = str(slot.get("id") or f"perspective_{index + 1}")
            prompt = str(slot.get("prompt") or "")
            if remaining <= 0:
                slot_rows.append(
                    {
                        "perspective_id": pid,
                        "outcome": "skipped",
                        "none_reason": "shared_round_budget_exhausted",
                    }
                )
                continue

            _reset_perspective_session(session)
            ctx["default_evidence_id"] = slot_evidence_id(task.id, pid, index)
            slot_model = _perspective_model(slot.get("model"))
            slot_cfg = role_cfg
            if slot_model and not fake:
                slot_cfg = bind_role_cfg(cfg, slot_model)
            try:
                packet = pack_hunt(
                    slot_cfg,
                    prompts_root,
                    payload,
                    architecture_txt,
                    known_keys,
                    codemap_notes,
                    seed_sinks=seed_sinks or [],
                    known_findings=known_findings,
                    codemap=codemap_struct,
                    perspective=prompt or None,
                    perspective_id=pid,
                )
            except PermissionError as e:
                return {"status": "failed_task", "error": str(e), "perspective_id": pid}
            try:
                refuse_if_over_budget(packet)
            except Exception as e:
                return {
                    "status": "failed_task",
                    "error": f"over_budget: {e}",
                    "perspective_id": pid,
                }

            active = client
            owned = None
            slot_model_id = model_id
            if slot_model and not fake:
                owned = make_client_for_model(slot_cfg, slot_model)
                active = owned
            tools_before = len(session.get("tools_used") or [])
            allotted = remaining
            try:
                if owned is not None:
                    try:
                        slot_model_id = owned.fingerprint_model()
                    except InfraError as e:
                        return {
                            "status": "failed_infra",
                            "error": str(e),
                            "perspective_id": pid,
                            "model_id": (
                                slot_model.get("model_id")
                                if isinstance(slot_model, dict)
                                else slot_model
                            ),
                        }
                result = run_agent_tool_loop(
                    active,
                    packet,
                    handler,
                    max_rounds=allotted,
                    temperature=temp,
                    cfg=slot_cfg,
                )
            finally:
                if owned is not None:
                    try:
                        owned.close()
                    except Exception:
                        pass

            used = _rounds_consumed(result, allotted)
            remaining = max(0, remaining - used)
            usage_fields = record_llm_result(
                run_dir,
                task_id=task.id,
                kind=f"hunt:{hunt_class}",
                model_id=slot_model_id,
                result=result,
                extra={
                    "class": hunt_class,
                    "area": payload.get("area"),
                    "perspective_id": pid,
                },
            )
            usage_acc = _merge_usage(usage_acc, usage_fields)
            model_id = slot_model_id or model_id
            slot_tools = list(session.get("tools_used") or [])[tools_before:]
            _save_perspective_transcript(
                run_dir,
                task,
                model_id=slot_model_id,
                result=result,
                session=session,
                usage_fields=usage_fields,
                payload=payload,
                temp=temp,
                allotted=allotted,
                total_rounds=total_rounds,
                perspective_id=pid,
                perspective=prompt,
                slot_tools=slot_tools,
            )

            if result.ok and session.get("continued"):
                # Child is a new hunt lease. Do not merge a half-finished panel.
                _moa_coverage(
                    db, payload, arch, cfg, area=area, cls=cls, depth="continued"
                )
                flush_notes_to_db(ctx, db)
                return {
                    "status": "succeeded",
                    "continued": True,
                    "auto_continued": bool(session.get("continue_auto")),
                    "child_task_id": session.get("continue_child_task_id"),
                    "spawned_hunts": list(session.get("spawned_hunts") or []),
                    "perspective_id": pid,
                    **_moa_base(task, model_id, usage_acc),
                }

            if not result.ok:
                status = classify_llm_failure(result)
                err = result.error or result.classification.value
                from vulnforge.agent_runtime.context_watch import (
                    is_context_overflow_error,
                )
                from vulnforge.tools.continue_task import maybe_auto_continue

                if is_context_overflow_error(err, result.classification):
                    cont = maybe_auto_continue(
                        ctx,
                        kind="hunt",
                        error=err,
                        transcript=list(result.transcript or []),
                    )
                    if cont:
                        _moa_coverage(
                            db,
                            payload,
                            arch,
                            cfg,
                            area=area,
                            cls=cls,
                            depth="continued",
                        )
                        return {
                            "status": "succeeded",
                            "error": err,
                            "perspective_id": pid,
                            **_moa_base(task, model_id, usage_acc),
                            **cont,
                        }
                if status == "failed_infra":
                    return {
                        "status": "failed_infra",
                        "error": err,
                        "perspective_id": pid,
                        **_moa_base(task, model_id, usage_acc),
                    }
                is_abort = status == "failed_task" and (
                    str(err) in ABORT_ERRORS or "max_tool_rounds" in str(err)
                )
                if is_abort:
                    last_abort_result = result
                slot_rows.append(
                    {
                        "perspective_id": pid,
                        "outcome": "aborted" if is_abort else "error",
                        "none_reason": (
                            "max_tool_rounds" if "max_tool_rounds" in str(err) else str(err)
                        ),
                        "status": status,
                    }
                )
                continue

            if session.get("none_reason") is not None:
                slot_rows.append(
                    {
                        "perspective_id": pid,
                        "outcome": "none",
                        "none_reason": session.get("none_reason"),
                    }
                )
                if session.get("operator_forced_submit_none"):
                    break
                continue

            if session.get("candidate"):
                slot_rows.append(
                    {
                        "perspective_id": pid,
                        "outcome": "candidate",
                        "candidate": dict(session["candidate"]),
                    }
                )
                continue

            last_abort_result = result
            slot_rows.append(
                {
                    "perspective_id": pid,
                    "outcome": "aborted",
                    "none_reason": "no_submit",
                    "status": "failed_task",
                }
            )

        while len(slot_rows) < len(perspectives):
            missing = perspectives[len(slot_rows)]
            slot_rows.append(
                {
                    "perspective_id": str(missing.get("id") or f"slot_{len(slot_rows) + 1}"),
                    "outcome": "skipped",
                    "none_reason": "not_run",
                }
            )

        return _finish_hunt_moa(
            task,
            db,
            run_dir,
            cfg,
            ctx=ctx,
            session=session,
            payload=payload,
            arch=arch,
            codemap_struct=codemap_struct,
            profile=profile,
            area=area,
            cls=cls,
            model_id=model_id,
            usage_acc=usage_acc,
            perspectives=perspectives,
            slot_rows=slot_rows,
            last_abort_result=last_abort_result,
        )
    finally:
        client.close()


def _finish_hunt_moa(
    task,
    db,
    run_dir: Path,
    cfg: dict,
    *,
    ctx: dict,
    session: dict,
    payload: dict,
    arch: dict,
    codemap_struct,
    profile: str,
    area: str,
    cls: str,
    model_id: str | None,
    usage_acc: dict[str, Any],
    perspectives: list[dict[str, Any]],
    slot_rows: list[dict[str, Any]],
    last_abort_result,
) -> dict[str, Any]:
    merge_input: list[dict[str, Any]] = []
    for row in slot_rows:
        outcome = row.get("outcome")
        if outcome == "candidate" and isinstance(row.get("candidate"), dict):
            merge_input.append(
                {
                    "perspective_id": row.get("perspective_id"),
                    "outcome": "candidate",
                    "candidate": row["candidate"],
                }
            )
        elif outcome == "none":
            merge_input.append(
                {
                    "perspective_id": row.get("perspective_id"),
                    "outcome": "none",
                    "none_reason": row.get("none_reason"),
                }
            )
    merged = merge_hunt_candidates(merge_input, profile=profile)
    tops = list(merged.get("candidates") or [])
    cell = "candidate" if tops else "none"
    agree = int(tops[0].get("agree_count") or 0) if tops else 0
    record = build_hunt_moa_body(
        slot_rows,
        n_perspectives=len(perspectives),
        agree_count=agree,
        cell_outcome=cell,
    )
    base = _moa_base(task, model_id, usage_acc)
    spawned = list(session.get("spawned_hunts") or [])
    shallow = is_shallow(session, profile=profile)

    if tops:
        _flush_moa_notes(ctx, db, session, codemap_struct)
        body = dict(tops[0].get("body") or {})
        body.pop("state", None)
        body["hunt_moa"] = record
        from vulnforge.findings.merge import merge_near_duplicate

        merge_info = merge_near_duplicate(db, body, profile=profile)
        if merge_info and merge_info.get("superseded_existing"):
            fid = merge_info["finding_id"]
            need_validate = bool(merge_info.get("revalidate", False))
        else:
            # Hunt MoA is propose-only. The column state is candidate, never confirmed.
            fid = db.insert_finding(body, state="candidate", profile=profile)
            need_validate = True
        if need_validate:
            db.enqueue_task(
                "validate_mech",
                {"finding_id": fid, "parent_task_id": task.id},
                priority=20,
            )
        _moa_coverage(db, payload, arch, cfg, area=area, cls=cls, depth="candidate")
        out_ok: dict[str, Any] = {
            "status": "succeeded",
            "finding_id": fid,
            "shallow": shallow,
            "spawned_hunts": spawned,
            "hunt_moa": record,
            **base,
        }
        if merge_info:
            out_ok["merge"] = merge_info
        return out_ok

    aborts = [r for r in slot_rows if r.get("outcome") == "aborted"]
    errors = [r for r in slot_rows if r.get("outcome") == "error"]
    nones = [r for r in slot_rows if r.get("outcome") == "none"]
    if aborts or (errors and nones) or (not nones and not errors):
        return _finish_moa_abort(
            task,
            db,
            run_dir,
            cfg,
            payload=payload,
            arch=arch,
            area=area,
            cls=cls,
            shallow=shallow,
            base=base,
            aborts=aborts,
            session=session,
            last_abort_result=last_abort_result,
        )
    if errors and not nones:
        err_row = errors[-1]
        return {
            "status": err_row.get("status") or "failed_task",
            "error": err_row.get("none_reason") or "no_submit",
            "perspective_id": err_row.get("perspective_id"),
            **base,
        }

    return _finish_moa_none(
        task,
        db,
        run_dir,
        cfg,
        ctx=ctx,
        session=session,
        payload=payload,
        arch=arch,
        codemap_struct=codemap_struct,
        area=area,
        cls=cls,
        shallow=shallow,
        base=base,
        spawned=spawned,
        record=record,
        slot_rows=slot_rows,
    )


def _finish_moa_abort(
    task,
    db,
    run_dir: Path,
    cfg: dict,
    *,
    payload: dict,
    arch: dict,
    area: str,
    cls: str,
    shallow: bool,
    base: dict[str, Any],
    aborts: list[dict[str, Any]],
    session: dict,
    last_abort_result,
) -> dict[str, Any]:
    reasons = [str(r.get("none_reason") or "") for r in aborts]
    if any("max_tool_rounds" in r for r in reasons):
        err = "max_tool_rounds"
    elif reasons:
        err = reasons[-1] or "no_submit"
    else:
        err = "max_tool_rounds"
    _moa_coverage(db, payload, arch, cfg, area=area, cls=cls, depth="aborted")
    diagnostics: dict[str, Any] = {}
    if last_abort_result is not None:
        diagnostics = _diagnose_no_submit(last_abort_result, session)
    out: dict[str, Any] = {
        "status": "failed_task",
        "error": err,
        "aborted_scope": True,
        "shallow": shallow,
        "diagnostics": diagnostics,
        **base,
    }
    split_info = maybe_auto_split(task, db, cfg, run_dir)
    if split_info:
        out["split"] = split_info
    import logging

    logging.getLogger(__name__).warning(
        "Hunt task %s MoA ended without a candidate (%s).",
        task.id,
        err,
    )
    return out


def _finish_moa_none(
    task,
    db,
    run_dir: Path,
    cfg: dict,
    *,
    ctx: dict,
    session: dict,
    payload: dict,
    arch: dict,
    codemap_struct,
    area: str,
    cls: str,
    shallow: bool,
    base: dict[str, Any],
    spawned: list,
    record: dict[str, Any],
    slot_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """All-none (or none plus budget skips). One coverage write. No finding insert."""
    _flush_moa_notes(ctx, db, session, codemap_struct)
    db.insert_note(
        "hunt_moa",
        {"area": area, "class": cls, "hunt_moa": record},
        task_id=task.id,
    )
    reasons = [
        str(r.get("none_reason") or "").strip()
        for r in slot_rows
        if r.get("outcome") == "none" and str(r.get("none_reason") or "").strip()
    ]
    reason = "; ".join(reasons) if reasons else "no issue"
    if shallow_none_should_requeue(session, payload, shallow):
        _moa_coverage(db, payload, arch, cfg, area=area, cls=cls, depth="shallow")
        child_payload = {
            **payload,
            "force_depth": True,
            "shallow_requeued": True,
            "parent_task_id": task.id,
        }
        child_id = db.enqueue_task("hunt", child_payload, priority=45)
        try:
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "shallow_requeue",
                    "task_id": task.id,
                    "child_task_id": child_id,
                    "area": area,
                    "class": cls,
                },
            )
        except OSError:
            pass
        return {
            "status": "succeeded",
            "none_found": True,
            "reason": reason,
            "shallow": True,
            "shallow_requeued": True,
            "child_task_id": child_id,
            "spawned_hunts": spawned,
            "hunt_moa": record,
            **base,
        }
    depth = "shallow" if shallow else "none"
    _moa_coverage(db, payload, arch, cfg, area=area, cls=cls, depth=depth)
    return {
        "status": "succeeded",
        "none_found": True,
        "reason": reason,
        "shallow": shallow,
        "spawned_hunts": spawned,
        "hunt_moa": record,
        **base,
    }


def _diagnose_no_submit(result: LLMResult, session: dict) -> dict[str, Any]:
    """Diagnose why a hunt transcript ended without successful submit_*."""
    diagnostics: dict[str, Any] = {
        "result_ok": result.ok,
        "error": result.error,
        "classification": result.classification.value if result.classification else None,
        "tool_calls_count": len(result.tool_calls) if result.tool_calls else 0,
        "submit_attempts": [],
    }

    # Check what tools were actually called
    if result.transcript:
        for msg in result.transcript:
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                tool_calls = msg.get("tool_calls", [])
                for tc in tool_calls:
                    name = tc.get("function", {}).get("name", "") if isinstance(tc.get("function"), dict) else ""
                    diagnostics["submit_attempts"].append(name)

    # Check session state
    if session:
        diagnostics["candidate_stored"] = bool(session.get("candidate"))
        diagnostics["none_reason_stored"] = session.get("none_reason") is not None

    # Determine likely cause
    if result.error == "max_tool_rounds":
        diagnostics["likely_cause"] = "exhausted_max_tool_rounds"
        diagnostics["suggestion"] = (
            "LLM called non-submit tools too many times. Consider: "
            "1) Increasing max_tool_rounds in config, 2) Using a more compliant model, "
            "3) Simplifying the task prompt"
        )
    elif result.error == "no_submit":
        diagnostics["likely_cause"] = "llm_non_compliance"
        diagnostics["suggestion"] = (
            "LLM did not call any submit_* tool. Consider: "
            "1) Checking model compliance, 2) Verifying tool schema in packet, "
            "3) Using a model known to comply with VulnForge tool contracts"
        )
    else:
        diagnostics["likely_cause"] = "other_failure"
        diagnostics["suggestion"] = f"Investigate error: {result.error}"

    return diagnostics


def _architecture_slice(
    arch: dict, payload: dict, *, codemap: dict | None = None
) -> str:
    """Compact architecture for hunt packet — not the full recon dump.

    When architecture is missing/empty, still returns compact JSON so hunt works.
    Includes related codemap module paths when available.
    """
    if not isinstance(arch, dict):
        arch = {}
    area = str(payload.get("area") or "app")
    path_hints = [
        normalize_relpath(str(h))
        for h in (payload.get("path_hints") or [])
        if h
    ]
    path_hint_set = {h.lower() for h in path_hints if h}
    components = arch.get("components") or []
    matched: list[dict] = []
    if isinstance(components, list):
        for c in components:
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or "")
            if name == area or area in name or (name and name in area):
                matched.append(c)
                continue
            # Match path_hints from payload against component paths / path_hints
            c_paths: list[str] = []
            for ph in c.get("path_hints") or []:
                if ph:
                    c_paths.append(normalize_relpath(str(ph)).lower())
            if c.get("path"):
                c_paths.append(normalize_relpath(str(c.get("path"))).lower())
            if path_hint_set and c_paths:
                for hint in path_hint_set:
                    for cp in c_paths:
                        if hint == cp or hint in cp or cp in hint:
                            matched.append(c)
                            break
                    else:
                        continue
                    break
        # Dedupe while preserving order
        seen_names: set[str] = set()
        deduped: list[dict] = []
        for c in matched:
            key = str(c.get("name") or id(c))
            if key in seen_names:
                continue
            seen_names.add(key)
            deduped.append(c)
        matched = deduped
        if not matched:
            matched = [c for c in components if isinstance(c, dict)][:3]

    # hunt_focus items matching area (cap 5)
    focus_matched: list = []
    raw_focus = arch.get("hunt_focus") or []
    if isinstance(raw_focus, list):
        for item in raw_focus:
            if isinstance(item, dict):
                fa = str(item.get("area") or "")
                if fa == area or area in fa or (fa and fa in area):
                    focus_matched.append(item)
            elif isinstance(item, str):
                if area in item or item in area:
                    focus_matched.append(item)
            if len(focus_matched) >= 5:
                break

    slim: dict[str, Any] = {
        "summary": (arch.get("summary") or "")[:800],
        "area": area,
        "components": matched[:5],
        "trust_boundaries": (arch.get("trust_boundaries") or [])[:8]
        if isinstance(arch.get("trust_boundaries"), list)
        else [],
        "input_surfaces": (arch.get("input_surfaces") or [])[:8]
        if isinstance(arch.get("input_surfaces"), list)
        else [],
    }
    if isinstance(codemap, dict) and (
        codemap.get("modules") or codemap.get("entrypoints")
    ):
        try:
            from vulnforge.tools.codemap import slice_codemap

            sliced = slice_codemap(
                codemap,
                path_hints=path_hints,
                area=area,
                max_modules=4,
            )
            slim["codemap_modules"] = [
                {
                    "path": m.get("path"),
                    "kind": m.get("kind"),
                    "label": m.get("label"),
                    "signals": (m.get("signals") or [])[:6],
                }
                for m in (sliced.get("modules") or [])
                if isinstance(m, dict)
            ][:4]
        except Exception:
            pass
    if focus_matched:
        slim["hunt_focus"] = focus_matched[:5]
    if arch.get("recon_generation") is not None:
        try:
            slim["recon_generation"] = int(arch["recon_generation"])
        except (TypeError, ValueError):
            pass
    return json.dumps(slim, indent=2)


def _known_findings_readable(db, limit: int = 20) -> list[str]:
    """Human-readable path|weakness|title lines for the hunt packet."""
    lines: list[str] = []
    for f in db.list_findings()[: limit * 2]:
        b = f.body or {}
        path = ""
        cits = b.get("citations") or []
        if cits and isinstance(cits[0], dict):
            path = normalize_relpath(str(cits[0].get("path") or ""))
        if not path:
            path = normalize_relpath(str(b.get("sink_path") or ""))
        wk = str(b.get("weakness_class") or "")
        title = str(b.get("title") or f.stable_key)[:80]
        state = f.state
        lines.append(f"{path}|{wk}|{state}|{title}")
        if len(lines) >= limit:
            break
    return lines


def maybe_auto_split(task, db, cfg: dict, run_dir: Path) -> dict[str, Any] | None:
    """
    P1.5: On abort, enqueue 2â€“4 child hunts with chunked path_hints.

    Caps: max_split_depth 2; split tasks â‰¤ 30% of max_tasks.
    """
    payload = dict(task.payload or {})
    depth = int(payload.get("split_depth") or 0)
    max_depth = int((cfg.get("run") or {}).get("max_split_depth", MAX_SPLIT_DEPTH))
    if depth >= max_depth:
        return None
    hints = [
        normalize_relpath(str(h))
        for h in (payload.get("path_hints") or [])
        if h
    ]
    # Deduplicate while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    hints = uniq
    if len(hints) < MIN_SPLIT_CHILDREN:
        return None

    max_tasks = int((cfg.get("run") or {}).get("max_tasks", 50))
    split_budget = max(1, int(max_tasks * SPLIT_BUDGET_FRACTION))
    existing_splits = _count_split_tasks(db)
    remaining = split_budget - existing_splits
    if remaining <= 0:
        return None

    n_chunks = min(MAX_SPLIT_CHILDREN, max(MIN_SPLIT_CHILDREN, len(hints)), remaining)
    chunks = _chunk_list(hints, n_chunks)
    child_ids: list[int] = []
    for chunk in chunks:
        if not chunk:
            continue
        child_payload = {
            "area": payload.get("area", "app"),
            "class": payload.get("class", "wildcard"),
            "path_hints": chunk,
            "path_prefix": payload.get("path_prefix") or "",
            "parent_task_id": task.id,
            "split_depth": depth + 1,
            "force_depth": True,
            "seed_sinks": payload.get("seed_sinks") or [],
        }
        # Prefer sinks that match this chunk
        if payload.get("seed_sinks"):
            from vulnforge.tools.sink_preindex import filter_sinks_for_paths

            child_payload["seed_sinks"] = filter_sinks_for_paths(
                payload["seed_sinks"], chunk, top_k=8
            )
        cid = db.enqueue_task("hunt", child_payload, priority=48)
        child_ids.append(cid)
    if not child_ids:
        return None
    info = {
        "parent_task_id": task.id,
        "child_task_ids": child_ids,
        "split_depth": depth + 1,
        "chunks": len(child_ids),
    }
    try:
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "hunt_split",
                "task_id": task.id,
                **info,
            },
        )
    except OSError:
        pass
    return info


def _count_split_tasks(db) -> int:
    """Count abort-split children only (split_depth > 0).

    Shallow requeues set parent_task_id without split_depth and must not
    consume the 30% split budget.
    """
    n = 0
    for t in db.list_tasks(limit=2000):
        if t.kind != "hunt":
            continue
        p = t.payload or {}
        if int(p.get("split_depth") or 0) > 0:
            n += 1
    return n


def _chunk_list(items: list[str], n: int) -> list[list[str]]:
    if n <= 0 or not items:
        return []
    n = min(n, len(items))
    # Round-robin distribute for balanced path clusters
    chunks: list[list[str]] = [[] for _ in range(n)]
    for i, item in enumerate(items):
        chunks[i % n].append(item)
    return [c for c in chunks if c]


def validate_candidate_shape(body: dict) -> list[str]:
    errs: list[str] = []
    if not body.get("title"):
        errs.append("missing title")
    if not body.get("summary"):
        errs.append("missing summary")
    if not body.get("weakness_class"):
        errs.append("missing weakness_class")
    tm = body.get("threat_model") or {}
    if not isinstance(tm, dict):
        errs.append("threat_model must be object")
        tm = {}
    for k in ("attacker", "boundary", "impact"):
        v = tm.get(k)
        if not v or not str(v).strip():
            errs.append(f"missing threat_model.{k}")
        elif len(str(v).strip()) < 3:
            errs.append(f"threat_model.{k} too short")
    cits = body.get("citations")
    if not cits or not isinstance(cits, list):
        errs.append("citations required")
    else:
        for i, c in enumerate(cits):
            if not isinstance(c, dict):
                errs.append(f"citations[{i}] must be object")
                continue
            # Source: path required. Binary: path OR address OR symbol.
            if c.get("path"):
                continue
            if c.get("address") or c.get("symbol"):
                continue
            errs.append(f"citations[{i}].path required (or address/symbol for binary)")
    return errs


def prepare_candidate_submission(
    body: dict, session: dict, evidence_root: Path
) -> tuple[dict | None, dict | None]:
    """
    Shape-check + evidence gate for submit_candidate.

    Returns (prepared_body, None) on success, or (None, error_dict with ok:false).

    Evidence policy (strict session auth):
    - evidence_id must have been written via write_evidence in *this* session
      (tracked in session["evidence_ids_written"]).
    - Foreign/pre-existing packs on disk are not accepted without a session write
      (no cross-task free-ride).
    - Always re-check the pack on disk with MIN_EVIDENCE_FILE_BYTES; if
      poc_relpath is set, that file must meet the min size (no pack-level fallback).
    """
    from vulnforge.tools.evidence_write import (
        MIN_EVIDENCE_FILE_BYTES,
        InvalidEvidenceId,
        evidence_exists,
        sanitize_evidence_id,
    )

    if not isinstance(body, dict):
        return None, {"ok": False, "error": "candidate body must be an object"}
    body = dict(body)

    written_ids = set(session.get("evidence_ids_written") or [])
    # Prefer explicit write tracking; tools_used alone is not auth for a foreign id.
    session_eid = session.get("evidence_id")
    if session_eid and session_eid in written_ids and not body.get("evidence_id"):
        body["evidence_id"] = session_eid

    errs = validate_candidate_shape(body)
    if errs:
        return None, {"ok": False, "errors": errs}

    # Optional severity_claim: canonicalize aliases or soft-drop free-text so
    # validate_mech does not reject solid candidates for a mis-filled enum.
    from vulnforge.findings.severity import apply_severity_claim

    body, _sev_action = apply_severity_claim(body)

    eid = body.get("evidence_id")
    if not eid:
        return None, {
            "ok": False,
            "error": (
                "submit_candidate requires write_evidence in this session "
                "(include the returned evidence_id)"
            ),
        }
    try:
        seid = sanitize_evidence_id(str(eid))
    except InvalidEvidenceId as e:
        return None, {"ok": False, "error": f"invalid evidence_id: {e}"}

    # Session membership: must have written this id via write_evidence this session.
    if seid not in written_ids:
        return None, {
            "ok": False,
            "error": (
                "submit_candidate requires write_evidence in this session for "
                f"evidence_id={seid!r} (foreign/pre-existing packs are not accepted)"
            ),
        }

    # Disk re-check (single source of truth with mech gates on size / poc path).
    poc = body.get("poc_relpath")
    poc_arg = str(poc) if poc else None
    if not evidence_exists(
        evidence_root, seid, poc_arg, min_file_bytes=MIN_EVIDENCE_FILE_BYTES
    ):
        if poc_arg:
            return None, {
                "ok": False,
                "error": (
                    f"submit_candidate: poc_relpath={poc_arg!r} missing or too small "
                    f"under evidence_id={seid!r} (min {MIN_EVIDENCE_FILE_BYTES} bytes)"
                ),
            }
        return None, {
            "ok": False,
            "error": (
                "submit_candidate requires a non-vacuous evidence pack "
                f"(min {MIN_EVIDENCE_FILE_BYTES} bytes) for evidence_id={seid!r}"
            ),
        }
    body["evidence_id"] = seid
    # Normalize primary sink identity for stable_key (P2.4).
    # Prefer a citation with a symbol, then a code-looking path â€” not just [0]
    # (models often list README/route tables first).
    if not body.get("sink_path") or not body.get("sink_symbol"):
        path, symbol = _pick_primary_sink_from_citations(body.get("citations") or [])
        if path and not body.get("sink_path"):
            body["sink_path"] = path
        if symbol and not body.get("sink_symbol"):
            body["sink_symbol"] = symbol
    return body, None


def _pick_primary_sink_from_citations(cits: list) -> tuple[str, str]:
    """Choose best (path, symbol) from citations for sink identity."""
    if not cits or not isinstance(cits, list):
        return "", ""
    dicts = [c for c in cits if isinstance(c, dict) and c.get("path")]
    if not dicts:
        return "", ""

    def _codeish(path: str) -> bool:
        p = path.lower().replace("\\", "/")
        name = Path(p).name
        if name.upper() in ("README.MD", "README", "LICENSE", "CHANGELOG.MD"):
            return False
        if p.endswith((".md", ".txt", ".rst", ".json")) and "test" not in p:
            # still allow package.json-ish only if no better option
            return name in ("package.json", "pyproject.toml", "go.mod", "cargo.toml")
        return True

    # 1) citation with non-empty symbol (prefer code-looking path)
    with_sym = [c for c in dicts if str(c.get("symbol") or "").strip()]
    if with_sym:
        with_sym_code = [c for c in with_sym if _codeish(str(c.get("path") or ""))]
        chosen = (with_sym_code or with_sym)[0]
        return (
            normalize_relpath(str(chosen.get("path") or "")),
            str(chosen.get("symbol") or "").strip(),
        )
    # 2) code-looking path without symbol
    code = [c for c in dicts if _codeish(str(c.get("path") or ""))]
    chosen = (code or dicts)[0]
    return normalize_relpath(str(chosen.get("path") or "")), str(
        chosen.get("symbol") or ""
    ).strip()


def is_shallow(session: dict, *, profile: str = "") -> bool:
    """True when the hunt did not use deeper source tools (read_file/grep)."""
    del profile  # reserved for future profile-specific depth rules
    used = set(session.get("tools_used") or [])
    return not bool(used & {"read_file", "grep"})
