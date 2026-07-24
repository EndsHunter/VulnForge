"""Stage: hunt â€” one areaÃ—class investigation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.llm import InfraError, classify_llm_failure, make_client
from vulnforge.packet import pack_hunt, refuse_if_over_budget
from vulnforge.tools import build_tool_handler
from vulnforge.tools.queue_note import flush_notes_to_db
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.paths import system_prompts_root
from vulnforge.util import append_event, normalize_relpath

# Abort errors that free the queue and may trigger auto-split (not infra).
ABORT_ERRORS = frozenset({"max_tool_rounds", "no_submit", "aborted_scope"})

MAX_SPLIT_DEPTH = 2
MAX_SPLIT_CHILDREN = 4
MIN_SPLIT_CHILDREN = 2
SPLIT_BUDGET_FRACTION = 0.30


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    run_row = db.get_run()
    if not run_row:
        return {"status": "failed_task", "error": "no_run"}
    target = Path(run_row["target_path"])
    arch = db.get_architecture() or {}
    payload = dict(task.payload or {})

    # Slim architecture slice for packet (area-focused, not full dump)
    architecture_txt = _architecture_slice(arch, payload)

    # P2.6: human-readable known findings for packet
    known_findings = _known_findings_readable(db)
    known_keys = [f.stable_key for f in db.list_findings()]
    codemap = [
        json.dumps(n["payload"])[:200]
        for n in db.list_notes(kind="codemap")
    ]

    seed_sinks = payload.get("seed_sinks")
    if not seed_sinks:
        # Pull from architecture inventory preindex when present
        inv = arch.get("inventory") or {}
        all_sinks = inv.get("seed_sinks") or arch.get("seed_sinks") or []
        if all_sinks:
            from vulnforge.tools.sink_preindex import filter_sinks_for_paths

            seed_sinks = filter_sinks_for_paths(
                all_sinks,
                payload.get("path_hints") or [],
                top_k=int((cfg.get("packet") or {}).get("max_seed_sinks", 12)),
            )

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
    packet = pack_hunt(
        cfg,
        prompts_root,
        payload,
        architecture_txt,
        known_keys,
        codemap,
        seed_sinks=seed_sinks or [],
        known_findings=known_findings,
    )
    try:
        refuse_if_over_budget(packet)
    except Exception as e:
        return {"status": "failed_task", "error": f"over_budget: {e}"}

    client = make_client(cfg)
    try:
        try:
            model_id = client.fingerprint_model()
        except InfraError as e:
            return {"status": "failed_infra", "error": str(e)}
        max_rounds = int((cfg.get("llm") or {}).get("max_tool_rounds", 12))
        temp = float((cfg.get("llm") or {}).get("temperature_hunt", 0.4))
        result = client.run_tool_loop(
            packet, handler, max_rounds=max_rounds, temperature=temp
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
                },
            )
        except OSError:
            pass
        area = payload.get("area", "app")
        cls = payload.get("class", "wildcard")

        if not result.ok:
            status = classify_llm_failure(result)
            err = result.error or result.classification.value
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
                # P1.5 auto-split hook
                split_info = maybe_auto_split(task, db, cfg, run_dir)
                if split_info:
                    out["split"] = split_info
            return out

        flush_notes_to_db(ctx, db)
        shallow = is_shallow(session, profile=profile)
        spawned_hunts = list(session.get("spawned_hunts") or [])

        if session.get("none_reason") is not None:
            # P1.3: shallow none â†’ requeue once with force_depth; do not close cell as done
            if shallow and not payload.get("force_depth") and not payload.get(
                "shallow_requeued"
            ):
                db.upsert_coverage_fact(area, cls, visit_delta=1, last_depth="shallow")
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


def _architecture_slice(arch: dict, payload: dict) -> str:
    """Compact architecture for hunt packet — not the full recon dump.

    When architecture is missing/empty, still returns compact JSON so hunt works.
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
