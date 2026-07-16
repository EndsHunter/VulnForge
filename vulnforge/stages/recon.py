"""Stage: recon - mechanical inventory + LLM architecture + hunt tasks."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from vulnforge.hunt_profiles import (
    all_class_ids,
    catalog_for_ui,
    normalize_class,
    resolve_run_class_ids,
    skill_policy_from_run_cfg,
)
from vulnforge.llm import InfraError, classify_llm_failure, make_client
from vulnforge.packet import pack_recon_agent
from vulnforge.recon_agents import (
    ReconAgentError,
    active_agents,
    get_body,
)
from vulnforge.tools import build_tool_handler
from vulnforge.tools.grep_index import build_file_index
from vulnforge.tools.queue_note import flush_notes_to_db
from vulnforge.tools.sink_preindex import (
    build_sink_preindex,
    class_has_sink_family,
    filter_sinks_for_paths,
    sink_kinds_present,
)
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.util import append_event, normalize_relpath

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Recoverable recon failures: parent stays failed_task but a child recon is
# enqueued so Ralph keeps looping (mirrors hunt shallow requeue).
# Non-recoverable: no_run, empty_inventory (broken target/data).
_RECON_RECOVERABLE_ERRORS = frozenset(
    {
        "max_tool_rounds",
        "no_submit",
        "no_architecture",
        "no_hunt_tasks",
        "empty",
        "truncated",
        "context_length",
        "error-like content",
        "error_text",
        "unknown",
        "fake exhausted",
    }
)


def hunt_class_catalog() -> dict[str, list[str]]:
    """Canonical hunt-class lists for UI, API, and operators.

    - active: bulk enqueue set (recon active_fallback, coverage all, file_by_file)
    - all: every registered profile in the operator collection
    """
    return catalog_for_ui()


def merge_skill_policy_into_cfg(
    cfg: dict,
    payload: Optional[dict] = None,
) -> dict:
    """Overlay task-payload hunt skill policy onto a shallow copy of cfg.run."""
    mode, skill_ids = skill_policy_from_run_cfg(cfg, payload=payload)
    base = dict(cfg) if isinstance(cfg, dict) else {}
    run = dict(base.get("run") or {})
    run["hunt_skill_mode"] = mode
    if skill_ids is not None:
        run["hunt_skill_ids"] = list(skill_ids)
    elif "hunt_skill_ids" not in run:
        run["hunt_skill_ids"] = []
    base["run"] = run
    return base


def _recon_generation(payload: dict[str, Any]) -> int:
    try:
        g = int(payload.get("recon_generation") or 1)
    except (TypeError, ValueError):
        g = 1
    return max(1, g)


def resolve_recon_agent_ids(agent_ids: Optional[list[str]] = None) -> list[str]:
    """Resolve which recon agent ids will run (selection or active collection)."""
    filter_ids: list[str] | None = None
    if agent_ids:
        filter_ids = [str(x).strip().lower() for x in agent_ids if str(x).strip()]
        if not filter_ids:
            filter_ids = None
    agents = active_agents(agent_ids=filter_ids)
    return [str(a.get("id") or "").strip().lower() for a in agents if a.get("id")]


def expand_recon_agent_tasks(
    base_payload: dict[str, Any],
    agent_ids: list[str],
    *,
    base_priority: int = 10,
) -> list[tuple[dict[str, Any], int]]:
    """
    Expand a recon request into one Ralph task payload per agent.

    Multiple agents share a recon_batch_id so results merge into one architecture
    and hunts finalize once when the batch is complete.
    """
    ids = [str(a).strip().lower() for a in (agent_ids or []) if str(a).strip()][:32]
    if not ids:
        return [(dict(base_payload), int(base_priority))]

    want_hunts = base_payload.get("enqueue_hunts")
    if want_hunts is None:
        want_hunts = True
    want_hunts = bool(want_hunts)
    include_prior = base_payload.get("include_prior_architecture")

    if len(ids) == 1:
        pl = dict(base_payload)
        pl["agent_ids"] = [ids[0]]
        pl["enqueue_hunts"] = want_hunts
        return [(pl, int(base_priority))]

    batch_id = str(uuid.uuid4())
    out: list[tuple[dict[str, Any], int]] = []
    n = len(ids)
    for i, aid in enumerate(ids):
        pl = dict(base_payload)
        pl["agent_ids"] = [aid]
        pl["recon_batch_id"] = batch_id
        pl["recon_batch_index"] = i
        pl["recon_batch_size"] = n
        pl["batch_enqueue_hunts"] = want_hunts
        # Per-task hunts stay off; the last completed sibling finalizes once.
        pl["enqueue_hunts"] = False
        if i == 0:
            if include_prior is not None:
                pl["include_prior_architecture"] = bool(include_prior)
            pl["merge_with_existing"] = False
        else:
            pl["include_prior_architecture"] = True
            pl["merge_with_existing"] = True
        out.append((pl, int(base_priority) + i))
    return out


def enqueue_recon_agent_tasks(
    db,
    base_payload: dict[str, Any],
    agent_ids: list[str],
    *,
    base_priority: int = 10,
) -> list[int]:
    """Enqueue one recon task per agent; return task ids in agent order."""
    task_ids: list[int] = []
    for pl, prio in expand_recon_agent_tasks(
        base_payload, agent_ids, base_priority=base_priority
    ):
        task_ids.append(db.enqueue_task("recon", pl, priority=prio))
    return task_ids


def _merge_agents_run(
    prior: list[dict[str, Any]] | None,
    new_entries: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Append agent-run metadata, replacing same id when re-run in a later pass."""
    out: list[dict[str, Any]] = []
    by_id: dict[str, int] = {}
    for entry in list(prior or []) + list(new_entries or []):
        if not isinstance(entry, dict):
            continue
        aid = str(entry.get("id") or "").strip()
        if not aid:
            out.append(dict(entry))
            continue
        if aid in by_id:
            out[by_id[aid]] = dict(entry)
        else:
            by_id[aid] = len(out)
            out.append(dict(entry))
    return out


def _arch_structure_part(arch: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(arch, dict):
        return {
            "summary": "",
            "components": [],
            "trust_boundaries": [],
            "input_surfaces": [],
            "hunt_focus": [],
        }
    return {
        "summary": arch.get("summary") or "",
        "components": list(arch.get("components") or [])
        if isinstance(arch.get("components"), list)
        else [],
        "trust_boundaries": list(arch.get("trust_boundaries") or [])
        if isinstance(arch.get("trust_boundaries"), list)
        else [],
        "input_surfaces": list(arch.get("input_surfaces") or [])
        if isinstance(arch.get("input_surfaces"), list)
        else [],
        "hunt_focus": list(arch.get("hunt_focus") or [])
        if isinstance(arch.get("hunt_focus"), list)
        else [],
    }


def store_merged_architecture(
    db,
    *,
    part: dict[str, Any],
    agents_run: list[dict[str, Any]],
    inventory: dict[str, Any],
    seed_sinks: list,
    operator_brief: str = "",
    merge_with_existing: bool = False,
) -> dict[str, Any]:
    """Write architecture, optionally merging with the map already in the DB."""
    existing = db.get_architecture() if merge_with_existing else None
    if merge_with_existing and existing:
        agents = _merge_agents_run(existing.get("recon_agents_run"), agents_run)
        arch = merge_architectures(
            [_arch_structure_part(existing), part],
            agents_run=agents,
        )
        # Prefer newest inventory; keep older if this pass lacks counts
        prev_inv = existing.get("inventory") if isinstance(existing.get("inventory"), dict) else {}
        inv = dict(prev_inv)
        inv.update({k: v for k, v in (inventory or {}).items() if v is not None})
        arch["inventory"] = inv
        if existing.get("operator_notes_applied") and not operator_brief:
            arch["operator_notes_applied"] = existing.get("operator_notes_applied")
        # Preserve batch finalize markers across merges
        if isinstance(existing.get("recon_batch_finalize"), dict):
            arch["recon_batch_finalize"] = dict(existing["recon_batch_finalize"])
    else:
        arch = merge_architectures([part], agents_run=agents_run)
        arch["inventory"] = inventory
        arch["recon_agents_run"] = list(agents_run)

    arch["seed_sinks"] = seed_sinks[:200]
    if operator_brief:
        arch["operator_notes_applied"] = operator_brief[:2000]
    db.set_architecture(arch)
    return arch


def _batch_sibling_tasks(db, batch_id: str) -> list:
    if not batch_id:
        return []
    out = []
    for t in db.list_tasks(limit=500):
        if getattr(t, "kind", None) != "recon":
            continue
        pl = t.payload if isinstance(getattr(t, "payload", None), dict) else {}
        if str(pl.get("recon_batch_id") or "") == str(batch_id):
            out.append(t)
    return out


def _batch_ready_to_finalize(db, batch_id: str, current_task_id: int) -> bool:
    """True when every sibling is terminal (treat current as about to succeed)."""
    siblings = _batch_sibling_tasks(db, batch_id)
    if not siblings:
        return True
    terminal = frozenset(
        {"succeeded", "failed_task", "failed_infra", "deadletter", "cancelled"}
    )
    for t in siblings:
        if int(t.id) == int(current_task_id):
            continue
        st = str(getattr(t, "state", "") or "").lower()
        if st not in terminal:
            return False
    return True


def _claim_batch_finalize(db, batch_id: str) -> bool:
    """Mark batch hunts/skills as claimed once (returns False if already done)."""
    if not batch_id:
        return True
    arch = db.get_architecture() or {}
    fin = arch.get("recon_batch_finalize")
    if not isinstance(fin, dict):
        fin = {}
    entry = fin.get(batch_id)
    if isinstance(entry, dict) and entry.get("done"):
        return False
    fin[batch_id] = {"done": True}
    arch["recon_batch_finalize"] = fin
    db.set_architecture(arch)
    return True


def _is_recoverable_recon_error(error: str) -> bool:
    err = (error or "").strip().lower()
    if not err:
        return False
    if err in ("no_run", "empty_inventory"):
        return False
    if err in _RECON_RECOVERABLE_ERRORS:
        return True
    # classify_llm_failure may pass classification values or longer messages
    for needle in (
        "max_tool_rounds",
        "no_submit",
        "no_architecture",
        "no_hunt_tasks",
        "empty",
        "truncat",
        "context",
    ):
        if needle in err:
            return True
    return False


def maybe_auto_retry_recon(
    task,
    db,
    cfg: dict,
    run_dir: Path,
    error: str,
) -> Optional[dict[str, Any]]:
    """
    On recoverable recon failed_task, enqueue a child recon so Ralph continues.

    Returns extras to merge into the parent result, or None if no child.
    Cap: run.max_recon_auto_retries (default 2) child generations after gen 1.
    """
    if not _is_recoverable_recon_error(error):
        return None
    payload = task.payload if isinstance(getattr(task, "payload", None), dict) else {}
    gen = _recon_generation(payload)
    try:
        max_auto = max(0, int((cfg.get("run") or {}).get("max_recon_auto_retries", 2)))
    except (TypeError, ValueError):
        max_auto = 2
    # gen 1 = first recon; children are gen 2 .. 1+max_auto
    if gen >= 1 + max_auto:
        return None

    child_payload: dict[str, Any] = {
        "parent_task_id": task.id,
        "recon_generation": gen + 1,
        "recon_auto_retry": True,
        "prior_error": str(error)[:200],
        "include_prior_architecture": True,
    }
    # Preserve operator / strategy / multi-agent batch context
    for key in (
        "operator_notes",
        "operator_requested",
        "operator_reason",
        "focus_paths",
        "path_hints",
        "enqueue_hunts",
        "batch_enqueue_hunts",
        "docs_digest",
        "target",
        "agent_ids",
        "recon_batch_id",
        "recon_batch_index",
        "recon_batch_size",
        "merge_with_existing",
        "dynamic_skills",
        "dynamic_skill_count",
        "dynamic_skills_activate",
        "strategy",
    ):
        if key in payload and payload[key] is not None:
            child_payload[key] = payload[key]
    # Batch members never hunt-enqueue alone; finalizer uses batch_enqueue_hunts.
    if payload.get("recon_batch_id"):
        child_payload["enqueue_hunts"] = False
        child_payload["merge_with_existing"] = True
        child_payload.setdefault(
            "batch_enqueue_hunts",
            payload.get("batch_enqueue_hunts", True),
        )
    elif "enqueue_hunts" not in child_payload:
        child_payload["enqueue_hunts"] = True

    # Ahead of default hunts (50) but after operator re-run (5)
    child_id = db.enqueue_task("recon", child_payload, priority=8)
    try:
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "recon_auto_retry",
                "task_id": task.id,
                "child_task_id": child_id,
                "recon_generation": gen + 1,
                "prior_error": str(error)[:200],
            },
        )
    except OSError:
        pass
    return {
        "recon_requeued": True,
        "child_task_id": child_id,
        "recon_generation": gen + 1,
    }


def _failed_task_result(
    task,
    db,
    cfg: dict,
    run_dir: Path,
    error: str,
    **extra: Any,
) -> dict[str, Any]:
    """Build failed_task result and optionally enqueue Ralph follow-up recon."""
    out: dict[str, Any] = {"status": "failed_task", "error": error, **extra}
    retry = maybe_auto_retry_recon(task, db, cfg, run_dir, error)
    if retry:
        out.update(retry)
    return out


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    run_row = db.get_run()
    if not run_row:
        return {"status": "failed_task", "error": "no_run"}
    target = Path(run_row["target_path"])
    ignore = list((cfg.get("run") or {}).get("ignore_globs") or [])
    inventory = build_file_index(target, ignore)
    if inventory["file_count"] == 0:
        return {"status": "failed_task", "error": "empty_inventory"}

    # P2.1: mechanical sink preindex (also used for class routing / hunt seeds)
    try:
        seed_sinks = build_sink_preindex(target, ignore)
    except OSError:
        seed_sinks = []
    inventory["seed_sinks"] = seed_sinks
    # Area names from stratified seed (full file_count remains authority for size).
    inventory["dir_partitions"] = partition_by_top_dir(
        inventory.get("sample_paths") or []
    )

    session: dict = {
        "architecture": None,
        "notes": [],
        "tools_used": [],
    }

    def submit_architecture(args: dict) -> dict:
        session["architecture"] = args
        return {"ok": True, "stored": "architecture"}

    ctx = {
        "target_root": str(target),
        "evidence_root": str(run_dir / "evidence"),
        "task_id": task.id,
        "cfg": cfg,
        "session": session,
        "submit_architecture": submit_architecture,
    }
    handler = build_tool_handler(ctx)
    prompts_root = PROJECT_ROOT / "prompts" / "v1"
    payload = task.payload if isinstance(getattr(task, "payload", None), dict) else {}
    # Operator re-run: optional prior architecture + brief + focus paths.
    # First-pass recon (no operator_requested) does not inject prior arch.
    include_prior = payload.get("include_prior_architecture")
    if include_prior is None:
        include_prior = bool(payload.get("operator_requested"))
    architecture_so_far = ""
    if include_prior or payload.get("architecture_so_far"):
        prior = payload.get("architecture_so_far")
        if not prior:
            existing = db.get_architecture()
            if existing:
                prior = json.dumps(
                    {
                        "summary": existing.get("summary"),
                        "components": existing.get("components"),
                        "trust_boundaries": existing.get("trust_boundaries"),
                        "input_surfaces": existing.get("input_surfaces"),
                        "hunt_focus": existing.get("hunt_focus"),
                    },
                    indent=2,
                )
        architecture_so_far = str(prior or "")
    operator_brief = str(
        payload.get("operator_notes")
        or payload.get("operator_brief")
        or payload.get("operator_reason")
        or ""
    )
    # recon_docs strategy: append docs digest text into the operator brief
    # so pack_recon can surface it without a separate packet field.
    docs_digest_ref = payload.get("docs_digest")
    if docs_digest_ref:
        digest_text = ""
        try:
            dpath = Path(str(docs_digest_ref))
            if dpath.is_file():
                digest_text = dpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            digest_text = ""
        if digest_text.strip():
            # Cap so recon packet stays under budget (pack_recon truncates brief too).
            max_digest = int((cfg.get("packet") or {}).get("max_docs_digest_chars", 8000))
            body = digest_text.strip()
            if len(body) > max_digest:
                body = body[: max_digest - 40] + "\n...[docs_digest truncated]...\n"
            if operator_brief:
                operator_brief = (
                    operator_brief.rstrip()
                    + "\n\n## Documentation digest\n"
                    + body
                )
            else:
                operator_brief = (
                    "Recon guided by operator documentation digest.\n\n" + body
                )
    focus_paths = payload.get("focus_paths") or payload.get("path_hints") or []
    if not isinstance(focus_paths, list):
        focus_paths = []

    # Run-scoped hunt skill mode (config + optional recon payload override).
    cfg = merge_skill_policy_into_cfg(cfg, payload)

    # Active recon agents (optional payload.agent_ids filter for operator re-runs).
    # Multi-agent selection is fanned out into one Ralph task per agent (recon batch).
    raw_agent_ids = payload.get("agent_ids")
    filter_ids: list[str] | None = None
    if isinstance(raw_agent_ids, list) and raw_agent_ids:
        filter_ids = [str(x) for x in raw_agent_ids if x]
    try:
        agents = active_agents(agent_ids=filter_ids)
    except ReconAgentError as e:
        return {"status": "failed_task", "error": f"recon_agents: {e}"}
    if not agents:
        return {"status": "failed_task", "error": "no_recon_agents"}

    # Legacy / unsplit multi-agent payload: fan out remaining agents as sibling tasks
    # so each profile gets its own Ralph loop, then run only the first here.
    fanout_task_ids: list[int] = []
    if len(agents) > 1 and not payload.get("recon_batch_id"):
        first = agents[0]
        all_ids = [str(a.get("id")) for a in agents if a.get("id")]
        expanded = expand_recon_agent_tasks(dict(payload), all_ids, base_priority=8)
        if expanded:
            first_pl = expanded[0][0]
            payload = {**payload, **first_pl}
            # Persist single-agent batch payload so auto-retry does not re-fan-out.
            try:
                db.update_task_payload(task.id, payload)
                if hasattr(task, "payload"):
                    task.payload = payload
            except Exception:
                pass
            for pl, prio in expanded[1:]:
                fanout_task_ids.append(db.enqueue_task("recon", pl, priority=prio))
            agents = active_agents(agent_ids=[str(first.get("id"))]) or [first]

    # Batch follow-ups always refine the map already written by earlier siblings.
    merge_with_existing = bool(payload.get("merge_with_existing"))
    if payload.get("recon_batch_id") and int(payload.get("recon_batch_index") or 0) > 0:
        merge_with_existing = True
        if not architecture_so_far:
            existing = db.get_architecture()
            if existing:
                architecture_so_far = json.dumps(
                    {
                        "summary": existing.get("summary"),
                        "components": existing.get("components"),
                        "trust_boundaries": existing.get("trust_boundaries"),
                        "input_surfaces": existing.get("input_surfaces"),
                        "hunt_focus": existing.get("hunt_focus"),
                    },
                    indent=2,
                )

    client = make_client(cfg)
    try:
        try:
            model_id = client.fingerprint_model()
        except InfraError as e:
            return {"status": "failed_infra", "error": str(e)}

        default_max_rounds = int((cfg.get("llm") or {}).get("max_tool_rounds", 12))
        default_temp = float((cfg.get("llm") or {}).get("temperature_recon", 0.3))

        usage_fields: dict[str, Any] = {}
        agents_run: list[dict[str, Any]] = []
        partial_archs: list[dict[str, Any]] = []
        arch_so_far_text = architecture_so_far
        last_result = None

        for agent in agents:
            agent_id = str(agent.get("id") or "agent")
            try:
                body_md = get_body(agent_id)
            except ReconAgentError as e:
                return {
                    "status": "failed_task",
                    "error": f"recon_agent_body: {e}",
                    "model_id": model_id,
                    "recon_agents_run": agents_run,
                }

            # Reset submit capture for this agent pass
            session["architecture"] = None
            tools_allow = agent.get("tools")
            if tools_allow is not None and not isinstance(tools_allow, list):
                tools_allow = None
            packet = pack_recon_agent(
                cfg,
                prompts_root,
                agent_body=body_md,
                inventory=inventory,
                architecture_so_far=arch_so_far_text,
                operator_brief=operator_brief,
                focus_paths=focus_paths,
                tools_allowlist=tools_allow,
                agent_id=agent_id,
            )
            max_rounds = agent.get("max_tool_rounds")
            if max_rounds is None:
                max_rounds = default_max_rounds
            else:
                try:
                    max_rounds = int(max_rounds)
                except (TypeError, ValueError):
                    max_rounds = default_max_rounds
            temp = agent.get("temperature")
            if temp is None:
                temp = default_temp
            else:
                try:
                    temp = float(temp)
                except (TypeError, ValueError):
                    temp = default_temp

            result = client.run_tool_loop(
                packet, handler, max_rounds=max_rounds, temperature=temp
            )
            last_result = result
            pass_usage = record_llm_result(
                run_dir,
                task_id=task.id,
                kind=f"recon:{agent_id}",
                model_id=model_id,
                result=result,
            )
            usage_fields = _merge_usage_fields(usage_fields, pass_usage)
            try:
                save_transcript(
                    run_dir,
                    task.id,
                    kind=f"recon:{agent_id}",
                    model_id=model_id,
                    messages=list(result.transcript or []),
                    result={
                        "ok": result.ok,
                        "classification": result.classification.value,
                        "error": result.error,
                        "content": result.content,
                        "recon_agent_id": agent_id,
                        **pass_usage,
                    },
                )
            except OSError:
                pass

            salvaged_from_content = False
            if not result.ok:
                status = classify_llm_failure(result)
                err = result.error or result.classification.value
                # Weak tool-use models often dump architecture as free text /
                # JSON without calling submit_architecture. Salvage only when
                # content actually parses to a non-empty summary — never invent.
                salvage_errs = ("no_submit", "max_tool_rounds")
                can_salvage = (
                    status != "failed_infra"
                    and err in salvage_errs
                    and bool((result.content or "").strip())
                )
                if can_salvage:
                    # Structured only: session submit args or JSON with summary.
                    # Do not promote arbitrary free-text chatter into architecture.
                    salvaged = parse_architecture(result, session)
                    if salvaged.get("summary"):
                        part = salvaged
                        salvaged_from_content = True
                        import logging

                        logging.getLogger(__name__).warning(
                            f"Recon task {task.id} agent {agent_id}: salvaged architecture "
                            f"from content/session after {err} (model skipped submit_architecture)."
                        )
                if not salvaged_from_content:
                    if err in salvage_errs:
                        import logging

                        logging.getLogger(__name__).warning(
                            f"Recon task {task.id} agent {agent_id} failed with error: {err}. "
                            f"This may indicate LLM non-compliance or max_tool_rounds exhaustion. "
                            f"Check model settings and consider increasing rounds or using a more compliant model."
                        )
                    agents_run.append(
                        {
                            "id": agent_id,
                            "ok": False,
                            "error": err,
                            "order": agent.get("order"),
                        }
                    )
                    if status == "failed_infra":
                        return {
                            "status": status,
                            "error": err,
                            "model_id": model_id,
                            "transcript": f"task-{task.id}",
                            "recon_agents_run": agents_run,
                            **usage_fields,
                        }
                    out_fail = _failed_task_result(
                        task,
                        db,
                        cfg,
                        run_dir,
                        err,
                        model_id=model_id,
                        transcript=f"task-{task.id}",
                        recon_agents_run=agents_run,
                    )
                    out_fail.update(usage_fields)
                    return out_fail
            else:
                part = parse_architecture(result, session)
                if not part.get("summary") and result.content:
                    part = {
                        "summary": result.content[:4000],
                        "components": [],
                        "trust_boundaries": [],
                        "input_surfaces": [],
                        "hunt_focus": [],
                    }
            if not part.get("summary"):
                agents_run.append(
                    {
                        "id": agent_id,
                        "ok": False,
                        "error": "no_architecture",
                        "order": agent.get("order"),
                    }
                )
                return _failed_task_result(
                    task,
                    db,
                    cfg,
                    run_dir,
                    "no_architecture",
                    model_id=model_id,
                    recon_agents_run=agents_run,
                )

            agents_run.append(
                {
                    "id": agent_id,
                    "ok": True,
                    "order": agent.get("order"),
                    "title": agent.get("title") or agent_id,
                    **(
                        {"salvaged_from_content": True}
                        if salvaged_from_content
                        else {}
                    ),
                }
            )
            partial_archs.append(part)
            # Feed merged-so-far into the next sequential agent
            merged_so_far = merge_architectures(
                partial_archs, agents_run=agents_run
            )
            arch_so_far_text = json.dumps(
                {
                    "summary": merged_so_far.get("summary"),
                    "components": merged_so_far.get("components"),
                    "trust_boundaries": merged_so_far.get("trust_boundaries"),
                    "input_surfaces": merged_so_far.get("input_surfaces"),
                    "hunt_focus": merged_so_far.get("hunt_focus"),
                },
                indent=2,
            )

        part_merged = merge_architectures(partial_archs, agents_run=agents_run)
        if not part_merged.get("summary"):
            return _failed_task_result(
                task,
                db,
                cfg,
                run_dir,
                "no_architecture",
                model_id=model_id,
                recon_agents_run=agents_run,
            )

        inv_blob = {
            "file_count": inventory["file_count"],
            "entrypoints": inventory["entrypoints"],
            "extensions": inventory["extensions"],
            "seed_sinks": seed_sinks[:200],
            "dir_partitions": inventory.get("dir_partitions") or [],
        }
        arch = store_merged_architecture(
            db,
            part=part_merged,
            agents_run=agents_run,
            inventory=inv_blob,
            seed_sinks=seed_sinks,
            operator_brief=operator_brief,
            merge_with_existing=merge_with_existing,
        )

        # Hunts / dynamic skills: single-task or last-completed batch member only.
        batch_id = str(payload.get("recon_batch_id") or "")
        want_hunts = payload.get("batch_enqueue_hunts")
        if want_hunts is None:
            want_hunts = payload.get("enqueue_hunts")
        if want_hunts is None:
            want_hunts = True
        want_hunts = bool(want_hunts)

        should_finalize = False
        if batch_id:
            if want_hunts and _batch_ready_to_finalize(db, batch_id, task.id):
                should_finalize = _claim_batch_finalize(db, batch_id)
        else:
            should_finalize = want_hunts and bool(
                payload.get("enqueue_hunts")
                if payload.get("enqueue_hunts") is not None
                else True
            )

        hunt_enqueued = 0
        hunt_plan_source = "skipped" if not should_finalize else "pending"
        if should_finalize and want_hunts:
            # Re-read full merged map after batch siblings
            arch = db.get_architecture() or arch
            tasks, hunt_plan_source = plan_hunt_tasks(arch, inventory, cfg)
            if not tasks:
                # Only fail the finalizer hard when this is a non-batch recon;
                # batch members already contributed architecture.
                if not batch_id:
                    return _failed_task_result(
                        task,
                        db,
                        cfg,
                        run_dir,
                        "no_hunt_tasks",
                        model_id=model_id,
                        hunt_plan_source=hunt_plan_source,
                        recon_agents_run=agents_run,
                    )
                hunt_plan_source = hunt_plan_source or "no_hunt_tasks"
            else:
                for t in tasks:
                    t["seed_sinks"] = filter_sinks_for_paths(
                        seed_sinks,
                        t.get("path_hints") or [],
                        top_k=int((cfg.get("packet") or {}).get("max_seed_sinks", 12)),
                    )
                    if payload.get("operator_requested"):
                        t["operator_requested"] = True
                        if operator_brief:
                            t["operator_notes"] = (
                                f"From refined recon: {operator_brief[:500]}"
                            )
                    db.enqueue_task("hunt", t, priority=50)
                    db.upsert_coverage_fact(
                        t.get("area", "app"),
                        t.get("class", "wildcard"),
                        path=(t.get("path_hints") or [""])[0],
                        visit_delta=0,
                    )
                hunt_enqueued = len(tasks)

        # Optional: enqueue dynamic skill authoring once (with hunt finalize)
        dynamic_skills = bool(payload.get("dynamic_skills"))
        dynamic_skill_count = 0
        generate_run_skills_task_id = None
        if should_finalize and dynamic_skills:
            from vulnforge.hunt_profiles.generate import clamp_skill_count

            dynamic_skill_count = clamp_skill_count(
                payload.get("dynamic_skill_count") or 3
            )
            try:
                kinds = sink_kinds_present(seed_sinks)
                sink_kinds = list(kinds)[:24] if kinds else []
            except Exception:
                sink_kinds = []
            inv_signals = {
                "extensions": inventory.get("extensions"),
                "file_count": inventory.get("file_count"),
                "entrypoints": inventory.get("entrypoints"),
                "dir_partitions": (inventory.get("dir_partitions") or [])[:20],
                "sink_kinds": sink_kinds,
            }
            arch = db.get_architecture() or arch
            gen_payload = {
                "count": dynamic_skill_count,
                "architecture": {
                    k: arch.get(k)
                    for k in (
                        "summary",
                        "trust_boundaries",
                        "components",
                        "input_surfaces",
                        "hunt_focus",
                        "inventory",
                        "seed_sinks",
                        "operator_notes_applied",
                    )
                    if arch.get(k) is not None
                },
                "signals": inv_signals,
                "operator_brief": operator_brief,
                "operator_notes": operator_brief,
                "enqueue_hunts": True,
                "activate": bool(payload.get("dynamic_skills_activate")),
                "reason": "dynamic_skills_init",
            }
            arch_snap = gen_payload["architecture"]
            if isinstance(arch_snap.get("seed_sinks"), list):
                arch_snap["seed_sinks"] = arch_snap["seed_sinks"][:80]
            try:
                generate_run_skills_task_id = db.enqueue_task(
                    "generate_run_skills", gen_payload, priority=20
                )
            except Exception:
                generate_run_skills_task_id = None

        flush_notes_to_db(ctx, db)
        _ = last_result  # last LLM result retained for debugging
        result_out: dict[str, Any] = {
            "status": "succeeded",
            "hunt_enqueued": hunt_enqueued,
            "hunt_plan_source": hunt_plan_source,
            "model_id": model_id,
            "file_count": inventory["file_count"],
            "operator_requested": bool(payload.get("operator_requested")),
            "enqueue_hunts": bool(should_finalize and want_hunts),
            "recon_agents_run": agents_run,
            "recon_batch_id": batch_id or None,
            "recon_batch_index": payload.get("recon_batch_index"),
            "recon_batch_size": payload.get("recon_batch_size"),
            "batch_finalized": bool(should_finalize),
            "fanout_task_ids": fanout_task_ids or None,
            "dynamic_skills": dynamic_skills,
            "dynamic_skill_count": dynamic_skill_count if dynamic_skills else 0,
            "generate_run_skills_task_id": generate_run_skills_task_id,
            "transcript": f"task-{task.id}",
            **usage_fields,
        }
        return result_out
    finally:
        client.close()


def _merge_usage_fields(acc: dict[str, Any], more: dict[str, Any]) -> dict[str, Any]:
    """Accumulate numeric usage counters across sequential agent passes."""
    if not acc:
        return dict(more or {})
    out = dict(acc)
    for k, v in (more or {}).items():
        if isinstance(v, (int, float)) and isinstance(out.get(k), (int, float)):
            out[k] = out[k] + v
        else:
            out[k] = v
    return out


def merge_architectures(
    parts: list[dict[str, Any]],
    *,
    agents_run: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Merge sequential recon agent architecture dicts.

    - List fields: deep-merge (append unique items; dict items by stable key).
    - summary: last non-empty wins.
    - recon_agents_run metadata attached when provided.
    """
    list_fields = (
        "trust_boundaries",
        "components",
        "input_surfaces",
        "hunt_focus",
    )
    summary = ""
    merged_lists: dict[str, list] = {f: [] for f in list_fields}
    seen: dict[str, set[str]] = {f: set() for f in list_fields}

    for part in parts:
        if not isinstance(part, dict):
            continue
        s = str(part.get("summary") or "").strip()
        if s:
            summary = s
        for f in list_fields:
            items = part.get(f)
            if not isinstance(items, list):
                continue
            for item in items:
                key = _arch_item_key(item)
                if key in seen[f]:
                    # Prefer later dict over earlier for same key
                    if isinstance(item, dict):
                        for i, prev in enumerate(merged_lists[f]):
                            if _arch_item_key(prev) == key:
                                merged_lists[f][i] = item
                                break
                    continue
                seen[f].add(key)
                merged_lists[f].append(item)

    out: dict[str, Any] = {
        "summary": summary,
        "trust_boundaries": merged_lists["trust_boundaries"],
        "components": merged_lists["components"],
        "input_surfaces": merged_lists["input_surfaces"],
        "hunt_focus": merged_lists["hunt_focus"],
    }
    if agents_run is not None:
        out["recon_agents_run"] = list(agents_run)
    return out


def _arch_item_key(item: object) -> str:
    if isinstance(item, str):
        return "s:" + item.strip().lower()
    if isinstance(item, dict):
        for k in ("name", "area", "id", "path"):
            if item.get(k):
                extra = ""
                if k == "area" and item.get("class"):
                    extra = "|" + str(item.get("class")).strip().lower()
                return f"d:{k}:{str(item.get(k)).strip().lower()}{extra}"
        try:
            return "j:" + json.dumps(item, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return "r:" + repr(item)
    return "r:" + repr(item)


def _coerce_list_field(value: object) -> list:
    """Normalize architecture list fields.

    Local models often double-encode arrays as JSON strings. Try one json.loads;
    never invent structure via bracket repair. Non-list / bad JSON â†’ [].
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        if s[0] in "[{":
            try:
                parsed = json.loads(s)
            except (json.JSONDecodeError, TypeError, ValueError):
                return []
            if isinstance(parsed, list):
                return parsed
        return []
    return []


def parse_architecture(llm_result, session: dict) -> dict:
    if session.get("architecture"):
        a = session["architecture"]
        return {
            "summary": a.get("summary") or "",
            "trust_boundaries": _coerce_list_field(a.get("trust_boundaries")),
            "components": _coerce_list_field(a.get("components")),
            "input_surfaces": _coerce_list_field(a.get("input_surfaces")),
            "hunt_focus": _coerce_list_field(a.get("hunt_focus")),
        }
    # try JSON block in content
    content = llm_result.content or ""
    try:
        start = content.find("{")
        end = content.rfind("}")
        if start >= 0 and end > start:
            data = json.loads(content[start : end + 1])
            if isinstance(data, dict) and data.get("summary"):
                return {
                    "summary": data.get("summary") or "",
                    "trust_boundaries": _coerce_list_field(data.get("trust_boundaries")),
                    "components": _coerce_list_field(data.get("components")),
                    "input_surfaces": _coerce_list_field(data.get("input_surfaces")),
                    "hunt_focus": _coerce_list_field(data.get("hunt_focus")),
                }
    except json.JSONDecodeError:
        pass
    return {
        "summary": "",
        "trust_boundaries": [],
        "components": [],
        "input_surfaces": [],
        "hunt_focus": [],
    }


def _normalize_class(raw: object) -> str:
    """Map recon class ids onto registered hunt skills; unknown → wildcard."""
    return normalize_class(raw)


def partition_by_top_dir(sample_paths: list[str], top_n: int = 12) -> list[dict]:
    """P2.2: package/dir partition + size rank for monorepo enqueue caps."""
    counts: dict[str, int] = defaultdict(int)
    for p in sample_paths:
        rel = normalize_relpath(str(p))
        parts = rel.split("/")
        top = parts[0] if len(parts) > 1 else "."
        counts[top] += 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]
    return [{"dir": d, "file_count": n} for d, n in ranked]


def _fallback_hunt_tasks(
    architecture: dict,
    inventory: dict,
    cfg: Optional[dict] = None,
) -> list[dict]:
    """Allowed hunt skills × areas when model focus is missing or unusable.

    Class set comes from run hunt_skill_mode (default all_active). Empty
    allowlist yields zero tasks (custom_only with no customs is OK).
    """
    components = architecture.get("components") or []
    if not isinstance(components, list):
        components = []
    areas = [c.get("name") for c in components if isinstance(c, dict) and c.get("name")]
    area_hints: dict[str, list[str]] = {}
    for c in components:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        ph = c.get("path_hints") or []
        if isinstance(ph, list) and ph:
            area_hints[str(c["name"])] = [normalize_relpath(str(x)) for x in ph if x]

    # P2.2: when components vague, use size-ranked dir partitions
    partitions = inventory.get("dir_partitions") or partition_by_top_dir(
        inventory.get("sample_paths") or []
    )
    if not areas:
        if partitions:
            areas = [p["dir"] for p in partitions[:6] if p.get("dir")]
        else:
            areas = ["app"]

    default_hints = inventory.get("entrypoints") or inventory.get("sample_paths", [])[:10]
    mode, skill_ids = skill_policy_from_run_cfg(cfg or {})
    use_classes = resolve_run_class_ids(mode, skill_ids)
    if not use_classes:
        return []
    tasks: list[dict] = []
    # Cap areas for monorepos (H3b: tests/test_mono_synth_plan.py)
    max_areas = 6 if (inventory.get("file_count") or 0) > 200 else 8
    for area in areas[:max_areas]:
        hints = area_hints.get(str(area)) or list(default_hints)
        # Prefer files under partition dir when area matches a top dir
        if area and area != "app" and area != ".":
            under = [
                p
                for p in (inventory.get("sample_paths") or [])
                if normalize_relpath(p) == area
                or normalize_relpath(p).startswith(str(area).rstrip("/") + "/")
            ][:12]
            if under:
                hints = under
        for cls in use_classes:
            tasks.append(
                {
                    "area": area,
                    "class": cls,
                    "path_hints": hints[:15],
                }
            )
    return tasks


def _normalize_path_hints(raw: object, inventory: dict) -> list[str]:
    if isinstance(raw, list):
        out = [normalize_relpath(str(x)) for x in raw if x]
        if out:
            return out[:15]
    return list(
        inventory.get("entrypoints")
        or inventory.get("sample_paths", [])[:5]
    )


def _apply_class_routing(tasks: list[dict], inventory: dict) -> list[dict]:
    """P2.3: avoid dual-enqueue injection+ai-llm on same paths without both sink families."""
    sinks = inventory.get("seed_sinks") or []
    # Group by frozenset of path hints
    by_paths: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for t in tasks:
        key = tuple(sorted(normalize_relpath(str(p)) for p in (t.get("path_hints") or []) if p))
        by_paths[key].append(t)

    drop: set[int] = set()
    for _paths, group in by_paths.items():
        classes = {t.get("class") for t in group}
        if "injection" in classes and "ai-llm" in classes:
            kinds = sink_kinds_present(sinks, list(_paths) if _paths else None)
            has_inj = class_has_sink_family("injection", kinds)
            has_llm = class_has_sink_family("ai-llm", kinds)
            # If only one family present, drop the other class
            if has_inj and not has_llm:
                for t in group:
                    if t.get("class") == "ai-llm":
                        drop.add(id(t))
            elif has_llm and not has_inj:
                for t in group:
                    if t.get("class") == "injection":
                        drop.add(id(t))
            elif not has_inj and not has_llm:
                # Prefer injection for generic code; drop ai-llm without llm sinks
                for t in group:
                    if t.get("class") == "ai-llm":
                        drop.add(id(t))
    if not drop:
        return tasks
    return [t for t in tasks if id(t) not in drop]


def plan_hunt_tasks(
    architecture: dict, inventory: dict, cfg: dict
) -> tuple[list[dict], str]:
    """Plan hunt tasks from recon architecture.

    Returns (tasks, hunt_plan_source) where source is ``hunt_focus`` or
    ``active_fallback``. Non-list / garbage focus never blocks active-set
    fallback (local models often string-encode nested arrays).

    Run ``hunt_skill_mode`` / ``hunt_skill_ids`` (cfg.run) restrict allowed
    class ids. hunt_focus entries outside the allowlist are dropped; empty
    allowlist yields zero tasks (including fallback).
    """
    max_tasks = int((cfg.get("run") or {}).get("max_tasks", 50))
    mode, skill_ids = skill_policy_from_run_cfg(cfg)
    # Fallback / bulk set (active under all_active; filtered for other modes).
    allowed = resolve_run_class_ids(mode, skill_ids)
    # hunt_focus allowlist: default mode may include inactive registered classes
    # (optional packs in the registry). Restricted modes use the same resolve set.
    if mode == "all_active":
        focus_allow = set(all_class_ids())
    else:
        focus_allow = set(allowed)
    raw_focus = architecture.get("hunt_focus")
    # Only a real list can enter the focus branch (truthy strings must not).
    focus = raw_focus if isinstance(raw_focus, list) else []
    tasks: list[dict] = []
    source = "active_fallback"
    if focus and (focus_allow or mode == "all_active"):
        for f in focus:
            if not isinstance(f, dict):
                continue
            raw_cls = f.get("class")
            # Map aliases onto registered ids, then enforce allowlist.
            # Unknown ids must not slip in via normalize→wildcard unless wildcard
            # is itself allowed for this run.
            cls = _normalize_class(raw_cls)
            if focus_allow and cls not in focus_allow:
                # Retry: if raw maps via alias to an allowed id without
                # wildcard fallback, keep it.
                from vulnforge.hunt_profiles.store import CLASS_ALIASES

                raw_s = str(raw_cls or "").strip().lower().replace("_", "-").replace(" ", "-")
                alt = CLASS_ALIASES.get(raw_s, raw_s)
                if alt in focus_allow:
                    cls = alt
                else:
                    continue
            if not focus_allow and mode != "all_active":
                continue
            tasks.append(
                {
                    "area": f.get("area") or "app",
                    "class": cls,
                    "path_hints": _normalize_path_hints(f.get("path_hints"), inventory),
                }
            )
        if tasks:
            source = "hunt_focus"
    if not tasks:
        # No usable focus → allowed hunt skills only (not full catalog).
        # Empty allowlist → zero tasks.
        tasks = _fallback_hunt_tasks(architecture, inventory, cfg)
        source = "active_fallback"
    tasks = _apply_class_routing(tasks, inventory)
    # Honor operator run.max_tasks only (no monorepo hard-cap override).
    max_tasks = max(0, int(max_tasks))
    return tasks[:max_tasks], source


def detect_profile_mismatch(inventory: dict, profile: str) -> str | None:
    from vulnforge.profiles import get_profile

    try:
        p = get_profile(profile)
        return p.validate_target_hint(inventory)
    except Exception:
        return None
