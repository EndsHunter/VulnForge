"""Home (fleet) operator-chat tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vulnforge.operator_chat.tools_common import (
    MUTATE_TOOLS,
    enqueue_hunt_impl,
    explain_product_impl,
    get_coverage_summary_impl,
    get_finding_impl,
    get_hunt_impl,
    get_project_excerpt_impl,
    get_status_impl,
    get_tool_gaps_summary_impl,
    list_findings_all_impl,
    list_hunt_profiles_impl,
    list_hunts_all_impl,
    list_hunts_impl,
    list_runs_impl,
    open_finding_impl,
    open_run_impl,
    openai_tool,
    query_hunts_impl,
    read_evidence_impl,
    requeue_hunt_impl,
    requeue_hunts_bulk_impl,
    resolve_run_dir,
    rollup_results_impl,
    runner_action,
    search_results_impl,
)
from vulnforge.ui.store import RunRef

_RUN_ID_PROPS = {
    "target_id": {"type": "string", "description": "Target id (runs/<target_id>/...)"},
    "run_id": {"type": "string", "description": "Run id (e.g. run-001)"},
}


def schemas() -> list[dict]:
    return [
        openai_tool(
            "list_runs",
            "List audit runs with task/finding summaries and runner alive flag.",
            {
                "filter": {
                    "type": "string",
                    "description": "all | running | incomplete | idle",
                },
                "limit": {"type": "integer"},
            },
        ),
        openai_tool(
            "get_run_summary",
            "Status card + runner for one run.",
            _RUN_ID_PROPS,
            ["target_id", "run_id"],
        ),
        openai_tool(
            "get_runner_status",
            "Ralph runner process status for one run.",
            _RUN_ID_PROPS,
            ["target_id", "run_id"],
        ),
        openai_tool(
            "list_findings_all",
            "Query findings across all runs (or filter by target/run/state/class/text).",
            {
                **_RUN_ID_PROPS,
                "state": {"type": "string", "description": "e.g. needs_human, confirmed, candidate"},
                "class": {"type": "string"},
                "q": {"type": "string", "description": "Text match on title/summary"},
                "limit": {"type": "integer"},
                "max_runs": {"type": "integer"},
            },
        ),
        openai_tool(
            "get_finding",
            "Get one finding body (truncated) by run + finding_id.",
            {**_RUN_ID_PROPS, "finding_id": {"type": "integer"}},
            ["target_id", "run_id", "finding_id"],
        ),
        openai_tool(
            "read_evidence",
            "Read an evidence pack file for a run (capped).",
            {
                **_RUN_ID_PROPS,
                "pack_id": {"type": "string"},
                "relpath": {"type": "string", "description": "Default evidence.md"},
            },
            ["target_id", "run_id", "pack_id"],
        ),
        openai_tool(
            "search_results",
            "Fleet search across findings and hunts by free text.",
            {"q": {"type": "string"}, "limit": {"type": "integer"}},
            ["q"],
        ),
        openai_tool(
            "rollup_results",
            "Per-run rollup: findings counts, tasks, coverage depths, runner alive.",
            {"max_runs": {"type": "integer"}},
        ),
        openai_tool(
            "get_coverage_summary",
            "Coverage residual cells for one run (or set all_runs=true for fleet skim).",
            {
                **_RUN_ID_PROPS,
                "all_runs": {"type": "boolean"},
                "limit": {"type": "integer"},
            },
        ),
        openai_tool(
            "get_project_excerpt",
            "Read project/REPORT.md or STATE.md excerpt for a run.",
            {
                **_RUN_ID_PROPS,
                "name": {"type": "string", "description": "REPORT|STATE|CODEMAP|ARCHITECTURE"},
            },
            ["target_id", "run_id"],
        ),
        openai_tool(
            "list_hunt_profiles",
            "List available hunt skill class ids for enqueue.",
            {},
        ),
        openai_tool(
            "list_hunts",
            "List hunt tasks for one run.",
            {
                **_RUN_ID_PROPS,
                "state": {"type": "string"},
                "class": {"type": "string"},
                "area": {"type": "string"},
                "limit": {"type": "integer"},
            },
            ["target_id", "run_id"],
        ),
        openai_tool(
            "list_hunts_all",
            "List/filter hunt tasks across runs.",
            {
                **_RUN_ID_PROPS,
                "state": {"type": "string"},
                "class": {"type": "string"},
                "limit": {"type": "integer"},
                "max_runs": {"type": "integer"},
            },
        ),
        openai_tool(
            "get_hunt",
            "Get one hunt (or task) outcome + transcript brief.",
            {**_RUN_ID_PROPS, "task_id": {"type": "integer"}},
            ["target_id", "run_id", "task_id"],
        ),
        openai_tool(
            "query_hunts",
            "Query hunts on one run by text or residual signals.",
            {
                **_RUN_ID_PROPS,
                "q": {"type": "string"},
                "residual_only": {"type": "boolean"},
                "limit": {"type": "integer"},
            },
            ["target_id", "run_id"],
        ),
        openai_tool(
            "enqueue_hunt",
            "Enqueue a hunt on a run (confirm required). Prefer class + area and/or paths.",
            {
                **_RUN_ID_PROPS,
                "class": {"type": "string"},
                "area": {"type": "string"},
                "paths": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
                "force_depth": {"type": "boolean"},
            },
            ["target_id", "run_id", "class"],
        ),
        openai_tool(
            "requeue_hunt",
            "Requeue one coverage cell area×class (confirm required).",
            {
                **_RUN_ID_PROPS,
                "area": {"type": "string"},
                "class": {"type": "string"},
                "path_hints": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
            },
            ["target_id", "run_id", "area", "class"],
        ),
        openai_tool(
            "requeue_hunts_bulk",
            "Bulk requeue cells: [{area, class, path_hints?}...] (confirm required).",
            {
                **_RUN_ID_PROPS,
                "cells": {"type": "array", "items": {"type": "object"}},
                "notes": {"type": "string"},
            },
            ["target_id", "run_id", "cells"],
        ),
        openai_tool(
            "start_run",
            "Start Ralph outer loop for a run (confirm required).",
            {
                **_RUN_ID_PROPS,
                "workers": {"type": "integer"},
                "max_tasks": {"type": "integer"},
                "task_timeout": {"type": "number"},
            },
            ["target_id", "run_id"],
        ),
        openai_tool(
            "pause_run",
            "Pause Ralph after current task (STOP file) (confirm required).",
            _RUN_ID_PROPS,
            ["target_id", "run_id"],
        ),
        openai_tool(
            "resume_run",
            "Resume Ralph (confirm required).",
            {**_RUN_ID_PROPS, "workers": {"type": "integer"}, "max_tasks": {"type": "integer"}},
            ["target_id", "run_id"],
        ),
        openai_tool(
            "hard_stop_run",
            "Hard-stop Ralph process tree (confirm required).",
            _RUN_ID_PROPS,
            ["target_id", "run_id"],
        ),
        openai_tool(
            "init_run",
            "Create a new audit run for a source directory or single source file "
            "(confirm required). Source-code analysis only (code_static). Optional start Ralph.",
            {
                "target": {
                    "type": "string",
                    "description": "Absolute path to source codebase directory or source file",
                },
                "strategy": {
                    "type": "string",
                    "description": "discovery | file_by_file | recon_docs",
                },
                "operator_notes": {"type": "string"},
                "start": {"type": "boolean", "description": "Start Ralph after init"},
                "enqueue_hunts": {"type": "boolean"},
                "profile": {
                    "type": "string",
                    "description": "code_static (default; only supported profile)",
                },
            },
            ["target"],
        ),
        openai_tool(
            "poll_init_job",
            "Poll async init job status by job_id.",
            {"job_id": {"type": "string"}},
            ["job_id"],
        ),
        openai_tool(
            "get_tool_gaps_summary",
            "Tool capability gaps rollup or for one run.",
            {**_RUN_ID_PROPS},
        ),
        openai_tool("explain_product", "Short VulnForge product handbook.", {}),
        openai_tool(
            "open_run",
            "Return dashboard URL to open a run (UI may navigate).",
            {**_RUN_ID_PROPS, "hash": {"type": "string"}},
            ["target_id", "run_id"],
        ),
        openai_tool(
            "open_finding",
            "Return URL to open a finding's run Report.",
            {**_RUN_ID_PROPS, "finding_id": {"type": "integer"}},
            ["target_id", "run_id", "finding_id"],
        ),
    ]


def dispatch(
    name: str,
    args: dict[str, Any],
    *,
    runs_root: Path,
    project_root: Path,
    execute_mutations: bool = False,
) -> dict[str, Any]:
    args = dict(args or {})

    if name in MUTATE_TOOLS and not execute_mutations:
        return {
            "ok": False,
            "pending_confirm": True,
            "tool_name": name,
            "arguments": args,
        }

    if name == "list_runs":
        return list_runs_impl(runs_root, args)
    if name == "list_findings_all":
        return list_findings_all_impl(runs_root, args)
    if name == "search_results":
        return search_results_impl(runs_root, args)
    if name == "rollup_results":
        return rollup_results_impl(runs_root, args)
    if name == "list_hunts_all":
        return list_hunts_all_impl(runs_root, args)
    if name == "list_hunt_profiles":
        return list_hunt_profiles_impl(args)
    if name == "explain_product":
        return explain_product_impl(args)
    if name == "open_run":
        return open_run_impl(args)
    if name == "open_finding":
        return open_finding_impl(args)
    if name == "get_tool_gaps_summary":
        return get_tool_gaps_summary_impl(runs_root, args)
    if name == "poll_init_job":
        from vulnforge.init_progress import read_job

        job = read_job(project_root, str(args.get("job_id") or ""))
        return {"ok": bool(job), "job": job}
    if name == "init_run":
        return _init_run(args, runs_root=runs_root, project_root=project_root)

    # run-scoped
    if name == "get_coverage_summary" and args.get("all_runs"):
        # skim fleet
        from vulnforge.ui.store import discover_runs

        rows = []
        for ref in discover_runs(runs_root)[:25]:
            rows.append(get_coverage_summary_impl(ref, args))
        return {"ok": True, "runs": rows}

    run, err = resolve_run_dir(runs_root, args)
    if err or not run:
        return {"ok": False, "error": err or "run not found"}

    if name == "get_run_summary" or name == "get_status":
        return get_status_impl(run, args)
    if name == "get_runner_status":
        from vulnforge.ui import runner as runctl

        return {"ok": True, "runner": runctl.runner_status(run.path), **_ids(run)}
    if name == "get_finding":
        return get_finding_impl(run, args)
    if name == "read_evidence":
        return read_evidence_impl(run, args)
    if name == "get_coverage_summary":
        return get_coverage_summary_impl(run, args)
    if name == "get_project_excerpt":
        return get_project_excerpt_impl(run, args)
    if name == "list_hunts":
        return list_hunts_impl(run, args)
    if name == "get_hunt":
        return get_hunt_impl(run, args)
    if name == "query_hunts":
        return query_hunts_impl(run, args)
    if name == "enqueue_hunt":
        return enqueue_hunt_impl(run, args)
    if name == "requeue_hunt":
        return requeue_hunt_impl(run, args)
    if name == "requeue_hunts_bulk":
        return requeue_hunts_bulk_impl(run, args)
    if name in ("start_run", "pause_run", "resume_run", "hard_stop_run"):
        return runner_action(run, name, args)

    return {"ok": False, "error": f"unknown tool: {name}"}


def _ids(run: RunRef) -> dict[str, str]:
    return {"target_id": run.target_id, "run_id": run.run_id}


def _init_run(args: dict, *, runs_root: Path, project_root: Path) -> dict[str, Any]:
    """Synchronous init for chat confirm path (blocking)."""
    from vulnforge.cli import cmd_init, load_config

    from vulnforge.util import is_pe_file

    target = Path(str(args.get("target") or ""))
    if not target.exists():
        return {"ok": False, "error": f"target not found: {target}"}
    profile = str(args.get("profile") or "code_static").strip().lower() or "code_static"
    if is_pe_file(target):
        return {
            "ok": False,
            "error": f"PE binaries are not supported (source analysis only): {target}",
        }
    if not target.is_dir() and not target.is_file():
        return {
            "ok": False,
            "error": f"target must be a directory or a single file: {target}",
        }

    class Args:
        pass

    a = Args()
    a.target = target
    a.profile = profile
    a.runs_root = runs_root
    a.strategy = str(args.get("strategy") or "discovery").strip().lower()
    a.docs_path = Path(args["docs_path"]) if args.get("docs_path") else None
    a.agent_ids = None
    a.operator_notes = str(args.get("operator_notes") or "")[:6000]
    a.dynamic_skills = bool(args.get("dynamic_skills") or False)
    a.dynamic_skill_count = int(args.get("dynamic_skill_count") or 3)
    a.hunt_skill_mode = str(args.get("hunt_skill_mode") or "all_active")
    a.hunt_skill_ids = None
    a.enqueue_hunts = bool(args.get("enqueue_hunts", True))
    a.progress = None
    a.job_id = None

    cfg = load_config()
    try:
        code = cmd_init(a, cfg)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    if code != 0:
        return {"ok": False, "error": f"init exit {code}"}

    # Discover run that matches this target path (never pick an unrelated newest run).
    from vulnforge.ui.store import discover_runs

    chosen: Optional[RunRef] = None
    try:
        target_resolved = target.resolve()
    except OSError:
        target_resolved = target
    for r in discover_runs(runs_root)[:30]:
        try:
            from vulnforge.operator_chat.tools_common import _open_db

            db = _open_db(r.path)
            try:
                row = db.get_run()
                tp = str(row["target_path"] if row else "")
            finally:
                db.close()
            if not tp:
                continue
            try:
                tp_path = Path(tp).resolve()
            except OSError:
                tp_path = Path(tp)
            if tp_path == target_resolved:
                chosen = r
                break
        except Exception:
            continue

    out: dict[str, Any] = {"ok": True, "init_exit": code}
    if chosen:
        out["target_id"] = chosen.target_id
        out["run_id"] = chosen.run_id
        out["url"] = f"/runs/{chosen.target_id}/{chosen.run_id}"
        if args.get("start"):
            out["start"] = runner_action(chosen, "start_run", args)
    else:
        # Init succeeded but we could not locate the new run by target path —
        # refuse wrong-run fallback (do not return newest unrelated run).
        out["warning"] = "init_ok_but_run_not_located_by_target_path"
    return out
