"""Run-scoped operator-chat tools (bound run_dir)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.operator_chat.tools_common import (
    MUTATE_TOOLS,
    browse_target_impl,
    enqueue_hunt_impl,
    explain_product_impl,
    get_architecture_impl,
    get_coverage_summary_impl,
    get_finding_impl,
    get_hunt_impl,
    get_project_excerpt_impl,
    get_status_impl,
    list_events_impl,
    list_findings_impl,
    list_hunt_profiles_impl,
    list_hunts_impl,
    list_tasks_impl,
    openai_tool,
    query_hunts_impl,
    read_evidence_impl,
    read_target_file_impl,
    requeue_hunt_impl,
    requeue_hunts_bulk_impl,
    runner_action,
)
from vulnforge.ui.store import RunRef


def schemas() -> list[dict]:
    return [
        openai_tool("get_status", "Runner + task/finding summary for this run.", {}),
        openai_tool(
            "list_tasks",
            "List tasks (any kind). Prefer list_hunts for hunts only.",
            {
                "kind": {"type": "string"},
                "state": {"type": "string"},
                "limit": {"type": "integer"},
            },
        ),
        openai_tool("list_hunt_profiles", "Available hunt class ids.", {}),
        openai_tool(
            "list_hunts",
            "List hunt tasks for this run.",
            {
                "state": {"type": "string"},
                "class": {"type": "string"},
                "area": {"type": "string"},
                "limit": {"type": "integer"},
            },
        ),
        openai_tool(
            "get_hunt",
            "One task outcome + transcript brief.",
            {"task_id": {"type": "integer"}, "allow_any_kind": {"type": "boolean"}},
            ["task_id"],
        ),
        openai_tool(
            "query_hunts",
            "Filter hunts by text or residual signals.",
            {
                "q": {"type": "string"},
                "residual_only": {"type": "boolean"},
                "limit": {"type": "integer"},
            },
        ),
        openai_tool(
            "enqueue_hunt",
            "Enqueue a hunt (confirm). class + area and/or paths.",
            {
                "class": {"type": "string"},
                "area": {"type": "string"},
                "paths": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
                "force_depth": {"type": "boolean"},
            },
            ["class"],
        ),
        openai_tool(
            "requeue_hunt",
            "Requeue one area×class cell (confirm).",
            {
                "area": {"type": "string"},
                "class": {"type": "string"},
                "path_hints": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
            },
            ["area", "class"],
        ),
        openai_tool(
            "requeue_hunts_bulk",
            "Bulk requeue cells (confirm).",
            {
                "cells": {"type": "array", "items": {"type": "object"}},
                "notes": {"type": "string"},
            },
            ["cells"],
        ),
        openai_tool(
            "list_findings",
            "List findings for this run.",
            {
                "state": {"type": "string"},
                "class": {"type": "string"},
                "q": {"type": "string"},
                "limit": {"type": "integer"},
            },
        ),
        openai_tool(
            "get_finding",
            "Get one finding.",
            {"finding_id": {"type": "integer"}},
            ["finding_id"],
        ),
        openai_tool(
            "read_evidence",
            "Read evidence pack file.",
            {"pack_id": {"type": "string"}, "relpath": {"type": "string"}},
            ["pack_id"],
        ),
        openai_tool("get_architecture", "Architecture map summary for this run.", {}),
        openai_tool(
            "get_coverage_summary",
            "Residual coverage cells.",
            {"limit": {"type": "integer"}},
        ),
        openai_tool(
            "get_project_excerpt",
            "project/REPORT|STATE|CODEMAP excerpt.",
            {"name": {"type": "string"}},
        ),
        openai_tool("list_events", "Tail events.jsonl.", {"limit": {"type": "integer"}}),
        openai_tool(
            "browse_target",
            "List directory under target tree (read-only).",
            {"path": {"type": "string"}},
        ),
        openai_tool(
            "read_target_file",
            "Read a target file slice (read-only).",
            {
                "path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            ["path"],
        ),
        openai_tool(
            "start_run",
            "Start Ralph (confirm).",
            {
                "workers": {"type": "integer"},
                "max_tasks": {"type": "integer"},
                "task_timeout": {"type": "number"},
            },
        ),
        openai_tool("pause_run", "Pause Ralph (confirm).", {}),
        openai_tool(
            "resume_run",
            "Resume Ralph (confirm).",
            {"workers": {"type": "integer"}, "max_tasks": {"type": "integer"}},
        ),
        openai_tool("hard_stop_run", "Hard-stop Ralph (confirm).", {}),
        openai_tool("explain_product", "Short product handbook.", {}),
    ]


def dispatch(
    name: str,
    args: dict[str, Any],
    *,
    run: RunRef,
    execute_mutations: bool = False,
) -> dict[str, Any]:
    args = dict(args or {})
    # inject identity for mutation summaries
    args.setdefault("target_id", run.target_id)
    args.setdefault("run_id", run.run_id)

    if name in MUTATE_TOOLS and not execute_mutations:
        return {
            "ok": False,
            "pending_confirm": True,
            "tool_name": name,
            "arguments": args,
        }

    if name == "get_status":
        return get_status_impl(run, args)
    if name == "list_tasks":
        return list_tasks_impl(run, args)
    if name == "list_hunt_profiles":
        return list_hunt_profiles_impl(args)
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
    if name == "list_findings":
        return list_findings_impl(run, args)
    if name == "get_finding":
        return get_finding_impl(run, args)
    if name == "read_evidence":
        return read_evidence_impl(run, args)
    if name == "get_architecture":
        return get_architecture_impl(run, args)
    if name == "get_coverage_summary":
        return get_coverage_summary_impl(run, args)
    if name == "get_project_excerpt":
        return get_project_excerpt_impl(run, args)
    if name == "list_events":
        return list_events_impl(run, args)
    if name == "browse_target":
        return browse_target_impl(run, args)
    if name == "read_target_file":
        return read_target_file_impl(run, args)
    if name in ("start_run", "pause_run", "resume_run", "hard_stop_run"):
        return runner_action(run, name, args)
    if name == "explain_product":
        return explain_product_impl(args)
    return {"ok": False, "error": f"unknown tool: {name}"}
