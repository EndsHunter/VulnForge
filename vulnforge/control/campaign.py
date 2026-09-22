"""Campaign control grammar.

Seven verbs — start, stop, pause, resume, status, findings, gate — are clients
of the existing Ralph runner (``scripts/ralph.py`` → ``vf run-once``) and of
durable ``harness.db`` / HITL state. This module does not spawn its own loop.
"""

from __future__ import annotations

from typing import Any, Optional

from vulnforge.db import Database
from vulnforge.operator_chat.tools_common import get_status_impl, list_findings_impl
from vulnforge.ui import runner as runctl
from vulnforge.ui.store import RunRef
from vulnforge.util import append_event

SCHEMA = "vulnforge.campaign@1"

VERBS = ("start", "stop", "pause", "resume", "status", "findings", "gate")
READ_VERBS = frozenset({"status", "findings", "gate"})
MUTATE_VERBS = frozenset({"start", "stop", "pause", "resume"})

_START_KEYS = (
    "task_timeout",
    "max_tasks",
    "max_iterations",
    "max_wall_seconds",
    "workers",
    "loop_profile_id",
    "config",
)

# Static contract. ``wires`` is the existing function each verb calls.
_SPECS: tuple[dict[str, Any], ...] = (
    {
        "verb": "start",
        "http": "POST",
        "mutates": True,
        "wires": "vulnforge.ui.runner.start_run",
        "legacy": "POST /api/runs/{target_id}/{run_id}/start",
        "chat": "start_run",
        "effect": (
            "Clear STOP and spawn Ralph (scripts/ralph.py → vf run-once). "
            "Same function as dashboard Start and operator chat start_run."
        ),
    },
    {
        "verb": "stop",
        "http": "POST",
        "mutates": True,
        "wires": "vulnforge.ui.runner.stop_run_hard",
        "legacy": "POST /api/runs/{target_id}/{run_id}/stop",
        "chat": "hard_stop_run",
        "effect": (
            "Hard stop: write STOP, kill Ralph workers, reclaim leased tasks "
            "to queued. Records runner_stop_hard. Leaves the run and findings in place."
        ),
    },
    {
        "verb": "pause",
        "http": "POST",
        "mutates": True,
        "wires": "vulnforge.ui.runner.pause_run",
        "legacy": "POST /api/runs/{target_id}/{run_id}/pause",
        "chat": "pause_run",
        "effect": (
            "Write STOP, kill Ralph workers, reclaim orphaned leases. "
            "Queued tasks stay queued. Runner state becomes paused."
        ),
    },
    {
        "verb": "resume",
        "http": "POST",
        "mutates": True,
        "wires": "vulnforge.ui.runner.resume_run",
        "legacy": "POST /api/runs/{target_id}/{run_id}/resume",
        "chat": "resume_run",
        "effect": (
            "Clear STOP, reclaim stale leases only, and spawn Ralph when it "
            "is not already alive (resume_run → start_run)."
        ),
    },
    {
        "verb": "status",
        "http": "GET",
        "mutates": False,
        "wires": "vulnforge.operator_chat.tools_common.get_status_impl",
        "legacy": "GET /api/runs/{target_id}/{run_id}/runner",
        "chat": "get_status",
        "effect": (
            "Read Ralph runner_status plus durable task and finding counts "
            "from harness.db. Does not lease or spawn."
        ),
    },
    {
        "verb": "findings",
        "http": "GET",
        "mutates": False,
        "wires": "vulnforge.operator_chat.tools_common.list_findings_impl",
        "legacy": "operator chat list_findings",
        "chat": "list_findings",
        "effect": (
            "Read findings from harness.db. Filters: state, class, q, limit. "
            "Does not change finding state."
        ),
    },
    {
        "verb": "gate",
        "http": "GET",
        "mutates": False,
        "wires": "vulnforge.hitl.list_inbox",
        "legacy": "GET /api/runs/{target_id}/{run_id}/hitl/inbox",
        "chat": "",
        "effect": (
            "Read the human gate: needs_human count and the awaiting-review "
            "HITL inbox. Reading never sets confirmed."
        ),
    },
)


def describe_grammar() -> dict[str, Any]:
    """Static verb map. Safe to call with no run directory."""
    return {
        "ok": True,
        "schema": SCHEMA,
        "engine": "ralph",
        "parallel_runner": False,
        "note": (
            "Each verb calls the existing Ralph runner or harness.db / HITL. "
            "Dashboard lifecycle routes and operator chat tools stay on the same functions."
        ),
        "verbs": [dict(row) for row in _SPECS],
    }


def _stamp(run: RunRef, verb: str, result: dict[str, Any]) -> dict[str, Any]:
    out = dict(result)
    out["schema"] = SCHEMA
    out["verb"] = verb
    out["engine"] = "ralph"
    out["parallel_runner"] = False
    out["target_id"] = run.target_id
    out["run_id"] = run.run_id
    return out


def _start_kwargs(args: dict[str, Any]) -> dict[str, Any]:
    return {key: args[key] for key in _START_KEYS if key in args}


def _with_http(result: dict[str, Any], code: int) -> dict[str, Any]:
    if result.get("ok"):
        return result
    out = dict(result)
    out.setdefault("http", code)
    return out


def _start(run: RunRef, args: dict[str, Any]) -> dict[str, Any]:
    return _with_http(runctl.start_run(run.path, **_start_kwargs(args)), 409)


def _stop(run: RunRef, _args: dict[str, Any]) -> dict[str, Any]:
    return _with_http(runctl.stop_run_hard(run.path), 400)


def _pause(run: RunRef, _args: dict[str, Any]) -> dict[str, Any]:
    return _with_http(runctl.pause_run(run.path), 400)


def _resume(run: RunRef, args: dict[str, Any]) -> dict[str, Any]:
    return _with_http(runctl.resume_run(run.path, **_start_kwargs(args)), 409)


def _status(run: RunRef, _args: dict[str, Any]) -> dict[str, Any]:
    base = get_status_impl(run, {})
    db = Database.open(run.path / "harness.db")
    try:
        summary = db.summary()
        leased = db.count_leased_tasks()
    finally:
        db.close()
    base["harness"] = {
        "db": "harness.db",
        "tasks": summary.get("tasks") or {},
        "findings": summary.get("findings") or {},
        "has_work": bool(summary.get("has_work")),
        "leased": int(leased or 0),
    }
    return base


def _findings(run: RunRef, args: dict[str, Any]) -> dict[str, Any]:
    return list_findings_impl(run, args)


def _gate(run: RunRef, _args: dict[str, Any]) -> dict[str, Any]:
    """Read HITL inbox. Same projection refresh as the inbox route; no review write."""
    from vulnforge.hitl import list_inbox, open_for_run

    db = open_for_run(run.path)
    try:
        before = {row.id: row.state for row in db.list_findings()}
        inbox = list_inbox(db, run.path)
        after = {row.id: row.state for row in db.list_findings()}
        counts = db.count_findings_by_state()
    finally:
        db.close()
    if before != after:
        return {
            "ok": False,
            "error": "gate read changed finding state",
            "http": 500,
            "confirms": False,
        }
    needs = int((counts or {}).get("needs_human") or 0)
    waiting = int(inbox.get("count") or 0)
    return {
        "ok": True,
        "confirms": False,
        "open": bool(needs or waiting),
        "needs_human": needs,
        "findings_by_state": counts,
        "inbox": inbox,
        "note": (
            "Human gate is read-only here. needs_human means mechanical gates "
            "passed, not exploit proof. confirmed is set only by Report review "
            "or vf hitl respond."
        ),
    }


_HANDLERS = {
    "start": _start,
    "stop": _stop,
    "pause": _pause,
    "resume": _resume,
    "status": _status,
    "findings": _findings,
    "gate": _gate,
}


def apply(run: RunRef, verb: str, args: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Dispatch one grammar verb. Unknown verbs return ``ok: false`` and ``http: 404``."""
    name = str(verb or "").strip().lower()
    payload = dict(args or {})
    if name not in _HANDLERS:
        return _stamp(
            run,
            name,
            {"ok": False, "error": f"unknown campaign verb: {name}", "http": 404},
        )
    result = _HANDLERS[name](run, payload)
    stamped = _stamp(run, name, result)
    if name in MUTATE_VERBS:
        append_event(
            run.path,
            {
                "source": "campaign",
                "event": f"campaign_{name}",
                "ok": bool(stamped.get("ok")),
            },
        )
    return stamped


def campaign_home(run: RunRef) -> dict[str, Any]:
    """Grammar bound to one run, plus a live status read."""
    described = describe_grammar()
    status = apply(run, "status")
    return {
        "ok": bool(status.get("ok")),
        "schema": SCHEMA,
        "engine": "ralph",
        "parallel_runner": False,
        "target_id": run.target_id,
        "run_id": run.run_id,
        "verbs": [row["verb"] for row in described["verbs"]],
        "grammar_url": "/api/campaign/grammar",
        "grammar": described,
        "status": status,
    }
