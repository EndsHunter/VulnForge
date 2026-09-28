"""Live tool-round progress and bounded mid-task steer for a leased task.

The dashboard and the leased worker are different processes. Progress and
steer live in the run directory:

- ``live/task-<id>.json`` — current model round (n/max) and tool-call steps
- ``steer/task-<id>.json`` — operator note / force submit_none / abort

Steer is applied at a **round boundary** (before the next model call). It
does not rewrite a tool the model already chose, and it never confirms or
rejects findings.

Live snapshot writers (``record_tool_call``, ``note_round_start``, bind /
unbind) and steer writers share ``_live_lock`` — an exclusive lock on the
steer file (``steer/task-<id>.lock``). The lock is reentrant on the
holding thread so a steer boundary can call a tool that records a step.

Model-wait contract: ``note_round_start`` sets ``phase`` to ``"thinking"``,
clears ``tool`` / ``args_summary`` / ``ok``, and stamps ``wait_started_at``.
While that phase lasts and no tool is current, a heartbeat refreshes
``updated_at`` and ``heartbeat_n`` only — no steps, no invented tools, no
round/call changes. ``record_tool_call`` sets ``phase`` back to ``"running"``
and ``unbind_task`` sets ``"ended"``; both clear ``wait_started_at``.

``prune_live_artifacts`` deletes ``live/task-*.json`` and empty
``steer/*.lock`` files after a successful idle. It does not delete steer
JSON. A ``STOP`` file or any other live Ralph PID skips the prune, so a
pause or a sibling worker keeps its files.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator, Optional
from uuid import uuid4

from vulnforge.file_lock import open_exclusive
from vulnforge.util import append_event, utc_now_iso

_MAX_STEPS = 40
_ARGS_SUMMARY_MAX = 180
_NOTE_MAX = 2000
_NOTES_CAP = 12
# Seconds between liveness touches while phase is "thinking". 5–15s.
_HEARTBEAT_INTERVAL_S = 8.0

_bind: ContextVar[Optional["LiveBind"]] = ContextVar("vf_live_bind", default=None)
_forcing_submit_none: ContextVar[bool] = ContextVar(
    "vf_operator_force_submit_none", default=False
)


class LiveBind:
    def __init__(self, run_dir: Path, task_id: int, kind: str, max_rounds: int) -> None:
        self.run_dir = Path(run_dir)
        self.task_id = int(task_id)
        self.kind = str(kind or "")
        self.max_rounds = max(1, int(max_rounds or 1))
        self.round_n = 0
        self._hb_stop: Optional[threading.Event] = None
        self._hb_thread: Optional[threading.Thread] = None


def operator_force_active() -> bool:
    """True only while the harness is applying an operator force-submit_none."""
    return bool(_forcing_submit_none.get())


def current_bind() -> Optional[LiveBind]:
    return _bind.get()


def bind_task(run_dir: Path, task_id: int, kind: str, max_rounds: int) -> object:
    """Bind the leased task for this worker and publish an empty live snapshot."""
    bind = LiveBind(run_dir, task_id, kind, max_rounds)
    token = _bind.set(bind)
    try:
        with _live_lock(bind.run_dir, bind.task_id):
            _write_json(
                _live_path(bind.run_dir, bind.task_id),
                {
                    "task_id": bind.task_id,
                    "kind": bind.kind,
                    "phase": "running",
                    "round": 0,
                    "max_rounds": bind.max_rounds,
                    "tool": None,
                    "args_summary": "",
                    "ok": None,
                    "steps": [],
                    "updated_at": utc_now_iso(),
                },
            )
    except OSError:
        pass
    return token


def unbind_task(token: object) -> None:
    bind = _bind.get()
    if bind is not None:
        try:
            with _live_lock(bind.run_dir, bind.task_id):
                snap = _read_json(_live_path(bind.run_dir, bind.task_id)) or {}
                snap["phase"] = "ended"
                snap["wait_started_at"] = None
                snap["updated_at"] = utc_now_iso()
                snap.setdefault("task_id", bind.task_id)
                snap.setdefault("max_rounds", bind.max_rounds)
                _write_json(_live_path(bind.run_dir, bind.task_id), snap)
        except OSError:
            pass
        _stop_thinking_heartbeat(bind)
    try:
        _bind.reset(token)  # type: ignore[arg-type]
    except (ValueError, LookupError):
        _bind.set(None)


def note_round_start() -> int:
    """Count a model round that is about to start. Returns the 1-based index.

    Enters ``phase="thinking"`` and clears the top-level "now" tool fields so
    the pane does not keep showing a finished tool while the model is
    thinking. Prior ``steps`` stay. Starts the liveness heartbeat.
    """
    bind = _bind.get()
    if bind is None:
        return 0
    incremented = False
    try:
        with _live_lock(bind.run_dir, bind.task_id):
            bind.round_n += 1
            incremented = True
            now = utc_now_iso()
            snap = _read_json(_live_path(bind.run_dir, bind.task_id)) or {}
            snap["round"] = bind.round_n
            snap["max_rounds"] = bind.max_rounds
            snap["phase"] = "thinking"
            snap["tool"] = None
            snap["args_summary"] = ""
            snap["ok"] = None
            snap["wait_started_at"] = now
            snap["heartbeat_n"] = 0
            snap["updated_at"] = now
            snap.setdefault("task_id", bind.task_id)
            snap.setdefault("kind", bind.kind)
            snap.setdefault("steps", [])
            _write_json(_live_path(bind.run_dir, bind.task_id), snap)
    except OSError:
        if not incremented:
            bind.round_n += 1
        return bind.round_n
    _ensure_thinking_heartbeat(bind)
    return bind.round_n


@contextmanager
def thinking_heartbeat() -> Iterator[None]:
    """Keep the live snapshot warm while a model call blocks.

    Refreshes ``updated_at`` / ``heartbeat_n`` on the interval. Does not append
    steps or set a tool. No-op when no task is bound. The heartbeat stops when
    the block exits; ``record_tool_call`` and ``unbind_task`` stop it too.
    """
    bind = _bind.get()
    if bind is None:
        yield
        return
    _ensure_thinking_heartbeat(bind)
    try:
        yield
    finally:
        _stop_thinking_heartbeat(bind)


def summarize_args(args: Any) -> str:
    """Short, single-line args summary safe to show in the live pane."""
    if isinstance(args, dict):
        parts: list[str] = []
        for key, val in list(args.items())[:8]:
            if key in ("operator_forced",):
                continue
            if isinstance(val, str):
                text = val
            else:
                try:
                    text = json.dumps(val, ensure_ascii=False, default=str)
                except (TypeError, ValueError):
                    text = str(val)
            text = " ".join(text.split())
            if len(text) > 60:
                text = text[:57] + "..."
            parts.append(f"{key}={text}")
        summary = " ".join(parts)
    else:
        summary = " ".join(str(args or "").split())
    if len(summary) > _ARGS_SUMMARY_MAX:
        summary = summary[: _ARGS_SUMMARY_MAX - 3] + "..."
    return summary


def record_tool_call(name: str, args: Any, out: Any) -> None:
    """Append one tool call to the live snapshot and emit ``task_step``."""
    bind = _bind.get()
    if bind is None:
        return
    tool = str(name or "").strip() or "tool"
    summary = summarize_args(args if isinstance(args, dict) else {})
    ok: Optional[bool]
    if isinstance(out, dict) and "ok" in out:
        ok = bool(out.get("ok"))
    else:
        ok = None
    rnd = bind.round_n if bind.round_n > 0 else 1
    # `round` is the model round from note_round_start. `call` numbers the
    # tool line inside that round so the pane does not treat each call as a round.
    # Count and append under the live lock. An unlocked read-modify-write
    # drops concurrent tools in one model round (last writer wins).
    call_n = 1
    step_ts = utc_now_iso()
    try:
        with _live_lock(bind.run_dir, bind.task_id):
            snap = _read_json(_live_path(bind.run_dir, bind.task_id)) or {}
            steps = [s for s in (snap.get("steps") or []) if isinstance(s, dict)]
            call_n = 1 + _max_call_in_round(steps, rnd)
            step_ts = utc_now_iso()
            step = {
                "call": call_n,
                "round": rnd,
                "max_rounds": bind.max_rounds,
                "tool": tool,
                "args_summary": summary,
                "ok": ok,
                "ts": step_ts,
            }
            steps.append(step)
            if len(steps) > _MAX_STEPS:
                steps = steps[-_MAX_STEPS:]
            snap.update(
                {
                    "task_id": bind.task_id,
                    "kind": bind.kind,
                    "phase": "running",
                    "round": rnd,
                    "max_rounds": bind.max_rounds,
                    "tool": tool,
                    "args_summary": summary,
                    "ok": ok,
                    "steps": steps,
                    "wait_started_at": None,
                    "updated_at": step_ts,
                }
            )
            _write_json(_live_path(bind.run_dir, bind.task_id), snap)
    except OSError:
        pass
    _stop_thinking_heartbeat(bind)
    try:
        append_event(
            bind.run_dir,
            {
                "source": "vf",
                "event": "task_step",
                "task_id": bind.task_id,
                "kind": bind.kind,
                "tool": tool,
                "args_summary": summary,
                "call": call_n,
                "round": rnd,
                "max_rounds": bind.max_rounds,
                "ok": ok,
            },
        )
    except OSError:
        pass


def format_operator_note(notes: list[str]) -> str:
    body = "\n\n".join(n.strip() for n in notes if str(n).strip())
    return (
        "OPERATOR NOTE (mid-task steer for the next round):\n"
        f"{body}\n\n"
        "This note does not confirm or reject findings. "
        "Continue the leased task. Do not treat this as permission to submit_candidate."
    )


def add_operator_note(run_dir: Path, task_id: int, text: str) -> dict[str, Any]:
    """Queue a note for the next round boundary. Does not touch findings."""
    note = " ".join(str(text or "").split())
    if not note:
        return {"ok": False, "error": "note is empty"}
    if len(note) > _NOTE_MAX:
        note = note[:_NOTE_MAX]
    task_id = int(task_id)
    with _steer_lock(run_dir, task_id):
        steer = _load_steer(run_dir, task_id)
        notes = [n for n in (steer.get("notes") or []) if isinstance(n, dict)]
        entry = {
            "id": uuid4().hex[:12],
            "text": note,
            "ts": utc_now_iso(),
            "consumed": False,
        }
        notes.append(entry)
        steer["notes"] = notes[-_NOTES_CAP:]
        _write_json(_steer_path(run_dir, task_id), steer)
    try:
        append_event(
            run_dir,
            {
                "source": "dashboard",
                "event": "operator_task_note",
                "task_id": task_id,
                "note_id": entry["id"],
                "preview": note[:160],
            },
        )
    except OSError:
        pass
    return {"ok": True, "task_id": task_id, "note_id": entry["id"], "note": note}


def request_force_submit_none(
    run_dir: Path,
    task_id: int,
    reason: str = "",
) -> dict[str, Any]:
    """Ask the harness to call submit_none at the next round boundary.

    Does not call the tool itself and does not confirm findings. The worker
    applies it before the next model call.
    """
    task_id = int(task_id)
    why = " ".join(str(reason or "").split()) or "operator forced submit_none"
    if len(why) > _NOTE_MAX:
        why = why[:_NOTE_MAX]
    with _steer_lock(run_dir, task_id):
        steer = _load_steer(run_dir, task_id)
        current = steer.get("force_submit_none")
        if (
            isinstance(current, dict)
            and current.get("requested")
            and not current.get("applied")
        ):
            return {
                "ok": True,
                "task_id": task_id,
                "already_pending": True,
                "reason": current.get("reason") or why,
            }
        steer["force_submit_none"] = {
            "requested": True,
            "applied": False,
            "reason": why,
            "ts": utc_now_iso(),
        }
        _write_json(_steer_path(run_dir, task_id), steer)
    try:
        append_event(
            run_dir,
            {
                "source": "dashboard",
                "event": "operator_force_submit_none",
                "task_id": task_id,
                "reason": why[:300],
            },
        )
    except OSError:
        pass
    return {"ok": True, "task_id": task_id, "already_pending": False, "reason": why}


def request_abort(run_dir: Path, task_id: int, reason: str = "operator_abort") -> dict[str, Any]:
    """Flag abort for the next round boundary. Caller still halts the worker."""
    task_id = int(task_id)
    why = " ".join(str(reason or "").split()) or "operator_abort"
    with _steer_lock(run_dir, task_id):
        steer = _load_steer(run_dir, task_id)
        steer["abort"] = {
            "requested": True,
            "seen": False,
            "reason": why[:500],
            "ts": utc_now_iso(),
        }
        _write_json(_steer_path(run_dir, task_id), steer)
    try:
        append_event(
            run_dir,
            {
                "source": "dashboard",
                "event": "operator_abort_task",
                "task_id": task_id,
                "reason": why[:300],
            },
        )
    except OSError:
        pass
    return {"ok": True, "task_id": task_id, "reason": why}


def tool_names_from_schema(tools_schema: list | None) -> set[str]:
    names: set[str] = set()
    for tool in tools_schema or []:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        if isinstance(fn, dict) and fn.get("name"):
            names.add(str(fn["name"]))
    return names


def apply_round_boundary(tool_handler, tools_schema) -> dict[str, Any]:
    """Consume pending steer before the next model call.

    Returns ``action`` of ``none`` | ``note`` | ``abort`` | ``submit_none``.
    Abort wins over force submit_none. Neither path confirms findings.
    """
    empty: dict[str, Any] = {
        "action": "none",
        "notes": [],
        "note_text": "",
        "result": None,
        "reason": "",
    }
    bind = _bind.get()
    if bind is None:
        return empty
    with _steer_lock(bind.run_dir, bind.task_id):
        steer = _load_steer(bind.run_dir, bind.task_id)
        abort = steer.get("abort") if isinstance(steer.get("abort"), dict) else None
        if abort and abort.get("requested") and not abort.get("seen"):
            abort["seen"] = True
            abort["seen_at"] = utc_now_iso()
            steer["abort"] = abort
            _write_json(_steer_path(bind.run_dir, bind.task_id), steer)
            return {
                **empty,
                "action": "abort",
                "reason": str(abort.get("reason") or "operator_abort"),
            }

        force = (
            steer.get("force_submit_none")
            if isinstance(steer.get("force_submit_none"), dict)
            else None
        )
        if force and force.get("requested") and not force.get("applied"):
            reason = str(force.get("reason") or "operator forced submit_none").strip()
            reason = reason or "operator forced submit_none"
            names = tool_names_from_schema(tools_schema)
            force["applied"] = True
            force["applied_at"] = utc_now_iso()
            if "submit_none" not in names:
                force["ok"] = False
                force["error"] = "submit_none is not available on this task"
                steer["force_submit_none"] = force
                _write_json(_steer_path(bind.run_dir, bind.task_id), steer)
                return {
                    **empty,
                    "action": "note",
                    "note_text": (
                        "OPERATOR STEER: force submit_none was requested, but this "
                        "task has no submit_none tool. The task was not finished and "
                        "no finding was confirmed. Abort the task to stop it."
                    ),
                    "reason": reason,
                }
            steer["force_submit_none"] = force
            _write_json(_steer_path(bind.run_dir, bind.task_id), steer)
            token = _forcing_submit_none.set(True)
            try:
                try:
                    out = tool_handler("submit_none", {"reason": reason})
                except Exception as e:
                    out = {"ok": False, "error": str(e)}
            finally:
                _forcing_submit_none.reset(token)
            if not isinstance(out, dict):
                out = {"ok": True, "result": out}
            force["ok"] = bool(out.get("ok"))
            if out.get("error"):
                force["error"] = str(out.get("error"))[:300]
            steer["force_submit_none"] = force
            _write_json(_steer_path(bind.run_dir, bind.task_id), steer)
            return {**empty, "action": "submit_none", "result": out, "reason": reason}

        pending: list[str] = []
        changed = False
        now = utc_now_iso()
        for note in steer.get("notes") or []:
            if not isinstance(note, dict) or note.get("consumed"):
                continue
            text = str(note.get("text") or "").strip()
            if not text:
                continue
            note["consumed"] = True
            note["consumed_at"] = now
            pending.append(text)
            changed = True
        if changed:
            _write_json(_steer_path(bind.run_dir, bind.task_id), steer)
        if pending:
            return {
                **empty,
                "action": "note",
                "notes": pending,
                "note_text": format_operator_note(pending),
            }
    return empty


def prune_live_artifacts(
    run_dir: Path,
    *,
    reason: str = "",
    ignore_pids: Optional[set[int]] = None,
) -> dict[str, Any]:
    """Delete ended live snapshots and empty steer lock files.

    No-op when ``STOP`` is present or a Ralph worker other than
    ``ignore_pids`` is still alive. Steer JSON is left in place so an
    unconsumed note survives. Empty-file locks only: a non-empty lock is
    kept. Call this after idle/complete, not while a task is running.
    """
    run_dir = Path(run_dir)
    skipped: dict[str, Any] = {
        "ok": True,
        "pruned": False,
        "reason": reason,
        "skip": None,
        "live": [],
        "locks": [],
    }
    if (run_dir / "STOP").is_file():
        skipped["skip"] = "stop"
        return skipped
    from vulnforge.ui.runner import foreign_runner_alive

    if foreign_runner_alive(run_dir, ignore_pids=ignore_pids):
        skipped["skip"] = "alive"
        return skipped

    removed_live: list[str] = []
    live_dir = run_dir / "live"
    if live_dir.is_dir():
        for path in sorted(live_dir.glob("task-*.json")):
            try:
                path.unlink()
                removed_live.append(path.name)
            except OSError:
                continue
    removed_locks: list[str] = []
    steer_dir = run_dir / "steer"
    if steer_dir.is_dir():
        for path in sorted(steer_dir.glob("*.lock")):
            try:
                if path.is_file() and path.stat().st_size == 0:
                    path.unlink()
                    removed_locks.append(path.name)
            except OSError:
                continue
    return {
        "ok": True,
        "pruned": True,
        "reason": reason,
        "skip": None,
        "live": removed_live,
        "locks": removed_locks,
    }


def read_live_view(run_dir: Path, task_id: int) -> dict[str, Any]:
    """Snapshot + steer inbox for the live pane. Missing files are empty."""
    task_id = int(task_id)
    snap = _read_json(_live_path(run_dir, task_id)) or {}
    steer = _read_json(_steer_path(run_dir, task_id)) or {}
    steps = [s for s in (snap.get("steps") or []) if isinstance(s, dict)]
    notes = [n for n in (steer.get("notes") or []) if isinstance(n, dict)]
    return {
        "task_id": task_id,
        "kind": snap.get("kind"),
        "phase": snap.get("phase") or "idle",
        "round": int(snap.get("round") or 0),
        "max_rounds": int(snap.get("max_rounds") or 0),
        "tool": snap.get("tool"),
        "args_summary": snap.get("args_summary") or "",
        "ok": snap.get("ok"),
        "steps": steps[-_MAX_STEPS:],
        "wait_started_at": snap.get("wait_started_at"),
        "heartbeat_n": _heartbeat_n(snap.get("heartbeat_n")),
        "updated_at": snap.get("updated_at"),
        "steer": {
            "pending_notes": [
                {"id": n.get("id"), "text": n.get("text"), "ts": n.get("ts")}
                for n in notes
                if not n.get("consumed")
            ],
            "delivered_notes": [
                {
                    "id": n.get("id"),
                    "text": n.get("text"),
                    "ts": n.get("ts"),
                    "consumed_at": n.get("consumed_at"),
                }
                for n in notes
                if n.get("consumed")
            ][-_NOTES_CAP:],
            "force_submit_none": steer.get("force_submit_none"),
            "abort": steer.get("abort"),
        },
    }


def _heartbeat_n(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _ensure_thinking_heartbeat(bind: LiveBind) -> None:
    """Start one daemon touch loop for this bind. A stopped thread is replaced."""
    current = bind._hb_thread
    stop = bind._hb_stop
    if (
        current is not None
        and current.is_alive()
        and stop is not None
        and not stop.is_set()
    ):
        return
    stop = threading.Event()
    bind._hb_stop = stop

    def _loop(stop_event: threading.Event) -> None:
        while not stop_event.wait(_HEARTBEAT_INTERVAL_S):
            try:
                _heartbeat_touch(bind)
            except OSError:
                return

    thread = threading.Thread(
        target=_loop,
        args=(stop,),
        name=f"vf-live-heartbeat-{bind.task_id}",
        daemon=True,
    )
    bind._hb_thread = thread
    thread.start()


def _stop_thinking_heartbeat(bind: LiveBind) -> None:
    stop = bind._hb_stop
    if stop is not None:
        stop.set()


def _heartbeat_touch(bind: LiveBind) -> None:
    """Refresh liveness metadata. Leaves steps, tool, round, and call alone."""
    with _live_lock(bind.run_dir, bind.task_id):
        path = _live_path(bind.run_dir, bind.task_id)
        snap = _read_json(path) or {}
        if snap.get("phase") != "thinking" or snap.get("tool"):
            return
        snap["updated_at"] = utc_now_iso()
        snap["heartbeat_n"] = _heartbeat_n(snap.get("heartbeat_n")) + 1
        _write_json(path, snap)


def _step_round(step: dict[str, Any]) -> int:
    try:
        return int(step.get("round") or 0)
    except (TypeError, ValueError):
        return 0


def _step_call(step: dict[str, Any]) -> int:
    try:
        return int(step.get("call") or 0)
    except (TypeError, ValueError):
        return 0


def _max_call_in_round(steps: list[dict[str, Any]], rnd: int) -> int:
    """Highest call index still stored for ``rnd``.

    Counting remaining rows breaks once ``_MAX_STEPS`` drops the oldest
    calls: the pane stays full and every new call would reuse the same index.
    """
    best = 0
    for step in steps:
        if _step_round(step) == rnd:
            best = max(best, _step_call(step))
    return best


def _live_path(run_dir: Path, task_id: int) -> Path:
    return Path(run_dir) / "live" / f"task-{int(task_id)}.json"


def _steer_path(run_dir: Path, task_id: int) -> Path:
    return Path(run_dir) / "steer" / f"task-{int(task_id)}.json"


def _lock_path(run_dir: Path, task_id: int) -> Path:
    """One flock file for steer JSON and the live snapshot of this task."""
    return Path(run_dir) / "steer" / f"task-{int(task_id)}.lock"


class _LockDepth(threading.local):
    """Per-thread reentry depth so steer can record a tool without deadlock."""

    def __init__(self) -> None:
        self.held: dict[tuple[str, int], int] = {}


_lock_depth = _LockDepth()


def _load_steer(run_dir: Path, task_id: int) -> dict[str, Any]:
    data = _read_json(_steer_path(run_dir, task_id))
    if not isinstance(data, dict):
        data = {}
    data.setdefault("task_id", int(task_id))
    data.setdefault("notes", [])
    return data


@contextmanager
def _live_lock(run_dir: Path, task_id: int) -> Iterator[None]:
    """Exclusive lock for live-snapshot and steer writers of one task.

    Same lock file as historical ``_steer_lock`` (``steer/task-<id>.lock``).
    Reentrant on the holding thread: ``apply_round_boundary`` calls a tool
    while the steer lock is held, and that tool records a live step.
    Other threads and processes block until the outer hold releases.
    """
    key = (str(Path(run_dir)), int(task_id))
    held = _lock_depth.held
    depth = held.get(key, 0)
    if depth > 0:
        held[key] = depth + 1
        try:
            yield
        finally:
            held[key] = depth
        return

    path = _lock_path(run_dir, task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    locked = open_exclusive(path)
    try:
        held[key] = 1
        try:
            yield
        finally:
            held.pop(key, None)
    finally:
        locked.close()


# Steer writers keep the old name. It is the same lock as live snapshots.
_steer_lock = _live_lock


def _read_json(path: Path) -> Optional[dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)
