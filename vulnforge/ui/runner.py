"""
Background Ralph / run lifecycle for the dashboard.

Start     -  spawn `scripts/ralph.py --run-dir ...` (or init + ralph)
Pause     -  write STOP and return. Ralph finishes the current task, then
             exits. Does not kill that worker or reclaim its lease.
             No live Ralph pid: STOP means paused.
Hard stop -  kill the Ralph session (in-flight run-once included),
             reclaim leases, clear run.lock when the holder is dead.
Resume    -  remove STOP and spawn Ralph again if not already running.
             A live run.lock holder blocks resume until that process is gone.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from vulnforge.paths import PROJECT_ROOT
from vulnforge.util import append_event, utc_now_iso
PID_NAME = "ralph.pid"
STOP_NAME = "STOP"
META_NAME = "runner.json"


def _pid_path(run_dir: Path) -> Path:
    return run_dir / PID_NAME


def _stop_path(run_dir: Path) -> Path:
    return run_dir / STOP_NAME


def _meta_path(run_dir: Path) -> Path:
    return run_dir / META_NAME


def _pid_is_zombie(pid: int) -> bool:
    """True when /proc/pid is a zombie (kill 0 still succeeds)."""
    if os.name == "nt" or pid <= 0:
        return False
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            rest = f.read().rsplit(")", 1)[-1].strip()
    except OSError:
        return False
    return bool(rest) and rest[0] == "Z"


def _reap_if_child(pid: int) -> None:
    if os.name == "nt" or pid <= 0:
        return
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return
    except OSError:
        return


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        os.kill(pid, 0)
        if _pid_is_zombie(pid):
            _reap_if_child(pid)
            return False
        return True
    except OSError:
        return False
    except Exception:
        return False


def read_pid(run_dir: Path) -> Optional[int]:
    p = _pid_path(run_dir)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return int(data.get("pid", -1))
    except (OSError, ValueError, json.JSONDecodeError):
        try:
            return int(p.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None


def _read_worker_pids(run_dir: Path) -> list[int]:
    """Primary pid + any multi-worker PIDs still listed."""
    pids: list[int] = []
    primary = read_pid(run_dir)
    if primary:
        pids.append(primary)
    wp = run_dir / "ralph_workers.json"
    if wp.is_file():
        try:
            data = json.loads(wp.read_text(encoding="utf-8"))
            for p in data.get("pids") or []:
                try:
                    ip = int(p)
                except (TypeError, ValueError):
                    continue
                if ip not in pids:
                    pids.append(ip)
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return pids


def runner_status(run_dir: Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    all_pids = _read_worker_pids(run_dir)
    live_pids = [p for p in all_pids if _pid_alive(p)]
    pid = live_pids[0] if live_pids else None
    # Prefer primary file pid if still alive
    file_pid = read_pid(run_dir)
    if file_pid and file_pid in live_pids:
        pid = file_pid
    alive = bool(live_pids)
    stop = _stop_path(run_dir).is_file()
    locked = (run_dir / "run.lock").is_file()
    meta = {}
    mp = _meta_path(run_dir)
    if mp.is_file():
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
    if not alive:
        # stale pid files
        try:
            _pid_path(run_dir).unlink(missing_ok=True)
        except OSError:
            pass
        try:
            (run_dir / "ralph_workers.json").unlink(missing_ok=True)
        except OSError:
            pass
    state = "idle"
    if alive and stop:
        state = "pausing"  # STOP set, waiting for current task to finish
    elif alive:
        state = "running"
    elif stop:
        state = "paused"
    elif locked:
        state = "busy"  # vf run-once holding lock without our pid
    workers = int(meta.get("workers") or len(live_pids) or 1)
    return {
        "state": state,
        "pid": pid,
        "pids": live_pids,
        "workers_alive": len(live_pids),
        "workers": workers,
        "alive": alive,
        "stop": stop,
        "locked": locked,
        "meta": meta,
    }


def _write_pid(run_dir: Path, pid: int, argv: list[str]) -> None:
    payload = {
        "pid": pid,
        "argv": argv,
        "started_at": utc_now_iso(),
    }
    _pid_path(run_dir).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    meta = {
        "last_start": utc_now_iso(),
        "argv": argv,
        "pid": pid,
    }
    _meta_path(run_dir).write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _ralph_cmd(
    run_dir: Path,
    *,
    task_timeout: float = 900,
    max_tasks: Optional[int] = None,
    max_iterations: int = 200,
    max_wall_seconds: Optional[float] = None,
    config: Optional[Path] = None,
) -> list[str]:
    ralph = PROJECT_ROOT / "scripts" / "ralph.py"
    cmd = [
        sys.executable,
        str(ralph),
        "--run-dir",
        str(run_dir.resolve()),
        "--task-timeout",
        str(task_timeout),
        "--max-iterations",
        str(max_iterations),
        "--sleep-seconds",
        "1",
    ]
    if max_tasks is not None:
        cmd += ["--max-tasks", str(max_tasks)]
    if max_wall_seconds is not None:
        cmd += ["--max-wall-seconds", str(max_wall_seconds)]
    if config is not None:
        cmd += ["--config", str(config)]
    return cmd


def _max_leases_from_settings() -> int:
    """How many Ralph workers can hold a lease at once (fallback 1).

    One configured pair with no number keeps the global cap. Several
    ``(host, model)`` pairs sum their own caps. The same pair is counted once.
    """
    try:
        from vulnforge.settings import load_ui_settings
        from vulnforge.settings.catalog import ui_lease_ceiling

        return ui_lease_ceiling(load_ui_settings())
    except Exception:
        return 1


def start_run(
    run_dir: Path,
    *,
    task_timeout: float = 900,
    max_tasks: Optional[int] = None,
    max_iterations: int = 10_000,
    max_wall_seconds: Optional[float] = None,
    config: Optional[Path] = None,
    workers: int = 1,
    loop_profile_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Start Ralph against an existing run directory.
    Clears STOP if present (start implies resume-from-stop).

    workers>1 spawns multiple Ralph processes. When the per-model lease
    ceiling is above 1, run-once skips exclusive run.lock and SQLite caps
    each model id so agents on different models can run in parallel.

    Worker count is capped to that ceiling so spare Ralph processes cannot
    busy-spin on EXIT_BUSY past the leases the models will accept.
    """
    run_dir = Path(run_dir).resolve()
    if not (run_dir / "harness.db").is_file():
        return {"ok": False, "error": "not a valid run dir (missing harness.db)"}

    st = runner_status(run_dir)
    if st["alive"]:
        return {"ok": False, "error": "already running", "status": st}

    try:
        from vulnforge.poc_runner import sandbox_poc_start_block

        block = sandbox_poc_start_block(run_dir)
    except Exception as e:
        return {"ok": False, "error": f"Sandbox PoC refused: preflight failed ({e})"}
    if block:
        return {"ok": False, "error": block}

    # clear pause flag
    try:
        _stop_path(run_dir).unlink(missing_ok=True)
    except OSError:
        pass

    lease_cap = _max_leases_from_settings()
    workers = max(1, min(int(workers), lease_cap))
    cmd = _ralph_cmd(
        run_dir,
        task_timeout=task_timeout,
        max_tasks=max_tasks,
        max_iterations=max_iterations,
        max_wall_seconds=max_wall_seconds,
        config=config,
    )
    log_path = run_dir / "ralph.log"
    try:
        log_f = open(log_path, "a", encoding="utf-8")
        log_f.write(f"\n--- start {utc_now_iso()} workers={workers} ---\n")
        log_f.write(" ".join(cmd) + "\n")
        log_f.flush()
    except OSError:
        log_f = subprocess.DEVNULL  # type: ignore[assignment]

    creationflags = 0
    if os.name == "nt":
        # Hide console + new process group. CREATE_NO_WINDOW avoids the CMD
        # flash that DETACHED_PROCESS alone does not suppress for python.exe.
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    pids: list[int] = []
    try:
        for _i in range(workers):
            proc = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                stdout=log_f if log_f is not subprocess.DEVNULL else subprocess.DEVNULL,
                stderr=subprocess.STDOUT
                if log_f is not subprocess.DEVNULL
                else subprocess.DEVNULL,
                creationflags=creationflags,
                start_new_session=(os.name != "nt"),
            )
            pids.append(proc.pid)
    except OSError as e:
        return {"ok": False, "error": f"spawn failed: {e}"}

    primary = pids[0]
    _write_pid(run_dir, primary, cmd)
    # Always write workers file when multi; also stamp workers in meta
    meta_extra = {
        "last_start": utc_now_iso(),
        "argv": cmd,
        "pid": primary,
        "pids": pids,
        "workers": workers,
        "task_timeout": task_timeout,
        "max_tasks": max_tasks,
        "max_iterations": max_iterations,
        "max_wall_seconds": max_wall_seconds,
        "loop_profile_id": loop_profile_id,
    }
    _meta_path(run_dir).write_text(json.dumps(meta_extra, indent=2), encoding="utf-8")
    if len(pids) > 1:
        (run_dir / "ralph_workers.json").write_text(
            json.dumps(
                {"pids": pids, "workers": workers, "started_at": utc_now_iso()},
                indent=2,
            ),
            encoding="utf-8",
        )
    else:
        try:
            (run_dir / "ralph_workers.json").unlink(missing_ok=True)
        except OSError:
            pass
    append_event(
        run_dir,
        {
            "source": "ui",
            "event": "runner_start",
            "pid": primary,
            "pids": pids,
            "workers": workers,
            "argv": cmd,
            "loop_profile_id": loop_profile_id,
            "max_tasks": max_tasks,
            "max_iterations": max_iterations,
            "task_timeout": task_timeout,
        },
    )
    return {
        "ok": True,
        "pid": primary,
        "pids": pids,
        "workers": workers,
        "loop_profile_id": loop_profile_id,
        "status": runner_status(run_dir),
        "note": (
            None
            if workers == 1
            else f"{workers} concurrent agents (SQLite multi-lease; no exclusive run.lock)"
        ),
    }


def _read_lock_pid(run_dir: Path) -> Optional[int]:
    lock_path = run_dir / "run.lock"
    if not lock_path.is_file():
        return None
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
        return int(data.get("pid", -1))
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return None


def _lock_holder_alive(run_dir: Path) -> Optional[int]:
    """PID that still owns run.lock, or None when the file is absent or stale."""
    pid = _read_lock_pid(run_dir)
    if pid and _pid_alive(pid):
        return pid
    return None


def _clear_run_lock(run_dir: Path) -> bool:
    """Remove run.lock when missing, corrupt, or holder PID is dead.

    Returns True only when a lock file was unlinked. A live holder is left
    in place (caller must kill it first).
    """
    lock_path = run_dir / "run.lock"
    if not lock_path.is_file():
        return False
    if _lock_holder_alive(run_dir):
        return False
    try:
        lock_path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _reclaim_leases_on_stop(run_dir: Path) -> int:
    """Requeue leased tasks after workers are killed (orphan cleanup)."""
    db_path = run_dir / "harness.db"
    if not db_path.is_file():
        return 0
    try:
        from vulnforge.db import Database

        db = Database.open(db_path)
        try:
            return int(db.reclaim_all_leased_tasks(reason="pause_kill_orphan") or 0)
        finally:
            db.close()
    except Exception:
        return 0


def _pause_result(
    run_dir: Path,
    *,
    pids: list[int],
    killed_any: bool,
    reclaimed: int,
) -> dict[str, Any]:
    """Hard-stop payload: lock_cleared means run.lock is gone.

    ok is false when a live PID still holds the lock after kill attempts.
    A dead holder's file is removed here; resume must not treat a live
    holder as a clean start.
    """
    if not _lock_holder_alive(run_dir):
        _clear_run_lock(run_dir)
    holder = _lock_holder_alive(run_dir)
    lock_cleared = not (run_dir / "run.lock").is_file()
    result: dict[str, Any] = {
        "ok": holder is None,
        "killed": killed_any,
        "reclaimed_leases": reclaimed,
        "lock_cleared": lock_cleared,
        "status": runner_status(run_dir),
    }
    if holder is not None:
        result["lock_holder"] = holder
        result["error"] = f"run.lock still held by live pid {holder}"
    return result


def _write_stop(run_dir: Path) -> Optional[str]:
    try:
        _stop_path(run_dir).write_text(
            f"paused_at={utc_now_iso()}\n", encoding="utf-8"
        )
    except OSError as e:
        return str(e)
    return None


def pause_run(run_dir: Path) -> dict[str, Any]:
    """Drain-then-pause: write STOP and return.

    Ralph checks STOP between iterations and exits after the current
    ``vf run-once`` finishes. Live workers and their leases stay so a
    mid-tool call is not reclaimed. Idle (no live Ralph pid): STOP is
    enough for ``paused``. Does not block on the task timeout.
    """
    run_dir = Path(run_dir).resolve()
    if not (run_dir / "harness.db").is_file():
        return {"ok": False, "error": "invalid run dir"}
    err = _write_stop(run_dir)
    if err:
        return {"ok": False, "error": err}

    # Dead lock only. A live holder is the in-flight task we are draining.
    if not _lock_holder_alive(run_dir):
        _clear_run_lock(run_dir)
    status = runner_status(run_dir)
    holder = _lock_holder_alive(run_dir)
    draining = status["state"] == "pausing"
    lock_cleared = not (run_dir / "run.lock").is_file()
    result: dict[str, Any] = {
        "ok": True,
        "draining": draining,
        "killed": False,
        "reclaimed_leases": 0,
        "lock_cleared": lock_cleared,
        "status": status,
    }
    if holder is not None:
        result["lock_holder"] = holder
    append_event(
        run_dir,
        {
            "source": "ui",
            "event": "runner_pause",
            "draining": draining,
            "killed": False,
            "reclaimed_leases": 0,
            "lock_cleared": lock_cleared,
            "lock_holder": holder,
        },
    )
    return result


def _kill_session_and_reclaim(run_dir: Path) -> dict[str, Any]:
    """Hard stop: STOP, tree-kill workers and the lock holder, reclaim leases.

    Linux workers are started with ``start_new_session=True``. Killing only
    the Ralph PID reparents run-once under the user service manager and
    leaves run.lock held. The kill matches Windows ``taskkill /T``: the
    process group, plus any descendant that left the group, plus the
    run.lock holder when that PID is not already in the worker list.

    In-flight work can be lost. ``ok`` is false when a live PID still holds
    ``run.lock`` after those kill attempts.
    """
    run_dir = Path(run_dir).resolve()
    if not (run_dir / "harness.db").is_file():
        return {"ok": False, "error": "invalid run dir"}
    err = _write_stop(run_dir)
    if err:
        return {"ok": False, "error": err}

    pids = _read_worker_pids(run_dir)
    lock_pid = _read_lock_pid(run_dir)
    if lock_pid and lock_pid not in pids:
        pids.append(lock_pid)
    killed_any = False
    for pid in pids:
        if _kill_pid(pid):
            killed_any = True
    try:
        _pid_path(run_dir).unlink(missing_ok=True)
    except OSError:
        pass
    try:
        (run_dir / "ralph_workers.json").unlink(missing_ok=True)
    except OSError:
        pass

    # Brief settle so OS reaps children before lease reclaim
    if killed_any:
        time.sleep(0.3)
    reclaimed = _reclaim_leases_on_stop(run_dir)
    result = _pause_result(
        run_dir, pids=pids, killed_any=killed_any, reclaimed=reclaimed
    )
    result["pids"] = pids
    return result


def resume_run(
    run_dir: Path,
    **start_kwargs: Any,
) -> dict[str, Any]:
    """Remove STOP and start Ralph if not running.

    When no Ralph worker is alive, a live ``run.lock`` holder is an orphaned
    run-once (hard stop that did not reap the tree, or a worker that died
    holding the lock). That holder is killed with the same tree kill as
    hard stop. If it is still alive, resume returns ``ok: false`` and does
    not spawn Ralph, so the next run-once does not loop on EXIT_INFRA 20
    (``run locked``).
    A still-running Ralph worker is left alone: its run-once owns the lock
    legitimately, and resume only clears STOP.
    """
    run_dir = Path(run_dir).resolve()
    workers_alive = bool(runner_status(run_dir)["alive"])
    if not workers_alive:
        holder = _lock_holder_alive(run_dir)
        if holder:
            _kill_pid(holder)
            if _lock_holder_alive(run_dir):
                return {
                    "ok": False,
                    "error": f"run.lock held by live pid {holder}",
                    "lock_cleared": False,
                    "lock_holder": holder,
                    "status": runner_status(run_dir),
                }
            _clear_run_lock(run_dir)
    try:
        _stop_path(run_dir).unlink(missing_ok=True)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    # Free ghost leases (dead worker PID / expired TTL) before Ralph starts.
    # Does NOT reclaim live workers — only stale owners.
    try:
        from vulnforge.db import Database

        db_path = run_dir / "harness.db"
        if db_path.is_file():
            db = Database.open(db_path)
            try:
                stale = db.reclaim_stale_leases()
            finally:
                db.close()
            if stale:
                append_event(
                    run_dir,
                    {
                        "source": "ui",
                        "event": "resume_reclaim_stale",
                        "reclaimed": stale,
                    },
                )
    except Exception:
        pass
    _clear_run_lock(run_dir)
    append_event(run_dir, {"source": "ui", "event": "runner_resume"})
    st = runner_status(run_dir)
    if st["alive"]:
        return {
            "ok": True,
            "status": st,
            "note": "already running; STOP cleared",
            "lock_cleared": not (run_dir / "run.lock").is_file(),
        }
    started = start_run(run_dir, **start_kwargs)
    started.setdefault("lock_cleared", not (run_dir / "run.lock").is_file())
    return started


# start_run signature includes workers=  -  resume_run forwards via **start_kwargs


def _descendant_pids(pid: int) -> list[int]:
    """Child processes of ``pid`` via /proc (empty when /proc is unavailable).

    Threads show up as /proc entries but their PPid is the thread-group
    parent's parent, so they are not walked. Process-group kill covers the
    threads that share the leader's group.
    """
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    children: dict[int, list[int]] = {}
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="utf-8")
            rest = raw.rsplit(")", 1)[1].split()
            ppid = int(rest[1])
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(int(entry.name))
    out: list[int] = []
    seen: set[int] = set()
    stack = list(children.get(pid, []))
    while stack:
        child = stack.pop()
        if child in seen or child <= 1 or child == os.getpid():
            continue
        seen.add(child)
        out.append(child)
        stack.extend(children.get(child, []))
    return out


def _kill_targets(pid: int) -> tuple[Optional[int], list[int]]:
    """Process group to signal, plus the leader and descendants.

    Group kill is skipped when the PID shares the caller's group so a
    dashboard pause cannot signal itself. ``start_new_session=True`` workers
    have their own group; that group is the Linux equivalent of Windows
    ``taskkill /T``.
    """
    if pid <= 1 or pid == os.getpid():
        return None, []
    try:
        pgid = os.getpgid(pid)
    except OSError:
        pgid = None
    use_group = pgid is not None and pgid > 1 and pgid != os.getpgrp()
    members: list[int] = []
    seen: set[int] = set()
    for member in [pid, *_descendant_pids(pid)]:
        if member <= 1 or member == os.getpid() or member in seen:
            continue
        seen.add(member)
        members.append(member)
    return (pgid if use_group else None), members


def _signal_targets(pgid: Optional[int], members: list[int], sig: int) -> None:
    if pgid:
        try:
            os.killpg(pgid, sig)
        except OSError:
            pass
    for member in members:
        try:
            os.kill(member, sig)
        except OSError:
            pass


def _wait_pids_dead(pids: list[int], timeout: float = 0.5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(_pid_alive(pid) for pid in pids):
            return
        time.sleep(0.05)


def _kill_unix_tree(pid: int) -> None:
    """SIGTERM, then SIGKILL, the process group and any descendants."""
    pgid, members = _kill_targets(pid)
    if pgid is None and not members:
        return
    _signal_targets(pgid, members, signal.SIGTERM)
    _wait_pids_dead(members, 0.5)
    if any(_pid_alive(member) for member in members):
        _signal_targets(pgid, members, signal.SIGKILL)
        _wait_pids_dead(members, 0.3)


def _kill_pid(pid: int) -> bool:
    if not pid or pid == os.getpid() or not _pid_alive(pid):
        return False
    try:
        if os.name == "nt":
            tk_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                check=False,
                creationflags=tk_flags,
            )
        else:
            _kill_unix_tree(pid)
        return True
    except OSError:
        return False


def stop_run_hard(run_dir: Path) -> dict[str, Any]:
    """Kill Ralph now and reclaim leased tasks. In-flight progress may be lost.

    Pause is the drain path. This is the dashboard Hard stop path.
    """
    run_dir = Path(run_dir).resolve()
    result = _kill_session_and_reclaim(run_dir)
    if (run_dir / "harness.db").is_file():
        append_event(
            run_dir,
            {
                "source": "ui",
                "event": "runner_stop_hard",
                "pids": result.get("pids"),
                "killed": result.get("killed"),
                "reclaimed_leases": result.get("reclaimed_leases"),
                "lock_cleared": result.get("lock_cleared"),
                "lock_holder": result.get("lock_holder"),
            },
        )
    return {
        "ok": bool(result.get("ok")),
        "killed": result.get("killed"),
        "reclaimed_leases": result.get("reclaimed_leases"),
        "lock_cleared": result.get("lock_cleared"),
        "lock_holder": result.get("lock_holder"),
        "status": result.get("status") or runner_status(run_dir),
        "error": result.get("error"),
    }
