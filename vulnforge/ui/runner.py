"""
Background Ralph / run lifecycle for the dashboard.

Start   -  spawn `scripts/ralph.py --run-dir ...` (or init + ralph)
Pause   -  write STOP so Ralph exits between iterations
Resume  -  remove STOP and spawn Ralph again if not already running
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

from vulnforge.util import append_event, utc_now_iso


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PID_NAME = "ralph.pid"
STOP_NAME = "STOP"
META_NAME = "runner.json"


def _pid_path(run_dir: Path) -> Path:
    return run_dir / PID_NAME


def _stop_path(run_dir: Path) -> Path:
    return run_dir / STOP_NAME


def _meta_path(run_dir: Path) -> Path:
    return run_dir / META_NAME


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


def start_run(
    run_dir: Path,
    *,
    task_timeout: float = 900,
    max_tasks: Optional[int] = 50,
    max_iterations: int = 200,
    max_wall_seconds: Optional[float] = None,
    config: Optional[Path] = None,
    workers: int = 1,
    loop_profile_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Start Ralph against an existing run directory.
    Clears STOP if present (start implies resume-from-stop).

    workers>1 spawns multiple Ralph processes. With
    ``run.max_leases_parallel`` > 1 (set from Settings max concurrent agents),
    run-once skips exclusive run.lock and SQLite caps concurrent leases so
    agents truly run in parallel.
    """
    run_dir = Path(run_dir).resolve()
    if not (run_dir / "harness.db").is_file():
        return {"ok": False, "error": "not a valid run dir (missing harness.db)"}

    st = runner_status(run_dir)
    if st["alive"]:
        return {"ok": False, "error": "already running", "status": st}

    # clear pause flag
    try:
        _stop_path(run_dir).unlink(missing_ok=True)
    except OSError:
        pass

    workers = max(1, int(workers))
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
        # detach from console; new process group
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0x00000008)

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


def pause_run(run_dir: Path) -> dict[str, Any]:
    """
    Cooperative pause: write STOP. Ralph exits after current run-once.
    """
    run_dir = Path(run_dir).resolve()
    if not (run_dir / "harness.db").is_file():
        return {"ok": False, "error": "invalid run dir"}
    try:
        _stop_path(run_dir).write_text(
            f"paused_at={utc_now_iso()}\n", encoding="utf-8"
        )
    except OSError as e:
        return {"ok": False, "error": str(e)}
    append_event(run_dir, {"source": "ui", "event": "runner_pause"})
    return {"ok": True, "status": runner_status(run_dir)}


def resume_run(
    run_dir: Path,
    **start_kwargs: Any,
) -> dict[str, Any]:
    """Remove STOP and start Ralph if not running."""
    run_dir = Path(run_dir).resolve()
    try:
        _stop_path(run_dir).unlink(missing_ok=True)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    append_event(run_dir, {"source": "ui", "event": "runner_resume"})
    st = runner_status(run_dir)
    if st["alive"]:
        return {"ok": True, "status": st, "note": "already running; STOP cleared"}
    return start_run(run_dir, **start_kwargs)


# start_run signature includes workers=  -  resume_run forwards via **start_kwargs


def _kill_pid(pid: int) -> bool:
    if not pid or not _pid_alive(pid):
        return False
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
        else:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            if _pid_alive(pid):
                os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def stop_run_hard(run_dir: Path) -> dict[str, Any]:
    """
    Hard stop: STOP + terminate all Ralph worker processes if alive.
    Use when cooperative pause is not enough.
    """
    run_dir = Path(run_dir).resolve()
    pause_run(run_dir)
    pids = _read_worker_pids(run_dir)
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
    append_event(
        run_dir,
        {
            "source": "ui",
            "event": "runner_stop_hard",
            "pid": pids[0] if pids else None,
            "pids": pids,
            "killed": killed_any,
        },
    )
    return {
        "ok": True,
        "killed": killed_any,
        "pids": pids,
        "status": runner_status(run_dir),
    }
