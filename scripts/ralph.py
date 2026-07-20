#!/usr/bin/env python3
"""
Ralph outer loop â€” cross-platform (Windows / Linux / macOS).

SpecterOps Day Shift style: each iteration is a fresh `vf run-once` process;
durable state lives on disk (DB + evidence), not in the model context.

Exit codes from `vf run-once` (PROTOCOL):
  0  progress   -> continue
  10 idle/done  -> success stop
  20 infra      -> retry with backoff
  30 config     -> halt

Usage:
  python scripts/ralph.py --run-dir runs/myapp/run-001
  python scripts/ralph.py --run-dir ... --max-iterations 100
  python -m scripts.ralph --run-dir ...   # if package path set

Stop early: create a file named STOP inside the run directory
  (or pass --stop-file PATH).
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence


# Mirror vulnforge.cli exit codes (keep in sync with PROTOCOL.md / exit_codes.py)
EXIT_PROGRESS = 0
EXIT_IDLE = 10
EXIT_BUSY = 11  # multi-worker: lease wait — do not count as progress
EXIT_INFRA = 20
EXIT_CONFIG = 30

# Ralph's own process exits (documented in PROTOCOL.md â€” outer loop section)
RALPH_OK = 0  # clean operator stop (STOP file) or dry-run finished
RALPH_IDLE = 10  # vf reported idle/complete
RALPH_INFRA = 20  # infra retries exhausted
RALPH_CONFIG = 30  # config / hard error
RALPH_BUDGET = 40  # max-iterations or wall-clock/task budget hit
RALPH_INTERRUPT = 130


@dataclass
class RalphConfig:
    run_dir: Optional[Path]
    max_iterations: int
    max_infra_retries: int
    sleep_seconds: float
    infra_backoff_base: float
    vf_command: list[str]
    stop_file: Optional[Path]
    config_path: Optional[Path]
    dry_run: bool
    verbose: bool
    task_timeout: Optional[float]  # seconds; None = no subprocess timeout
    max_wall_seconds: Optional[float]
    max_tasks: Optional[int]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str, *, verbose: bool = True) -> None:
    if verbose:
        print(f"[ralph {utc_now()}] {msg}", flush=True)


def _subprocess_no_window_kwargs() -> dict:
    """
    On Windows, hide console windows for child python.exe / console apps.

    CREATE_NO_WINDOW prevents the brief CMD flash when Ralph spawns
    ``vf run-once`` / ``vf project`` from a detached dashboard worker.
    No-op on non-Windows.
    """
    if os.name != "nt":
        return {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return {"creationflags": flags}


def default_vf_command() -> list[str]:
    """
    Prefer the same interpreter running ralph, so venv is respected.

    Override with --vf-command 'python -m vulnforge.cli' or a full path to vulnforge.
    """
    return [sys.executable, "-m", "vulnforge.cli"]


def parse_vf_command(s: str) -> list[str]:
    """
    Split a shell-like command string portably.

    On Windows, shlex.split(..., posix=False) handles backslashes better.
    """
    posix = os.name != "nt"
    parts = shlex.split(s, posix=posix)
    if not parts:
        raise ValueError("--vf-command must not be empty")
    return parts


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ralph",
        description="Outer loop driver for vulnforge (vf run-once).",
    )
    p.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Run directory containing harness.db (passed to vf as --run-dir)",
    )
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional config YAML path forwarded to vf",
    )
    p.add_argument(
        "--max-iterations",
        type=int,
        default=200,
        help="Hard cap on run-once invocations (default: 200)",
    )
    p.add_argument(
        "--max-infra-retries",
        type=int,
        default=5,
        help=(
            "Consecutive EXIT_INFRA (20) before giving up (default: 5). "
            "For unattended runs keep this >= run.max_task_attempts (default 3) "
            "so the DB can deadletter poison tasks before Ralph infra_give_up."
        ),
    )
    p.add_argument(
        "--sleep-seconds",
        type=float,
        default=2.0,
        help="Pause after each successful progress iteration (default: 2)",
    )
    p.add_argument(
        "--infra-backoff-base",
        type=float,
        default=5.0,
        help="Base seconds for infra backoff: base * attempt (default: 5)",
    )
    p.add_argument(
        "--vf-command",
        type=str,
        default=None,
        help='Command to invoke vf, e.g. "python -m vulnforge.cli" or path to vf entrypoint',
    )
    p.add_argument(
        "--stop-file",
        type=Path,
        default=None,
        help="STOP file path (default: <run-dir>/STOP if run-dir set)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned vf argv once and exit 0 (does not fake idle/complete)",
    )
    p.add_argument(
        "--task-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "Kill a hung vf run-once after this many seconds "
            "(recommended: llm.timeout_seconds + slack, e.g. 900). "
            "Default: no timeout (unsafe for unattended runs)."
        ),
    )
    p.add_argument(
        "--max-wall-seconds",
        type=float,
        default=None,
        help="Stop with exit 40 after this many wall-clock seconds",
    )
    p.add_argument(
        "--max-tasks",
        type=int,
        default=None,
        help="Stop with exit 40 after this many progress (exit 0) iterations",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Less logging",
    )
    return p


def config_from_args(args: argparse.Namespace) -> RalphConfig:
    vf_cmd = (
        parse_vf_command(args.vf_command)
        if args.vf_command
        else default_vf_command()
    )
    run_dir = args.run_dir.resolve() if args.run_dir else None
    stop = args.stop_file
    if stop is None and run_dir is not None:
        stop = run_dir / "STOP"
    elif stop is not None:
        stop = stop.resolve()

    return RalphConfig(
        run_dir=run_dir,
        max_iterations=args.max_iterations,
        max_infra_retries=args.max_infra_retries,
        sleep_seconds=args.sleep_seconds,
        infra_backoff_base=args.infra_backoff_base,
        vf_command=vf_cmd,
        stop_file=stop,
        config_path=args.config.resolve() if args.config else None,
        dry_run=args.dry_run,
        verbose=not args.quiet,
        task_timeout=args.task_timeout,
        max_wall_seconds=args.max_wall_seconds,
        max_tasks=args.max_tasks,
    )


def build_run_once_argv(cfg: RalphConfig) -> list[str]:
    # --config is a global argparse option and must precede the subcommand.
    argv = list(cfg.vf_command)
    if cfg.config_path is not None:
        argv += ["--config", str(cfg.config_path)]
    argv += ["run-once"]
    if cfg.run_dir is not None:
        argv += ["--run-dir", str(cfg.run_dir)]
    return argv


def stop_requested(cfg: RalphConfig) -> bool:
    if cfg.stop_file is None:
        return False
    return cfg.stop_file.is_file()


def append_ralph_event(cfg: RalphConfig, event: dict) -> None:
    """Best-effort append to run-dir/events.jsonl (no-op if no run_dir)."""
    if cfg.run_dir is None:
        return
    path = cfg.run_dir / "events.jsonl"
    try:
        import json

        event = {"ts": utc_now(), "source": "ralph", **event}
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError as e:
        log(f"warning: could not write events.jsonl: {e}", verbose=cfg.verbose)


def project_on_stop(cfg: RalphConfig, reason: str) -> None:
    """
    Best-effort ``vf project`` so STATE/REPORT are fresh when Ralph stops
    with residual work (give-up, budget, STOP) rather than only on idle.
    """
    if cfg.run_dir is None:
        return
    argv = list(cfg.vf_command)
    if cfg.config_path is not None:
        argv += ["--config", str(cfg.config_path)]
    argv += ["project", "--run-dir", str(cfg.run_dir)]
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    log(f"project-on-stop ({reason}): {argv!r}", verbose=cfg.verbose)
    try:
        completed = subprocess.run(
            argv,
            cwd=str(PROJECT_ROOT),
            check=False,
            timeout=120,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            **_subprocess_no_window_kwargs(),
        )
        append_ralph_event(
            cfg,
            {
                "event": "project_on_stop",
                "reason": reason,
                "exit_code": int(completed.returncode),
            },
        )
        if completed.returncode != 0 and cfg.verbose:
            tail = (completed.stderr or completed.stdout or "")[-1500:]
            if tail:
                log(f"project-on-stop stderr/stdout:\n{tail}", verbose=True)
    except Exception as e:
        log(f"project-on-stop failed: {e}", verbose=cfg.verbose)
        append_ralph_event(
            cfg,
            {"event": "project_on_stop", "reason": reason, "error": str(e)},
        )


def invoke_run_once(cfg: RalphConfig) -> int:
    """
    Run one vf run-once as a subprocess. Returns process exit code.

    Notes:
      - Does not shell=True (safe on Windows/Linux).
      - Optional --task-timeout kills hung children (counts as EXIT_INFRA).
    """
    argv = build_run_once_argv(cfg)
    log(f"exec: {argv!r}", verbose=cfg.verbose)

    # cwd: harness package root (parent of scripts/) so `python -m vulnforge.cli` works
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    t0 = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(PROJECT_ROOT),
            check=False,
            timeout=cfg.task_timeout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            **_subprocess_no_window_kwargs(),
        )
    except FileNotFoundError as e:
        log(f"vf command not found: {e}", verbose=True)
        append_ralph_event(cfg, {"event": "spawn_error", "error": str(e), "argv": argv})
        return EXIT_CONFIG
    except subprocess.TimeoutExpired as e:
        dur = time.monotonic() - t0
        log(
            f"vf run-once timed out after {cfg.task_timeout}s (elapsed={dur:.1f}s)",
            verbose=True,
        )
        append_ralph_event(
            cfg,
            {
                "event": "timeout",
                "timeout_s": cfg.task_timeout,
                "duration_s": dur,
                "argv": argv,
            },
        )
        # Best-effort: TimeoutExpired may include partial output
        if e.stdout:
            log(f"vf stdout (partial): {e.stdout[-2000:]}", verbose=cfg.verbose)
        if e.stderr:
            log(f"vf stderr (partial): {e.stderr[-2000:]}", verbose=cfg.verbose)
        return EXIT_INFRA
    except OSError as e:
        log(f"failed to spawn vf: {e}", verbose=True)
        append_ralph_event(cfg, {"event": "spawn_error", "error": str(e), "argv": argv})
        return EXIT_INFRA

    dur = time.monotonic() - t0
    code = int(completed.returncode)
    quiet_codes = (EXIT_PROGRESS, EXIT_BUSY, EXIT_IDLE)
    if completed.stdout and (cfg.verbose or code not in quiet_codes):
        tail = completed.stdout[-4000:]
        log(f"vf stdout:\n{tail}", verbose=cfg.verbose)
    if completed.stderr:
        tail = completed.stderr[-4000:]
        log(f"vf stderr:\n{tail}", verbose=True if code not in quiet_codes else cfg.verbose)

    append_ralph_event(
        cfg,
        {
            "event": "run_once",
            "exit_code": code,
            "duration_s": round(dur, 3),
            "argv": argv,
        },
    )
    return code


def run_loop(cfg: RalphConfig) -> int:
    """
    Main Ralph loop. Returns process exit code for the loop itself.
    """
    if cfg.dry_run:
        argv = build_run_once_argv(cfg)
        log(f"dry-run argv: {argv!r}", verbose=True)
        log("dry-run complete (no execution)", verbose=True)
        return RALPH_OK

    if cfg.max_iterations < 1:
        log("max-iterations must be >= 1", verbose=True)
        return RALPH_CONFIG

    if cfg.run_dir is not None and not cfg.run_dir.is_dir():
        log(f"run-dir does not exist: {cfg.run_dir}", verbose=True)
        return RALPH_CONFIG

    infra_streak = 0
    progress_count = 0
    # Charged iterations count toward --max-iterations. EXIT_BUSY must NOT charge
    # (same idea as max_tasks): a waiting multi-worker burns ~1 loop/sec while a
    # peer holds recon, and default max_iterations=200 would exit mid-recon with
    # progress_count=0 — leaving only one agent for post-recon hunts.
    charged = 0
    attempt = 0
    wall_start = time.monotonic()

    log(
        f"start max_iterations={cfg.max_iterations} "
        f"task_timeout={cfg.task_timeout} "
        f"max_wall_seconds={cfg.max_wall_seconds} "
        f"max_tasks={cfg.max_tasks} "
        f"vf={cfg.vf_command!r} run_dir={cfg.run_dir}",
        verbose=cfg.verbose,
    )
    append_ralph_event(
        cfg,
        {
            "event": "ralph_start",
            "max_iterations": cfg.max_iterations,
            "task_timeout": cfg.task_timeout,
            "max_wall_seconds": cfg.max_wall_seconds,
            "max_tasks": cfg.max_tasks,
        },
    )

    while charged < cfg.max_iterations:
        if stop_requested(cfg):
            log(f"STOP file present ({cfg.stop_file}); exiting cleanly", verbose=True)
            append_ralph_event(
                cfg,
                {
                    "event": "stop_file",
                    "iteration": charged,
                    "attempt": attempt,
                },
            )
            project_on_stop(cfg, "stop_file")
            return RALPH_OK

        if cfg.max_wall_seconds is not None:
            elapsed = time.monotonic() - wall_start
            if elapsed >= cfg.max_wall_seconds:
                log(
                    f"wall-clock budget hit ({elapsed:.0f}s >= {cfg.max_wall_seconds}s)",
                    verbose=True,
                )
                append_ralph_event(
                    cfg,
                    {
                        "event": "budget_wall",
                        "elapsed_s": elapsed,
                        "iteration": charged,
                        "attempt": attempt,
                    },
                )
                project_on_stop(cfg, "budget_wall")
                return RALPH_BUDGET

        if cfg.max_tasks is not None and progress_count >= cfg.max_tasks:
            log(
                f"task budget hit (progress_count={progress_count} >= {cfg.max_tasks})",
                verbose=True,
            )
            append_ralph_event(
                cfg,
                {
                    "event": "budget_tasks",
                    "progress_count": progress_count,
                    "iteration": charged,
                    "attempt": attempt,
                },
            )
            project_on_stop(cfg, "budget_tasks")
            return RALPH_BUDGET

        attempt += 1
        log(
            f"iteration {charged + 1}/{cfg.max_iterations} (attempt {attempt})",
            verbose=cfg.verbose,
        )
        code = invoke_run_once(cfg)

        if code == EXIT_BUSY:
            # Peer working / lease cap full — keep looping without charging
            # --max-tasks or --max-iterations (critical for multi-worker Start
            # while recon is the only leased task for minutes).
            infra_streak = 0
            log("busy (lease wait / peer working)", verbose=cfg.verbose)
            if cfg.sleep_seconds > 0:
                time.sleep(cfg.sleep_seconds)
            continue

        # All non-busy outcomes consume one iteration slot.
        charged += 1

        if code == EXIT_PROGRESS:
            infra_streak = 0
            progress_count += 1
            log(f"progress (total={progress_count})", verbose=cfg.verbose)
            if cfg.sleep_seconds > 0:
                time.sleep(cfg.sleep_seconds)
            continue

        if code == EXIT_IDLE:
            log("idle/complete — nothing left to do", verbose=True)
            append_ralph_event(
                cfg,
                {
                    "event": "idle",
                    "progress_count": progress_count,
                    "iteration": charged,
                    "attempt": attempt,
                },
            )
            # Idle path already projects inside vf run-once; no extra project needed.
            return RALPH_IDLE

        if code == EXIT_INFRA:
            infra_streak += 1
            log(
                f"infra failure streak={infra_streak}/{cfg.max_infra_retries}",
                verbose=True,
            )
            if infra_streak >= cfg.max_infra_retries:
                log("max consecutive infra failures; giving up", verbose=True)
                append_ralph_event(
                    cfg,
                    {
                        "event": "infra_give_up",
                        "infra_streak": infra_streak,
                        "iteration": charged,
                        "attempt": attempt,
                    },
                )
                project_on_stop(cfg, "infra_give_up")
                return RALPH_INFRA
            delay = cfg.infra_backoff_base * infra_streak
            log(f"backoff sleep {delay}s", verbose=cfg.verbose)
            time.sleep(delay)
            continue

        if code == EXIT_CONFIG:
            log("config/hard error from vulnforge; halting", verbose=True)
            append_ralph_event(
                cfg,
                {
                    "event": "config_halt",
                    "iteration": charged,
                    "attempt": attempt,
                },
            )
            project_on_stop(cfg, "config_halt")
            return RALPH_CONFIG

        # Unknown exit code: treat as config-level halt (safer than infinite retry)
        log(f"unknown vf exit code {code}; halting", verbose=True)
        append_ralph_event(
            cfg,
            {
                "event": "unknown_exit",
                "exit_code": code,
                "iteration": charged,
                "attempt": attempt,
            },
        )
        project_on_stop(cfg, "unknown_exit")
        return RALPH_CONFIG

    log(
        f"max iterations reached (progress_count={progress_count})",
        verbose=True,
    )
    append_ralph_event(
        cfg,
        {
            "event": "budget_iterations",
            "progress_count": progress_count,
            "attempt": attempt,
        },
    )
    project_on_stop(cfg, "budget_iterations")
    return RALPH_BUDGET


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    cfg = config_from_args(args)
    try:
        return run_loop(cfg)
    except KeyboardInterrupt:
        log("interrupted by user", verbose=True)
        return RALPH_INTERRUPT


if __name__ == "__main__":
    sys.exit(main())
