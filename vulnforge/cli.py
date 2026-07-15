"""
CLI entrypoints for vulnforge.

Commands: vf init | run-once | status | project | apply-candidate | delete-run | dashboard | tool-gaps
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
import uuid
from pathlib import Path
from typing import Any, Optional

import yaml

from vulnforge.db import Database, RunLock
from vulnforge.util import (
    append_event,
    build_target_manifest,
    hash_prompt_bundle,
    next_run_id,
    target_id_from_path,
    write_json,
)

from vulnforge.control.exit_codes import (
    DEFERRED_TASK_KINDS,
    EXIT_BUSY,
    EXIT_CONFIG,
    EXIT_IDLE,
    EXIT_INFRA,
    EXIT_PROGRESS,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main(argv: Optional[list[str]] = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        cfg = load_config(getattr(args, "config", None))
        cmd = args.command
        if cmd == "init":
            return cmd_init(args, cfg)
        if cmd == "run-once":
            return cmd_run_once(args, cfg)
        if cmd == "status":
            return cmd_status(args, cfg)
        if cmd == "project":
            return cmd_project(args, cfg)
        if cmd == "apply-candidate":
            return cmd_apply_candidate(args, cfg)
        if cmd == "dashboard":
            return cmd_dashboard(args, cfg)
        if cmd == "delete-run":
            return cmd_delete_run(args, cfg)
        if cmd == "tool-gaps":
            return cmd_tool_gaps(args, cfg)
        print(f"unknown command: {cmd}", file=sys.stderr)
        return EXIT_CONFIG
    except SystemExit as e:
        # argparse
        code = e.code if isinstance(e.code, int) else EXIT_CONFIG
        return code if code is not None else EXIT_CONFIG
    except Exception as e:
        print(f"vf fatal: {e}", file=sys.stderr)
        if os.environ.get("VF_DEBUG"):
            traceback.print_exc()
        return EXIT_CONFIG


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vf", description="VulnForge CLI")
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config YAML (default: config/default.yaml)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="Initialize a new audit run")
    init_p.add_argument("--target", type=Path, required=True)
    init_p.add_argument("--profile", default=None, help="Profile (default from config)")
    init_p.add_argument(
        "--runs-root",
        type=Path,
        default=None,
        help="Override runs root directory",
    )
    init_p.add_argument(
        "--strategy",
        choices=["discovery", "file_by_file", "recon_docs"],
        default="discovery",
        help="Init strategy: discovery, file_by_file, or recon_docs",
    )
    init_p.add_argument(
        "--docs-path",
        type=Path,
        default=None,
        help="Docs file or directory for recon_docs strategy",
    )
    init_p.add_argument(
        "--recon-agent",
        dest="agent_ids",
        action="append",
        default=None,
        help="Recon agent id to run (repeatable; default: active collection set)",
    )
    init_p.add_argument(
        "--recon-brief",
        dest="operator_notes",
        default="",
        help="Extra instructions for the recon agent(s)",
    )
    init_p.add_argument(
        "--dynamic-skills",
        action="store_true",
        default=False,
        help="After recon, generate N target-specific hunt skills for this run",
    )
    init_p.add_argument(
        "--dynamic-skill-count",
        type=int,
        default=3,
        help="Number of custom hunt skills to generate (1–10; default 3)",
    )

    once = sub.add_parser("run-once", help="Lease and execute one task")
    once.add_argument("--run-dir", type=Path, default=None)

    st = sub.add_parser("status", help="Show run summary")
    st.add_argument("--run-dir", type=Path, default=None)

    proj = sub.add_parser("project", help="Regenerate project/ from DB")
    proj.add_argument("--run-dir", type=Path, default=None)

    ac = sub.add_parser("apply-candidate", help="Apply inbox candidate JSON")
    ac.add_argument("--file", type=Path, required=True)
    ac.add_argument("--run-dir", type=Path, default=None)

    dash = sub.add_parser("dashboard", help="Open web UI for runs (live + history)")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=8787)
    dash.add_argument(
        "--runs-root",
        type=Path,
        default=None,
        help="Override runs root (default from config)",
    )

    del_p = sub.add_parser(
        "delete-run",
        help="Permanently delete a run directory (DB, evidence, transcripts)",
    )
    del_p.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Run directory (default: latest under runs/)",
    )
    del_p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Required: confirm permanent deletion",
    )
    del_p.add_argument(
        "--force",
        action="store_true",
        help="Hard-stop runner if alive; allow delete even without harness.db",
    )

    tg = sub.add_parser(
        "tool-gaps",
        help="Analyze run transcripts for missing/failed tool signals (mech/llm/hybrid)",
    )
    tg.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Single run directory (default: latest under runs/)",
    )
    tg.add_argument(
        "--runs-root",
        type=Path,
        default=None,
        help="Runs root when using --all",
    )
    tg.add_argument(
        "--all",
        action="store_true",
        help="Analyze every run under --runs-root (default: runs/)",
    )
    tg.add_argument(
        "--mode",
        choices=("mechanical", "llm", "hybrid"),
        default=None,
        help="Analysis mode (default: run.tool_gaps_mode or mechanical)",
    )
    tg.add_argument(
        "--llm",
        action="store_true",
        help="Shortcut for --mode hybrid",
    )

    return p


def load_config(path: Optional[Path] = None) -> dict:
    cfg_path = path or (PROJECT_ROOT / "config" / "default.yaml")
    cfg_path = Path(cfg_path)
    if not cfg_path.is_file():
        raise FileNotFoundError(f"config not found: {cfg_path}")
    with cfg_path.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    # GUI / ui_settings.json overrides (host, model, context, concurrency)
    try:
        from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings

        cfg = apply_ui_settings_to_cfg(cfg, load_ui_settings())
    except Exception:
        pass
    # env overrides win last
    if os.environ.get("VF_BASE_URL"):
        cfg.setdefault("llm", {})["base_url"] = os.environ["VF_BASE_URL"]
    if os.environ.get("VF_MODEL"):
        cfg.setdefault("llm", {})["model"] = os.environ["VF_MODEL"]
    if os.environ.get("VF_HOST") and os.environ.get("VF_PORT"):
        cfg.setdefault("llm", {})["base_url"] = (
            f"http://{os.environ['VF_HOST']}:{os.environ['VF_PORT']}/v1"
        )
    cfg["_config_path"] = str(cfg_path.resolve())
    return cfg


def resolve_runs_root(cfg: dict, override: Optional[Path] = None) -> Path:
    if override is not None:
        return override.resolve()
    root = cfg.get("run", {}).get("runs_root", "runs")
    p = Path(root)
    if not p.is_absolute():
        p = (PROJECT_ROOT / p).resolve()
    return p


def resolve_run_dir(args, cfg: dict) -> Path:
    rd = getattr(args, "run_dir", None)
    if rd is not None:
        path = Path(rd).resolve()
        if not path.is_dir():
            raise FileNotFoundError(f"run-dir not found: {path}")
        return path
    runs_root = resolve_runs_root(cfg)
    if not runs_root.is_dir():
        raise FileNotFoundError(
            f"no runs under {runs_root}; pass --run-dir or run vf init"
        )
    # latest run-* by mtime
    candidates: list[Path] = []
    for target_dir in runs_root.iterdir():
        if not target_dir.is_dir():
            continue
        for run in target_dir.iterdir():
            if run.is_dir() and (run / "harness.db").is_file():
                candidates.append(run)
    if not candidates:
        raise FileNotFoundError("no harness.db runs found; run vf init first")
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def cmd_init(args, cfg: dict) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"target not found or not a directory: {target}", file=sys.stderr)
        return EXIT_CONFIG

    strategy = str(getattr(args, "strategy", None) or "discovery").strip().lower()
    docs_path_arg = getattr(args, "docs_path", None)
    docs_path: Optional[Path] = Path(docs_path_arg).resolve() if docs_path_arg else None

    from vulnforge.strategies import (
        STRATEGY_DISCOVERY,
        STRATEGY_FILE_BY_FILE,
        STRATEGY_RECON_DOCS,
        VALID_STRATEGIES,
        plan_file_by_file_hunts,
    )

    if strategy not in VALID_STRATEGIES:
        print(
            f"invalid strategy: {strategy}; "
            f"choose from {sorted(VALID_STRATEGIES)}",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    if strategy == STRATEGY_RECON_DOCS:
        if docs_path is None:
            print(
                "recon_docs strategy requires --docs-path (file or directory)",
                file=sys.stderr,
            )
            return EXIT_CONFIG
        if not docs_path.exists():
            print(f"docs-path not found: {docs_path}", file=sys.stderr)
            return EXIT_CONFIG

    profile = args.profile or cfg.get("run", {}).get("profile", "code_static")
    runs_root = resolve_runs_root(cfg, getattr(args, "runs_root", None))
    tid = target_id_from_path(target)
    rid = next_run_id(runs_root, tid)
    run_dir = runs_root / tid / rid
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "evidence").mkdir()
    (run_dir / "inbox").mkdir()
    (run_dir / "project").mkdir()

    # Optional progress callback (dashboard job or CLI stderr)
    progress = getattr(args, "progress", None)
    if progress is None:
        from vulnforge.init_progress import make_progress_writer

        progress = make_progress_writer(
            PROJECT_ROOT,
            getattr(args, "job_id", None),
            also_print=True,
        )
    progress(
        {
            "phase": "prepare",
            "status": "running",
            "message": f"Created run dir {tid}/{rid}",
            "target": str(target),
            "strategy": strategy,
            "target_id": tid,
            "run_id": rid,
            "run_dir": str(run_dir),
            "percent": 2,
        }
    )

    ignore = cfg.get("run", {}).get("ignore_globs") or []
    progress(
        {
            "phase": "inventory",
            "status": "running",
            "message": "Building target inventory (this can take a while on 10k+ files)...",
            "percent": 5,
        }
    )
    manifest = build_target_manifest(target, ignore, progress=progress)
    write_json(run_dir / "target_manifest.json", manifest)
    # Lightweight status for the run page while Ralph works
    write_json(
        run_dir / "init_status.json",
        {
            "phase": "inventory_done",
            "file_count": manifest.get("file_count"),
            "incomplete": manifest.get("incomplete"),
            "hashed_files": manifest.get("hashed_files"),
            "strategy": strategy,
        },
    )

    progress(
        {
            "phase": "prompt_pin",
            "status": "running",
            "message": "Hashing prompt bundle...",
            "files_seen": manifest.get("file_count"),
            "percent": 70,
        }
    )
    prompts_root = PROJECT_ROOT / "prompts" / "v1"
    prompt_pin = hash_prompt_bundle(prompts_root)

    max_tasks = int(cfg.get("run", {}).get("max_tasks") or 50)
    docs_path_stored = str(docs_path) if docs_path else None
    docs_meta: dict[str, Any] = {}
    digest_path_s: Optional[str] = None

    # recon_docs: ingest before run row so config_json has digest path
    if strategy == STRATEGY_RECON_DOCS:
        from vulnforge.docs_ingest import ingest_docs

        progress(
            {
                "phase": "docs",
                "status": "running",
                "message": f"Ingesting docs from {docs_path}...",
                "percent": 80,
            }
        )
        digest_path = run_dir / "docs_digest.md"
        docs_meta = ingest_docs(docs_path, digest_path)  # type: ignore[arg-type]
        digest_path_s = str(digest_path.resolve())

    progress(
        {
            "phase": "database",
            "status": "running",
            "message": "Creating harness.db and queue...",
            "percent": 90,
        }
    )
    db = Database.create(run_dir / "harness.db")
    # store compact config (no huge blobs)
    # Dynamic skills: only for recon-based strategies
    init_dynamic_skills = bool(getattr(args, "dynamic_skills", False))
    try:
        init_dynamic_skill_count = int(getattr(args, "dynamic_skill_count", 3) or 3)
    except (TypeError, ValueError):
        init_dynamic_skill_count = 3
    init_dynamic_skill_count = max(1, min(init_dynamic_skill_count, 10))
    if strategy == STRATEGY_FILE_BY_FILE:
        init_dynamic_skills = False

    cfg_store = {
        "llm": cfg.get("llm", {}),
        "run": {
            **cfg.get("run", {}),
            "profile": profile,
            "strategy": strategy,
            "docs_path": docs_path_stored,
            "docs_digest": digest_path_s,
            "max_tasks": max_tasks,
            "dynamic_skills": init_dynamic_skills,
            "dynamic_skill_count": init_dynamic_skill_count if init_dynamic_skills else 0,
        },
        "stages": cfg.get("stages", {}),
        "packet": cfg.get("packet", {}),
        "tools": cfg.get("tools", {}),
    }
    db.insert_run(
        run_id=rid,
        target_path=str(target),
        profile=profile,
        prompt_pin=prompt_pin,
        config=cfg_store,
    )

    # Optional operator recon selection / brief (UI + CLI)
    init_agent_ids = [
        str(a).strip().lower()
        for a in (getattr(args, "agent_ids", None) or [])
        if str(a).strip()
    ][:32]
    init_operator_notes = str(getattr(args, "operator_notes", None) or "").strip()[:6000]

    def _attach_dynamic_skills(recon_pl: dict[str, Any]) -> None:
        if init_dynamic_skills:
            recon_pl["dynamic_skills"] = True
            recon_pl["dynamic_skill_count"] = init_dynamic_skill_count

    from vulnforge.stages.recon import enqueue_recon_agent_tasks, resolve_recon_agent_ids

    try:
        recon_agent_ids = resolve_recon_agent_ids(init_agent_ids or None)
    except Exception:
        recon_agent_ids = list(init_agent_ids or [])

    hunts_enqueued = 0
    recon_task_ids: list[int] = []
    if strategy == STRATEGY_FILE_BY_FILE:
        # No recon — plan hunts from file index at init.
        payloads = plan_file_by_file_hunts(
            target,
            ignore=ignore,
            max_tasks=max_tasks,
            classes=None,
        )
        for pl in payloads:
            db.enqueue_task("hunt", pl, priority=50)
            db.upsert_coverage_fact(
                pl.get("area", "app"),
                pl.get("class", "wildcard"),
                path=(pl.get("path_hints") or [""])[0],
                visit_delta=0,
            )
        hunts_enqueued = len(payloads)
    elif strategy == STRATEGY_RECON_DOCS:
        docs_summary = str(docs_meta.get("summary") or "")
        if init_operator_notes and docs_summary:
            operator_brief = (
                init_operator_notes.rstrip()
                + "\n\n## Docs summary\n"
                + docs_summary
            )
        else:
            operator_brief = init_operator_notes or docs_summary
        recon_payload: dict[str, Any] = {
            "target": str(target),
            "strategy": STRATEGY_RECON_DOCS,
            "docs_digest": digest_path_s,
            "docs_path": docs_path_stored,
            "operator_brief": operator_brief,
            "operator_notes": operator_brief,
            "recon_generation": 1,
        }
        _attach_dynamic_skills(recon_payload)
        # One Ralph task per recon agent; architecture merges when batch completes.
        recon_task_ids = enqueue_recon_agent_tasks(
            db,
            recon_payload,
            recon_agent_ids or resolve_recon_agent_ids(None),
            base_priority=10,
        )
    else:
        # discovery (default): recon only — one Ralph loop per agent profile
        recon_payload = {
            "target": str(target),
            "strategy": STRATEGY_DISCOVERY,
            "recon_generation": 1,
        }
        if init_operator_notes:
            recon_payload["operator_notes"] = init_operator_notes
            recon_payload["operator_brief"] = init_operator_notes
        _attach_dynamic_skills(recon_payload)
        recon_task_ids = enqueue_recon_agent_tasks(
            db,
            recon_payload,
            recon_agent_ids or resolve_recon_agent_ids(None),
            base_priority=10,
        )

    db.close()

    append_event(
        run_dir,
        {
            "source": "vf",
            "event": "init",
            "target": str(target),
            "profile": profile,
            "prompt_pin": prompt_pin,
            "file_count": manifest["file_count"],
            "strategy": strategy,
            "docs_path": docs_path_stored,
            "hunts_enqueued": hunts_enqueued,
            "docs_files": docs_meta.get("files"),
            "docs_chars": docs_meta.get("chars"),
            "manifest_incomplete": manifest.get("incomplete"),
        },
    )

    progress(
        {
            "phase": "done",
            "status": "done",
            "message": (
                f"Ready: {manifest.get('file_count')} files indexed"
                + (
                    " (inventory capped — large target)"
                    if manifest.get("incomplete")
                    else ""
                )
                + (f", {hunts_enqueued} hunts queued" if hunts_enqueued else "")
            ),
            "files_seen": manifest.get("file_count"),
            "percent": 100,
            "run_dir": str(run_dir),
            "key": f"{tid}/{rid}",
            "target_id": tid,
            "run_id": rid,
            "strategy": strategy,
        }
    )
    write_json(
        run_dir / "init_status.json",
        {
            "phase": "done",
            "status": "done",
            "file_count": manifest.get("file_count"),
            "incomplete": manifest.get("incomplete"),
            "strategy": strategy,
            "hunts_enqueued": hunts_enqueued,
        },
    )

    print(str(run_dir))
    return EXIT_PROGRESS


def cmd_status(args, cfg: dict) -> int:
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    db = Database.open(run_dir / "harness.db")
    s = db.summary()
    db.close()
    run = s.get("run") or {}
    print(f"run_dir: {run_dir}")
    print(f"target:  {run.get('target_path')}")
    print(f"profile: {run.get('profile')}")
    print(f"prompt:  {run.get('prompt_pin')}")
    print(f"tasks:   {s.get('tasks')}")
    print(f"findings:{s.get('findings')}")
    print(f"has_work:{s.get('has_work')}")
    stages = cfg.get("stages") or {}
    if stages.get("validate_llm"):
        print(
            "warning: stages.validate_llm is ON — mech-pass is needs_human; "
            "disprove may rejected_llm only (never auto-confirm). Same model "
            "as hunter is weak signal; leave false unless you want the extra "
            "LLM pass.",
            file=sys.stderr,
        )
    return EXIT_PROGRESS


def cmd_run_once(args, cfg: dict) -> int:
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG

    db_path = run_dir / "harness.db"
    if not db_path.is_file():
        print(f"missing harness.db in {run_dir}", file=sys.stderr)
        return EXIT_CONFIG

    max_parallel = max(1, int((cfg.get("run") or {}).get("max_leases_parallel") or 1))
    # Serial mode (default): exclusive run.lock for the whole task.
    # Parallel mode: skip exclusive lock — SQLite lease_next_task enforces
    # max_leases_parallel so multiple Ralph workers can run concurrent agents.
    lock: Optional[RunLock] = None
    if max_parallel <= 1:
        try:
            lock = RunLock(run_dir)
            lock.acquire()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return EXIT_INFRA

    db: Optional[Database] = None
    try:
        db = Database.open(db_path)
        db.reclaim_expired_leases()
        if not db.has_queued_or_leased():
            # Project projection on idle (idempotent, no LLM)
            # Only one worker should render: skip if others may still be leased.
            if db.count_leased_tasks() == 0:
                try:
                    from vulnforge.stages.render import render_all

                    render_all(run_dir, db)
                except Exception as e:
                    append_event(
                        run_dir, {"source": "vf", "event": "render_error", "error": str(e)}
                    )
                # Optional post-idle tool-gap projection (default off)
                if (cfg.get("run") or {}).get("auto_tool_gaps"):
                    try:
                        from vulnforge.tool_gaps import analyze_run_mode, write_reports

                        tg_mode = (cfg.get("run") or {}).get("tool_gaps_mode") or "mechanical"
                        analysis = analyze_run_mode(run_dir, str(tg_mode), cfg)
                        write_reports(run_dir, analysis)
                        append_event(
                            run_dir,
                            {
                                "source": "vf",
                                "event": "tool_gaps",
                                "gap_count": analysis.get("gap_count"),
                                "mode": analysis.get("mode"),
                                "auto": True,
                            },
                        )
                    except Exception as e:
                        append_event(
                            run_dir,
                            {
                                "source": "vf",
                                "event": "tool_gaps_error",
                                "error": str(e),
                            },
                        )
            append_event(run_dir, {"source": "vf", "event": "idle"})
            return EXIT_IDLE

        ttl = int(cfg.get("run", {}).get("lease_ttl_seconds", 1800))
        worker_id = f"vf-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        task = db.lease_next_task(
            worker_id, ttl_seconds=ttl, max_parallel=max_parallel
        )
        if task is None:
            # Empty queue → idle. Cap saturated (or peers still working) →
            # EXIT_BUSY so multi-worker Ralph keeps retrying WITHOUT burning
            # the --max-tasks progress budget (was EXIT_PROGRESS; second agent
            # would hit budget after ~50 lease waits and exit).
            leased_n = db.count_leased_tasks()
            still_work = db.has_queued_or_leased()
            if still_work and leased_n > 0:
                append_event(
                    run_dir,
                    {
                        "source": "vf",
                        "event": "lease_cap",
                        "max_leases_parallel": max_parallel,
                        "leased": leased_n,
                        "worker": worker_id,
                    },
                )
                return EXIT_BUSY
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "idle",
                    "reason": "no_lease",
                    "max_leases_parallel": max_parallel,
                    "leased": leased_n,
                },
            )
            return EXIT_IDLE

        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "lease",
                "task_id": task.id,
                "kind": task.kind,
                "worker": worker_id,
            },
        )

        try:
            result = dispatch_task(task, db, run_dir, cfg)
        except NotImplementedError as e:
            # Incomplete optional stages must not EXIT_CONFIG the campaign.
            # Known deferred kinds â†’ failed_task + progress.
            # Truly unknown kinds â†’ EXIT_CONFIG (control-plane error).
            kind = task.kind
            err = f"not_implemented: {e}"
            if kind == "validate_llm":
                # Should not raise after P0.2 stub; if it does, hold finding.
                try:
                    from vulnforge.stages import validate_llm as _vllm

                    raw_fid = (task.payload or {}).get("finding_id")
                    hold_fid, _fid_err = _vllm._parse_finding_id(raw_fid)
                    result = _vllm._safe_hold_incomplete(
                        task,
                        db,
                        run_dir,
                        hold_fid,
                        reason="validate_llm_not_implemented_caught",
                    )
                    # fall through to normal success / failed_task path below
                except Exception as hold_err:
                    db.fail_task(task.id, "failed_task", f"{err}; hold_failed: {hold_err}")
                    append_event(
                        run_dir,
                        {
                            "source": "vf",
                            "event": "not_implemented",
                            "task_id": task.id,
                            "kind": kind,
                            "attempt": task.attempt,
                            "error": err,
                        },
                    )
                    return EXIT_PROGRESS
            elif kind in DEFERRED_TASK_KINDS:
                db.fail_task(task.id, "failed_task", err)
                append_event(
                    run_dir,
                    {
                        "source": "vf",
                        "event": "not_implemented",
                        "task_id": task.id,
                        "kind": kind,
                        "attempt": task.attempt,
                        "error": str(e),
                    },
                )
                print(f"stage not implemented: {e}", file=sys.stderr)
                # Progress (0), not CONFIG (30): deferred stage must not halt Ralph
                return EXIT_PROGRESS
            else:
                # Unknown task kind â€” hard control-plane error
                db.fail_task(task.id, "failed_task", err)
                append_event(
                    run_dir,
                    {
                        "source": "vf",
                        "event": "unknown_task_kind",
                        "task_id": task.id,
                        "kind": kind,
                        "attempt": task.attempt,
                        "error": str(e),
                    },
                )
                print(f"unknown task kind: {kind}: {e}", file=sys.stderr)
                return EXIT_CONFIG
        except Exception as e:
            # Prefer typed infra; string match is a narrow fallback only.
            if _is_infra_exception(e):
                return handle_failed_infra(
                    db, run_dir, task, cfg, str(e), kind=task.kind
                )
            msg = str(e)
            db.fail_task(task.id, "failed_task", msg)
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "failed_task",
                    "task_id": task.id,
                    "kind": task.kind,
                    "attempt": task.attempt,
                    "error": msg,
                },
            )
            print(f"task failed: {e}", file=sys.stderr)
            if os.environ.get("VF_DEBUG"):
                traceback.print_exc()
            return EXIT_PROGRESS  # progress: task terminated

        status = result.get("status", "succeeded")
        if status == "failed_infra":
            return handle_failed_infra(
                db,
                run_dir,
                task,
                cfg,
                result.get("error", "infra"),
                kind=task.kind,
            )
        if status in ("failed_task", "blocked"):
            err = result.get("error", status)
            db.fail_task(task.id, status, err, result_extra=result)
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "failed_task",
                    "task_id": task.id,
                    "kind": task.kind,
                    "attempt": task.attempt,
                    "error": err,
                    "child_task_id": result.get("child_task_id"),
                    "recon_requeued": result.get("recon_requeued"),
                    "recon_generation": result.get("recon_generation"),
                },
            )
            return EXIT_PROGRESS

        db.complete_task(task.id, result, state="succeeded")
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "task_done",
                "task_id": task.id,
                "kind": task.kind,
                "result_keys": list(result.keys()),
            },
        )
        return EXIT_PROGRESS
    finally:
        if db is not None:
            db.close()
        if lock is not None:
            lock.release()


# Narrow transport phrases for uncaught exceptions (avoid bare "connection").
_INFRA_EXCEPTION_MARKERS = (
    "connection refused",
    "connection reset",
    "connection aborted",
    "connection error",
    "econnreset",
    "econnrefused",
    "timed out",
    "timeout",
    "temporarily unavailable",
)


def _is_infra_exception(exc: BaseException) -> bool:
    """True for typed / stdlib transport errors; string match is fallback only."""
    from vulnforge.llm import InfraError

    if isinstance(exc, InfraError):
        return True
    if isinstance(exc, (TimeoutError, ConnectionError, BrokenPipeError)):
        return True
    try:
        import httpx

        if isinstance(exc, (httpx.TransportError, httpx.TimeoutException)):
            return True
    except ImportError:
        pass
    low = str(exc).lower()
    return any(m in low for m in _INFRA_EXCEPTION_MARKERS)


def max_task_attempts(cfg: dict) -> int:
    """Cap on lease attempts before deadletter (default 3)."""
    return max(1, int((cfg.get("run") or {}).get("max_task_attempts", 3)))


def handle_failed_infra(
    db: Database,
    run_dir: Path,
    task,
    cfg: dict,
    error: str,
    *,
    kind: Optional[str] = None,
) -> int:
    """
    Infra failure path: requeue while under attempt cap; else deadletter.

    Returns EXIT_INFRA (retryable, under cap) or EXIT_PROGRESS (deadlettered).
    """
    err = error or "infra"
    attempt = int(getattr(task, "attempt", 0) or 0)
    max_att = max_task_attempts(cfg)
    kind = kind or getattr(task, "kind", None)
    if attempt >= max_att:
        db.deadletter_task(task.id, err)
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "deadletter",
                "task_id": task.id,
                "kind": kind,
                "attempt": attempt,
                "max_task_attempts": max_att,
                "error": err,
            },
        )
        return EXIT_PROGRESS
    # Under cap: mark last error and requeue for retry
    db.requeue_task(task.id, error=err)
    append_event(
        run_dir,
        {
            "source": "vf",
            "event": "failed_infra",
            "task_id": task.id,
            "kind": kind,
            "attempt": attempt,
            "max_task_attempts": max_att,
            "error": err,
        },
    )
    return EXIT_INFRA


def dispatch_task(task, db: Database, run_dir: Path, cfg: dict) -> dict[str, Any]:
    """Route task.kind to stage handler.

    Known deferred optional stages (``DEFERRED_TASK_KINDS``) raise
    ``NotImplementedError`` and are handled as ``failed_task`` + progress.
    Truly unknown kinds also raise, but ``cmd_run_once`` maps them to
    ``EXIT_CONFIG`` + event ``unknown_task_kind``.
    """
    kind = task.kind
    if kind == "recon":
        from vulnforge.stages import recon

        return recon.run(task, db, run_dir, cfg)
    if kind == "hunt":
        from vulnforge.stages import hunt

        return hunt.run(task, db, run_dir, cfg)
    if kind == "validate_mech":
        from vulnforge.stages import validate_mech

        return validate_mech.run(task, db, run_dir, cfg)
    if kind == "validate_llm":
        from vulnforge.stages import validate_llm

        return validate_llm.run(task, db, run_dir, cfg)
    if kind == "develop_poc":
        from vulnforge.stages import develop_poc

        return develop_poc.run(task, db, run_dir, cfg)
    if kind == "render":
        from vulnforge.stages import render

        return render.run(task, db, run_dir, cfg)
    if kind == "gapfill":
        from vulnforge.stages import gapfill

        return gapfill.run(task, db, run_dir, cfg)
    if kind == "tool_gaps":
        from vulnforge.stages import tool_gaps as tool_gaps_stage

        return tool_gaps_stage.run(task, db, run_dir, cfg)
    if kind == "generate_skill":
        from vulnforge.stages import generate_skill as generate_skill_stage

        return generate_skill_stage.run(task, db, run_dir, cfg)
    if kind == "generate_run_skills":
        from vulnforge.stages import generate_run_skills as generate_run_skills_stage

        return generate_run_skills_stage.run(task, db, run_dir, cfg)
    if kind in ("dedup", "feedback"):
        # Modules exist; not product stages â€” explicit deferred error (progress).
        raise NotImplementedError(f"deferred stage: {kind}")
    raise NotImplementedError(f"unknown task kind: {kind}")


def cmd_project(args, cfg: dict) -> int:
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    db = Database.open(run_dir / "harness.db")
    try:
        from vulnforge.stages.render import render_all

        paths = render_all(run_dir, db)
        print("wrote:", ", ".join(paths))
        return EXIT_PROGRESS
    except NotImplementedError as e:
        print(f"render not implemented: {e}", file=sys.stderr)
        return EXIT_CONFIG
    finally:
        db.close()



def cmd_tool_gaps(args, cfg: dict) -> int:
    """Mine tool-gap signals from transcripts/events/DB; write project projections."""
    from vulnforge.tool_gaps import analyze_run_mode, discover_run_dirs, write_reports

    mode = getattr(args, "mode", None)
    if getattr(args, "llm", False) and not mode:
        mode = "hybrid"
    if not mode:
        mode = (cfg.get("run") or {}).get("tool_gaps_mode") or "mechanical"

    if getattr(args, "all", False):
        runs_root = resolve_runs_root(cfg, getattr(args, "runs_root", None))
        if not runs_root.is_dir():
            print(f"runs-root not found: {runs_root}", file=sys.stderr)
            return EXIT_CONFIG
        run_dirs = discover_run_dirs(runs_root)
        if not run_dirs:
            print(f"no runs under {runs_root}", file=sys.stderr)
            return EXIT_CONFIG
        total_gaps = 0
        for rd in run_dirs:
            try:
                analysis = analyze_run_mode(rd, mode, cfg)
                write_reports(rd, analysis)
                n = int(analysis.get("gap_count") or 0)
                total_gaps += n
                print(f"{rd}: gaps={n} mode={analysis.get('mode')}")
            except Exception as e:
                print(f"{rd}: error: {e}", file=sys.stderr)
        print(f"analyzed {len(run_dirs)} run(s), total_gaps={total_gaps} mode={mode}")
        return EXIT_PROGRESS

    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    if not run_dir.is_dir():
        print(f"run-dir not found: {run_dir}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        analysis = analyze_run_mode(run_dir, mode, cfg)
        paths = write_reports(run_dir, analysis)
    except Exception as e:
        print(f"tool-gaps failed: {e}", file=sys.stderr)
        if os.environ.get("VF_DEBUG"):
            traceback.print_exc()
        return EXIT_CONFIG
    print(f"run_dir: {run_dir}")
    print(f"mode:    {analysis.get('mode') or mode}")
    print(f"gaps:    {analysis.get('gap_count', 0)}")
    stats = analysis.get("stats") or {}
    print(
        f"scanned: transcripts={stats.get('transcripts_scanned', 0)} "
        f"tool_calls={stats.get('tool_calls', 0)} notes={stats.get('notes_scanned', 0)}"
    )
    print("wrote:", ", ".join(paths))
    return EXIT_PROGRESS


def cmd_dashboard(args, cfg: dict) -> int:
    """Launch FastAPI dashboard (blocks)."""
    try:
        from vulnforge.ui.app import run_dashboard
    except ImportError as e:
        print(
            f"dashboard dependencies missing: {e}\n"
            "  pip install -e \".[ui]\"   # or install fastapi uvicorn jinja2",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    runs_root = None
    if getattr(args, "runs_root", None):
        runs_root = Path(args.runs_root).resolve()
    try:
        run_dashboard(
            host=args.host,
            port=int(args.port),
            runs_root=runs_root,
        )
    except KeyboardInterrupt:
        return EXIT_PROGRESS
    return EXIT_PROGRESS


def cmd_delete_run(args, cfg: dict) -> int:
    """Permanently delete a run directory under the runs root."""
    from vulnforge.ui import store as run_store

    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG

    runs_root = resolve_runs_root(cfg)
    try:
        run_dir = run_dir.resolve()
        runs_root = runs_root.resolve()
        rel = run_dir.relative_to(runs_root)
    except ValueError:
        print(
            f"run-dir is not under runs root {runs_root}: {run_dir}",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    parts = rel.parts
    if len(parts) < 2:
        print(
            f"expected runs/<target_id>/<run_id>, got: {run_dir}",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    target_id, run_id = parts[0], parts[1]

    if not args.yes:
        print(
            f"Refusing to delete without --yes:\n  {run_dir}\n"
            f"  target={target_id} run={run_id}\n"
            "This permanently removes harness.db, evidence/, transcripts/, project/.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    # --yes: always hard-stop runner if alive. --force: also allow missing harness.db.
    result = run_store.delete_run(
        runs_root,
        target_id,
        run_id,
        force=True,
        stop_runner=True,
        require_db=not bool(args.force),
    )
    if not result.get("ok"):
        print(result.get("error") or "delete failed", file=sys.stderr)
        return EXIT_CONFIG

    print(f"deleted: {result.get('path')}")
    if result.get("removed_parent"):
        print(f"removed empty target dir: {target_id}")
    return EXIT_PROGRESS


def cmd_apply_candidate(args, cfg: dict) -> int:
    """
    Apply inbox candidate JSON â†’ finding (candidate) + enqueue validate_mech.

    Same mechanical state machine as hunt submit *after* insert (validate_mech).
    Differences vs hunt ``submit_candidate`` (documented residuals):
      - No session-auth on evidence_id (disk pack under evidence/ is enough for mech)
      - ``no_poc`` + â‰¥20-char ``no_poc_justification`` can pass mech without a pack
      - Shape-checked here before insert; evidence existence checked only at mech
    """
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    path = Path(args.file)
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        return EXIT_CONFIG
    import json

    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"invalid JSON: {e}", file=sys.stderr)
        return EXIT_CONFIG
    if not isinstance(body, dict):
        print("candidate body must be a JSON object", file=sys.stderr)
        return EXIT_CONFIG

    from vulnforge.stages.hunt import validate_candidate_shape

    shape_errs = validate_candidate_shape(body)
    if shape_errs:
        print("candidate shape errors:", "; ".join(shape_errs), file=sys.stderr)
        return EXIT_CONFIG

    # Evidence policy note (not enforced here â€” validate_mech owns gates):
    # require evidence_id OR documented no_poc exception so operators get early feedback.
    has_eid = bool(body.get("evidence_id"))
    no_poc = bool(body.get("no_poc")) and len(
        str(body.get("no_poc_justification") or "")
    ) >= 20
    if not has_eid and not no_poc:
        print(
            "warning: no evidence_id and no no_poc+justification (â‰¥20 chars); "
            "validate_mech will set state rejected_mech unless a pack is added",
            file=sys.stderr,
        )

    db = Database.open(run_dir / "harness.db")
    try:
        run = db.get_run()
        profile = run["profile"] if run else "code_static"
        body = dict(body)
        body.setdefault("source", "apply_candidate")
        fid = db.insert_finding(body, state="candidate", profile=profile)
        db.enqueue_task("validate_mech", {"finding_id": fid}, priority=20)
        print(f"candidate finding_id={fid}")
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "apply_candidate",
                "finding_id": fid,
                "has_evidence_id": has_eid,
                "no_poc": bool(body.get("no_poc")),
            },
        )
        return EXIT_PROGRESS
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
