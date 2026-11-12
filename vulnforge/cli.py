"""
CLI entrypoints for vulnforge.

Commands: vf init | run-once | status | project | apply-candidate | delete-run |
dashboard | tool-gaps | export | export-validation-job | validate-poc |
develop-fix | verify-fix | hitl | policy | ci
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
import uuid
from pathlib import Path
from typing import Any, Optional

import yaml

from vulnforge.db import Database, RunLock
from vulnforge.errors import note_swallowed
from vulnforge.paths import PROJECT_ROOT
from vulnforge.settings.load import load_config
from vulnforge.util import (
    append_event,
    build_target_manifest,
    hash_prompt_bundle,
    next_run_id,
    target_id_from_path,
    write_json,
)

from vulnforge.control.exit_codes import (
    EXIT_BUSY,
    EXIT_CONFIG,
    EXIT_IDLE,
    EXIT_INFRA,
    EXIT_PROGRESS,
)


def main(argv: Optional[list[str]] = None) -> int:
    cmd: Optional[str] = None
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        cmd = args.command
        cfg = load_config(getattr(args, "config", None))
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
        if cmd == "export":
            return cmd_export(args, cfg)
        if cmd == "export-validation-job":
            return cmd_export_validation_job(args, cfg)
        if cmd == "validate-poc":
            return cmd_validate_poc(args, cfg)
        if cmd == "develop-fix":
            return cmd_develop_fix(args, cfg)
        if cmd == "verify-fix":
            return cmd_verify_fix(args, cfg)
        if cmd == "hitl":
            return cmd_hitl(args, cfg)
        if cmd == "policy":
            return cmd_policy(args, cfg)
        if cmd == "ci":
            return cmd_ci(args, cfg)
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
        if cmd == "ci":
            # vf ci speaks outcome codes only (vulnforge/ci/exit_codes.py).
            from vulnforge.ci.exit_codes import CI_ERROR

            return CI_ERROR
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
    add_init_arguments(init_p)

    ci_p = sub.add_parser(
        "ci",
        help="Headless CI campaign: init → Ralph → render, outcome exit code",
        description=(
            "Run a campaign to completion without a UI and exit with an OUTCOME "
            "code (not the run-once protocol codes): 0 = finished (or stopped "
            "on a budget) with no finding meeting --fail-on-*, 1 = threshold "
            "met, 2 = infra/integrity failure. Coverage gaps alone do not fail. "
            "CI never sets confirmed; a needs_human hit means needs review, "
            "not proven."
        ),
    )
    add_init_arguments(ci_p, target_required=False)
    ci_p.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Resume an existing run instead of --target (no init)",
    )
    ci_p.add_argument(
        "--max-cost-usd",
        type=float,
        default=None,
        help=(
            "Advisory spend cap for this invocation: stop leasing new tasks once "
            "the estimate reaches it (in-flight tasks may overrun). Needs prices "
            "(--price-*-per-mtok or ci.pricing). Unpriced or unmeasured usage "
            "stops leasing and exits 2."
        ),
    )
    ci_p.add_argument(
        "--price-input-per-mtok",
        type=float,
        default=None,
        help="Default USD per 1M input tokens for models without a ci.pricing entry",
    )
    ci_p.add_argument(
        "--price-output-per-mtok",
        type=float,
        default=None,
        help="Default USD per 1M output tokens for models without a ci.pricing entry",
    )
    ci_p.add_argument(
        "--max-time",
        default=None,
        help=(
            "Advisory wall-clock cap (seconds, or 90s / 45m / 2h / 1h30m): stop "
            "leasing new tasks once exceeded; in-flight tasks may overrun"
        ),
    )
    ci_p.add_argument(
        "--fail-on-state",
        action="append",
        default=None,
        metavar="STATE",
        help=(
            "Exit 1 if a finding is in this state: needs_human (needs review, "
            "not proven) or confirmed (human-accepted). Repeatable or comma list. "
            "With --fail-on-severity both must match."
        ),
    )
    ci_p.add_argument(
        "--fail-on-severity",
        default=None,
        metavar="LEVEL",
        help=(
            "Exit 1 if a needs_human/confirmed finding has severity_claim >= LEVEL "
            "(critical|high|medium|low|informational). Unrated findings meet it "
            "(fail closed)."
        ),
    )
    ci_p.add_argument(
        "--task-timeout",
        type=float,
        default=900.0,
        metavar="SECONDS",
        help=(
            "Kill one hung vf run-once after this many seconds (default 900). "
            "Raise it for slow models: 5 consecutive timeouts end the run with exit 2."
        ),
    )
    ci_p.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Optional cap on run-once invocations (default: unlimited)",
    )
    ci_p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Copy ci_result.json and the rendered report (project/) here for upload",
    )
    ci_p.add_argument(
        "--sarif",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Write SARIF 2.1.0 here (default with --output-dir: DIR/vulnforge.sarif). "
            "Includes confirmed and needs_human; needs_human alerts are titled "
            "'not a confirmed vulnerability'. An export failure exits 2."
        ),
    )
    ci_p.add_argument(
        "--sarif-confirmed-only",
        action="store_true",
        help="Leave needs_human (review items) out of the SARIF file",
    )
    ci_p.add_argument("-q", "--quiet", action="store_true", help="Less Ralph logging")

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

    exp = sub.add_parser(
        "export",
        help="Export findings report (json|md|csv|html|xlsx|docx|sarif; comma list → zip)",
    )
    exp.add_argument("--run-dir", type=Path, default=None)
    exp.add_argument(
        "--format",
        default="json",
        help="One format or comma-separated list (multi → zip). Default: json",
    )
    exp.add_argument(
        "--out",
        default=None,
        help="Output file, or - for stdout (default: <run>/exports/<report file>)",
    )
    exp.add_argument(
        "--include-needs-human",
        action="store_true",
        help="SARIF: also export needs_human (default: confirmed only)",
    )
    exp.add_argument(
        "--include-rejected",
        action="store_true",
        help="SARIF: also export rejected_* and superseded",
    )
    exp.add_argument(
        "--state",
        action="append",
        default=None,
        help="SARIF: explicit finding state to export (repeatable; overrides the include flags)",
    )
    for flag, label in (
        ("architecture", "recon architecture map"),
        ("hunts", "hunt coverage + hunt tasks"),
        ("summary", "campaign / task summary"),
        ("codemap", "mechanical codemap brief"),
        ("poc", "PoC / evidence pack contents"),
    ):
        exp.add_argument(
            f"--{flag}",
            action="store_true",
            help=f"Include {label} (narrative formats; SARIF/CSV are findings-only)",
        )

    evj = sub.add_parser(
        "export-validation-job",
        help="Export a finding + evidence pack as a validation handoff bundle",
    )
    evj.add_argument("--finding-id", type=int, required=True)
    evj.add_argument("--run-dir", type=Path, default=None)
    evj.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output directory (default: <run>/exports/validation-job-finding-N)",
    )
    evj.add_argument(
        "--no-zip",
        action="store_true",
        help="Skip writing the .zip sibling",
    )
    evj.add_argument(
        "--no-citations",
        action="store_true",
        help="Do not slice cited target files into the bundle",
    )

    vp = sub.add_parser(
        "validate-poc",
        help="Enqueue or run sandbox validate_poc (one-shot, or --iterate; never host exec, never confirms)",
    )
    vp.add_argument("--finding-id", type=int, required=True)
    vp.add_argument("--run-dir", type=Path, default=None)
    vp.add_argument(
        "--execute",
        action="store_true",
        help="Run immediately in-process (else only enqueue)",
    )
    vp.add_argument(
        "--iterate",
        action="store_true",
        help="Keep one microVM/gVisor session and rewrite/re-run until success or caps",
    )
    vp.add_argument(
        "--referee",
        action="store_true",
        help="Also run optional LLM referee (or set stages.validate_poc_referee)",
    )
    vp.add_argument(
        "--target-url",
        default="",
        help="Optional TARGET_URL env for the PoC process",
    )

    dfx = sub.add_parser(
        "develop-fix",
        help="Enqueue or run develop_fix: write evidence/<pack>/fix.patch (never applied, never confirms)",
    )
    dfx.add_argument("--finding-id", type=int, required=True)
    dfx.add_argument("--run-dir", type=Path, default=None)
    dfx.add_argument("--notes", default="", help="Operator notes for the patch author")
    dfx.add_argument("--force", action="store_true", help="Allow findings outside confirmed/needs_human")
    dfx.add_argument("--execute", action="store_true", help="Run immediately in-process (else only enqueue)")

    vfx = sub.add_parser(
        "verify-fix",
        help="Enqueue or run independent verify_fix against a patched tree (fixed/still_vulnerable/inconclusive)",
    )
    vfx.add_argument("--finding-id", type=int, required=True)
    vfx.add_argument("--run-dir", type=Path, default=None)
    src = vfx.add_mutually_exclusive_group(required=True)
    src.add_argument("--patched-path", default="", help="Existing patched checkout (read-only)")
    src.add_argument("--git-rev", default="", help="Git revision to export (raw blobs, read-only)")
    src.add_argument("--use-fix-patch", action="store_true", help="Target + evidence fix.patch in scratch")
    vfx.add_argument("--repo", default="", help="Repo for --git-rev (default: the run target)")
    vfx.add_argument("--subdir", default="", help="Subdirectory of --repo that matches the target")
    vfx.add_argument("--no-baseline", action="store_true", help="Skip the PoC baseline run on the original tree")
    vfx.add_argument("--target-url", default="", help="Optional TARGET_URL env for the PoC process")
    vfx.add_argument("--keep-tree", action="store_true", help="Keep the scratch tree after the run")
    vfx.add_argument("--force", action="store_true", help="Allow findings outside confirmed/needs_human")
    vfx.add_argument("--execute", action="store_true", help="Run immediately in-process (else only enqueue)")

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

    hitl = sub.add_parser(
        "hitl",
        help="Durable human-review inbox (report↔responses). Never auto-confirms.",
    )
    hitl_sub = hitl.add_subparsers(dest="hitl_cmd", required=True)
    for name, help_text in (
        ("inbox", "List awaiting-review packets for a run"),
        ("responses", "Print the durable responses document"),
    ):
        p_cmd = hitl_sub.add_parser(name, help=help_text)
        p_cmd.add_argument("--run-dir", type=Path, default=None)
    show_p = hitl_sub.add_parser("show", help="Print one report packet and its responses")
    show_p.add_argument("--run-dir", type=Path, default=None)
    show_p.add_argument("--id", required=True, help="Report id (e.g. finding-1)")
    respond_p = hitl_sub.add_parser(
        "respond",
        help="Record an explicit human answer (finding approval delegates to review)",
    )
    respond_p.add_argument("--run-dir", type=Path, default=None)
    respond_p.add_argument("--id", required=True, help="Report id")
    respond_p.add_argument("--block", required=True, help="Interactive block id")
    respond_p.add_argument("--value", required=True, help="Answer value")
    respond_p.add_argument("--note", default="", help="Optional note stored with the answer")
    respond_p.add_argument("--operator", default="operator")
    emit_p = hitl_sub.add_parser(
        "emit",
        help="Store an explicit HITL packet (gate). Does not touch findings.",
    )
    emit_p.add_argument("--run-dir", type=Path, default=None)
    emit_p.add_argument("--file", type=Path, required=True, help="Report JSON file")

    pol = sub.add_parser(
        "policy",
        help="Operator security policy (exclusions, trust boundaries, severity rubric). "
        "Narrows / demotes only; never confirms.",
    )
    pol_sub = pol.add_subparsers(dest="policy_cmd", required=True)
    pol_show = pol_sub.add_parser("show", help="Print the current policy (or --revision N)")
    pol_show.add_argument("--run-dir", type=Path, default=None)
    pol_show.add_argument("--revision", type=int, default=None)
    pol_set = pol_sub.add_parser("set", help="Validate and store a policy JSON file as a new revision")
    pol_set.add_argument("--run-dir", type=Path, default=None)
    pol_set.add_argument("--file", type=Path, required=True, help="Policy JSON file")
    pol_set.add_argument("--note", default="", help="Why this change")
    pol_hist = pol_sub.add_parser("history", help="List policy revisions (newest first)")
    pol_hist.add_argument("--run-dir", type=Path, default=None)
    pol_restore = pol_sub.add_parser("restore", help="Restore a revision as the new current policy")
    pol_restore.add_argument("--run-dir", type=Path, default=None)
    pol_restore.add_argument("--revision", type=int, required=True)
    pol_md = pol_sub.add_parser(
        "draft-security-md",
        help="Print a draft policy from the target's SECURITY.md (saved only with --save)",
    )
    pol_md.add_argument("--run-dir", type=Path, default=None)
    pol_md.add_argument("--save", action="store_true", help="Store the draft as a new revision")

    return p


# load_config imported from vulnforge.settings.load (shim for callers of cli.load_config)


def add_init_arguments(init_p: argparse.ArgumentParser, *, target_required: bool = True) -> None:
    """``vf init`` flags. ``vf ci`` reuses them so CI passes the real init surface."""
    init_p.add_argument("--target", type=Path, required=target_required, default=None)
    init_p.add_argument(
        "--profile",
        default=None,
        help="Profile (default from config; source analysis only: code_static)",
    )
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
        help="Number of custom hunt skills to generate (min 1; default 3)",
    )
    init_p.add_argument(
        "--hunt-skill-mode",
        dest="hunt_skill_mode",
        choices=["all_active", "seed_active", "custom_only", "explicit"],
        default=None,
        help=(
            "Run-scoped hunt skills: all_active (default), seed_active, "
            "custom_only, or explicit (with --hunt-skill)"
        ),
    )
    init_p.add_argument(
        "--hunt-skill",
        dest="hunt_skill_ids",
        action="append",
        default=None,
        help="Hunt skill id when --hunt-skill-mode=explicit (repeatable)",
    )
    init_p.add_argument(
        "--model-validate",
        default=None,
        help=(
            "Dedicated validate_llm / PoC referee model. "
            "Bare model id when no hosts are saved (ids may contain slashes). "
            "host_id/model_id when a host catalog is saved — the first slash "
            "separates the host; a bare id is refused so it cannot match another host. "
            "Writes Settings and this run's config. Omit to leave the role unchanged "
            "(blank = same as hunt). Never auto-confirms."
        ),
    )
    init_p.add_argument(
        "--sandbox-poc",
        dest="sandbox_poc_validate",
        action="store_true",
        default=False,
        help=(
            "Opt in at run start: queue one sandbox validate_poc per harness-ready "
            "needs_human finding (microVM or gVisor only). Default off. "
            "Refuses to create the run when this process cannot use the Docker API "
            "or select_isolation would be sandbox_unavailable. "
            "A missing sandbox at task time fails closed and does not confirm."
        ),
    )
    init_p.add_argument(
        "--no-enqueue-hunts",
        dest="enqueue_hunts",
        action="store_false",
        default=True,
        help=(
            "Do not auto-queue hunt tasks after recon (architecture-only). "
            "Enqueue later from Hunts / Explorer. "
            "For file_by_file, create the run with zero hunt tasks."
        ),
    )
    init_p.add_argument(
        "--diff",
        dest="diff",
        default=None,
        metavar="BASE..HEAD",
        help=(
            "Diff-scoped audit: hunt only files changed between the BASE and HEAD "
            "commit trees (two-tree compare, not merge-base) plus their callers/"
            "callees from the codemap. BASE.. means BASE..HEAD. The target checkout "
            "must be at HEAD; the repository is never modified."
        ),
    )
    init_p.add_argument(
        "--diff-depth",
        dest="diff_depth",
        type=int,
        default=None,
        help="Caller/callee expansion depth for --diff (0-3; default diff.expand_depth or 1)",
    )


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


def parse_model_validate_flag(raw: str, *, hosts: list) -> Any:
    """Bare model id, or ``host_id/model_id`` when hosts are saved.

    No hosts: the whole string is the model id, including ``org/model``.
    Hosts saved: the first ``/`` or ``|`` separates host from model. A bare id
    is refused (no cross-host fallback).
    """
    text = str(raw or "").strip()
    if not text:
        raise ValueError("--model-validate is empty")
    if not hosts:
        return text
    sep = "|" if "|" in text else ("/" if "/" in text else "")
    if not sep:
        raise ValueError(
            "--model-validate needs host_id/model_id when hosts are saved "
            "(refusing a bare id that could match another host)"
        )
    host_id, model_id = text.split(sep, 1)
    host_id, model_id = host_id.strip(), model_id.strip()
    if not host_id or not model_id:
        raise ValueError("--model-validate needs host_id/model_id")
    return {"host_id": host_id, "model_id": model_id}


def apply_init_model_validate(cfg: dict, raw: str) -> dict:
    """Store the Validate / Referee role in Settings and return the merged cfg."""
    from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings, save_ui_settings

    ui = load_ui_settings()
    ref = parse_model_validate_flag(raw, hosts=list(ui.get("hosts") or []))
    saved = save_ui_settings({"model_validate": ref})
    return apply_ui_settings_to_cfg(cfg, saved)


def cmd_init(args, cfg: dict) -> int:
    from vulnforge.util import is_pe_file

    target = Path(args.target).resolve()
    profile = str(
        args.profile or cfg.get("run", {}).get("profile", "code_static")
    ).strip().lower() or "code_static"

    if not target.exists():
        print(f"target not found: {target}", file=sys.stderr)
        return EXIT_CONFIG

    if is_pe_file(target):
        print(
            f"PE binaries are not supported (source analysis only): {target}",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    if not target.is_dir() and not target.is_file():
        print(f"target not found or not a directory/file: {target}", file=sys.stderr)
        return EXIT_CONFIG

    flag = getattr(args, "model_validate", None)
    if flag is not None and str(flag).strip():
        try:
            cfg = apply_init_model_validate(cfg, str(flag))
        except ValueError as e:
            print(str(e), file=sys.stderr)
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

    if bool(getattr(args, "sandbox_poc_validate", False)):
        from vulnforge.poc_runner import sandbox_poc_preflight

        try:
            pre = sandbox_poc_preflight(cfg)
        except Exception as e:
            pre = {
                "ok": False,
                "message": f"Sandbox PoC refused: preflight failed ({e})",
            }
        if not pre.get("ok"):
            msg = str(pre.get("message") or "Sandbox PoC refused: isolation unavailable")
            setattr(args, "init_error", msg)
            print(msg, file=sys.stderr)
            return EXIT_CONFIG

    # Diff-scoped audit (#185): validate spec + revisions before creating the run dir.
    diff_spec = str(getattr(args, "diff", None) or "").strip()
    diff_changes: Optional[dict[str, Any]] = None
    if diff_spec:
        from vulnforge.diff_scope import DiffScopeError, collect_changes, require_changes

        try:
            diff_changes = collect_changes(
                target,
                diff_spec,
                ignore_globs=list(cfg.get("run", {}).get("ignore_globs") or []),
            )
            require_changes(diff_changes)
        except DiffScopeError as e:
            setattr(args, "init_error", str(e))
            print(str(e), file=sys.stderr)
            return EXIT_CONFIG

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
            "fingerprinted_files": manifest.get("fingerprinted_files"),
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
    from vulnforge.paths import effective_prompt_pin_root

    prompts_root = effective_prompt_pin_root()
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
    from vulnforge.hunt_profiles.generate import clamp_skill_count

    init_dynamic_skill_count = clamp_skill_count(init_dynamic_skill_count)
    if strategy == STRATEGY_FILE_BY_FILE:
        init_dynamic_skills = False

    # Run-scoped hunt skill policy (does not mutate global Dev active toggles)
    from vulnforge.hunt_profiles import HUNT_SKILL_MODES

    init_hunt_mode = str(
        getattr(args, "hunt_skill_mode", None) or "all_active"
    ).strip().lower().replace("-", "_")
    if init_hunt_mode not in HUNT_SKILL_MODES:
        init_hunt_mode = "all_active"
    init_hunt_ids = [
        str(x).strip().lower().replace("_", "-")
        for x in (getattr(args, "hunt_skill_ids", None) or [])
        if str(x).strip()
    ][:64]
    # Default True (auto-queue). Explicit False = architecture-only / manual hunts.
    init_enqueue_hunts = bool(getattr(args, "enqueue_hunts", True))
    init_sandbox_poc = bool(getattr(args, "sandbox_poc_validate", False))
    poc_harness_store = dict(cfg.get("poc_harness") or {})
    poc_harness_store["sandbox_oneshot"] = init_sandbox_poc

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
            "hunt_skill_mode": init_hunt_mode,
            "hunt_skill_ids": init_hunt_ids,
            "enqueue_hunts": init_enqueue_hunts,
            "sandbox_poc_validate": init_sandbox_poc,
        },
        "poc_harness": poc_harness_store,
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

    # Diff scope: expand changed files to callers/callees via the mechanical
    # codemap (same builder recon uses), then persist the manifest.
    diff_scope: Optional[dict[str, Any]] = None
    if diff_changes is not None:
        from vulnforge.diff_scope import DiffScopeError, build_diff_scope
        from vulnforge.tools.codemap import build_codemap

        progress(
            {
                "phase": "diff_scope",
                "status": "running",
                "message": f"Scoping diff {diff_spec} (callers/callees via codemap)...",
                "percent": 92,
            }
        )
        try:
            init_codemap = build_codemap(target, None, cfg=cfg, ignore_globs=ignore)
            db.set_codemap(init_codemap, source="mechanical")
        except Exception as exc:
            note_swallowed(exc, context="cli.init.diff_codemap")
            init_codemap = {}
        try:
            diff_scope = build_diff_scope(
                target,
                diff_spec,
                codemap=init_codemap,
                cfg=cfg,
                ignore_globs=ignore,
                depth=getattr(args, "diff_depth", None),
                changes=diff_changes,
            )
        except DiffScopeError as e:  # pragma: no cover - validated above
            db.close()
            setattr(args, "init_error", str(e))
            print(str(e), file=sys.stderr)
            return EXIT_CONFIG
        db.set_diff_scope(diff_scope)
        write_json(run_dir / "diff_scope.json", diff_scope)

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

    def _attach_hunt_skill_policy(recon_pl: dict[str, Any]) -> None:
        recon_pl["hunt_skill_mode"] = init_hunt_mode
        recon_pl["hunt_skill_ids"] = list(init_hunt_ids)

    def _attach_enqueue_hunts(recon_pl: dict[str, Any]) -> None:
        recon_pl["enqueue_hunts"] = init_enqueue_hunts

    def _attach_diff_scope(recon_pl: dict[str, Any]) -> None:
        """Focus recon on the change; hunts are clipped to the scope at finalize."""
        if diff_scope is None:
            return
        brief = recon_brief(diff_scope)
        prior = str(recon_pl.get("operator_notes") or "").strip()
        merged = (brief + "\n\n" + prior) if prior else brief
        recon_pl["operator_notes"] = merged
        recon_pl["operator_brief"] = merged
        changed = changed_paths(diff_scope)
        recon_pl["focus_paths"] = (
            changed + [p for p in scope_files(diff_scope) if p not in changed]
        )[:40]
        recon_pl["diff_scoped"] = True

    from vulnforge.stages.recon import enqueue_recon_agent_tasks, resolve_recon_agent_ids

    try:
        recon_agent_ids = resolve_recon_agent_ids(init_agent_ids or None)
    except Exception:
        recon_agent_ids = list(init_agent_ids or [])

    from vulnforge.diff_scope import (
        changed_paths,
        hunt_diff_context,
        recon_brief,
        scope_brief,
        scope_files,
    )

    hunts_enqueued = 0
    recon_task_ids: list[int] = []
    if strategy == STRATEGY_FILE_BY_FILE:
        # No recon — plan hunts from file index at init (unless manual mode).
        if init_enqueue_hunts:
            payloads = plan_file_by_file_hunts(
                target,
                ignore=ignore,
                max_tasks=max_tasks,
                classes=None,
                hunt_skill_mode=init_hunt_mode,
                hunt_skill_ids=init_hunt_ids or None,
                only_paths=(
                    None
                    if diff_scope is None
                    else changed_paths(diff_scope)
                    + [p for p in scope_files(diff_scope) if p not in changed_paths(diff_scope)]
                ),
            )
            for pl in payloads:
                if diff_scope is not None:
                    pl["diff_scope"] = hunt_diff_context(diff_scope, pl.get("path_hints") or [])
                db.enqueue_task("hunt", pl, priority=50)
                db.upsert_coverage_fact(
                    pl.get("area", "app"),
                    pl.get("class", "wildcard"),
                    path=(pl.get("path_hints") or [""])[0],
                    visit_delta=0,
                )
            hunts_enqueued = len(payloads)
        else:
            payloads = []
            hunts_enqueued = 0
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
        _attach_hunt_skill_policy(recon_payload)
        _attach_enqueue_hunts(recon_payload)
        _attach_diff_scope(recon_payload)
        # One Ralph task per recon agent; architecture merges when batch completes.
        from vulnforge.task_priority import RECON_INIT_PRIORITY

        recon_task_ids = enqueue_recon_agent_tasks(
            db,
            recon_payload,
            recon_agent_ids or resolve_recon_agent_ids(None),
            base_priority=RECON_INIT_PRIORITY,
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
        _attach_hunt_skill_policy(recon_payload)
        _attach_enqueue_hunts(recon_payload)
        _attach_diff_scope(recon_payload)
        from vulnforge.task_priority import RECON_INIT_PRIORITY

        recon_task_ids = enqueue_recon_agent_tasks(
            db,
            recon_payload,
            recon_agent_ids or resolve_recon_agent_ids(None),
            base_priority=RECON_INIT_PRIORITY,
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
            "diff": scope_brief(diff_scope),
        },
    )

    progress(
        {
            "phase": "done",
            "status": "done",
            "message": (
                f"Ready: {manifest.get('file_count')} files indexed "
                f"(hashed {manifest.get('hashed_files')}, "
                f"fingerprinted {manifest.get('fingerprinted_files')})"
                + (
                    " (listing capped)"
                    if manifest.get("listing_capped")
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
            "hashed_files": manifest.get("hashed_files"),
            "fingerprinted_files": manifest.get("fingerprinted_files"),
            "strategy": strategy,
            "hunts_enqueued": hunts_enqueued,
        },
    )

    setattr(args, "created_run_dir", run_dir)
    print(str(run_dir))
    return EXIT_PROGRESS


def cmd_ci(args, cfg: dict) -> int:
    """Headless CI campaign. Returns vulnforge.ci.exit_codes (0/1/2) only."""
    from vulnforge.ci.exit_codes import CI_ERROR
    from vulnforge.ci.runner import CIOptions, run_ci

    if getattr(args, "run_dir", None) is not None and getattr(args, "target", None):
        print("vf ci: pass --target or --run-dir, not both", file=sys.stderr)
        return CI_ERROR
    if getattr(args, "run_dir", None) is None and not getattr(args, "target", None):
        print("vf ci: pass --target (new run) or --run-dir (resume)", file=sys.stderr)
        return CI_ERROR
    if getattr(args, "run_dir", None) is not None and getattr(args, "diff", None):
        # A run's diff scope is fixed at init; ignoring --diff here would
        # silently audit (or report) a different scope than asked.
        print("vf ci: --diff applies to a new run (--target), not --run-dir", file=sys.stderr)
        return CI_ERROR
    opts = CIOptions(
        run_dir=args.run_dir,
        init_args=args,
        config_path=getattr(args, "config", None),
        max_cost_usd=args.max_cost_usd,
        price_input_per_mtok=args.price_input_per_mtok,
        price_output_per_mtok=args.price_output_per_mtok,
        max_time=args.max_time,
        fail_on_states=list(args.fail_on_state or []),
        fail_on_severity=args.fail_on_severity,
        task_timeout=args.task_timeout,
        max_iterations=args.max_iterations,
        output_dir=args.output_dir,
        sarif_path=args.sarif,
        sarif_confirmed_only=bool(args.sarif_confirmed_only),
        verbose=not args.quiet,
    )
    return run_ci(opts, cfg).exit_code


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
    from vulnforge.llm_models import status_model_summary, validate_same_as_hunt

    summary = status_model_summary(cfg)
    print(f"models:  {summary}")
    stages = cfg.get("stages") or {}
    if stages.get("validate_llm"):
        if validate_same_as_hunt(cfg):
            note = (
                "note: stages.validate_llm is ON (default) — after mech pass, dual "
                "disprove may rejected_llm only (never auto-confirm). "
                f"{summary} — validate matches hunt (weak signal). "
                "Set stages.validate_llm: false to skip for speed or debug."
            )
        else:
            note = (
                "note: stages.validate_llm is ON (default) — after mech pass, dual "
                "disprove may rejected_llm only (never auto-confirm). "
                f"{summary}."
            )
        print(note, file=sys.stderr)
    return EXIT_PROGRESS


def lease_one_for_run(db: Database, cfg: dict, worker_id: str):
    """Lease one task under the per ``(host, model)`` concurrent cap.

    ``run.max_leases_parallel`` is the cap when that pair has no number.
    ``run.model_concurrent_caps`` is ``{host_id: {model_id: n}}``. A flat
    model-id map is not a cap.
    """
    from vulnforge.llm_models import lease_pair
    from vulnforge.settings.catalog import normalize_model_concurrent_caps

    run = cfg.get("run") or {}
    max_parallel = max(1, int(run.get("max_leases_parallel") or 1))
    caps = normalize_model_concurrent_caps(run.get("model_concurrent_caps"))
    ttl = int(run.get("lease_ttl_seconds", 1800))

    def resolve(kind: str, payload: dict) -> tuple[str, str]:
        return lease_pair(cfg, kind, payload)

    return db.lease_next_task(
        worker_id,
        ttl_seconds=ttl,
        max_parallel=max_parallel,
        model_caps=caps,
        resolve_model=resolve,
    )


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

    from vulnforge.settings.catalog import cfg_lease_ceiling

    max_parallel = max(1, int((cfg.get("run") or {}).get("max_leases_parallel") or 1))
    # Serial mode (ceiling 1): exclusive run.lock for the whole task.
    # Parallel mode: skip exclusive lock — SQLite lease_one_for_run enforces
    # the per (host, model) cap (global max_leases_parallel when a pair has no number).
    lease_ceiling = cfg_lease_ceiling(cfg)
    lock: Optional[RunLock] = None
    if lease_ceiling <= 1:
        try:
            lock = RunLock(run_dir)
            lock.acquire()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return EXIT_INFRA

    db: Optional[Database] = None
    try:
        db = Database.open(db_path)
        # TTL expiry + dead worker PIDs (hard stop can leave leases for 30m)
        reclaimed = db.reclaim_stale_leases()
        if reclaimed:
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "reclaim_stale_leases",
                    "reclaimed": reclaimed,
                },
            )
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
                # Sandbox one-shot phase (run-start toggle). Missing sandbox
                # fails closed inside validate_poc and does not block the run.
                try:
                    from vulnforge.poc_phase import enqueue_sandbox_oneshot_phase

                    sandbox_ids = enqueue_sandbox_oneshot_phase(
                        db, run_dir, reason="run_idle"
                    )
                except Exception as e:
                    sandbox_ids = []
                    append_event(
                        run_dir,
                        {
                            "source": "vf",
                            "event": "sandbox_poc_phase_error",
                            "error": str(e),
                        },
                    )
                if sandbox_ids:
                    append_event(
                        run_dir,
                        {
                            "source": "vf",
                            "event": "sandbox_poc_enqueued",
                            "task_ids": sandbox_ids,
                            "count": len(sandbox_ids),
                        },
                    )
                    return EXIT_PROGRESS
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

        worker_id = f"vf-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        task = lease_one_for_run(db, cfg, worker_id)
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
                "model_id": task.lease_model_id,
                "host_id": task.lease_host_id,
            },
        )

        try:
            result = dispatch_task(task, db, run_dir, cfg)
        except NotImplementedError as e:
            # Incomplete optional stages must not EXIT_CONFIG the campaign when
            # validate_llm can still hold the finding. Unknown kinds → EXIT_CONFIG.
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
                    updated = db.fail_task(
                        task.id, "failed_task", f"{err}; hold_failed: {hold_err}"
                    )
                    append_event(
                        run_dir,
                        {
                            "source": "vf",
                            "event": "not_implemented" if updated else "task_fail_race",
                            "task_id": task.id,
                            "kind": kind,
                            "attempt": task.attempt,
                            "error": err,
                        },
                    )
                    return EXIT_PROGRESS
            else:
                # Unknown task kind — hard control-plane error
                updated = db.fail_task(task.id, "failed_task", err)
                append_event(
                    run_dir,
                    {
                        "source": "vf",
                        "event": "unknown_task_kind" if updated else "task_fail_race",
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
            updated = db.fail_task(task.id, "failed_task", msg)
            if not updated:
                cur = db.get_task(task.id)
                append_event(
                    run_dir,
                    {
                        "source": "vf",
                        "event": "task_fail_race",
                        "task_id": task.id,
                        "kind": task.kind,
                        "attempt": task.attempt,
                        "error": msg,
                        "task_state": cur.state if cur else None,
                    },
                )
                return EXIT_PROGRESS
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
            updated = db.fail_task(task.id, status, err, result_extra=result)
            if not updated:
                cur = db.get_task(task.id)
                append_event(
                    run_dir,
                    {
                        "source": "vf",
                        "event": "task_fail_race",
                        "task_id": task.id,
                        "kind": task.kind,
                        "attempt": task.attempt,
                        "error": err,
                        "task_state": cur.state if cur else None,
                    },
                )
                return EXIT_PROGRESS
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

        updated = db.complete_task(task.id, result, state="succeeded")
        if not updated:
            cur = db.get_task(task.id)
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "task_complete_race",
                    "task_id": task.id,
                    "kind": task.kind,
                    "task_state": cur.state if cur else None,
                    "result_keys": list(result.keys()),
                },
            )
            return EXIT_PROGRESS
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
        updated = db.deadletter_task(task.id, err)
        if not updated:
            cur = db.get_task(task.id)
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "deadletter_race",
                    "task_id": task.id,
                    "kind": kind,
                    "attempt": attempt,
                    "max_task_attempts": max_att,
                    "error": err,
                    "task_state": cur.state if cur else None,
                },
            )
            return EXIT_PROGRESS
        # Clear stuck pending_llm so Report UI is honest after validate_llm deadletter.
        if kind == "validate_llm":
            try:
                raw_fid = (getattr(task, "payload", None) or {}).get("finding_id")
                if raw_fid is not None:
                    fid = int(raw_fid)
                    finding = db.get_finding(fid)
                    if finding is not None:
                        body = dict(finding.body or {})
                        mech = body.get("validation_mech")
                        if isinstance(mech, dict) and mech.get("pending_llm"):
                            mech = dict(mech)
                            mech["pending_llm"] = False
                            mech["deadlettered"] = True
                            body["validation_mech"] = mech
                            from vulnforge.util import utc_now_iso

                            db.conn.execute(
                                "UPDATE findings SET body_json=?, updated_at=? WHERE id=?",
                                (json.dumps(body), utc_now_iso(), fid),
                            )
                            db.conn.commit()
            except Exception as exc:
                note_swallowed(exc, context="cli.deadletter_clear_pending_llm", run_dir=run_dir)
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

    Unknown kinds raise ``NotImplementedError``; ``cmd_run_once`` maps them to
    ``EXIT_CONFIG`` + event ``unknown_task_kind``.

    Binds a live-task snapshot so tool rounds can stream while the lease is held.
    """
    from vulnforge.live_task import bind_task, unbind_task

    try:
        max_rounds = int(((cfg or {}).get("llm") or {}).get("max_tool_rounds", 12) or 12)
    except (TypeError, ValueError):
        max_rounds = 12
    token = bind_task(
        Path(run_dir),
        int(task.id),
        str(getattr(task, "kind", "") or ""),
        max_rounds,
    )
    try:
        return _dispatch_task_kind(task, db, run_dir, cfg)
    finally:
        unbind_task(token)


def _dispatch_task_kind(task, db: Database, run_dir: Path, cfg: dict) -> dict[str, Any]:
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
    if kind == "validate_poc":
        from vulnforge.stages import validate_poc

        return validate_poc.run(task, db, run_dir, cfg)
    if kind == "iterate_poc":
        from vulnforge.stages import iterate_poc

        return iterate_poc.run(task, db, run_dir, cfg)
    if kind == "develop_fix":
        from vulnforge.stages import develop_fix

        return develop_fix.run(task, db, run_dir, cfg)
    if kind == "verify_fix":
        from vulnforge.stages import verify_fix

        return verify_fix.run(task, db, run_dir, cfg)
    if kind == "render":
        from vulnforge.stages import render

        return render.run(task, db, run_dir, cfg)
    if kind == "tool_gaps":
        from vulnforge.stages import tool_gaps as tool_gaps_stage

        return tool_gaps_stage.run(task, db, run_dir, cfg)
    if kind == "generate_skill":
        from vulnforge.stages import generate_skill as generate_skill_stage

        return generate_skill_stage.run(task, db, run_dir, cfg)
    if kind == "generate_run_skills":
        from vulnforge.stages import generate_run_skills as generate_run_skills_stage

        return generate_run_skills_stage.run(task, db, run_dir, cfg)
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



def cmd_export(args, cfg: dict) -> int:
    """Write a findings report export (same exporters as the dashboard Report menu)."""
    from vulnforge.export_findings import ExportOptions, export_bundle, export_filename

    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    db_path = run_dir / "harness.db"
    if not db_path.is_file():
        print(f"harness.db not found in {run_dir}", file=sys.stderr)
        return EXIT_CONFIG
    opts = ExportOptions(
        include_findings=True,
        include_architecture=bool(args.architecture),
        include_hunts=bool(args.hunts),
        include_summary=bool(args.summary),
        include_poc=bool(args.poc),
        include_codemap=bool(args.codemap),
        sarif_include_needs_human=bool(args.include_needs_human),
        sarif_include_rejected=bool(args.include_rejected),
        sarif_states=tuple(args.state) if args.state else None,
    )
    db = Database.open(db_path)
    try:
        try:
            payload, ext, _media = export_bundle(args.format, run_dir, db, options=opts)
        except (ValueError, ImportError) as e:
            print(str(e), file=sys.stderr)
            return EXIT_CONFIG
    finally:
        db.close()
    if args.out == "-":
        sys.stdout.buffer.write(payload)
        sys.stdout.flush()
        return EXIT_PROGRESS
    if args.out:
        out = Path(args.out)
    else:
        name = export_filename(
            run_dir.parent.name, run_dir.name, ext, include_poc=bool(args.poc)
        )
        out = run_dir / "exports" / name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(payload)
    print(f"wrote {out} ({len(payload)} bytes)")
    return EXIT_PROGRESS


def cmd_export_validation_job(args, cfg: dict) -> int:
    """Export finding + pack as HANDOFF bundle for external/in-process harness."""
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    fid = int(args.finding_id)
    db = Database.open(run_dir / "harness.db")
    try:
        finding = db.get_finding(fid)
        if finding is None:
            print(f"finding not found: {fid}", file=sys.stderr)
            return EXIT_CONFIG
        run_row = db.get_run()
        target_path = (run_row["target_path"] if run_row else "") or ""
        run_id = (run_row["id"] if run_row else "") or run_dir.name
        from vulnforge.poc_handoff import export_validation_job

        r = export_validation_job(
            run_dir,
            finding,
            target_path=str(target_path),
            run_id=str(run_id),
            out_dir=Path(args.out) if getattr(args, "out", None) else None,
            as_zip=not bool(getattr(args, "no_zip", False)),
            include_citations=not bool(getattr(args, "no_citations", False)),
        )
        if not r.get("ok"):
            print(r.get("error") or "export failed", file=sys.stderr)
            return EXIT_CONFIG
        print("out_dir:", r.get("out_dir"))
        if r.get("zip_path"):
            print("zip:", r.get("zip_path"))
        ready = (r.get("readiness") or {}).get("ready")
        print("harness_ready:", ready)
        issues = (r.get("readiness") or {}).get("issues") or []
        if issues:
            print("issues:", ", ".join(issues))
        return EXIT_PROGRESS
    finally:
        db.close()


def cmd_validate_poc(args, cfg: dict) -> int:
    """Enqueue validate_poc, or execute immediately with --execute."""
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    fid = int(args.finding_id)
    iterate = bool(getattr(args, "iterate", False))
    payload: dict[str, Any] = {
        "finding_id": fid,
        "operator": "cli",
    }
    if getattr(args, "referee", False):
        payload["referee"] = True
    url = str(getattr(args, "target_url", "") or "").strip()
    if url:
        payload["TARGET_URL"] = url

    db = Database.open(run_dir / "harness.db")
    try:
        finding = db.get_finding(fid)
        if finding is None:
            print(f"finding not found: {fid}", file=sys.stderr)
            return EXIT_CONFIG
        if getattr(args, "execute", False):
            from types import SimpleNamespace

            if iterate:
                from vulnforge.stages import iterate_poc

                task = SimpleNamespace(id=0, kind="iterate_poc", payload=payload)
                result = iterate_poc.run(task, db, run_dir, cfg)
                print(json.dumps({k: result.get(k) for k in (
                    "status", "finding_id", "verdict", "end_reason",
                    "cycles_run", "evidence_id", "error", "finding_state",
                ) if k in result or result.get(k) is not None}, indent=2))
            else:
                from vulnforge.stages import validate_poc

                task = SimpleNamespace(id=0, kind="validate_poc", payload=payload)
                result = validate_poc.run(task, db, run_dir, cfg)
                print(json.dumps({k: result.get(k) for k in (
                    "status", "finding_id", "verdict", "signal_matched",
                    "exit_code", "evidence_id", "error",
                ) if k in result or result.get(k) is not None}, indent=2))
            if result.get("status") == "failed_infra":
                return EXIT_INFRA
            if result.get("status") != "succeeded":
                return EXIT_CONFIG
            return EXIT_PROGRESS
        kind = "iterate_poc" if iterate else "validate_poc"
        task_id = db.enqueue_task(kind, payload, priority=28)
        append_event(
            run_dir,
            {
                "source": "vf",
                "event": "poc_iterate_enqueued" if iterate else "poc_validate_enqueued",
                "finding_id": fid,
                "task_id": task_id,
            },
        )
        print(f"enqueued {kind} task_id={task_id} finding_id={fid}")
        return EXIT_PROGRESS
    finally:
        db.close()


def _run_fix_task_inline(kind: str, payload: dict, run_dir: Path, cfg: dict) -> int:
    from types import SimpleNamespace

    db = Database.open(run_dir / "harness.db")
    try:
        task = SimpleNamespace(id=0, kind=kind, payload=payload)
        result = _dispatch_task_kind(task, db, run_dir, cfg)
    finally:
        db.close()
    keys = (
        "status", "finding_id", "evidence_id", "verdict", "confidence", "basis",
        "would_resolve", "poc_evidence", "applies", "patch_errors", "fix_relpath",
        "verify_relpath", "error", "finding_state",
    )
    print(json.dumps({k: result.get(k) for k in keys if result.get(k) is not None}, indent=2))
    if result.get("status") == "failed_infra":
        return EXIT_INFRA
    if result.get("status") != "succeeded":
        return EXIT_CONFIG
    return EXIT_PROGRESS


def cmd_develop_fix(args, cfg: dict) -> int:
    """Enqueue develop_fix, or execute immediately with --execute."""
    from vulnforge.control import fix_ops

    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    fid = int(args.finding_id)
    if getattr(args, "execute", False):
        payload: dict[str, Any] = {"finding_id": fid, "operator": "cli"}
        if args.notes:
            payload["operator_notes"] = str(args.notes)[:4000]
        if args.force:
            payload["force"] = True
        return _run_fix_task_inline("develop_fix", payload, run_dir, cfg)
    r = fix_ops.enqueue_develop_fix(
        run_dir, fid, operator="cli", operator_notes=args.notes or "", force=bool(args.force)
    )
    if not r.get("ok"):
        print(r.get("error"), file=sys.stderr)
        return EXIT_CONFIG
    print(f"enqueued develop_fix task_id={r['task_id']} finding_id={fid}")
    return EXIT_PROGRESS


def cmd_verify_fix(args, cfg: dict) -> int:
    """Enqueue verify_fix, or execute immediately with --execute."""
    from vulnforge.control import fix_ops

    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    fid = int(args.finding_id)
    opts = dict(
        patched_path=args.patched_path or "",
        git_rev=args.git_rev or "",
        repo_path=args.repo or "",
        subdir=args.subdir or "",
        use_fix_patch=bool(args.use_fix_patch),
        baseline=not args.no_baseline,
        target_url=args.target_url or "",
        operator="cli",
        force=bool(args.force),
        keep_tree=bool(args.keep_tree),
    )
    if getattr(args, "execute", False):
        db = Database.open(run_dir / "harness.db")
        try:
            finding = db.get_finding(fid)
        finally:
            db.close()
        if finding is None:
            print(f"finding not found: {fid}", file=sys.stderr)
            return EXIT_CONFIG
        payload, err = fix_ops.build_verify_payload(finding, **opts)
        if err or payload is None:
            print(err, file=sys.stderr)
            return EXIT_CONFIG
        return _run_fix_task_inline("verify_fix", payload, run_dir, cfg)
    r = fix_ops.enqueue_verify_fix(run_dir, fid, **opts)
    if not r.get("ok"):
        print(r.get("error"), file=sys.stderr)
        return EXIT_CONFIG
    print(f"enqueued verify_fix task_id={r['task_id']} finding_id={fid}")
    return EXIT_PROGRESS


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


def cmd_hitl(args, cfg: dict) -> int:
    """Read or update the durable HITL inbox. Does not invent human answers."""
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    db_path = run_dir / "harness.db"
    if not db_path.is_file():
        print(f"missing harness.db in {run_dir}", file=sys.stderr)
        return EXIT_CONFIG
    from vulnforge.hitl import (
        emit_packet,
        get_report,
        list_inbox,
        open_for_run,
        respond,
        write_projections,
    )

    action = str(getattr(args, "hitl_cmd", "") or "")
    db = open_for_run(run_dir)
    try:
        if action == "inbox":
            payload = list_inbox(db, run_dir)
        elif action == "responses":
            payload = write_projections(db, run_dir)
        elif action == "show":
            payload = get_report(db, run_dir, str(args.id))
        elif action == "respond":
            payload = respond(
                db,
                run_dir,
                str(args.id),
                block_id=str(args.block),
                value=str(args.value),
                note=str(args.note or ""),
                operator=str(args.operator or "operator"),
            )
        elif action == "emit":
            path = Path(args.file)
            if not path.is_file():
                print(f"file not found: {path}", file=sys.stderr)
                return EXIT_CONFIG
            try:
                packet = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                print(f"invalid JSON: {e}", file=sys.stderr)
                return EXIT_CONFIG
            if not isinstance(packet, dict):
                print("packet must be a JSON object", file=sys.stderr)
                return EXIT_CONFIG
            payload = emit_packet(db, run_dir, packet)
        else:
            print(f"unknown hitl command: {action}", file=sys.stderr)
            return EXIT_CONFIG
    finally:
        db.close()
    if not payload.get("ok", True) and payload.get("error"):
        print(json.dumps(payload, indent=2), file=sys.stderr)
        return EXIT_CONFIG
    # responses document has no ok flag; inbox/show/respond/emit do.
    if action == "responses":
        print(json.dumps(payload, indent=2))
        return EXIT_PROGRESS
    if payload.get("ok") is False:
        print(json.dumps(payload, indent=2), file=sys.stderr)
        return EXIT_CONFIG
    print(json.dumps(payload, indent=2))
    return EXIT_PROGRESS


def cmd_policy(args, cfg: dict) -> int:
    """Read or update the run's operator security policy. Never touches findings."""
    try:
        run_dir = resolve_run_dir(args, cfg)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return EXIT_CONFIG
    db_path = run_dir / "harness.db"
    if not db_path.is_file():
        print(f"missing harness.db in {run_dir}", file=sys.stderr)
        return EXIT_CONFIG
    from vulnforge.db import Database
    from vulnforge.security_policy import PolicyError, draft_from_security_md

    action = str(getattr(args, "policy_cmd", "") or "")
    db = Database.open(db_path)
    try:
        if action == "show":
            if args.revision is not None:
                payload = db.get_security_policy_revision(int(args.revision))
                if payload is None:
                    print(f"revision not found: {args.revision}", file=sys.stderr)
                    return EXIT_CONFIG
            else:
                payload = db.get_security_policy() or {"revision": None, "policy": None}
        elif action == "set":
            path = Path(args.file)
            if not path.is_file():
                print(f"file not found: {path}", file=sys.stderr)
                return EXIT_CONFIG
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                print(f"invalid JSON: {e}", file=sys.stderr)
                return EXIT_CONFIG
            try:
                rev = db.set_security_policy(doc, source="cli", note=str(args.note or ""))
            except PolicyError as e:
                print(json.dumps({"ok": False, "errors": e.errors}, indent=2), file=sys.stderr)
                return EXIT_CONFIG
            payload = {"ok": True, "revision": rev}
        elif action == "history":
            payload = {"revisions": db.list_security_policy_revisions(limit=100)}
        elif action == "restore":
            try:
                rev = db.restore_security_policy_revision(int(args.revision))
            except PolicyError as e:
                print(json.dumps({"ok": False, "errors": e.errors}, indent=2), file=sys.stderr)
                return EXIT_CONFIG
            if rev is None:
                print(f"revision not found: {args.revision}", file=sys.stderr)
                return EXIT_CONFIG
            payload = {"ok": True, "revision": rev, "restored_from": int(args.revision)}
        elif action == "draft-security-md":
            row = db.get_run()
            draft = draft_from_security_md(row["target_path"]) if row else None
            if not draft:
                print("no SECURITY.md found in the target", file=sys.stderr)
                return EXIT_CONFIG
            payload = {"saved": False, **draft}
            if args.save:
                rev = db.set_security_policy(
                    draft["policy"],
                    source="security_md",
                    note=f"seeded from {draft['source_path']}",
                )
                payload["saved"] = True
                payload["revision"] = rev
        else:
            print(f"unknown policy command: {action}", file=sys.stderr)
            return EXIT_CONFIG
    finally:
        db.close()
    print(json.dumps(payload, indent=2))
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
