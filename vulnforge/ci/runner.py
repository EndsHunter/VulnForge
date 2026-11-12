"""Headless CI campaign: init → Ralph → render → outcome exit code.

``vf ci`` drives the existing Ralph loop in-process (``scripts/ralph.py``,
one ``vf run-once`` subprocess per task), with one worker and no sleep
between tasks. Budgets are advisory: Ralph checks them before each lease and
never kills an in-flight task for them.

The result is written to ``{run_dir}/ci_result.json`` (schema
``vulnforge/ci-result@1``) and, with ``--output-dir``, copied there with the
rendered report for artifact upload. Exit codes: ``vulnforge.ci.exit_codes``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from vulnforge.ci.budget import CostGuard, PriceTable, parse_duration
from vulnforge.ci.exit_codes import CI_ERROR, CI_PASS, CI_THRESHOLD, OUTCOME_NAMES
from vulnforge.ci.outcome import (
    EARLY_STOP_REASONS,
    RALPH_STOP_EVENTS,
    Threshold,
    classify_ralph_stop,
    confirmed_integrity_errors,
    coverage_gaps,
    matched_findings,
    parse_fail_on_states,
    parse_min_severity,
    task_integrity_errors,
)
from vulnforge.paths import PROJECT_ROOT
from vulnforge.util import append_event, utc_now_iso

SCHEMA = "vulnforge/ci-result@1"
RESULT_NAME = "ci_result.json"
REPORT_FILES = ("REPORT.md", "findings.json")
SARIF_NAME = "vulnforge.sarif"
# CI uploads review items too: code scanning shows needs_human alerts with a
# "not a confirmed vulnerability" title (vulnforge/sarif_export.py).
SARIF_CI_STATES: tuple[str, ...] = ("confirmed", "needs_human")
DEFAULT_TASK_TIMEOUT = 900.0
# Ralph needs an integer cap; CI default is effectively unlimited so a large
# repo does not stop at Ralph's interactive default (200) and exit green.
UNLIMITED_ITERATIONS = 1_000_000

HONESTY_NOTE = (
    "CI never sets confirmed. needs_human = mechanical gates passed and "
    "awaiting human review, not a proven vulnerability. confirmed = a human "
    "accepted it, still not exploit proof."
)


@dataclass
class CIOptions:
    run_dir: Optional[Path] = None  # resume; else init from init_args
    init_args: Any = None  # argparse.Namespace accepted by cli.cmd_init
    config_path: Optional[Path] = None
    max_cost_usd: Optional[float] = None
    price_input_per_mtok: Optional[float] = None
    price_output_per_mtok: Optional[float] = None
    max_time: Optional[str] = None
    fail_on_states: list[str] = field(default_factory=list)
    fail_on_severity: Optional[str] = None
    task_timeout: Optional[float] = DEFAULT_TASK_TIMEOUT
    max_iterations: Optional[int] = None
    max_infra_retries: int = 5
    output_dir: Optional[Path] = None
    sarif_path: Optional[Path] = None  # default: {output_dir}/vulnforge.sarif
    sarif_confirmed_only: bool = False
    verbose: bool = True

    @property
    def sarif_target(self) -> Optional[Path]:
        if self.sarif_path is not None:
            return Path(self.sarif_path)
        if self.output_dir is not None:
            return Path(self.output_dir) / SARIF_NAME
        return None

    @property
    def sarif_states(self) -> tuple[str, ...]:
        return ("confirmed",) if self.sarif_confirmed_only else SARIF_CI_STATES


@dataclass
class CIResult:
    exit_code: int
    record: dict[str, Any]


def _log(msg: str) -> None:
    print(f"[vf ci] {msg}", file=sys.stderr, flush=True)


def _gh_annotation(level: str, msg: str) -> None:
    """GitHub workflow command so a green job still shows gaps in the UI."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        clean = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level}::{clean}", flush=True)


def load_ralph_module():
    """Import ``scripts/ralph.py`` (it is a script, not a package module)."""
    name = "vulnforge_ci_ralph"
    if name in sys.modules:
        return sys.modules[name]
    path = PROJECT_ROOT / "scripts" / "ralph.py"
    if not path.is_file():
        raise FileNotFoundError(f"Ralph loop not found: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _events_size(run_dir: Path) -> int:
    try:
        return (run_dir / "events.jsonl").stat().st_size
    except OSError:
        return 0


def last_ralph_stop_event(run_dir: Path, offset: int = 0) -> Optional[dict[str, Any]]:
    """Last Ralph stop event written after ``offset`` bytes of events.jsonl."""
    path = run_dir / "events.jsonl"
    try:
        with path.open("rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError:
        return None
    last = None
    for raw in data.decode("utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(ev, dict)
            and ev.get("source") == "ralph"
            and ev.get("event") in RALPH_STOP_EVENTS
        ):
            last = ev
    return last


def _validate(opts: CIOptions, cfg: dict) -> tuple[Threshold, Optional[float], Optional[PriceTable]]:
    threshold = Threshold(
        states=parse_fail_on_states(opts.fail_on_states),
        min_severity=parse_min_severity(opts.fail_on_severity),
    )
    max_wall = parse_duration(opts.max_time)
    prices: Optional[PriceTable] = None
    if opts.max_cost_usd is not None:
        if opts.max_cost_usd < 0:
            raise ValueError("--max-cost-usd must be non-negative")
        prices = PriceTable.from_sources(
            cfg,
            default_input=opts.price_input_per_mtok,
            default_output=opts.price_output_per_mtok,
        )
        if prices.empty:
            raise ValueError(
                "--max-cost-usd needs prices: pass --price-input-per-mtok and "
                "--price-output-per-mtok, or set ci.pricing in config "
                "(use 0 for a local model)"
            )
    elif opts.price_input_per_mtok is not None or opts.price_output_per_mtok is not None:
        # Validate the pair even without a cap so a typo is not silent.
        PriceTable.from_sources(
            cfg,
            default_input=opts.price_input_per_mtok,
            default_output=opts.price_output_per_mtok,
        )
    if opts.task_timeout is not None and opts.task_timeout <= 0:
        raise ValueError("--task-timeout must be positive")
    if opts.max_iterations is not None and opts.max_iterations < 1:
        raise ValueError("--max-iterations must be >= 1")
    return threshold, max_wall, prices


def _init_run(opts: CIOptions, cfg: dict, init_fn: Callable[[Any, dict], int]) -> Path:
    args = opts.init_args
    if args is None or getattr(args, "target", None) is None:
        raise ValueError("pass --target (new run) or --run-dir (resume)")

    def progress(ev: dict) -> None:
        if opts.verbose and ev.get("message"):
            _log(f"init {ev.get('phase')}: {ev.get('message')}")

    args.progress = progress
    if not hasattr(args, "job_id"):
        args.job_id = None
    code = init_fn(args, cfg)
    created = getattr(args, "created_run_dir", None)
    if code != 0 or created is None:
        detail = str(getattr(args, "init_error", "") or "").strip()
        raise RuntimeError(f"init failed (exit {code}){': ' + detail if detail else ''}")
    return Path(created).resolve()


def _sarif_summary(doc: dict[str, Any], path: Path, states: tuple[str, ...]) -> dict[str, Any]:
    run = (doc.get("runs") or [{}])[0]
    notes = ((run.get("invocations") or [{}])[0]).get("toolExecutionNotifications") or []
    return {
        "path": str(path),
        "states": list(states),
        "results": len(run.get("results") or []),
        "skipped_no_location": len(notes),
    }


def _write_sarif_doc(doc: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_run_sarif(run_dir: Path, path: Path, states: tuple[str, ...]) -> dict[str, Any]:
    """SARIF 2.1.0 for the run via the #187 exporter. Raises on failure."""
    from vulnforge.db import Database
    from vulnforge.export_findings import ExportOptions, sarif_document

    db = Database.open(run_dir / "harness.db")
    try:
        doc = sarif_document(run_dir, db, options=ExportOptions(sarif_states=states))
    finally:
        db.close()
    _write_sarif_doc(doc, path)
    return _sarif_summary(doc, path, states)


def write_empty_sarif(path: Path, states: tuple[str, ...]) -> dict[str, Any]:
    """Valid SARIF with no results (a diff with nothing in scope)."""
    from vulnforge.export_findings import DISCLAIMER
    from vulnforge.sarif_export import build_sarif, tool_version

    doc = build_sarif(
        [],
        states=states,
        exported_at=utc_now_iso(),
        tool_version=tool_version(),
        disclaimer=DISCLAIMER,
    )
    _write_sarif_doc(doc, path)
    return _sarif_summary(doc, path, states)


def _diff_precheck(opts: CIOptions, cfg: dict, spec: str) -> dict[str, Any]:
    """Validate a ``--diff`` spec before init (same checks ``vf init`` runs)."""
    from vulnforge.diff_scope import DiffScopeError, collect_changes, scope_brief

    target = getattr(opts.init_args, "target", None)
    if target is None:
        return {"error": "--diff needs --target"}
    from vulnforge.diff_scope import parse_diff_spec, resolve_commit

    try:
        base_ref, head_ref = parse_diff_spec(spec)
        base_sha = resolve_commit(Path(target).resolve(), base_ref)
        head_sha = resolve_commit(Path(target).resolve(), head_ref)
    except Exception:  # noqa: BLE001 — collect_changes below reports the real error
        base_sha = head_sha = None
    if base_sha is not None and base_sha == head_sha:
        # e.g. a PR whose head is already in the base: merge-base == head.
        return {
            "empty": True,
            "brief": {
                "spec": spec,
                "compare": "two_tree",
                "base": {"ref": base_ref, "sha": base_sha},
                "head": {"ref": head_ref, "sha": head_sha},
                "changed": 0,
                "expanded": 0,
                "scope_files": 0,
                "excluded": 0,
                "excluded_by_reason": {},
                "same_commit": True,
                "empty": True,
            },
        }
    try:
        changes = collect_changes(
            Path(target).resolve(),
            spec,
            ignore_globs=list((cfg.get("run") or {}).get("ignore_globs") or []),
        )
    except DiffScopeError as e:
        return {"error": str(e)}
    if changes.get("changed"):
        return {}
    return {"empty": True, "brief": {**(scope_brief(changes) or {}), "empty": True}}


def _run_diff_scope(run_dir: Path) -> Optional[dict[str, Any]]:
    """Scope summary of a diff-scoped run (None for a full audit)."""
    from vulnforge.diff_scope import scope_brief

    path = run_dir / "diff_scope.json"
    if not path.is_file():
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"diff_scope.json unreadable: {e}"}
    brief = scope_brief(manifest)
    if brief is not None:
        brief["drift"] = len(((manifest.get("worktree") or {}).get("drift")) or [])
    return brief


def _cost_error(est: Any) -> Optional[str]:
    if est.unmeasured:
        return f"cost_unmeasured: cost cap cannot be enforced ({est.detail})"
    if est.unpriced_models:
        return f"cost_unpriced: cost cap cannot be enforced ({est.unpriced_models})"
    return None


def _run_ralph(
    opts: "CIOptions",
    record: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    run_dir: Path,
    stop_file: Path,
    max_wall: Optional[float],
    guard: Optional[CostGuard],
    ralph_module: Any = None,
) -> tuple[str, bool]:
    events_offset = _events_size(run_dir)
    append_event(
        run_dir,
        {
            "source": "vf_ci",
            "event": "ci_start",
            "mode": record["mode"],
            "budget": record["budget"],
            "threshold": record["threshold"],
        },
    )
    try:
        ralph = ralph_module or load_ralph_module()
        rcfg = ralph.RalphConfig(
            run_dir=run_dir,
            max_iterations=int(opts.max_iterations or UNLIMITED_ITERATIONS),
            max_infra_retries=int(opts.max_infra_retries),
            sleep_seconds=0.0,
            infra_backoff_base=5.0,
            vf_command=ralph.default_vf_command(),
            stop_file=stop_file,
            config_path=Path(opts.config_path).resolve() if opts.config_path else None,
            dry_run=False,
            verbose=opts.verbose,
            task_timeout=opts.task_timeout,
            max_wall_seconds=max_wall,
            max_tasks=None,
            budget_check=guard,
        )
        try:
            ralph_code = int(ralph.run_loop(rcfg))
        except KeyboardInterrupt:
            ralph_code = 130
    except Exception as e:  # noqa: BLE001
        errors.append(f"infra: Ralph failed to run: {e}")
        ralph_code = -1
    last_event = last_ralph_stop_event(run_dir, events_offset)
    stop_reason, stop_error = classify_ralph_stop(ralph_code, last_event)
    record["ralph"] = {"exit_code": ralph_code, "stop_reason": stop_reason}
    if stop_error and ralph_code != -1:
        errors.append(stop_error)
    completed = stop_reason == "idle"
    record["completed"] = completed
    if stop_reason in EARLY_STOP_REASONS or stop_reason == "budget":
        warnings.append(
            f"stopped early ({stop_reason}): remaining work is a coverage gap, "
            "not a pass on unaudited code"
        )
    return stop_reason, completed


def run_ci(
    opts: CIOptions,
    cfg: dict,
    *,
    init_fn: Optional[Callable[[Any, dict], int]] = None,
    ralph_module: Any = None,
) -> CIResult:
    """Run a headless campaign and return the outcome code + result record."""
    t0 = time.monotonic()
    started = utc_now_iso()
    errors: list[str] = []
    warnings: list[str] = []
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "started_at": started,
        "honesty": HONESTY_NOTE,
        "run_dir": None,
    }

    def finish(run_dir: Optional[Path]) -> CIResult:
        if errors:
            code = CI_ERROR
        elif record.get("matched_findings"):
            code = CI_THRESHOLD
        else:
            code = CI_PASS
        record.update(
            {
                "outcome": OUTCOME_NAMES[code],
                "exit_code": code,
                "errors": errors,
                "warnings": warnings,
                "threshold_met": bool(record.get("matched_findings")),
                "finished_at": utc_now_iso(),
                "elapsed_s": round(time.monotonic() - t0, 3),
            }
        )
        _write_outputs(run_dir, opts.output_dir, record)
        _report(record)
        return CIResult(code, record)

    try:
        threshold, max_wall, prices = _validate(opts, cfg)
    except ValueError as e:
        errors.append(f"config: {e}")
        return finish(None)
    record["threshold"] = threshold.to_dict()
    record["budget"] = {
        "max_time_s": max_wall,
        "max_cost_usd": opts.max_cost_usd,
        "task_timeout_s": opts.task_timeout,
        "advisory": "checked before each lease; in-flight tasks may overrun",
    }

    # 1. init or resume ------------------------------------------------------
    run_dir: Optional[Path] = None
    diff_spec = str(getattr(opts.init_args, "diff", None) or "").strip()
    if opts.run_dir is None and diff_spec:
        # PR mode. A bad spec / unresolvable revision / wrong checkout is exit 2.
        # A diff with no hunt-able code (docs-only PR) passes explicitly as
        # "nothing audited" instead of failing init: there is nothing in scope.
        pre = _diff_precheck(opts, cfg, diff_spec)
        if pre.get("error"):
            errors.append(f"diff: {pre['error']}")
            return finish(None)
        if pre.get("empty"):
            record.update(
                {
                    "mode": "new",
                    "diff_scope": pre["brief"],
                    "completed": True,
                    "ralph": {"exit_code": None, "stop_reason": "no_changes"},
                    "tasks": {},
                    "findings": {},
                    "coverage_gaps": {},
                    "matched_findings": [],
                }
            )
            warnings.append(
                f"--diff {diff_spec}: no hunt-able code changes in the target "
                f"({pre['brief']['excluded']} changed path(s) excluded); nothing was "
                "audited and no run was created"
            )
            if opts.sarif_target is not None:
                try:
                    record["sarif"] = write_empty_sarif(opts.sarif_target, opts.sarif_states)
                except Exception as e:  # noqa: BLE001
                    errors.append(f"integrity: SARIF export failed: {e}")
            return finish(None)
    if opts.run_dir is not None:
        run_dir = Path(opts.run_dir).resolve()
        if not (run_dir / "harness.db").is_file():
            errors.append(f"integrity: missing harness.db in {run_dir}")
            return finish(None)
        record["mode"] = "resume"
    else:
        if init_fn is None:
            from vulnforge.cli import cmd_init as init_fn  # noqa: PLW0127
        try:
            run_dir = _init_run(opts, cfg, init_fn)
        except Exception as e:  # noqa: BLE001 — any init failure is exit 2
            errors.append(f"init: {e}")
            return finish(None)
        record["mode"] = "new"
    record["run_dir"] = str(run_dir)
    record["diff_scope"] = _run_diff_scope(run_dir)
    if (record["diff_scope"] or {}).get("drift"):
        warnings.append(
            f"diff scope: {record['diff_scope']['drift']} changed file(s) differ from "
            "the head commit in the working tree; hunts read the working tree"
        )

    stop_file = run_dir / "STOP"
    # A STOP file left in place would make Ralph exit at once and look like an
    # early stop. Fail, but still evaluate so findings and SARIF are reported.
    skip_loop = stop_file.exists()
    if skip_loop:
        errors.append(
            f"integrity: STOP file already present ({stop_file}); remove it to run"
        )

    from vulnforge.db import Database

    try:
        db = Database.open(run_dir / "harness.db")
        try:
            confirmed_before = [f.id for f in db.list_findings(["confirmed"])]
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        errors.append(f"integrity: cannot read harness.db: {e}")
        return finish(run_dir)

    guard: Optional[CostGuard] = None
    if prices is not None and opts.max_cost_usd is not None:
        guard = CostGuard(run_dir, opts.max_cost_usd, prices)

    # 2. Ralph ---------------------------------------------------------------
    if skip_loop:
        record["ralph"] = {"exit_code": None, "stop_reason": "not_run"}
        record["completed"] = False
        stop_reason = "not_run"
        completed = False
    else:
        stop_reason, completed = _run_ralph(
            opts, record, errors, warnings, run_dir, stop_file, max_wall, guard,
            ralph_module=ralph_module,
        )
    if guard is not None:
        est = guard.estimate()
        record["cost"] = {"max_usd": guard.max_usd, **est.to_dict()}
        # Ralph checks the cap only before a lease; a wall/STOP/iteration stop
        # can end the loop before it reads the last task's usage. An
        # unenforceable cap is an error whatever the stop reason.
        cost_err = _cost_error(est)
        if cost_err and not any(e.startswith(cost_err.split(":")[0] + ":") for e in errors):
            errors.append(cost_err)

    # 3. render (authoritative; Ralph's own project step swallows errors) ---
    try:
        from vulnforge.stages.render import render_all

        db = Database.open(run_dir / "harness.db")
        try:
            render_all(run_dir, db)
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        errors.append(f"integrity: render failed: {e}")
    project_dir = run_dir / "project"
    missing = [n for n in REPORT_FILES if not (project_dir / n).is_file()]
    if missing:
        errors.append(f"integrity: report missing {missing} under {project_dir}")
    record["report"] = {
        "dir": str(project_dir),
        "files": [n for n in REPORT_FILES if (project_dir / n).is_file()],
    }

    # 4. evaluate ------------------------------------------------------------
    try:
        db = Database.open(run_dir / "harness.db")
        try:
            findings = db.list_findings()
            task_counts = db.count_tasks_by_state()
            finding_counts = db.count_findings_by_state()
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        errors.append(f"integrity: cannot read results: {e}")
        return finish(run_dir)
    errors.extend(confirmed_integrity_errors(findings, confirmed_before))
    errors.extend(task_integrity_errors(task_counts, completed=completed))
    record["tasks"] = task_counts
    record["findings"] = finding_counts
    record["coverage_gaps"] = coverage_gaps(task_counts)
    # Listed on exit 2 as well, so an infra failure does not hide review items.
    record["matched_findings"] = matched_findings(findings, threshold)
    # 5. SARIF (written on exit 2 too, so partial results still reach code scanning)
    if opts.sarif_target is not None:
        try:
            record["sarif"] = write_run_sarif(run_dir, opts.sarif_target, opts.sarif_states)
        except Exception as e:  # noqa: BLE001
            errors.append(f"integrity: SARIF export failed: {e}")
    append_event(
        run_dir,
        {
            "source": "vf_ci",
            "event": "ci_done",
            "stop_reason": stop_reason,
            "errors": len(errors),
            "matched": len(record["matched_findings"]),
        },
    )
    return finish(run_dir)


# Output ----------------------------------------------------------------------


def _write_outputs(run_dir: Optional[Path], output_dir: Optional[Path], record: dict) -> None:
    text = json.dumps(record, indent=2, ensure_ascii=False, default=str) + "\n"
    if run_dir is not None:
        try:
            (run_dir / RESULT_NAME).write_text(text, encoding="utf-8")
        except OSError as e:
            _log(f"warning: could not write {RESULT_NAME}: {e}")
    if output_dir is None:
        return
    out = Path(output_dir)
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / RESULT_NAME).write_text(text, encoding="utf-8")
        if run_dir is not None and (run_dir / "project").is_dir():
            dest = out / "report"
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(run_dir / "project", dest)
    except OSError as e:
        _log(f"warning: could not write --output-dir {out}: {e}")


def summary_markdown(record: dict) -> str:
    outcome = record.get("outcome")
    lines = [f"## VulnForge CI: {outcome} (exit {record.get('exit_code')})", ""]
    ralph = record.get("ralph") or {}
    if ralph:
        lines.append(f"- Stop reason: `{ralph.get('stop_reason')}`")
    scope = record.get("diff_scope")
    if scope and not scope.get("error"):
        lines.append(
            f"- Diff scope `{scope.get('spec')}`: {scope.get('changed')} changed, "
            f"{scope.get('scope_files')} file(s) in scope, {scope.get('excluded')} excluded "
            "(code outside the scope was not audited)"
        )
    if record.get("findings") is not None:
        lines.append(f"- Findings by state: `{record.get('findings')}`")
    sarif = record.get("sarif")
    if sarif:
        lines.append(
            f"- SARIF: {sarif.get('results')} result(s) ({', '.join(sarif.get('states') or [])}), "
            f"{sarif.get('skipped_no_location')} without a location"
        )
    gaps = record.get("coverage_gaps") or {}
    if gaps:
        lines.append(f"- Coverage gaps (do not fail the job): `{gaps}`")
    cost = record.get("cost")
    if cost:
        lines.append(
            f"- Estimated cost since start: ${cost.get('estimate_usd', 0):.4f} "
            f"of ${cost.get('max_usd')} (conservative; cache discounts ignored)"
        )
    for e in record.get("errors") or []:
        lines.append(f"- Error: {e}")
    for w in record.get("warnings") or []:
        lines.append(f"- Warning: {w}")
    matched = record.get("matched_findings") or []
    if matched:
        lines += [
            "",
            f"### {len(matched)} finding(s) meet the threshold",
            "",
            "| id | state | severity | title | location |",
            "|---|---|---|---|---|",
        ]
        for m in matched[:50]:
            loc = m.get("path") or ""
            if loc and m.get("line"):
                loc += f":{m['line']}"
            title = str(m.get("title") or "").replace("|", "\\|")
            lines.append(
                f"| {m['id']} | {m['state']} | {m.get('severity') or 'unrated'} "
                f"| {title} | {loc} |"
            )
    lines += ["", f"_{record.get('honesty')}_", ""]
    return "\n".join(lines)


def _report(record: dict) -> None:
    md = summary_markdown(record)
    print(md, flush=True)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        try:
            with open(step, "a", encoding="utf-8") as f:
                f.write(md + "\n")
        except OSError as e:
            _log(f"warning: could not write GITHUB_STEP_SUMMARY: {e}")
    for e in record.get("errors") or []:
        _gh_annotation("error", f"VulnForge CI: {e}")
    for w in record.get("warnings") or []:
        _gh_annotation("warning", f"VulnForge CI: {w}")
    n = len(record.get("matched_findings") or [])
    if n:
        _gh_annotation(
            "warning",
            f"VulnForge CI: {n} finding(s) meet the threshold — needs_human means "
            "needs review, not proven",
        )
