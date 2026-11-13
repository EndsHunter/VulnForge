"""``vf bench``: run suites and compare runs from the shell (per release, in CI).

    vf bench suites
    vf bench run --suite realworld [--repeat 3] [--no-validate-llm] [--baseline] [--note ...]
    vf bench run --suite fixtures --tier l0
    vf bench compare <baseline_run_id> <run_id>
    vf bench baseline <run_id>

Live runs block until done (Ctrl-C stops the run). Uses the Settings LLM.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


def add_bench_parser(sub: Any) -> None:
    p = sub.add_parser("bench", help="Benchmarks: run suites, pin baselines, compare runs")
    bsub = p.add_subparsers(dest="bench_cmd", required=True)
    bsub.add_parser("suites", help="List suites, case counts and baselines")
    run = bsub.add_parser("run", help="Run a suite (directed is live, l0 is mechanical)")
    run.add_argument("--suite", required=True, help="realworld | synthetic | fixtures")
    run.add_argument("--tier", default=None, help="directed | l0 (default: the suite's first)")
    run.add_argument("--repeat", type=int, default=1, help="Repeat each case N times (live)")
    run.add_argument("--only", nargs="*", default=None, help="Subset of case ids")
    run.add_argument(
        "--no-validate-llm",
        dest="validate_llm",
        action="store_false",
        help="Skip adversarial disprove (default on, as in production)",
    )
    run.add_argument("--note", default="", help="Free-text note stored on the run")
    run.add_argument("--baseline", action="store_true", help="Pin the finished run as baseline")
    run.add_argument("--json", action="store_true", help="Print the full run JSON")
    cmp = bsub.add_parser("compare", help="Diff run B against baseline run A")
    cmp.add_argument("a")
    cmp.add_argument("b")
    cmp.add_argument("--json", action="store_true")
    base = bsub.add_parser("baseline", help="Pin a finished suite run as baseline")
    base.add_argument("run_id")


def _fmt(v: Any, pct: bool = False) -> str:
    if v is None:
        return "–"
    if pct:
        return f"{float(v) * 100:.1f}%"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def _print_summary(run: dict[str, Any]) -> None:
    m = run.get("metrics") or {}
    head = (m.get("summary") or {}).get("headline") or {}
    print(f"run       {run.get('id')}  [{run.get('status')}]  {run.get('suite_id')} / {run.get('tier')}")
    if run.get("tier") == "l0":
        print(f"cases     {m.get('passed_count')}/{m.get('count')} passed (L0: fixtures/scorers, not model quality)")
        return
    print(f"recall    {_fmt(head.get('recall'), True)} gated   {_fmt(head.get('recall_raw'), True)} raw")
    print(f"unmatched {_fmt(head.get('unmatched_per_target'))} per target (not proven false positives)")
    print(f"tokens    {_fmt(head.get('tokens_per_hit'))} per oracle-matched finding")
    print(f"wall      {_fmt(head.get('wall_s'))} s")
    if run.get("error"):
        print(f"error     {run['error']}")


def cmd_bench(args: argparse.Namespace, cfg: dict) -> int:  # noqa: ARG001 — cfg unused, Settings is read by live
    from vulnforge.benchmarks import (
        BenchmarkRunError,
        cancel_live_run,
        compare_runs,
        ensure_library,
        get_run,
        list_defs,
        load_baselines,
        run_fixture_checks,
        set_baseline,
        start_live_suite,
    )
    from vulnforge.benchmarks.live import drive_live_suite
    from vulnforge.benchmarks.suites import SUITES, suite_catalog

    action = str(getattr(args, "bench_cmd", "") or "")
    ensure_library()
    try:
        if action == "suites":
            base = load_baselines()
            for s in suite_catalog(list_defs()):
                tiers = ", ".join(
                    f"{t} (baseline {base.get(s['id'] + ':' + t, '–')})" for t in s["tiers"]
                )
                print(f"{s['id']:<10} {s['case_count']:>3} cases  {tiers}")
            return EXIT_OK
        if action == "baseline":
            print(json.dumps(set_baseline(args.run_id)))
            return EXIT_OK
        if action == "compare":
            out = compare_runs(get_run(args.a), get_run(args.b))
            if args.json:
                print(json.dumps(out, indent=2, default=str))
            elif not out["comparable"]:
                print(f"not comparable: {out['refusal']}")
                return EXIT_FAIL
            else:
                for w in out["warnings"]:
                    print(f"warning: {w}")
                for d in out["fingerprint_diff"]:
                    print(f"changed {d['key']}: {d['a']} -> {d['b']}")
                for k, v in out["deltas"].items():
                    print(f"Δ {k:<22} {_fmt(v)}")
                print(f"regressions {out['counts']['regression']}  gains {out['counts']['gain']}")
                for f in out["flips"]:
                    if f["change"] in ("regression", "gain"):
                        print(f"  {f['change']:<10} {f['def_id']} {f['oracle_id']}  {f['a_rate']} -> {f['b_rate']}")
            return EXIT_OK
        if action == "run":
            sid = str(args.suite).strip().lower()
            tier = args.tier or (SUITES.get(sid, {}).get("tiers") or ("directed",))[0]
            if tier == "l0":
                run = run_fixture_checks(note=args.note)
            else:
                parent = start_live_suite(
                    suite_id=sid,
                    repeat=args.repeat,
                    only=args.only,
                    validate_llm=args.validate_llm,
                    note=args.note,
                    worker=lambda _pid: None,
                )
                if parent["status"] == "error":
                    print(f"error: {parent.get('error')}", file=sys.stderr)
                    return EXIT_FAIL
                print(f"started {parent['id']} ({len(parent['metrics'].get('member_run_ids') or [])} case runs)")
                try:
                    run = drive_live_suite(parent["id"])
                except KeyboardInterrupt:
                    run = cancel_live_run(parent["id"])
            if args.baseline and run["status"] in ("passed", "failed"):
                set_baseline(run["id"])
                print(f"pinned {run['id']} as baseline")
            if args.json:
                print(json.dumps(run, indent=2, default=str))
            else:
                _print_summary(get_run(run["id"]))
            return EXIT_OK if run["status"] in ("passed", "failed") else EXIT_FAIL
    except BenchmarkRunError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_FAIL
    print(f"unknown bench command: {action}", file=sys.stderr)
    return EXIT_USAGE
