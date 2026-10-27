"""CLI entry: python -m bench run --stub | --live, or score --from-cache."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from bench.config import load_config
from bench.runner import emit_results, run_bench
from bench.tasks import load_tasks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="Score the seed per model")
    run_p.add_argument("--config", type=Path, default=None)
    mode = run_p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--stub", action="store_true", help="Offline deterministic personas")
    mode.add_argument("--live", action="store_true", help="OpenAI-compatible endpoint in config")
    run_p.add_argument("--k", type=int, default=None)
    run_p.add_argument("--workers", type=int, default=None)

    sub.add_parser("self-test", help="Check stub scorecard invariants")

    score_p = sub.add_parser("score", help="Rebuild a scorecard from cached responses")
    score_p.add_argument(
        "--from-cache",
        action="store_true",
        required=True,
        help="Score cached responses only; do not call a model",
    )
    score_p.add_argument("--config", type=Path, default=None)
    score_p.add_argument("--cache-dir", type=Path, default=Path("bench/cache"))
    score_p.add_argument("--mode", choices=("live", "stub"), default="live")
    score_p.add_argument("--k", type=int, default=None)
    score_p.add_argument("--workers", type=int, default=None)

    args = parser.parse_args(argv)
    if args.cmd == "self-test":
        from bench.selftest import main as selftest_main

        return selftest_main()

    if args.cmd == "score":
        if not args.cache_dir.is_dir():
            sys.stderr.write(f"cache directory not found: {args.cache_dir}\n")
            return 1
        config = load_config(args.config)
        if args.k is not None:
            config.k = args.k
        if args.workers is not None:
            config.workers = args.workers
        tasks = load_tasks()
        payload = run_bench(
            config,
            tasks,
            mode=args.mode,
            cache_dir=args.cache_dir,
            from_cache=True,
        )
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        if payload.get("partial"):
            sys.stderr.write(
                "INCOMPLETE CACHE: scorecard is partial "
                f"(cache_misses={payload['cache_misses']}, "
                f"coverage={payload.get('cache_coverage')}).\n"
            )
        if payload["disprove_gate"]["failed"]:
            return 3
        if payload.get("partial"):
            return 2
        return 0

    config = load_config(args.config)
    if args.k is not None:
        config.k = args.k
    if args.workers is not None:
        config.workers = args.workers
    tasks = load_tasks()
    if args.stub:
        with TemporaryDirectory(prefix="vf-bench-cache-") as cache:
            payload = run_bench(config, tasks, mode="stub", cache_dir=Path(cache))
    else:
        payload = dict(run_bench(config, tasks, mode="live", cache_dir=Path("bench/cache")))
        payload["wrote_results"] = True
        emit_results(payload, Path("bench/results"))
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if payload["disprove_gate"]["failed"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
