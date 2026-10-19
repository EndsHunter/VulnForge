"""CLI entry: python -m bench run --stub | --live"""

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

    args = parser.parse_args(argv)
    if args.cmd == "self-test":
        from bench.selftest import main as selftest_main

        return selftest_main()

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
