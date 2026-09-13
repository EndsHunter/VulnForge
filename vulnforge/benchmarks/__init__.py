"""Benchmark library + runs (hunt / recon / finding_report / poc_dev).

First ``ensure_library()`` seeds from ``fixtures/ground_truth/*.json`` (hunt,
including profile_eval ``pe-*`` one-finding defs),
``fixtures/hunt_extra/*.json`` (micro-fixture hunts),
``fixtures/vulngym/slice.json`` (one hunt def per finding), and
``fixtures/benchmarks/*.json`` (recon / finding_report / poc_dev). Re-seed
via ``seed_from_ground_truth(missing_only=True)`` / ``POST /api/benchmarks/seed``
adds missing ids only and never clobbers operator edits.

Runs: ``run_benchmark`` / ``POST /api/benchmarks/runs`` — mechanical L0 by
default; ``mode=live`` hunts go through ``start_live_run`` (async).
``poc_dev`` refused on the Run path. Workshop:
``run_poc_workshop`` / ``POST /api/benchmarks/poc/runs`` (network:none).
Results under ``benchmarks/runs/``.
"""

from __future__ import annotations

from vulnforge.benchmarks.live import (
    HuntHint,
    cancel_live_run,
    eval_runs_root_for,
    list_active_runs,
    live_refusal,
    reconcile_live_run,
    require_live_llm,
    start_live_run,
    start_live_suite,
)
from vulnforge.benchmarks.poc_workshop import (
    generate_pack_stub,
    run_pack_subprocess,
    run_poc_workshop,
    score_poc_dev,
)
from vulnforge.benchmarks.runner import (
    SUITE_DEF_IDS,
    defs_for_suite,
    mechanical_hunt_score,
    run_benchmark,
    run_benchmark_suite,
    run_hunt,
    suite_types_for,
)
from vulnforge.benchmarks.runs import (
    PERSISTED_TYPES,
    RUN_STATUSES,
    RUNNABLE_TYPES,
    SORT_KEYS,
    SUITE_PARENT_IDS,
    TERMINAL_STATUSES,
    BenchmarkRunError,
    create_run,
    get_run,
    is_suite_run,
    list_runs,
    reset_runs_root_override,
    runs_root,
    set_runs_root,
    update_run,
)
from vulnforge.benchmarks.scorers import score_finding_report, score_recon
from vulnforge.benchmarks.series import (
    build_series,
    compare_versions,
    empty_side,
    extract_score,
    run_duration_s,
    summarize_version,
)
from vulnforge.benchmarks.store import (
    BENCH_TYPES,
    BENCHMARK_FIXTURES_ROOT,
    HUNT_EXTRA_ROOT,
    COLLECTION_FORMAT,
    DEF_ID_RE,
    BenchmarkLibraryError,
    create_def,
    delete_def,
    ensure_library,
    get_def,
    get_version,
    library_root,
    list_defs,
    list_versions,
    oracle_snapshot_hash,
    reset_library_root_override,
    seed_from_ground_truth,
    set_library_root,
    update_def,
)

__all__ = [
    "BENCH_TYPES",
    "BENCHMARK_FIXTURES_ROOT",
    "HUNT_EXTRA_ROOT",
    "COLLECTION_FORMAT",
    "DEF_ID_RE",
    "PERSISTED_TYPES",
    "RUNNABLE_TYPES",
    "RUN_STATUSES",
    "SORT_KEYS",
    "SUITE_PARENT_IDS",
    "TERMINAL_STATUSES",
    "BenchmarkLibraryError",
    "BenchmarkRunError",
    "HuntHint",
    "build_series",
    "cancel_live_run",
    "compare_versions",
    "create_def",
    "create_run",
    "delete_def",
    "empty_side",
    "eval_runs_root_for",
    "extract_score",
    "run_duration_s",
    "ensure_library",
    "get_def",
    "get_run",
    "get_version",
    "library_root",
    "list_defs",
    "is_suite_run",
    "list_runs",
    "list_versions",
    "list_active_runs",
    "live_refusal",
    "mechanical_hunt_score",
    "oracle_snapshot_hash",
    "reconcile_live_run",
    "require_live_llm",
    "reset_library_root_override",
    "reset_runs_root_override",
    "generate_pack_stub",
    "run_pack_subprocess",
    "run_poc_workshop",
    "score_poc_dev",
    "SUITE_DEF_IDS",
    "defs_for_suite",
    "run_benchmark",
    "run_benchmark_suite",
    "run_hunt",
    "start_live_run",
    "start_live_suite",
    "suite_types_for",
    "runs_root",
    "score_finding_report",
    "score_recon",
    "seed_from_ground_truth",
    "set_library_root",
    "set_runs_root",
    "summarize_version",
    "update_def",
    "update_run",
]
