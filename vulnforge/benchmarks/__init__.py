"""Benchmark library + runs (hunt / recon / finding_report).

First ``ensure_library()`` seeds from ``fixtures/ground_truth/*.json`` (hunt)
and ``fixtures/benchmarks/*.json`` (recon / finding_report). Re-seed via
``seed_from_ground_truth(missing_only=True)`` / ``POST /api/benchmarks/seed``
adds missing ids only and never clobbers operator edits.

Runs: ``run_benchmark`` / ``POST /api/benchmarks/runs`` — mechanical L0 by
default; ``poc_dev`` refused on the Run path. Results under ``benchmarks/runs/``.
"""

from __future__ import annotations

from vulnforge.benchmarks.runner import (
    mechanical_hunt_score,
    run_benchmark,
    run_hunt,
)
from vulnforge.benchmarks.runs import (
    RUN_STATUSES,
    RUNNABLE_TYPES,
    SORT_KEYS,
    TERMINAL_STATUSES,
    BenchmarkRunError,
    create_run,
    get_run,
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
    summarize_version,
)
from vulnforge.benchmarks.store import (
    BENCH_TYPES,
    BENCHMARK_FIXTURES_ROOT,
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
    "COLLECTION_FORMAT",
    "DEF_ID_RE",
    "RUNNABLE_TYPES",
    "RUN_STATUSES",
    "SORT_KEYS",
    "TERMINAL_STATUSES",
    "BenchmarkLibraryError",
    "BenchmarkRunError",
    "build_series",
    "compare_versions",
    "create_def",
    "create_run",
    "delete_def",
    "empty_side",
    "extract_score",
    "ensure_library",
    "get_def",
    "get_run",
    "get_version",
    "library_root",
    "list_defs",
    "list_runs",
    "list_versions",
    "mechanical_hunt_score",
    "oracle_snapshot_hash",
    "reset_library_root_override",
    "reset_runs_root_override",
    "run_benchmark",
    "run_hunt",
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
