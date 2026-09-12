"""Benchmark library + hunt runs.

First ``ensure_library()`` seeds hunt benches from ``fixtures/ground_truth/*.json``.
Re-seed via ``seed_from_ground_truth(missing_only=True)`` / ``POST /api/benchmarks/seed``
adds missing ids only and never clobbers operator edits.

Hunt runs (ticket 3): ``run_hunt`` / ``POST /api/benchmarks/runs`` — mechanical L0
by default (sink preindex → score_findings); results under ``benchmarks/runs/``.
"""

from __future__ import annotations

from vulnforge.benchmarks.runner import mechanical_hunt_score, run_hunt
from vulnforge.benchmarks.runs import (
    RUN_STATUSES,
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
from vulnforge.benchmarks.store import (
    BENCH_TYPES,
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
    "COLLECTION_FORMAT",
    "DEF_ID_RE",
    "RUN_STATUSES",
    "TERMINAL_STATUSES",
    "BenchmarkLibraryError",
    "BenchmarkRunError",
    "create_def",
    "create_run",
    "delete_def",
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
    "run_hunt",
    "runs_root",
    "seed_from_ground_truth",
    "set_library_root",
    "set_runs_root",
    "update_def",
    "update_run",
]
