"""Benchmarks: did a change make VulnForge find more real bugs, for less?

- **Library** (``store``): versioned case defs seeded from
  ``fixtures/ground_truth``, ``fixtures/hunt_extra``, ``fixtures/benchmarks``
  (recon / finding_report) and ``fixtures/vulngym/slice.json``.
- **Suites** (``suites``): ``realworld`` / ``synthetic`` / ``fixtures``.
- **Tiers**: ``l0`` (mechanical fixture checks, ``runner``) and ``directed``
  (live hunts pointed at the oracle file, ``live``).
- **Scoring**: oracle matching (``match``), state-aware live scoring
  (``live_score``), aggregates and run-vs-baseline compare (``compare``),
  run fingerprints (``fingerprint``).
- Runs persist under ``benchmarks/runs/``. Nothing here ever sets a finding
  ``confirmed``.
"""

from __future__ import annotations

from vulnforge.benchmarks.compare import (
    aggregate,
    compare_runs,
    member_row,
    run_duration_s,
    summarize_repeats,
)
from vulnforge.benchmarks.fingerprint import capture_fingerprint, fingerprint_diff
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
from vulnforge.benchmarks.live_score import GATED_STATES, score_case
from vulnforge.benchmarks.runner import (
    mechanical_hunt_score,
    run_benchmark,
    run_fixture_checks,
    run_hunt,
)
from vulnforge.benchmarks.runs import (
    PERSISTED_TYPES,
    RUN_STATUSES,
    RUNNABLE_TYPES,
    SORT_KEYS,
    SUITE_PARENT_IDS,
    TERMINAL_STATUSES,
    BenchmarkRunError,
    baseline_for,
    create_run,
    get_run,
    is_suite_run,
    list_runs,
    load_baselines,
    reset_runs_root_override,
    runs_root,
    set_baseline,
    set_runs_root,
    update_run,
)
from vulnforge.benchmarks.scorers import score_finding_report, score_recon
from vulnforge.benchmarks.store import (
    BENCH_TYPES,
    BENCHMARK_FIXTURES_ROOT,
    COLLECTION_FORMAT,
    DEF_ID_RE,
    HUNT_EXTRA_ROOT,
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
from vulnforge.benchmarks.suites import SUITES, TIERS, suite_members, suite_of

__all__ = [
    "BENCH_TYPES",
    "BENCHMARK_FIXTURES_ROOT",
    "COLLECTION_FORMAT",
    "DEF_ID_RE",
    "GATED_STATES",
    "HUNT_EXTRA_ROOT",
    "PERSISTED_TYPES",
    "RUNNABLE_TYPES",
    "RUN_STATUSES",
    "SORT_KEYS",
    "SUITES",
    "SUITE_PARENT_IDS",
    "TERMINAL_STATUSES",
    "TIERS",
    "BenchmarkLibraryError",
    "BenchmarkRunError",
    "HuntHint",
    "aggregate",
    "baseline_for",
    "cancel_live_run",
    "capture_fingerprint",
    "compare_runs",
    "create_def",
    "create_run",
    "delete_def",
    "ensure_library",
    "eval_runs_root_for",
    "fingerprint_diff",
    "get_def",
    "get_run",
    "get_version",
    "is_suite_run",
    "library_root",
    "list_active_runs",
    "list_defs",
    "list_runs",
    "list_versions",
    "live_refusal",
    "load_baselines",
    "mechanical_hunt_score",
    "member_row",
    "oracle_snapshot_hash",
    "reconcile_live_run",
    "require_live_llm",
    "reset_library_root_override",
    "reset_runs_root_override",
    "run_benchmark",
    "run_duration_s",
    "run_fixture_checks",
    "run_hunt",
    "runs_root",
    "score_case",
    "score_finding_report",
    "score_recon",
    "seed_from_ground_truth",
    "set_baseline",
    "set_library_root",
    "set_runs_root",
    "start_live_run",
    "start_live_suite",
    "suite_members",
    "suite_of",
    "summarize_repeats",
    "update_def",
    "update_run",
]
