"""Benchmark library — mutable BenchmarkDef heads + immutable versions.

First ``ensure_library()`` seeds hunt benches from ``fixtures/ground_truth/*.json``.
Re-seed via ``seed_from_ground_truth(missing_only=True)`` / ``POST /api/benchmarks/seed``
adds missing ids only and never clobbers operator edits.
"""

from __future__ import annotations

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
    "BenchmarkLibraryError",
    "create_def",
    "delete_def",
    "ensure_library",
    "get_def",
    "get_version",
    "library_root",
    "list_defs",
    "list_versions",
    "oracle_snapshot_hash",
    "reset_library_root_override",
    "seed_from_ground_truth",
    "set_library_root",
    "update_def",
]
