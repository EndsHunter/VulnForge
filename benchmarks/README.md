# Benchmark library

Durable filesystem store for bench-desk **Library** definitions.

## Layout

```
benchmarks/library/           # default root (override: VULNFORGE_BENCHMARKS_LIBRARY_ROOT)
  collection.json             # mutable BenchmarkDef heads
  versions/<id>/<n>.json      # immutable BenchmarkVersion + oracle snapshot
```

Not under `project/` (run projection). Package code: `vulnforge/benchmarks/`.

## Seed

**First init** (`ensure_library()` when `collection.json` is missing) imports each
`fixtures/ground_truth/*.json` as a **hunt** bench. Id = filename stem
(`toy_sqli`, `mono_synth`). `target_ref` comes from the GT `target` field;
oracle findings are snapshotted onto version 1.

**Re-seed** (`POST /api/benchmarks/seed` or `seed_from_ground_truth(missing_only=True)`)
adds **missing** seed ids only. Existing ids (including operator edits) are
skipped — never duplicated or clobbered.

## API

| Method | Path | Notes |
|--------|------|--------|
| GET    | `/api/benchmarks` | list heads (seeds on first init) |
| GET    | `/api/benchmarks/{id}` | mutable head + current oracle |
| POST   | `/api/benchmarks` | create (writes version 1) |
| PUT    | `/api/benchmarks/{id}` | update; content change bumps `head_version` |
| DELETE | `/api/benchmarks/{id}` | hard-delete def + versions |
| GET    | `/api/benchmarks/{id}/versions` | version summaries |
| GET    | `/api/benchmarks/{id}/versions/{n}` | frozen snapshot (immutable) |
| POST   | `/api/benchmarks/seed` | missing-only GT import |

Runs pin a version (BenchmarkRun is out of scope for ticket 2).
