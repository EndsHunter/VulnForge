# Benchmark library + runs

Durable filesystem store for bench-desk **Library** definitions and **BenchmarkRun**
results.

## Layout

```
benchmarks/library/           # default root (override: VULNFORGE_BENCHMARKS_LIBRARY_ROOT)
  collection.json             # mutable BenchmarkDef heads
  versions/<id>/<n>.json      # immutable BenchmarkVersion + oracle snapshot
benchmarks/runs/<br-id>/      # BenchmarkRun result.json (override: VULNFORGE_BENCHMARKS_RUNS_ROOT)
  result.json
```

Not under `project/` (run projection). Package code: `vulnforge/benchmarks/`.

## Seed

**First init** (`ensure_library()` when `collection.json` is missing) imports:

| Source | Types |
|--------|-------|
| `fixtures/ground_truth/*.json` | `hunt` (id = stem) |
| `fixtures/benchmarks/*.json` | `recon` / `finding_report` (id = stem; not `reports/` or `architecture/`) |

`target_ref` comes from the fixture `target` field; oracle body is snapshotted
onto version 1 (type-specific — hunt keeps `findings[]`; recon keeps components /
relation checks; finding_report keeps required fields / citation / honesty).

**Re-seed** (`POST /api/benchmarks/seed` or `seed_from_ground_truth(missing_only=True)`)
adds **missing** seed ids only. Existing ids (including operator edits) are
skipped — never duplicated or clobbered.

See `fixtures/benchmarks/README.md` for oracle shapes.

## Runs

`POST /api/benchmarks/runs` accepts types `recon` | `hunt` | `finding_report`
(not `poc_dev`). Mechanical mode only for now:

| Type | Scorer |
|------|--------|
| `hunt` | sink preindex → `score_findings` |
| `recon` | `score_recon` — architecture.json or FS/codemap heuristics vs expected components / path_hints; relations + trust_boundaries presence |
| `finding_report` | `score_finding_report` — required fields, citation density, honesty labels (fixture report JSON) |

## API

| Method | Path | Notes |
|--------|------|--------|
| GET    | `/api/benchmarks` | list heads (seeds on first init) |
| GET    | `/api/benchmarks/{id}` | mutable head + current oracle |
| POST   | `/api/benchmarks` | create (writes version 1; multi-type OK) |
| PUT    | `/api/benchmarks/{id}` | update; content change bumps `head_version` |
| DELETE | `/api/benchmarks/{id}` | hard-delete def + versions |
| GET    | `/api/benchmarks/{id}/versions` | version summaries |
| GET    | `/api/benchmarks/{id}/versions/{n}` | frozen snapshot (immutable) |
| POST   | `/api/benchmarks/seed` | missing-only GT + bench fixture import |
| GET    | `/api/benchmarks/runs` | list runs (filters/sort) |
| POST   | `/api/benchmarks/runs` | create + execute (mechanical) |
| GET    | `/api/benchmarks/runs/series` | score-over-time points (`def_id`, optional `type`) |
| GET    | `/api/benchmarks/runs/{id}` | run detail + type metrics |
| GET    | `/api/benchmarks/compare` | version A vs B (`def_id`, `version_a`, `version_b`, optional `type`) |

Results UI (`/benchmarks/results`) charts score over time (inline SVG) and
compares two versions of the same def (latest + aggregate + Δ). Missing
version runs return zeros / empty latest.
