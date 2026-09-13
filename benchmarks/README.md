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
| `fixtures/ground_truth/*.json` | `hunt` (id = stem; `pe-*` are one-finding profile_eval hunt seeds) |
| `fixtures/hunt_extra/*.json` | `hunt` (id = stem; Juliet/CVE-shaped micro-fixtures under `fixtures/hunt_extra/<id>/`) |
| `fixtures/vulngym/slice.json` | `hunt` (id = finding `entry-*`; oracle is that finding only) |
| `fixtures/benchmarks/*.json` | `recon` / `finding_report` / `poc_dev` (id = stem; includes recon×10 + toy_*; not `reports/` or `architecture/`) |

`target_ref` comes from the fixture `target` field; oracle body is snapshotted
onto version 1 (type-specific — hunt keeps `findings[]`; recon keeps components /
relation checks; finding_report keeps required fields / citation / honesty).

**Re-seed** (`POST /api/benchmarks/seed` or `seed_from_ground_truth(missing_only=True)`)
adds **missing** seed ids only. Existing ids (including operator edits) are
skipped — never duplicated or clobbered.

See `fixtures/benchmarks/README.md` for oracle shapes.

## Runs

`POST /api/benchmarks/runs` accepts types `recon` | `hunt` | `finding_report`
(not `poc_dev`). Mechanical mode is sync create+score. Live mode is hunt-only
and async (`start_live_run`); the Run tab polls `GET /api/benchmarks/runs/{id}`.
Suite ids `all-hunt` / `all-recon` / `all-finding_report` / `all-runnable`
(or `suite: true` + `types`) run every matching library def as one parent
BenchmarkRun plus a child per def. Live suites must be `all-hunt`. The Run
dropdown lists those suites at the top.

| Type | Scorer |
|------|--------|
| `hunt` | mechanical: sink preindex → `score_findings`. live: Ralph findings → `score_findings` (`confirmed` always false) |
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
| POST   | `/api/benchmarks/seed` | missing-only GT + VulnGym slice + bench fixture import |
| GET    | `/api/benchmarks/runs` | list runs (filters/sort) |
| POST   | `/api/benchmarks/runs` | create + execute (mechanical sync; live hunt async; `all-*` / `suite` = type suite; live `only` subsets) |
| GET    | `/api/benchmarks/runs/series` | score-over-time points (`def_id`, optional `type`) |
| POST   | `/api/benchmarks/runs/{id}/stop` | cancel a live run (stops Ralph; suite skips queued children) |
| GET    | `/api/benchmarks/runs/{id}` | run detail + type metrics (live queued/running rows are reconciled) |
| GET    | `/api/benchmarks/compare` | version A vs B (`def_id`, `version_a`, `version_b`, optional `type`) |

Results UI (`/benchmarks/results`) charts score over time (inline SVG) and
compares two versions of the same def (latest + aggregate + Δ). Missing
version runs return zeros / empty latest.
