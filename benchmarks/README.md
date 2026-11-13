# Benchmarks

The Benchmarks desk (`/benchmarks`) and `vf bench` answer one question:

> Compared to a baseline, did a change (prompt, tool, hunt profile, model or
> VulnForge commit) find more real bugs, with fewer unmatched findings, for
> fewer tokens and less time?

Package code: `vulnforge/benchmarks/`. Design and decisions: issue #204.
Real-world suite roadmap: issue #171.

## Concepts

| Concept | What it is |
|---------|------------|
| **Case** | A versioned library def: target + oracle (`store.py`). Editing a case bumps its version and oracle hash. |
| **Suite** | Cases grouped by what they measure (`suites.py`). A `suite:<id>` tag wins, else the suite is derived from the case's shape. |
| **Tier** | What kind of number a run produces. Tiers never mix in one aggregate. |
| **Run** | A `BenchmarkRun` (`runs.py`). A suite run is a `suite-<id>` parent with one child per case × repeat. |
| **Fingerprint** | Recorded on every live run (`fingerprint.py`): git SHA + dirty flag, model, endpoint host (never keys), API mode, hashes of `seeds/system/`, the hunt-profile collection and the agent tool registry, and whether `validate_llm` ran. |
| **Baseline** | One pinned run per suite × tier (`benchmarks/runs/baselines.json`). |

### Suites

| Suite | Cases | Tiers |
|-------|-------|-------|
| `realworld` | OSS projects pinned at pre-fix commits: the 16-case VulnGym GHSA slice (`fixtures/vulngym/slice.json`, checked out under `.audit/vulngym/trees/`). | `directed` |
| `synthetic` | Vendored apps with planted bugs: `toy_sqli`, `mono_synth`, `pe-*`, `hx-*`. | `directed` |
| `fixtures` | Recon and finding-report scorer fixtures. Its L0 run covers **every vendored case** (synthetic hunts too). | `l0` |

To add a real-world CVE, add a hunt case whose target is a pinned checkout and
tag it `suite:realworld`.

### Tiers

| Tier | Meaning |
|------|---------|
| `l0` | **Fixture check.** Mechanical, no LLM. Hunt L0 builds synthetic findings from the sink preindex at the oracle's own path; recon and finding_report score fixture inputs. It says the fixtures and scorers still line up. **It says nothing about model quality.** Some `pe-*` cases fail L0 because the sink preindex has no sink kind for their class (crypto, SSRF, upload, XSS, XXE). |
| `directed` | **Live hunt pointed at the oracle file and class** (`hunt_hints_from_oracle`), in a throwaway harness under `.audit/benchmarks/eval_runs/`, using the Settings LLM. Recall here means "recall when told where to look". `validate_llm` is on by default, as in production. |

A `campaign` tier (full unguided init → recon → hunt per target) is the next
step for #171.

## Metrics

Scored per case by `live_score.score_case`, aggregated by `compare.aggregate`
and `compare.summarize_repeats` (mean, min and max across repeats).

| Metric | Definition | Caveat |
|--------|------------|--------|
| **Recall (gated)** | Oracle hits from findings that passed the gates (`needs_human`, or `confirmed`) divided by oracles. Headline. | |
| Recall (raw) | Hits from findings in any state. | Shows gate losses. |
| **Unmatched per target** | Gated findings matching no oracle, divided by scored case runs. | Not proven false positives. Real-OSS oracles are incomplete. |
| **Tokens per hit** | Total LLM tokens (eval run `llm_usage_summary.json`) divided by gated hits. | Oracle-matched, never human-confirmed. `$` waits for a per-model price in Settings. |
| **Wall time** | Sum of per-case `finished_at - started_at`. | |

Nothing in the benchmarks package sets a finding `confirmed`. Every bench
record carries `confirmed: false`.

## Compare

`compare.compare_runs(a, b)` diffs run B against baseline A:

- the fingerprint diff ("what changed"),
- headline deltas,
- a per-oracle **flip table**: regressions (hit → miss), gains (miss → hit), unchanged.

It **refuses** across tiers or suites, and when a shared case's oracle hash
changed (not like-for-like). It **warns** when either side has one repeat
(LLM variance not measured) or when the case sets differ.

## CLI

```bash
vf bench suites
vf bench run --suite fixtures --tier l0                 # fixture checks, seconds
vf bench run --suite realworld --repeat 3 --note "new hunt prompt" [--baseline]
vf bench run --suite synthetic --only toy_sqli --no-validate-llm
vf bench compare <baseline_run_id> <run_id>
vf bench baseline <run_id>
```

Live runs block until done. Ctrl-C stops the run.
`scripts/vulngym_slice.py` keeps slice maintenance (`--freeze`, `--prepare`, `--sensitivity`).

## Layout

```
benchmarks/library/           # default root (override: VULNFORGE_BENCHMARKS_LIBRARY_ROOT)
  collection.json             # mutable case heads
  versions/<id>/<n>.json      # immutable version + oracle snapshot
benchmarks/runs/              # override: VULNFORGE_BENCHMARKS_RUNS_ROOT
  <br-id>/result.json         # one BenchmarkRun
  <br-id>/live_overlay.yaml   # Settings snapshot a live case ran with
  baselines.json              # {"<suite>:<tier>": run_id}
```

Not under `project/` (run projection).

## Seed

First init (`ensure_library()` when `collection.json` is missing) imports:

| Source | Types |
|--------|-------|
| `fixtures/ground_truth/*.json` | `hunt` (`pe-*` are one-finding profile_eval seeds) |
| `fixtures/hunt_extra/*.json` | `hunt` (micro-fixtures under `fixtures/hunt_extra/<id>/`) |
| `fixtures/vulngym/slice.json` | `hunt`, one case per finding (`entry-*`) |
| `fixtures/benchmarks/*.json` | `recon` / `finding_report` (not `reports/` or `architecture/`) |

Reseed (`POST /api/benchmarks/seed`) adds **missing** ids only and never
clobbers operator edits. Library entries of the retired `poc_dev` type are
skipped on load. See `fixtures/benchmarks/README.md` for oracle shapes.

## API

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/benchmarks/suites` | suites, case counts, tiers, baseline + latest + trend per suite × tier |
| POST | `/api/benchmarks/runs` | `{suite, tier, repeat, validate_llm, note, only}` (directed: async; `fixtures`/`l0`: sync) or a single case `{def_id, mode}` |
| GET | `/api/benchmarks/runs` | list (`suite=true|false`, `suite_id`, `tier`, `def_id`, `status`, `type`, `sort`, `order`, `limit`) |
| GET | `/api/benchmarks/runs/active` | queued/running (live rows reconciled; suite parents first) |
| GET | `/api/benchmarks/runs/{id}` | run detail + `baseline_id` for suite runs |
| POST | `/api/benchmarks/runs/{id}/stop` | cancel a live run (stops Ralph; suite skips queued children) |
| POST | `/api/benchmarks/runs/{id}/baseline` | pin a finished suite run as baseline for its suite × tier |
| GET | `/api/benchmarks/compare?a=&b=` | run B vs baseline A |
| GET | `/api/benchmarks` · `/{id}` · `/{id}/versions[/{n}]` | library heads, head + oracle, frozen versions |
| POST / PUT / DELETE | `/api/benchmarks[/{id}]` | create / update (content change bumps version) / delete |
| POST | `/api/benchmarks/seed` | missing-only reseed |

Only one live run (single case or suite) may be queued or running at a time
(409 otherwise).

## UI

`/benchmarks` (scoreboard: suite cards vs baseline, running now, fixture
checks, recent runs), `/benchmarks/runs/<id>`, `/benchmarks/compare?a=&b=`,
`/benchmarks/cases`. Page modules live in `vulnforge/ui/static/pages/bench/`.
`helpers.js` holds the pure helpers (`tests/js/bench_helpers.test.js`). Old
URLs (`/benchmarks/run|poc|results|library`) redirect.
