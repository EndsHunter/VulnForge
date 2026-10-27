# Benchmarks desk

Branch `cursor/bench-desk-0844`. Screenshots are in commit `3985cb4fe3aadde3d7c2dd9c352c68c3bd0a6117`, branched from `0831584d62a6d5d43d0e972088e962415a555c19` (bench honesty). Not merged. No pull request.

## What the page shows

`/benchmarks` reads a directory of `python -m bench` runs. `vf dashboard --bench-results` sets it. Without the flag, `VF_BENCH_RESULTS` wins, then `bench/results`. The proof server pointed at `tests/fixtures/bench_desk`, which is not `bench/results/`.

The old Run, POC workshop, Results, and Library seed desk redirects here.

A run directory is one of:

- `scorecard.json` — scored, or partial when `partial` is true. Excluded leaderboard rows stay on the table.
- `error.json` — failed. `rows` are the error rows.
- `run.json`, `errors.json`, `error.txt`, or a directory with no scorecard — unscored, with whatever error rows it left.

Columns on a scorecard: precision (`precision`), recall (disprove-stage `recall`), recall at the FPR cap (`recall_at_fpr_le_0.5pct`, the headline), VD-S (`vd_s`, that same headline), FPR (`fpr`), Youden (`youden`). Youden is its own column. With fewer than 200 negatives it reads `equals VD-S (fewer than 200 negatives)` and `youden_in_ranking` is false. A ranked Youden is a number and `youden_in_ranking` is true. Run stats: `partial`, `cache_coverage`, `stored_failure_count`, `infra_error_row_count`, `infra_error_count`, `fpr_cap`.

The after screenshot is the fixture:

| Run | Status | partial | cache_coverage | stored_failure_count | infra_error_row_count | Headline recall |
| --- | --- | --- | --- | --- | --- | --- |
| `20261027T120000Z` | scored | false | 1 | 2 | 1 | 0.75 |
| `20261027T110000Z` | partial | true | 0.85 | 4 | 0 | 0.333333 |
| `20261027T100000Z-failed` | failed | true | 0.15 | 11 | 2 | — |
| `20261027T090000Z-unscored` | unscored | true | 0 | 0 | 0 | — |

`20261027T120000Z` sharp L0: precision 1, recall 0.875, recall at the FPR cap 0.75, VD-S 0.75, FPR 0, Youden `equals VD-S (fewer than 200 negatives)`. sharp L1: precision 0.5, recall 0.5, headline 0.5, VD-S 0.5, FPR 0.004, Youden 0.496 (`youden_in_ranking` true). blind L0 is an infra error row (`exclude_reason` `infra_errors`, headline null). Error rows: `pair-sqli` `hunt_error` "connection refused", and the blind infra row.

`20261027T110000Z` warns `INCOMPLETE CACHE` and is partial. cached L0: precision 0.25, recall 0.4, headline and VD-S 0.333333.

`20261027T100000Z-failed` has no scorecard. The error is "live run stopped before a scorecard: connection refused". Error rows: `pair-ssrf` / vulnerable / `hunt_error`, and `pair-xss` / fixed / `timeout`.

`20261027T090000Z-unscored` has no scorecard. The error is "score did not finish; no scorecard was written". Error row: `pair-path` / benign / `cache_miss` / "missing cache entry".

## Screenshots

Before, the old seed desk:

`docs/verification/benchmarks-desk/before.png`

https://raw.githubusercontent.com/EndsHunter/VulnForge/3985cb4fe3aadde3d7c2dd9c352c68c3bd0a6117/docs/verification/benchmarks-desk/before.png

After, the scorecard desk:

`docs/verification/benchmarks-desk/after.png`

https://raw.githubusercontent.com/EndsHunter/VulnForge/3985cb4fe3aadde3d7c2dd9c352c68c3bd0a6117/docs/verification/benchmarks-desk/after.png

## Proof

```bash
vf dashboard --host 127.0.0.1 --port 18792 \
  --runs-root /tmp/vf-bench-after/runs \
  --bench-results /workspace/tests/fixtures/bench_desk
```

`GET /api/health` returned `ok` with that runs root. `GET /api/bench/runs` returned the four runs and `results_root` `/workspace/tests/fixtures/bench_desk`. `GET /benchmarks/run` returned 307 to `/benchmarks`.
