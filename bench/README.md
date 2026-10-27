# Pair bench

Reproducible vuln-finding scorecard. One task is a vulnerable/fixed pair or a benign control. A true positive is a finding at the oracle sink on the vulnerable side only. The same sink on both sides is a false positive.

Labels are hand-checked oracles in `seed/` (8 pairs, 4 benign). Disclosure dates are contamination clocks for those authored snippets, not BigVul or Devign labels. Every task has `split` (`train`, `dev`, or `held_out`) and is run at L0 (tree only) and L1 (tree plus CWE and component).

Harness stages are not imported. `adapters.py` scores hunt JSON, a formed-vs-reproduced mech check, and a disprove verdict. Disprove errors, timeouts, and unparsed verdicts are `inconclusive` and do not survive.

## Scorecard

- Recall at FPR ≤ 0.5% (`vd_s`) on surviving pairs, plus `recall_lower_bound` and `recall_at_fpr_lower_bound` (errored pairs count as misses). `pairs_lost` is how many pair runs were dropped. Youden, and the four pair outcomes: `paired_correct`, `both_vulnerable`, `both_benign`, `reversed`. Paired recall is not monotonic in the threshold: a true positive needs the vulnerable score at or above the cut and the fixed score below it.
- Precision, recall, and FPR at hunt raw, mech formed, mech reproduced, and disprove
- `union_at_n` across the k repeats
- Pre/post knowledge-cutoff and train/dev/held-out slices
- Disprove false-reject rate (real oracle findings killed) against `disprove.false_reject_max` (`warn` or `fail`)
- Path-contract validity and the share of findings that cite `poc/`, `exploit/`, or `harness/`
- Tokens, active time, wall estimate, errors kept apart from misses, findings per 1k tokens, Student-t 95% CI for k ≥ 3
- Score-vs-token Pareto (`pareto` and `pareto_markdown`)
- Deduped oracle precision, recall per CWE, duplicate rate, per-gate false-reject/false-pass, canary catch rate, disprove-vs-mech precision lift net of false-reject, mech-pass/disprove-kill disagreement, verdict flip across repeats, tokens and active seconds per exclusive true finding, time to first true

There is no LLM-judge headline. `confirmed` is not set here. Human accept rate, inbox precision, pending-llm dwell, GPU-seconds, and recon recall are listed under `not_measured`.

## Commands

Offline proof (writes nothing under `bench/results/`):

```bash
python -m bench run --stub --config bench/config.yaml
python -m bench self-test
```

Live run against the OpenAI-compatible server in config. Do not point this at a host you cannot reach. Results land in `bench/results/<timestamp>/` and stay uncommitted:

```bash
python -m bench run --live --config bench/config.yaml
```

Rebuild the scorecard from cached responses only. This does not call a model and does not write `bench/results/`. Means take the union of keys across repeats. A missing count is zero; a rate with no denominator is left out of that key's mean, and `_contributed` records how many repeats entered it. Infrastructure-error rows stay on `leaderboard.infra_error_row_count`, apart from `scored_row_count`. A missing cache file is a cache miss, counted per side (`cache_misses_by_side`) with `cache_coverage`. Coverage below 1 marks the scorecard `partial` and the command exits 2. Stored error records are infrastructure errors (`infra_error_count`), not hits.

```bash
python -m bench score --from-cache --config bench/config.yaml
```

`bench/config.yaml` sets `base_url` (default `http://10.0.0.232:1234/v1`) and `models`. Live requests send each model's `id`. `httpx>=0.27` is a project dependency because the live client imports it. `max_inflight` (default 4) is a semaphore around every HTTP call to that base URL, shared by hunt, disprove, and every worker. The disk cache stores successful completions and failed jobs (`error_kind` plus the error text). A live rerun retries a failed job instead of replaying it as a success. Hits and misses are counted when the lookup happens: a file written during the run is not a hit. A model×difficulty row is excluded from rank and from the Pareto frontier when every call, or a majority of calls, is an infrastructure error (`recall` null, `rank` null, `on_frontier` false). The leaderboard `fpr` is the false-positive rate at the same operating point as `recall_at_fpr_le_0.5pct` (FPR at most `fpr_cap`). Youden is TPR minus FPR at the best capped threshold. With fewer than 200 negatives the smallest nonzero FPR is above that cap, so the column reads `equals VD-S (fewer than 200 negatives)` and is not used for rank. `stored_failure_count` sits next to `cache_coverage`. Stub mode ignores config model names and scores only `stub-sharp`, `stub-noisy`, and `stub-blind`.

## Scale-up

Grow toward about 30 pairs and 10 benign tasks from CASTLE-style cases or dated CVE pairs with hand-checked sinks. Refresh `held_out` quarterly. Do not import BigVul or Devign.
