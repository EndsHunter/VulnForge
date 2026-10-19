# Pair bench

Reproducible vuln-finding scorecard. One task is a vulnerable/fixed pair or a benign control. A true positive is a finding at the oracle sink on the vulnerable side only. The same sink on both sides is a false positive.

Labels are hand-checked oracles in `seed/` (8 pairs, 4 benign). Disclosure dates are contamination clocks for those authored snippets, not BigVul or Devign labels. Every task has `split` (`train`, `dev`, or `held_out`) and is run at L0 (tree only) and L1 (tree plus CWE and component).

Harness stages are not imported. `adapters.py` scores hunt JSON, a formed-vs-reproduced mech check, and a disprove verdict. Disprove errors, timeouts, and unparsed verdicts are `inconclusive` and do not survive.

## Scorecard

- Recall at FPR ≤ 0.5%, Youden, and the four pair outcomes: `paired_correct`, `both_vulnerable`, `both_benign`, `reversed`
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

`bench/config.yaml` sets `base_url` (default `http://10.0.0.232:1234/v1`) and `models`. Stub mode ignores those names and scores only `stub-sharp`, `stub-noisy`, and `stub-blind`.

## Scale-up

Grow toward about 30 pairs and 10 benign tasks from CASTLE-style cases or dated CVE pairs with hand-checked sinks. Refresh `held_out` quarterly. Do not import BigVul or Devign.
