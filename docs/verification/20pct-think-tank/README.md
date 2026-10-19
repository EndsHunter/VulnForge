# 20%-usage-dev think-tank — independent verification + bench findings (2026-10-19)

Six independent, read-only runs (no cross-reading): Crit, Green, Scout (verify + bench), Lens, QA Gauge (d2e067ef), expeditor Gauge (6bb6b4ec, since removed from roster). Collected by Ops. Baseline: main @ b1ff002.

## Convergent findings (raised independently by ≥2)
1. **Sandbox PoC signal_observed is self-certifying** — Crit, Green, Scout, (Lens via observed-repro). PoC prints its own marker; regex from PoC frontmatter (poc_runner.py:358, :1225, :1332). Fix: harness-planted per-run canary read back only via exploitation; control/differential replay; stdout-only + exit 0; k runs.
2. **LLM disprove is uncalibrated / can unlock or kill silently** — Crit (zero parsed verdicts clears pending_llm, validate_llm.py 520-552, 880-962), Green (#5 false-reject rate unmeasured), QA Gauge (#2 rejected_llm unaudited auto-kill, same-model fallback), Scout (#6 benchmark the disprove).
3. **Mech pass checks shape, not reproduction; no_poc hatch weak** — Green #2, QA Gauge #3, Crit residual.
4. **Feature map lacks the verification gate itself** — Crit #4, Green #3, QA Gauge #6, expeditor Gauge #3. Add finding-review-gate / sandbox-poc features; maintain on validate/HITL changes.
5. **pending_llm stuck/dwell invisible** — Crit #3 (deadletter re-arm dead code), Green #6, QA Gauge #4.
6. **Ready-bar proof is happy-path and not SHA-pinned** — expeditor Gauge #1/#2/#4, Green #4.
7. **Runner hygiene (doctor, orphans, sandbox preflight)** — Lens #2–#4.

## Bench overhaul (Scout + QA Gauge)
Minimal v1: ~30 vulnerable/fixed pairs + ~10 benign; VD-S (recall @ FPR ≤ 0.5%), Youden, pair outcomes, stage funnel; per-gate false-reject/false-pass; tokens/$/time/errors, k=3 + CI; L0/L1 difficulty; pre/post-cutoff view. Theo's benches (SnitchBench/Skatebench) are one runner-pattern data point only.

Per-bot files in this folder.
