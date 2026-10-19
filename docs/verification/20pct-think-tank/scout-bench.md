# Scout — bench design inputs (Oct 19, ranked on merit; also sent to Forge)

Naming: Theo has no "Slop Bench" — his benches are SnitchBench, Skatebench, Quipslop (https://github.com/t3dotgg/t3dotgg). SlopBench is Dan Cleary's (https://github.com/Dan-Cleary/slopbench).
Gaps in today's VF bench (per benchmarks/README): no cost/token tracking, no benign controls/FPR, no vulnerable/fixed pairs, no contamination split, no repeat runs.

1. Vulnerable/fixed pairs (M) — run on both commits; TP = finding at oracle sink on vulnerable side only; both sides = FP. Same pairs grade dual disprove. PrimeVul https://arxiv.org/abs/2403.18624 , CyberGym https://arxiv.org/abs/2506.02548 , SEC-bench https://arxiv.org/abs/2506.11791
2. FP-punishing headline + benign tasks (S) — recall at FPR ≤ 0.5% (PrimeVul VD-S) and Youden, per stage (hunt raw → mech → disprove). CASTLE https://arxiv.org/abs/2503.09433
3. Stage funnel + union@N (S-M) — unique TPs per hunter, FPs removed per TP lost at mech, disprove kill rate on true vs false.
4. Cost/time/variance columns (S) — tokens, $, wall time; errors separate from misses; k≥3 with CI; score-vs-$ Pareto. https://aider.chat/docs/leaderboards/
5. Difficulty by hint level (S) — L0 repo only, L1 +CWE/component, L2 +file/function (CyberGym, BountyBench).
6. Contamination control (M) — disclosure-date tags, pre/post-cutoff per model, dedup hashes, quarterly held-out split.
7. Source tasks from verified datasets (L) — oracle data only from CASTLE, SEC-bench, CyberGym; poc_dev scoring sandbox-only.
8. Theo's runner pattern, one data point (S) — caching, parallel workers, separate error counts; avoid LLM-judge headlines. https://skatebench.t3.gg/

**Minimal v1:** ~30 vuln/fixed pairs + ~10 benign; scorecard VD-S, Youden, 4 pair outcomes, stage funnel; efficiency tokens/$/time/errors, k=3 + CI; difficulty L0/L1; pre/post-cutoff view; confirmed stays human-only.
**Skip:** bounty-$ scores, live-exploit/CTF benches, LLM-judge headlines, BigVul/Devign labels.
