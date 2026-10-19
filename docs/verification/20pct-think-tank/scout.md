# Scout — how others verify LLM-found vulns (independent run, 2026-10-19, part a 1/2)

1. **Per-class evidence contract + deterministic oracle + sandbox canaries (M)** — XBOW: plain code checks a fixed evidence format; LLM never decides success. UUID canary planted where only a real exploit can reach (file for RCE, DB row for SQLi); Naptime's "perfect verification". For VF: each class declares evidence_contract, mech rejects a PoC that can't produce that evidence, validate_poc plants a fresh canary in the microVM/gVisor, signal_observed = canary/sanitizer fired, checked by code. https://docs.xbow.com/console/how-to/validate-with-canaries/ , https://googleprojectzero.blogspot.com/2024/06/project-naptime.html
2. **Source→sink path contract + disprove that checks the path can run (M)** — submit_candidate carries ordered path nodes as file:line; mech checks each line exists and hops agree with query_flows; disprove gets CWE-specific prompts and must name the branch/sanitizer that breaks the path; "source is false" prunes sibling candidates. IRIS https://arxiv.org/abs/2405.17238 , ZeroFalse https://arxiv.org/html/2510.02534v1 , LLM4PFA https://arxiv.org/html/2506.10322 (filters 72-96% FPs, wrongly killed 3/45 real).
3. **Signal must come from the target, not the PoC itself (S)** — XBOW: validators get gamed (a "cmd injection" that ran on attacker's own box). If PoC contains the marker literal or prints it itself → poc_broken/inconclusive, never signal_observed. https://blog.aidanjohn.org/2025/09/27/xbow-agentic-pentesting-with-zero.html

(bench-design inputs expected in a later batch)

## Scout part 2/2
4. Split findings into sub-claims; each disprover its own read-only trajectory, record agreement (S-M). XBOW step-by-step, ~4 agents per area; Naptime: independent trajectories beat one. Sub-claims: source attacker-reachable, no sanitizer on path, sink dangerous for CWE. Store k_agree/k_total per sub-claim beside pending_llm; ranking only. https://xbow.com/blog/ai-pentesting-strengths-weaknesses-xbow-fills-gaps
5. HITL Reject+note proposes a triage memory scoped to target+class; only Jonathan activates (M). validate_llm cites memory used, can only move to rejected_llm (visible/reopenable). Semgrep: one customer filtered 588 FPs with memory vs 18 without. https://semgrep.dev/blog/2025/making-zero-false-positive-sast-a-reality-with-ai-powered-memory
6. Benchmark the disprove itself per model: FPs killed vs seeded real bugs wrongly killed; warn/block above threshold (M). IRIS: LLM filter made F1 worse for small models. New scoring axis for bench rework. https://arxiv.org/abs/2405.17238

From pstack: (a) steal blast-radius "how sure" ladder as evidence_level badge on needs_human (mech=rung2 file:line, validate_poc=4-5). (b) benchmark-checklist Q4/Q7: PROTOCOL.md silent on disprove error/timeout → should be inconclusive w/ count, never "survived"; Forge/Gauge check code. (c) create-verification-skill: capped iterate_poc must not quietly weaken PoC until it passes.

Skip: live-target validation (canaries sandbox-only), mandatory PoC to report (kills justified no_poc), auto-hiding/auto-activated memories, full IRIS+CodeQL engine (L, license).
Gaps: couldn't read validate_mech/validate_llm code (search empty); didn't assess Vulnhuntr, Big Sleep, Buttercup, Strix, AIxCC. Bench inputs separate.
