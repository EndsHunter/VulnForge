# QA Gauge (d2e067ef) — verification + efficiency think-tank (main @ b1ff002, solo, read-only, Oct 19)

Corrections: inbox Accept IS already UI-disabled for pending_llm (hitl_inbox.js:22,:128; server ops.py:2482). Repo already has .cursor/skills/verify-vulnforge/ with a feature map.

1. **No gate scored vs ground truth (M).** eval/recall.py:162 recall-only; benchmarks/scorers.py:352 re-implements mech vacuous check (drift); benchmarks/library/ empty until seed; only 4 known-bad fixtures (test the scorer, not gates). Fix: labeled calibration set (true + seeded canaries: fake cite, wrong line, dead PoC, overclaimed severity) through real mech+LLM; confusion matrix per gate.
2. **rejected_llm is an unaudited auto-kill; verifier defaults to hunter's model (S–M).** validate_llm.py:202 all-reject → rejected_llm; hitl.py:49 terminal; validate_llm.py:373-374 falls back to cfg.llm.model. Fix: blind-sample 10–20% of rejected_llm to inbox; log mech-pass/LLM-reject + slot splits; auto-reject only when verifier model/host ≠ hunter, else needs_human 'llm-doubt'.
3. **Mech pass = well-formed, not reproduced (M–L).** validate_mech.py:667-673 gates; check_evidence_pack :409-442 never runs PoC; no_poc passes on any 20+ char justification; tests all hand-built on toy_sqli. Fix: split mech:formed vs mech:reproduced (sandbox PoC preflight + expected oracle); surface both in UI and bench.
4. **pending_llm fails closed but can sit forever invisibly (S).** validate_llm.py:520-538, :600-615; ops.py:2482; re-arm only ops.py:3077; no dwell metric; retry cap unverified. Fix: dwell p50/p95 + stuck count; after N infra fails → needs_human 'llm_unverified' badge with explicit ack.
5. **Efficiency only partly computable (S–M).** tokens per task usage.py:139,:231,:314; findings carry task_id; tasks only created_at/updated_at (db.py:265-279); no cost field; findings current-state only. Fix: task started_at/finished_at, per-attempt usage, finding_events transition table, per-run summary.json.
6. **Feature map covers one feature (cli-init-status.md) for verification (S–M).** Fix: add validate, pending_llm, rejected_llm, HITL Accept/Reject, hunt→validate, recon, bench feature files driven by scripted FakeLLM (tests/test_validate_llm_safety.py:102); maintain after PRs touching them.

## Bench should measure
- Precision (oracle-matched / all, dedup by stable_key), recall per class, dup rate
- Per-gate false-reject / false-pass (mech, llm, human)
- Canary catch rate (target 100%)
- LLM lift: precision at needs_human LLM-on vs mech-only, net of false-reject cost
- Disagreement rate (mech-pass/LLM-reject; slot splits); verdict flip rate over k repeats
- Inbox precision + Accept rate
- Tokens per confirmed true finding (recon/hunt/validate split); tokens per candidate
- Active seconds per confirmed true finding, wall time, time-to-first-true
- pending_llm health: dwell p50/p95, stuck count, failed_infra per model/host
- LM Studio cost proxy: GPU-seconds/tokens + model fingerprint (validate_llm.py:389) + quant
- Recon: keep component_recall / path_hint_recall (scorers.py:227-266)

Not inspected: open-PR heads, live run data, LM Studio, eval_* internals, poc_runner/poc_phase, recon_agents/, failed_infra retry cap.
