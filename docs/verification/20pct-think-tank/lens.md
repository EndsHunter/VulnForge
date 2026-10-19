# Lens — operator-seat verification findings (independent run, 2026-10-19)

Framing: pstack verifies *intended behavior* (drive app like a user, prove a feature map). VulnForge verifies a *vuln claim* (prove finding real, not FP). pstack's evidence/doctor/isolation discipline ports; its feature-map model mostly doesn't.

1. **validate_llm passes FPs an observed repro would kill (M)** — HITL gated on "LLM couldn't disprove" = reasoning, not observation. Evidence: tool-gaps sh/fresh FP (#117). Fix: gate HITL on one observed sandbox repro (action + resulting state + side effect); LLM-disprove becomes pre-filter.
2. **No doctor/preflight on runner (S/M)** — Evidence: dump1090 runner.json listed ralph.pid 2062935 alive; kill -0 showed dead. Fix: read-only doctor before start/resume (PID liveness, lock ownership, orphans).
3. **Pause/resume leaves orphans (M)** — Evidence: WordPress-59f20626/run-001 (2026-09-27) orphan run-once → resume EXIT 20 on run.lock. Fix: kill whole session group, confirm lease reclaim, refuse resume on un-owned live lock.
4. **Sandbox setup friction found mid-run (S)** — Evidence: dump1090 docker-group re-login / newgrp / runsc gating. Fix: one-shot sandbox doctor that refuses early with exact remediation.
5. **No standardized evidence bundle for HITL (M)** — Evidence: dump1090 findings surfaced as {} / raw. Fix: per-finding template: claim / repro path / observed sandbox end-state / side effects / confidence.

**Does NOT port:** maintain-verification loop (needs stable enumerable features; hunts don't have one). create-skill's "fix checkout / scaffold missing asset" is dangerous — VulnForge must never modify a target.
