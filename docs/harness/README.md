# Harness stages — recon, hunt, validate

VulnForge’s campaign loop is a **task queue** over a read-only target tree:

```text
init → recon → hunt → validate_mech → validate_llm (default on) → human review → project/*
```

Ralph (`scripts/ralph.py` / `vf run-once`) leases one task, runs the stage handler, and exits. Durable state lives in `harness.db`, `evidence/`, transcripts, and events.

| Stage | Task kind | LLM? | Maintainer docs |
|-------|-----------|------|-----------------|
| **Recon** | `recon` | Yes | [recon/](recon/) |
| **Hunt** | `hunt` | Yes | [hunt/](hunt/) |
| **Validate (mech)** | `validate_mech` | No | [validate/](validate/) |
| **Validate (LLM)** | `validate_llm` | Yes (default; opt out via config) | [validate/](validate/) |

Related (not covered here as full folders): `develop_poc`, `generate_skill`, `tool_gaps`, `render`. Near-dup merge is `stages/dedup.py` (not a leased kind).

**Quality upgrades (additive):** sink residual coverage, citation content mech gate, safer PoC defaults (`docker` + `network: none`), `query_flows` reachability tool, L0 fixture recall (`fixtures/ground_truth/`, `scripts/eval_recall.py`).

## Honesty (do not weaken)

- Target tree is **read-only** for agents.
- Evidence only under `evidence/`.
- `needs_human` = mechanical gates passed — **not** exploit proof.
- `confirmed` is **only** set by human review (Report). Automation never auto-confirms.
- Same-model `validate_llm` can only demote/reject; never raise severity or confirm.

## Task priority (lower int = sooner)

| Kind | Typical priority | Notes |
|------|------------------|--------|
| Operator recon (Mission re-run) | `min(queued)−1` | Front of queue vs bulk hunts |
| Init recon | `5` (`RECON_INIT_PRIORITY`) | Ahead of hunts |
| Recon child / fan-out | `8` | Still ahead of hunts |
| `validate_mech` / generate | ~20–25 | |
| Operator / residual hunts | 35–50 | |
| Default recon-planned hunts | 50 | |

Constants: `vulnforge/task_priority.py`. UI tiers: `control/ops.py` `PRIORITY_TIERS` (`high`=30, `normal`=50, `low`=90).

## System prompts

Stage LLM packets load markdown from `seeds/system/` (with optional `config/prompts/overrides/`). Catalog: **[docs/system/](../system/)**.

## Where is the code?

| Want… | Look in… |
|-------|----------|
| Stage handlers | `vulnforge/stages/<kind>.py` |
| Enqueue / requeue ops | `vulnforge/control/ops.py` |
| Packet builders | `vulnforge/packet.py` |
| Package layout map | [docs/LAYOUT.md](../LAYOUT.md) |
| Topology / flow | [docs/AGENTS_MAP.md](../AGENTS_MAP.md) |
