# Recon stage

**Goal:** Map the target’s architecture so hunts have areas, surfaces, and focus — without treating the map as ground truth for exploit claims.

## What runs

1. **Init** (`vf init`) or **Mission re-run** enqueues one or more `recon` tasks (one Ralph lease per recon agent).
2. Each agent uses tools (`file_inventory`, `grep`, reads, etc.) and finishes with architecture submission.
3. When a **batch** of agents completes, results **merge** into `runs.architecture_json` (LLM merge with mechanical fallback). Prior maps are refined, not blank-overwritten when `include_prior_architecture` / merge flags say so.
4. Mechanical **codemap** (`runs.codemap_json`) is structure-only (modules/entrypoints) — separate from the LLM architecture map.
5. Optionally **plan hunt tasks** from the map (`enqueue_hunts`) using the run’s hunt skill mode.

## Operator surfaces

| Surface | Action |
|---------|--------|
| Mission | Operator re-run card: agents, brief, focus paths, prior arch, enqueue hunts |
| Architecture panel | Re-run recon (arch-only or + hunts) |
| History | View/restore prior architecture revisions |

## Priority

Operator re-run uses **front-of-queue** priority so recon jumps ahead of bulk hunts. Init uses `RECON_INIT_PRIORITY` (5). See [harness README](../README.md#task-priority-lower-int--sooner).

## Prompts

- Shared: `preamble.md` ([docs/system/SHARED.md](../../system/SHARED.md))
- Legacy single-packet body: `recon.md` ([docs/system/RECON.md](../../system/RECON.md))
- Per-agent bodies: runtime `config/recon_agents/` (seeded from `seeds/recon_agents/`)
- Merge: `architecture_merge.md` ([docs/system/RECON.md](../../system/RECON.md))

## Not proof

Recon quality affects hunt steering only. A rich architecture does not mean findings are real.
