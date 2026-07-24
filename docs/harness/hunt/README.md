# Hunt stage

**Goal:** Investigate one **area × weakness class** (and optional path hints) with tools; either submit a candidate finding or `submit_none`.

## What runs

1. Task payload: `area`, `class`, `path_hints`, optional `operator_notes`, `force_depth`, etc.
2. Packet: PRINCIPLES + class skill body + hunting angles slice + architecture slice + tools schema.
3. LLM tool loop (`code_static` tools) → `submit_candidate` or `submit_none`.
4. On candidate: insert/upsert finding; may enqueue `validate_mech`; near-dup helpers may annotate merge metadata.
5. Coverage facts update visit/depth for residual matrix.

## Operator surfaces

| Surface | Action |
|---------|--------|
| Explorer | Select file/lines, pick class, enqueue hunt |
| Coverage | Re-queue residual cells (shallow/aborted/none) |
| Report | Review findings; Develop POC workshop |
| AI chat | Enqueue/requeue hunts (Confirm for mutators) |
| Tasks | Queue / transcripts |

## Skills (classes)

- **Runtime authority:** `config/hunt_profiles/` (Dev collection).
- **Package seeds:** `seeds/hunt_classes/` (Reseed only).
- Active ids drive recon `active_fallback`, Coverage “all”, file-by-file planning.

## Priority

Typical operator/residual hunts: **35–50**. Recon at 1–8 always leases first among queued work. See [harness README](../README.md#task-priority-lower-int--sooner).

## Prompts

- `PRINCIPLES.md`, `preamble.md`, `hunting_angles.md` — [docs/system/](../../system/)
- Per-class body — hunt profile markdown (not under `seeds/system/`)

## Honesty

A submitted candidate is **not** confirmed. Mechanical validation and human review follow.
