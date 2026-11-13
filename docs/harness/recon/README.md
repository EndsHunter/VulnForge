# Recon stage

**Goal:** Map the target’s architecture so hunts have areas, surfaces, and focus — without treating the map as ground truth for exploit claims.

## What runs

Recon pipeline v2 ([FLOWS.md](FLOWS.md)). Ralph order: R0 → R1 map batch → R5 merge → R3 flow fan-out → R5 merge → hunts.

1. **Init** (`vf init`) or **Mission re-run** enqueues one or more `recon` tasks (one Ralph lease per map agent).
2. **R0 skeleton** (no LLM): at the start of each recon task the codemap and sink pre-index are rebuilt and `{run_dir}/architecture_skeleton.json` is refreshed (`recon_skeleton.build_and_store_skeleton`). It holds mechanical components, import / `db` / `http_out` relations (`confidence: mechanical`), entrypoints, sinks and heuristic zones. It is never `runs.architecture_json` on its own.
3. **R1 map agents** (`default-map`, plus `surface-mapper`, `auth-model`, `dependency-risk` when active) get a compact skeleton in their packet and each owns a slice of the v2 schema (names/roles/zones/boundaries + hunt_focus, entrypoints with lines, auth boundaries / `auth_gate`, external + build zones). They finish with `submit_architecture` (v1 fields still accepted). If context is nearly full, an agent calls `continue_recon` (child recon, fresh window). Context overflow also auto-enqueues a continuation.
4. **R5 merge** (`store_merged_architecture`, deterministic): start from the prior map (a v1 prior is first laid over the skeleton) or the skeleton → `merge_v2` the agent's part → `validate_citations` against the read-only target (good `path:line` → `cited`, bad or missing → `inferred`, line dropped) → stored with `schema: vulnforge/architecture@2`. Only the two `summary` paragraphs go through the LLM (`run.architecture_llm_merge`, default on); concatenation is the fallback. Each write records an architecture revision (Mission **History**).
5. **R3 flow tracer**: when the map batch finalizes, `_enqueue_flow_tracer_tasks` enqueues one `recon` task per selected entrypoint (`recon_phase: flows`, shared `flow_batch_id`, priority `RECON_CHILD_PRIORITY + 2 + i`). Entrypoints come from the merged map: internet-zone components first, then components with sinks, then the rest; deduped by `path:line` (a file-level entrypoint is dropped when the same file has a lined one); capped by `recon.flow_tracer.max_flows`. Each task runs the `flow-tracer` agent, which finishes with `submit_flow`; flows are normalized (registered class ids only, components resolved by id/name or by path, stable ids), citation-checked and merged into the map (`merge_flows_into_architecture`). Zero flows is a valid answer. Out of rounds → the flows the model described in text are salvaged (`round_limit.flows_from_content`).
6. **Hunts** are planned once, by the last flow task of the batch (or by the map finalizer when R3 is off or found no entrypoints) — `plan_hunt_tasks` as before (hunt_focus or active fallback). Dynamic skills run at the same point. Planning from flows (R6) is not built yet.
7. Mechanical **codemap** (`runs.codemap_json`) is structure-only (modules/entrypoints) — separate from the architecture map.

Orchestrators (`llm.recon_orchestrator`): `ralph` (default) fans out map agents and flow tracers as Ralph tasks; `inprocess` and `graph` run the map agents in one task and then trace the flows sequentially in that same task (`_trace_flows_inprocess`).

When recon **omits** `hunt_focus` (shy, thin, binary-only, or low confidence), planning enqueues the **active** profile set. That path is the intentional **B0 hybrid fallback** until live A2, not a bug. When surfaces are clear, `default-map` must emit a small path-backed `hunt_focus`, including justified inactive class ids. Prefer Active is only a tie-break among equally fitting classes.

## Config

| Key | Default | Effect |
|-----|---------|--------|
| `recon.flow_tracer.enabled` | `true` | R3 on/off. A recon payload `flow_tracer: false` turns it off for that recon. |
| `recon.flow_tracer.max_flows` | `8` | Entrypoints traced per recon (cap 32; `0` disables). |
| `recon.flow_tracer.max_tool_rounds` | `llm.max_tool_rounds` | Rounds per flow-tracer task (the agent's own `max_tool_rounds` wins). |
| `run.architecture_llm_merge` | `true` | LLM merge of the summary paragraphs only. |
| `packet.max_skeleton_chars` / `max_prior_architecture_chars` / `max_flow_map_chars` | 3000 / 6000 / 3000 | Packet section caps. |

The `flow-tracer` entry in the recon agent collection is a phase agent (`output: flows`): it never runs in the first map batch, and its **Active** flag turns R3 off for every run. Selecting only `flow-tracer` in a recon re-run ("Run recon with brief") re-traces flows from the current map without re-running the map agents.

## Operator surfaces

| Surface | Action |
|---------|--------|
| Mission (Recon) | Refine / run recon with brief (arch-only or + hunts) |
| Mission (History) | View/restore prior architecture revisions |
| Init | Strategy + recon agents + brief when creating a run |

## Priority

Operator re-run uses **front-of-queue** priority so recon jumps ahead of bulk hunts. Init uses `RECON_INIT_PRIORITY` (5). See [harness README](../README.md#task-priority-lower-int--sooner).

## Prompts

- Shared: `preamble.md` ([docs/system/SHARED.md](../../system/SHARED.md))
- Legacy single-packet body: `recon.md` ([docs/system/RECON.md](../../system/RECON.md))
- Per-agent bodies: runtime `config/recon_agents/` (seeded from `seeds/recon_agents/`)
- Flow tracer: `seeds/recon_agents/flow-tracer.md` (tool `submit_flow`)
- Merge: summary-only inline prompt; `architecture_merge.md` is the legacy whole-map prompt ([docs/system/RECON.md](../../system/RECON.md))

## Not proof

Recon quality affects hunt steering only. A rich architecture does not mean findings are real. A flow, a `cited` relation or a zone is a steering hint, never evidence for a finding, and an empty zone or no flow never means safe.
