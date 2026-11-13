# Recon system prompts

## `recon.md`

| | |
|--|--|
| **What** | Legacy single-packet recon body (default-map equivalent) used when packing without a multi-agent body. |
| **Loaded by** | `packet.pack_recon` → body for `pack_recon_agent`. |
| **Impact** | Shape of architecture instructions: v1 fields (summary, components, surfaces, hunt focus) plus the v2 slices (start from the mechanical skeleton, keep its ids, a zone per component, `boundaries` with `path:line`, relations with `evidence` or `confidence: "inferred"`). Multi-agent runs usually use **`config/recon_agents/`** bodies instead; this file still matters for fallback/legacy paths. |
| **Override** | `config/prompts/overrides/recon.md` |
| **Note** | Per-agent prompts live in recon agent collection seeds, not this file. |

## `architecture_merge.md`

| | |
|--|--|
| **What** | Instructions for LLM merge of prior + incoming architecture maps (whole-map form). |
| **Loaded by** | `stages/recon.py` `llm_merge_architectures` when called without `summary_only` (kept for callers and tests). The recon stage itself no longer uses it: since recon v2 the **structure merges deterministically** (`merge_v2` → `validate_citations`) and the LLM only merges the two `summary` paragraphs, with a short inline prompt (`summary_only=True`). |
| **Impact** | None on the stored structure. Summary merge failures fall back to paragraph concatenation (`merge_method: mechanical`). |
| **Do not break** | JSON with a non-empty `summary`. |

## Recon v2 packet sections (not prompt files)

| Section | Built by | Content |
|---------|----------|---------|
| *Mechanical skeleton* | `packet._skeleton_block` (map agents) | Compact text of `architecture_skeleton.json`: zones, components (id, kind, zone, paths, entrypoints, sinks), mechanical relations. Capped by `packet.max_skeleton_chars` (default 3000). |
| *Prior architecture* | `recon_flows.prior_architecture_text` | v1 fields + the same compact v2 view of the stored map. Capped by `packet.max_prior_architecture_chars` (default 6000). |
| *Entrypoint to trace* / *Current map* | `packet.pack_flow_tracer` (flow-tracer) | The one entrypoint (component, zone, label, path, line, component sinks), the map's component ids, and the registered class ids. Map capped by `packet.max_flow_map_chars` (default 3000). |

## `flow-tracer` (recon agent, not a system seed)

Body: `seeds/recon_agents/flow-tracer.md` (runtime `config/recon_agents/bodies/flow-tracer.md` after a Dev **Reseed**; until then the package seed is read directly, nothing is written to `config/`). Tools: `query_flows`, `find_symbol`, `query_sinks`, `read_file`, `grep`, finishing with `submit_flow`. `submit_architecture` and `continue_recon` are removed from its packet; map agents never see `submit_flow`. Editing the body changes how flows are traced and cited; the citation check and class-id filter in `recon_flows.normalize_submitted_flows` apply regardless of the prompt.

`continue_recon` is a recon-stage tool (not a prompt file): when context is high the
harness instructs the model to hand off remaining mapping to a child recon that
refines the prior architecture.

## Runtime agents (not system seeds)

| Library | Path |
|---------|------|
| Package seeds | `seeds/recon_agents/` |
| Runtime | `config/recon_agents/` |

See [docs/harness/recon/MODIFY.md](../harness/recon/MODIFY.md).
