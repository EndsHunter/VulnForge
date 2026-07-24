# Recon system prompts

## `recon.md`

| | |
|--|--|
| **What** | Legacy single-packet recon body (default-map equivalent) used when packing without a multi-agent body. |
| **Loaded by** | `packet.pack_recon` → body for `pack_recon_agent`. |
| **Impact** | Shape of architecture JSON instructions (summary, components, surfaces, hunt focus). Multi-agent runs usually use **`config/recon_agents/`** bodies instead; this file still matters for fallback/legacy paths. |
| **Override** | `config/prompts/overrides/recon.md` |
| **Note** | Per-agent prompts live in recon agent collection seeds, not this file. |

## `architecture_merge.md`

| | |
|--|--|
| **What** | Instructions for LLM merge of prior + incoming architecture maps. |
| **Loaded by** | `stages/recon.py` `llm_merge_architectures` — currently `system_prompts_root() / architecture_merge.md` (package path; not `load_prompt_slice` override path as of writing). |
| **Impact** | Quality of multi-agent / re-run merges. Failures fall back to **mechanical** merge. Poor prompt → more mechanical fallbacks or lossy merges. |
| **Safer experiment** | Edit package seed carefully, or patch loader to use `load_prompt_slice` if you need overrides. |
| **Do not break** | Expect JSON fields the parser understands (`summary`, `components`, `trust_boundaries`, `input_surfaces`, `hunt_focus`). |

## Runtime agents (not system seeds)

| Library | Path |
|---------|------|
| Package seeds | `seeds/recon_agents/` |
| Runtime | `config/recon_agents/` |

See [docs/harness/recon/MODIFY.md](../harness/recon/MODIFY.md).
