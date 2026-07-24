# Package seed library

This directory is the **git-tracked reseed source** for VulnForge prompts.
It is **not** what live campaigns edit day-to-day.

## Layout

```text
seeds/
  system/           # Stage/system markdown (flat names: preamble.md, PRINCIPLES.md, …)
  hunt_classes/     # Hunt skill seed bodies → reseed into config/hunt_profiles/
  recon_agents/     # Recon agent seed bodies → reseed into config/recon_agents/
```

## Edit rules

| What you want | Edit |
|---------------|------|
| Live campaign hunts / recon agents | `config/hunt_profiles/`, `config/recon_agents/` (runtime authority) |
| Package library that **Reseed from package** copies | files under `seeds/` (this tree) |
| Optional system-prompt override for one machine | `config/prompts/overrides/<basename>.md` |
| Hunt skill **author** prompt (Dev generate) | `config/prompts/generate_skill.md` (special-case; not under `overrides/`) |

Do **not** treat `seeds/` as the operator collection. Reseed overwrites runtime bodies
from these seeds; runtime collections can diverge intentionally.

### Override convention

1. **System stage markdown** (`preamble.md`, `PRINCIPLES.md`, `disprove.md`, …): put a file with the **same basename** under `config/prompts/overrides/`. `load_prompt_slice` prefers it over `seeds/system/` for top-level basenames only (no path separators).
2. **Generate-skill author prompt**: single file `config/prompts/generate_skill.md` (existing Dev UI path). Restoring package seed removes the override file.

## Loaders

- System prompts: `vulnforge.paths.system_prompts_root()` → `seeds/system/`
- Hunt class seeds: `hunt_class_seeds_root()` → `seeds/hunt_classes/`
- Recon agent seeds: `recon_agent_seeds_root()` → `seeds/recon_agents/`
- Prompt pin at `vf init`: hashes the effective seeds tree (`SEEDS_ROOT`)

See also:

- [`docs/LAYOUT.md`](../docs/LAYOUT.md) — seed vs runtime map
- [`docs/system/`](../docs/system/) — catalog of every `seeds/system/*` file, loaders, and impact of changes
- [`docs/harness/`](../docs/harness/) — recon / hunt / validate stage behavior and MODIFY guides
