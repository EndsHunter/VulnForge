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
| Optional system-prompt override for one machine | `config/prompts/overrides/<name>.md` |

Do **not** treat `seeds/` as the operator collection. Reseed overwrites runtime bodies
from these seeds; runtime collections can diverge intentionally.

## Loaders

- System prompts: `vulnforge.paths.system_prompts_root()` → `seeds/system/`
- Hunt class seeds: `hunt_class_seeds_root()` → `seeds/hunt_classes/`
- Recon agent seeds: `recon_agent_seeds_root()` → `seeds/recon_agents/`
- Prompt pin at `vf init`: hashes the effective seeds tree (`SEEDS_ROOT`)

Legacy fallback: if `seeds/system` is missing, loaders still accept `prompts/v1/` for mid-migration checkouts.

See also [`docs/LAYOUT.md`](../docs/LAYOUT.md).
