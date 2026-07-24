# Prompts moved to `seeds/`

The package seed library no longer lives under `prompts/v1/`.

**Look here instead:**

| Content | New location |
|---------|----------------|
| System / stage prompts | [`seeds/system/`](../seeds/system/) |
| Hunt class seed bodies | [`seeds/hunt_classes/`](../seeds/hunt_classes/) |
| Recon agent seed bodies | [`seeds/recon_agents/`](../seeds/recon_agents/) |
| Edit rules | [`seeds/README.md`](../seeds/README.md) |
| Developer map | [`docs/LAYOUT.md`](../docs/LAYOUT.md) |

Runtime (operator) collections remain under `config/hunt_profiles/` and `config/recon_agents/`.

Code loads seeds via `vulnforge.paths.system_prompts_root()` (and related helpers), with a temporary fallback to `prompts/v1` only if `seeds/system` is absent.
