# Prompts moved to `seeds/`

The package seed library lives under `seeds/`, not `prompts/v1/`.

**Look here instead:**

| Content | Location |
|---------|----------|
| System / stage prompts | [`seeds/system/`](../seeds/system/) |
| Hunt class seed bodies | [`seeds/hunt_classes/`](../seeds/hunt_classes/) |
| Recon agent seed bodies | [`seeds/recon_agents/`](../seeds/recon_agents/) |
| Edit rules | [`seeds/README.md`](../seeds/README.md) |
| Developer map | [`docs/LAYOUT.md`](../docs/LAYOUT.md) |

Runtime (operator) collections remain under `config/hunt_profiles/` and `config/recon_agents/`.

Code loads seeds exclusively via `vulnforge.paths.system_prompts_root()` and related helpers under `seeds/`.
