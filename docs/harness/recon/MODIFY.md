# Recon — what and where to change

## Common changes

| Want to… | Edit |
|----------|------|
| Change default recon agent library | Package seeds `seeds/recon_agents/*.md`, then Dev **Reseed** → runtime `config/recon_agents/` |
| Change live agents without reseeding | `config/recon_agents/` (runtime authority) |
| Change shared recon packet framing | `seeds/system/preamble.md` or override `config/prompts/overrides/preamble.md` |
| Change legacy single-body recon text | `seeds/system/recon.md` (+ override) — multi-agent path uses agent bodies instead |
| Change LLM architecture merge instructions | `seeds/system/architecture_merge.md` (loaded from `system_prompts_root()`; prefer package edit or future override support) |
| Change enqueue / re-run payload | `vulnforge/control/ops.py` → `requeue_recon` |
| Change init recon enqueue | `vulnforge/cli.py` (init path) + `stages/recon.py` `enqueue_recon_agent_tasks` |
| Change recon priority bands | `vulnforge/task_priority.py` |
| Change merge / batch / hunt planning logic | `vulnforge/stages/recon.py` |
| Change recon packet packing | `vulnforge/packet.py` → `pack_recon` / `pack_recon_agent` |
| Change Architecture re-run UI | `vulnforge/ui/static/app.js` (`submitArchRecon` / Refine recon section) + API in `ui/app.py` |
| Change mechanical codemap | `vulnforge/tools/codemap.py` (not architecture); symbols: `vulnforge/tools/symbols/` |
| Function-level extract / backends | `vulnforge/tools/symbols/` + `codemap.symbol_backend` in config |
| Hunt area slice budgets | `config/default.yaml` → `codemap.packet_max_*` / `packet.max_codemap_chars` |

## Key files

```text
vulnforge/stages/recon.py      # run(), merge, plan hunts, batch finalize
vulnforge/control/ops.py       # requeue_recon
vulnforge/task_priority.py     # RECON_INIT_PRIORITY, recon_front_priority
vulnforge/packet.py            # pack_recon*
vulnforge/recon_agents/        # collection load/import (if present)
seeds/recon_agents/            # package seed library
config/recon_agents/           # runtime collection
seeds/system/recon.md
seeds/system/architecture_merge.md
seeds/system/preamble.md
```

## Tests to run after changes

```powershell
python -m pytest tests/test_dashboard_ops.py tests/test_recon_plan.py tests/test_architecture_history.py -q
```

## See also

- [README.md](README.md) — behavior
- [docs/system/RECON.md](../../system/RECON.md) — prompt impact
- [docs/LAYOUT.md](../../LAYOUT.md) — seed vs runtime
