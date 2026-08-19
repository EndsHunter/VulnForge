# Hunt — what and where to change

## Common changes

| Want to… | Edit |
|----------|------|
| Add/edit hunt skill (class) | Dev dashboard → hunt profiles, or `config/hunt_profiles/`; package seeds in `seeds/hunt_classes/` for Reseed |
| Change global audit principles | `seeds/system/PRINCIPLES.md` or `config/prompts/overrides/PRINCIPLES.md` |
| Change hunting angle library | `seeds/system/hunting_angles.md` (+ profile `angle_ids`) |
| Change hunt packet packing | `vulnforge/packet.py` → hunt pack helpers |
| Change hunt stage loop / split / abort | `vulnforge/stages/hunt.py` |
| Context-window continuation | `continue_hunt` tool + `vulnforge/tools/continue_task.py` + `agent_runtime/context_watch.py` |
| Add or extend agent tools | `vulnforge/tools/agent/<name>.py` (see `toolgen.md`, [LAYOUT](../../LAYOUT.md)) |
| Change tool allowlists | profile tools + `config/default_tools.json` / Dev Tools defaults |
| Change requeue / selection enqueue | `vulnforge/control/ops.py` (`requeue_hunt`, `hunt_from_selection`, coverage bulk) |
| Change near-dup merge on insert | `vulnforge/stages/dedup.py` + findings insert path |
| Change skill authoring prompt | `seeds/system/generate_skill.md` / `config/prompts/generate_skill.md` |

## Key files

```text
vulnforge/stages/hunt.py
vulnforge/packet.py
vulnforge/hunt_profiles/       # store, resolve, generate
vulnforge/tools/agent/         # model-facing tools
vulnforge/control/ops.py
seeds/hunt_classes/
config/hunt_profiles/
seeds/system/PRINCIPLES.md
seeds/system/hunting_angles.md
seeds/system/preamble.md
```

## Tests

```powershell
python -m pytest tests/test_tools.py tests/test_phase1_scope.py tests/test_pipeline_fake.py -q
```

## See also

- [README.md](README.md)
- [docs/system/HUNT.md](../../system/HUNT.md), [SHARED.md](../../system/SHARED.md)
- Root [AGENTS.md](../../../AGENTS.md) — Extending hunt skills
