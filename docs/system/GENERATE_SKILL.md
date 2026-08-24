# Generate skill system prompt

## `generate_skill.md`

| | |
|--|--|
| **What** | Author prompt for generating a custom hunt skill (schema, fields, angle expectations). |
| **Loaded by** | `hunt_profiles/author_prompt.py` / generate paths; package seed under `seeds/system/generate_skill.md`. |
| **Special override** | `config/prompts/generate_skill.md` (not under `overrides/`). Restoring package seed removes the override file. |
| **Impact** | Shape of Dev-authored and Hunts-authored hunt profiles. Does not change existing profiles until regenerated. |
| **Tasks** | Ralph `generate_skill` (Dev or Hunts generate). |

## Related

- Runtime profiles: `config/hunt_profiles/`
- Package seeds: `seeds/hunt_classes/`
