# Hunt system prompts

## `hunting_angles.md`

| | |
|--|--|
| **What** | Numbered library of attack angles. Hunt packets include a **slim slice** (selected angles), not always the full file. |
| **Loaded by** | `packet.py` hunt packing; selection driven by class profile `angle_ids` / defaults (`hunt_profiles`). |
| **Impact** | Which investigative angles the model sees for a class. Reordering or renumbering angles can desync stored `angle_ids` (1-based indices). Prefer append new angles; update profile metadata if renumbering. |
| **Override** | `config/prompts/overrides/hunting_angles.md` |
| **Related** | Per-class skill body in `config/hunt_profiles/` / `seeds/hunt_classes/` (not this file). |

## Also used on hunt packets

- `PRINCIPLES.md` as the hunt **system** prompt — [SHARED.md](SHARED.md)
- `continue_hunt` is a hunt-stage tool (not a prompt file): when context is high the
  harness instructs the model to hand off remaining work to a child hunt.

## See also

- [docs/harness/hunt/](../harness/hunt/)
