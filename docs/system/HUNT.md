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

## Hunt MoA perspectives

Loaded by `pack_hunt(..., perspective=, perspective_id=)` only when `stages.hunt_moa` is true. They are extra lenses on the same area × class. The class skill stays the skill. Default slots: `llm.hunt_perspectives` in `config/default.yaml`.

## `hunt_sink.md`

| | |
|--|--|
| **What** | Sink-driven lens: start from seed sinks / dangerous APIs and walk callers. |
| **Loaded by** | Default perspective `sink_driven`. |
| **Impact** | Which sites that slot investigates first. Does not confirm. |
| **Override** | `config/prompts/overrides/hunt_sink.md` |

## `hunt_dataflow.md`

| | |
|--|--|
| **What** | Dataflow lens: untrusted input toward a sink. `query_flows` is a heuristic, not taint proof. |
| **Loaded by** | Default perspective `dataflow`. |
| **Impact** | Pushes the slot to trace reachability and read the edges it cites. |
| **Override** | `config/prompts/overrides/hunt_dataflow.md` |

## `hunt_authz.md`

| | |
|--|--|
| **What** | Authorization lens: missing or wrong checks against documented trust boundaries. |
| **Loaded by** | Default perspective `authz`. |
| **Impact** | Pushes the slot at authn/authz/tenant checks. Does not confirm. |
| **Override** | `config/prompts/overrides/hunt_authz.md` |

## See also

- [docs/harness/hunt/](../harness/hunt/)
