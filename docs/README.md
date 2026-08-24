# Pick the right doc

VulnForge keeps operator docs, maintainer maps, and campaign prompts in different trees. Open the file that matches the job.

## Operator (human)

| Job | File |
|-----|------|
| Install, smoke, daily CLI | [`README.md`](../README.md) |
| Labels, exit codes, CLI contract | [`PROTOCOL.md`](../PROTOCOL.md) |
| Research cockpit while a run is live | Dashboard at `http://127.0.0.1:8787` |

## Coding agents

| Job | File |
|-----|------|
| Work **on** this repo | [`AGENTS.md`](../AGENTS.md) then [`LAYOUT.md`](LAYOUT.md) |
| Drive VulnForge as a **client** of `vf` | [`skill/SKILL.md`](../skill/SKILL.md) |
| Topology and stage flow | [`AGENTS_MAP.md`](AGENTS_MAP.md) (explanation; code + PROTOCOL win on conflict) |

Campaign hunt/recon models do **not** read these files. They see `seeds/system/` plus `config/hunt_profiles/` and `config/recon_agents/`.

## Maintainer

| Job | File |
|-----|------|
| Where is X in the package | [`LAYOUT.md`](LAYOUT.md) |
| Stage behavior and what to edit | [`harness/`](harness/) (`README.md` + `MODIFY.md` per stage) |
| Impact of editing a system prompt | [`system/`](system/) |
| Seed vs runtime collections | [`seeds/README.md`](../seeds/README.md) |
| Add or extend an agent tool | [`toolgen.md`](../toolgen.md) |
| Check living docs against seeds, CLI, and tools | `python scripts/check_docs.py` (`tests/test_docs_living.py`) |

## Historical (not current product truth)

- [`plans/`](plans/)
- [`superpowers/`](superpowers/)
- [`vulnforge/docs/plans/`](../vulnforge/docs/plans/)

## Authority

| Authoritative | Not authoritative |
|---------------|-------------------|
| `harness.db`, `evidence/`, `events.jsonl` | Run-dir `project/*` |
| `config/hunt_profiles/`, `config/recon_agents/` for live campaigns | `seeds/hunt_classes/` and `seeds/recon_agents/` after first seed |
| `seeds/system/` (plus `config/prompts/overrides/`) for stage markdown | This `docs/` tree (navigation and impact notes only) |
