# System seeds catalog (`seeds/system/`)

Package **stage/system markdown** prompts. This folder documents **what each file is** and **impact of changing it**. It is not a second copy of the prompts.

## Edit rules (short)

| Goal | Where |
|------|--------|
| Change package library (all installs / Reseed pin) | `seeds/system/<file>.md` |
| Experiment on one machine without committing | `config/prompts/overrides/<same basename>.md` |
| Hunt skill **author** prompt override | `config/prompts/generate_skill.md` (special-case; not under `overrides/`) |

Loader: `vulnforge.packet.load_prompt_slice` prefers override for top-level basenames, then `system_prompts_root()` → `seeds/system/`.

**Prompt pin:** `vf init` hashes the effective seeds tree. Editing package seeds changes the pin for **new** runs; it does not rewrite existing run transcripts.

**Not here:** hunt class bodies (`seeds/hunt_classes/`) and recon agent bodies (`seeds/recon_agents/`) — see [seeds/README.md](../../seeds/README.md) and [docs/LAYOUT.md](../LAYOUT.md).

## Index

| Seed file | Group doc | Used by | Stage / feature |
|-----------|-----------|---------|-----------------|
| `preamble.md` | [SHARED.md](SHARED.md) | `packet.py` | recon, hunt, disprove, develop_poc packing |
| `PRINCIPLES.md` | [SHARED.md](SHARED.md) | `packet.py` | hunt (audit principles) |
| `recon.md` | [RECON.md](RECON.md) | `packet.py` legacy pack | recon |
| `architecture_merge.md` | [RECON.md](RECON.md) | `stages/recon.py` merge | recon multi-agent / re-run |
| `hunting_angles.md` | [HUNT.md](HUNT.md) | `packet.py` + profile `angle_ids` | hunt |
| `disprove.md` | [VALIDATE.md](VALIDATE.md) | `pack_disprove` | validate_llm |
| `disprove_threat.md` | [VALIDATE.md](VALIDATE.md) | perspective slice | validate_llm |
| `disprove_code.md` | [VALIDATE.md](VALIDATE.md) | perspective slice | validate_llm |
| `develop_poc.md` | [DEVELOP_POC.md](DEVELOP_POC.md) | develop_poc packet | develop_poc task |
| `generate_skill.md` | [GENERATE_SKILL.md](GENERATE_SKILL.md) | hunt skill author | generate_skill / Dev |
| `tool_gaps.md` | [TOOL_GAPS.md](TOOL_GAPS.md) | tool_gaps hybrid LLM | tool gap analysis |
| `toolgen_spec.md` | [TOOLGEN.md](TOOLGEN.md) | toolgen pipeline | Dev Tools |
| `toolgen_impl.md` | [TOOLGEN.md](TOOLGEN.md) | toolgen pipeline | Dev Tools |
| `toolgen_test.md` | [TOOLGEN.md](TOOLGEN.md) | toolgen pipeline | Dev Tools |
| `toolgen_validation.md` | [TOOLGEN.md](TOOLGEN.md) | toolgen pipeline | Dev Tools |

## Related harness docs

Stage behavior and code touchpoints: [docs/harness/](../harness/).
