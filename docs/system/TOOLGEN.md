# Toolgen system prompts

Used by the Dev **Tools** draft pipeline (`vulnforge/toolgen/`), not by the campaign hunt loop.

| Seed file | Role |
|-----------|------|
| `toolgen_spec.md` | Specify a new/extended agent tool |
| `toolgen_impl.md` | Implementation authoring guidance |
| `toolgen_test.md` | Test generation guidance |
| `toolgen_validation.md` | Validation rules / safety checks (with `toolgen.md`) |

| | |
|--|--|
| **Loaded by** | `toolgen/generate.py` via `load_prompt_slice` on `system_prompts_root()`; drafts may also store overrides. |
| **Impact** | Quality and safety of generated tool drafts. Integrated tools still must obey jail/evidence rules in `toolgen.md` / AGENTS honesty. |
| **Override** | `config/prompts/overrides/toolgen_*.md` and/or per-draft overrides in toolgen store. |

## See also

- Root `toolgen.md`
- [docs/LAYOUT.md](../LAYOUT.md) — agent tool layout
