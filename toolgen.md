# toolgen.md — adding agent tools to VulnForge

Checklist of record for humans and local/offline models. Linked from `AGENT.md`.

## When to open this

- Tool-gap report suggests a missing capability (`vf tool-gaps`, dashboard **Tool gaps**)
- Extending `grep` / `file_inventory` / etc. with new args
- Adding a brand-new `code_static` tool name
- Dev dashboard **Tools** tab → **Generate tool…**

**Prefer extend** when the model only needs a filter or argument on an existing tool.

## Safety rules

| Rule | Detail |
|------|--------|
| Target RO | Never write/delete under the audit target tree |
| Evidence | Only under `evidence/` via `write_evidence` patterns |
| Path jail | `resolve_target_path` + soft jail helpers for path tools |
| No shell | No unrestricted shell/network on default `code_static` |
| Return shape | Always `{"ok": true\|false, ...}` |

## Wire-up order (manual)

| Step | Where |
|------|--------|
| Implement | `vulnforge/tools/<module>.py` |
| Dispatch | `build_tool_handler` **or** `extra_registry.EXTRA_TOOL_SPECS` (toolgen integrate) |
| Allowlist | `CodeStaticProfile.allowed_tools()` (auto-includes extras) |
| LLM schema | `packet.tool_schemas_for` (auto-merges extras) |
| Caps | `config/default.yaml` → `tools.*` (optional) |
| Docs | `PROTOCOL.md` tool list |
| Tests | `tests/test_tools.py` or `tests/test_tool_<id>.py` |

## Dev workflow (AI-assisted)

1. **Tool gaps** (`/tool-gaps`) or Dev **Tools** → note a capability.
2. **Create draft** — brief, stages, risk class, prompt slots (problem / non-goals / I/O / safety).
3. **Preview prompts** — see exactly what the model will be told.
4. **Generate spec** → review `spec.md`.
5. **Generate impl** → review `impl.py` + `schema.json` + tests.
6. **Validate** — `python scripts/validate_tool.py config/tool_drafts/<id>`
7. Optional **AI fix** loop (capped) using the validation report.
8. **Integrate** (dry-run then apply) — writes module + `extra_registry`.
9. **Select** on hunt profiles (optional tools allowlist) or recon agents.

Drafts live in `config/tool_drafts/<id>/` and are **never** imported by the agent until Integrate.

### Draft layout

```
config/tool_drafts/<id>/
  meta.json
  brief.json
  spec.md
  schema.json
  impl.py
  handler_snippet.py
  wireup.json
  test_stub.py
  validation_report.json
  prompt_overrides/   # optional
```

Status: `draft` → `generated` → `validated` → `integrated` | `rejected`

## Validation checks {#validation-checks}

Run:

```bash
python scripts/validate_tool.py config/tool_drafts/<id>
python scripts/validate_tool.py config/tool_drafts/<id> --json
python scripts/validate_tool.py config/tool_drafts/<id> --integrate
```

| id | Level | Rule |
|----|-------|------|
| `id_slug` | hard | `[a-z][a-z0-9_]{0,47}` |
| `meta_complete` | hard | id, stages, risk_class, module |
| `spec_present` | hard | non-empty `spec.md` within size cap |
| `impl_present` | hard | non-empty `impl.py` within size cap |
| `impl_syntax` | hard | `ast.parse` |
| `returns_ok_dict` | hard | returns / builds dict with `ok` |
| `forbidden_imports` | hard | no subprocess/network/etc. for read_only |
| `no_path_escape` | hard | path params use resolve/soft-jail helpers |
| `no_target_write` | hard | no arbitrary target writes |
| `schema_openai_shape` | hard | name, description, parameters.type=object |
| `schema_matches_impl` | hard | required params referenced; function name present |
| `risk_class_consistent` | hard | risk matches code |
| `code_static_safe` | hard | no exec/shell on code_static |
| `size_limits` | hard | file size caps |
| `no_network_default` | hard | unless risk allows |
| `handler_snippet_names` | soft | snippet mentions tool names |
| `wireup_complete` | soft / hard@integrate | required wireup keys |
| `test_stub_present` | soft / hard@integrate | pytest stub |
| `aliases_safe` | soft | aliases do not shadow carelessly |

## Pasteable offline prompt

```
You are adding a VulnForge code_static agent tool.

Rules: read toolgen.md and prompts/v1/toolgen_validation.md.
Target is read-only. Return {"ok": bool}. No subprocess/network.
Paths use resolve_target_path.

Produce: impl.py module, OpenAI function schema JSON, pytest stub,
and wireup.json fields (impl_path, allowed_tools_add, packet_stages).

After writing files under config/tool_drafts/<id>/, I will run:
  python scripts/validate_tool.py config/tool_drafts/<id>
Fix any hard_fail without weakening safety.
```

## Hunt profile tools allowlist

On Dev → Hunt profiles, set **Approved tools** (optional). `null`/empty = full hunt set.
When set, `pack_hunt` filters schemas; `submit_candidate` and `submit_none` always remain.

## Verify

```bash
python -m pytest tests/test_tools.py tests/test_tool_gaps.py tests/test_toolgen_validate.py -q
python scripts/validate_tool.py config/tool_drafts/<id> --integrate
```
