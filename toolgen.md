# toolgen.md — adding agent tools to VulnForge

Checklist of record for humans and local/offline models. Linked from `AGENTS.md`.

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

**Preferred (one file):** `vulnforge/tools/agent/<name>.py` with `SPEC = ToolSpec(...)` and `run(ctx, **args)`. Registry auto-discovers name, OpenAI schema, stages, aliases, and `critical_for`. No hand-edit of `packet.py` or giant if/elif.

| Step | Where |
|------|--------|
| Implement (preferred) | `vulnforge/tools/agent/<name>.py` — co-located `SPEC` + `run()` |
| Shared backends | `vulnforge/tools/fs_read.py`, `grep_index.py`, … (optional helpers) |
| Dispatch | Auto via `tools/registry` + `tools/dispatch` (`build_tool_handler`) |
| Allowlist | `CodeStaticProfile.allowed_tools()` ← registry (+ extras) |
| LLM schema | `packet.tool_schemas_for` ← registry SPECs (+ extras) |
| Critical keep | `ToolSpec.critical_for` (e.g. `submit_*` on hunt) |
| Legacy extras | `extra_registry.EXTRA_TOOL_SPECS` only when not writing agent SPECs |
| Caps | `config/default.yaml` → `tools.*` (optional) |
| Docs | `PROTOCOL.md` tool list; `docs/LAYOUT.md` |
| Tests | `tests/test_tools.py`, `tests/test_tool_registry.py`, or `tests/test_tool_<id>.py` |

## Local Ornith (recommended for AI generate)

Primary surface for VulnForge: **LM Studio** (or compatible) OpenAI chat API on `http://127.0.0.1:1234/v1`.

1. Load Ornith (listed id is usually `ornith-1.0-35b` — match **`GET /v1/models`**).
2. Dashboard **Settings → Optimize AI settings → Save** so host/model/`max_tokens` match the server.
   - Reasoning models need **high** `max_tokens` (often ≥ 4096–8192). Low budgets yield empty `content` and only `reasoning_content`.
3. Optional config keys in `config/default.yaml` → `llm.toolgen_max_tokens` (default 8192) and `llm.temperature_code` (≈0.15).
4. Env overrides: `VF_BASE_URL`, `VF_MODEL`, or `VF_HOST`+`VF_PORT`.

**Toolgen vs recon/hunt:** generate stages are **text JSON only** (no `tool_calls`). A green toolgen smoke does **not** prove recon/hunt tool-use works — use Settings Optimize’s tool probe for that.

**Alternate mlx servers** (often `:8080`, used by Grok CLI) are not shipped in this repo. If you point VulnForge at one, raise the server token cap well above 512 and set Settings host/port/model to match. A 512-token server cap truncates toolgen JSON even when the client requests 8192.

**AI fix** is **single-shot per click** in the Dev wizard — re-run validate / AI fix until hard checks pass. Do not weaken safety to pass.

**Integrate apply** defaults to `vulnforge/tools/agent/<id>.py` (SPEC module). Explicit wireup may still write `vulnforge/tools/<id>.py` + `extra_registry.py` (legacy). Always dry-run first; review `impl.py` before Apply.

### Live smoke (not FakeLLM)

```bash
# Offline unit path (FakeLLM / hand-seeded drafts)
pytest tests/test_toolgen_validate.py tests/test_toolgen_integrate.py tests/test_toolgen_generate.py -q

# Live Ornith (opt-in)
VF_LIVE=1 pytest tests/test_live_ornith.py tests/test_live_toolgen.py -v -s
python scripts/live_toolgen_smoke.py   # dry-run integrate only
```

## Dev workflow (AI-assisted)

1. **Tool gaps** (`/tool-gaps`) or Dev **Tools** → note a capability.
2. Confirm Ornith settings (section above).
3. **Create draft** — brief, stages, risk class, prompt slots (problem / non-goals / I/O / safety). Prefer a **small** first tool.
4. **Preview prompts** — see exactly what the model will be told.
5. **Generate spec** → review `spec.md`.
6. **Generate impl** → review `impl.py` + `schema.json` + tests.
7. **Validate** — `python scripts/validate_tool.py config/tool_drafts/<id>`
8. Optional **AI fix** (click again if still failing) using the validation report.
9. **Integrate** (dry-run then apply) — writes `tools/agent/<id>.py` SPEC (or legacy extra path).
10. **Select** on hunt profiles (optional tools allowlist) or recon agents.

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

Rules: read toolgen.md and seeds/system/toolgen_validation.md.
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
python -m pytest tests/test_tools.py tests/test_tool_gaps.py tests/test_toolgen_validate.py tests/test_toolgen_generate.py -q
python scripts/validate_tool.py config/tool_drafts/<id> --integrate
# Live (optional): VF_LIVE=1 pytest tests/test_live_toolgen.py -v -s
```
