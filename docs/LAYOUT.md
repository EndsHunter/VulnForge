# VulnForge layout — where is X?

Developer map for the package. Product behavior (task loop, honesty rules, Ralph
exit codes) is unchanged by this layout; this document is navigation only.

## Want… → Look in…

| Want… | Look in… |
|-------|----------|
| **Agent tool X** (model-facing `code_static`) | `vulnforge/tools/agent/<x>.py` — `SPEC` + `run()` |
| Tool registry / dispatch / schemas | `vulnforge/tools/base.py`, `registry.py`, `dispatch.py` |
| Shared FS/grep backends (not one-tool-one-file) | `vulnforge/tools/fs_read.py`, `grep_index.py`, `evidence_write.py`, … |
| Extra tools (toolgen integrate) | `vulnforge/tools/extra_registry.py` + optional `tools/extra/` |
| Stage / task kind | `vulnforge/stages/<kind>.py` — behavior + modify guides: [`docs/harness/`](harness/) |
| PoC handoff / harness | `vulnforge/poc_handoff.py`, `poc_runner.py`, stage `validate_poc` |
| System prompt catalog (impact of edits) | [`docs/system/`](system/) |
| Packet builders + prompt packing | `vulnforge/packet.py` (schemas live on tool SPECs; **`packets/` package split deferred**) |
| System / stage markdown prompts | `seeds/system/` — see `paths.system_prompts_root()`; impact catalog: [`docs/system/`](system/) |
| Hunt skill **runtime** authority | `config/hunt_profiles/` (collection + bodies) |
| Hunt skill **package seeds** (reseed only) | `seeds/hunt_classes/` |
| Recon agent **runtime** | `config/recon_agents/` |
| Recon agent **seeds** | `seeds/recon_agents/` |
| Config knobs (yaml) | `config/default.yaml` |
| UI / runtime overrides | `config/ui_settings.json` (+ env `VF_*`) — edit via **`/settings`** page |
| Stage / multi-model routing | `vulnforge/llm_models.py` + Settings `model_*` / `validate_models` |
| Load path helpers | `vulnforge/paths.py` |
| Config load | `vulnforge/settings/load.py` (`cli.load_config` is a shim) |
| Operator chat tools (control plane) | `vulnforge/operator_chat/tools_*.py` — **not** agent tools |
| Control-plane ops | `vulnforge/control/` |
| Dashboard routes / static | `vulnforge/ui/` |
| Hunt profile store / reseed | `vulnforge/hunt_profiles/` |
| Mechanical codemap (not architecture) | `vulnforge/tools/codemap.py` → `runs.codemap_json` (v2: modules + files + symbols; hunts get area slice) |
| Sink residual coverage (per path:line:kind) | `db.sink_coverage_facts` + `tools/sink_preindex.record_sink_coverage`; Coverage cell detail |
| Coarse reachability (`query_flows`) | `tools/flows.py` + `tools/agent/query_flows.py` — import BFS + call heuristic (**not** taint) |
| Fixture recall oracles (L0 CI) | `fixtures/ground_truth/*.json` + `vulnforge/eval/recall.py` + `tests/test_fixture_recall_mechanical.py` |
| Function-level symbol extract | `vulnforge/tools/symbols/` (heuristic always; tree-sitter via optional `vulnforge[codemap]`) |
| Languages / extensions / entrypoints catalog | `vulnforge/languages.py` (SOURCE_EXTS, ENTRYPOINT_NAMES, package markers; used by inventory, codemap, sinks, strategies) |
| Tool-gap mining | `vulnforge/tool_gaps.py` |
| Toolgen (draft → validate → integrate) | `vulnforge/toolgen/` + `toolgen.md` |

## Agent tools vs operator chat

| Surface | Audience | Location |
|---------|----------|----------|
| **Agent tools** | Hunt/recon LLM during Ralph | `vulnforge/tools/agent/*` via `build_tool_handler` |
| **Agent tool-loop runtime** | Hunt/recon/PoC/operator LLM↔tools | `vulnforge/agent_runtime/` (Strands Agents) |
| **Recon multi-agent orchestrator** | How multi recon agents run | `llm.recon_orchestrator`: `ralph` \| `inprocess` \| `graph` |
| **Operator chat tools** | Home / run AI co-pilot | `vulnforge/operator_chat/` — Confirm for mutators |

Do not mix names: chat cannot call `grep`/`submit_candidate` as code tools; agent loop cannot call chat fleet tools.

## Config precedence

```text
schema / code defaults
  < config/default.yaml
    < harness profile (when selected)
      < config/ui_settings.json
        < env VF_*  (wins last)
```

Collections (`config/hunt_profiles`, `config/recon_agents`, `config/default_tools.json`)
are **separate** concerns — not folded into one mega-yaml.

### Seed vs runtime prompts

| Kind | Runtime authority | Package seed (reseed / first open) |
|------|-------------------|-------------------------------------|
| Hunt skills | `config/hunt_profiles/` | `seeds/hunt_classes/` |
| Recon agents | `config/recon_agents/` | `seeds/recon_agents/` |
| System prompts | optional `config/prompts/overrides/<name>.md` then package | `seeds/system/` — catalog: [`docs/system/`](system/) |

**Edit runtime collections** for live campaigns. Edit package seeds only when changing the library that Dev **Reseed** copies from.

## Adding an agent tool

1. Create `vulnforge/tools/agent/<name>.py` with `SPEC = ToolSpec(...)` and `run(ctx, **args)`.
2. Registry auto-discovers the module (no hand edit of `packet.py` / giant if/elif).
3. Add a unit test under `tests/`.
4. Or use Dev → Tools → generate/validate/integrate (writes SPEC module when possible).

Wire-up checklist (historical multi-touch path): see `toolgen.md`.

## Deferred refactors

| Item | Status |
|------|--------|
| Split `packet.py` → `vulnforge/packets/` package with re-export shim | **Deferred** — schemas already left for SPECs; further split is opportunistic polish |
| Full settings DRY (`settings/schema.py` single defaults source) | **Deferred (Phase 2 residual)** — UI defaults still live in `settings/ui.py` + `config/default.yaml`; not blocking tool/seeds rearch |

## System prompt overrides (one convention)

| Kind | Path | Loader |
|------|------|--------|
| **System stage prompts** (preamble, PRINCIPLES, disprove*, toolgen*, …) | `config/prompts/overrides/<basename>.md` | `load_prompt_slice` prefers override for basenames (no `/`) |
| **Hunt skill author prompt** (Dev generate skill) | `config/prompts/generate_skill.md` | `hunt_profiles.author_prompt` special-case (not under `overrides/`) |

Package seeds remain under `seeds/system/`. Do not put hunt/recon collection bodies in `overrides/`.

## Package seeds (`seeds/`)

```text
seeds/
  README.md           # edit rules
  system/*.md         # PRINCIPLES, preamble, disprove*, toolgen*, recon.md, …
  hunt_classes/*.md   # reseed → config/hunt_profiles
  recon_agents/*.md   # reseed → config/recon_agents
```

Legacy `prompts/` holds only a redirect README. Runtime seeds load exclusively from `seeds/`.

## Dead / out-of-scope paths

- **`binary_re` / Ghidra reverse-engineering** — fully removed; VulnForge is `code_static` only.
- **`project/*` under a run** — projection only, not authority (`harness.db` + evidence are).

## Project roots (single source)

```python
from vulnforge.paths import (
    PROJECT_ROOT,
    CONFIG_ROOT,
    SEEDS_ROOT,
    system_prompts_root,
    hunt_class_seeds_root,
    recon_agent_seeds_root,
)
```

Do not redeclare `Path(__file__).resolve().parents[N]` for the project root.
