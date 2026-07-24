# AGENTS.md — using and extending VulnForge

**Where is X?** See [`docs/LAYOUT.md`](docs/LAYOUT.md) for the developer directory map (agent tools, seeds vs runtime, config precedence).

## What this system is

**VulnForge** runs a durable security-audit loop against a **read-only target tree**:

1. **init** — snapshot inventory, create `harness.db`, enqueue `recon`
2. **recon** (LLM) — map architecture; enqueue **hunt** tasks. When a map already exists, each recon **merges** (LLM merge with mechanical fallback) instead of blank-overwriting; Mission **History** can view/restore prior revisions. Mechanical **codemap** (`runs.codemap_json`) is structure-only (modules/entrypoints), separate from architecture.
3. **hunt** (LLM) — one area × weakness class; candidate or `submit_none`
4. **validate_mech** (no LLM) — mechanical gates → `needs_human` or `rejected_mech`
5. **human review** (dashboard Report) — accept → `confirmed`, reject → `rejected_human`, optional notes/docs
6. **project projection** — regenerates `project/*` on idle `run-once` / `vf project`

**`needs_human` = mech gates passed. `confirmed` = human accepted.** Neither is exploit proof.

## Quick start

```powershell
cd VulnForge
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

vf init --target C:\path\to\codebase
python scripts/ralph.py --run-dir runs\<target_id>\run-001 --task-timeout 900 --max-tasks 50
# or: vf dashboard → http://127.0.0.1:8787
```

## Research cockpit (UI)

The dashboard is the main operator surface:

| Mode | Job |
|------|-----|
| **Mission** | Overview, architecture, campaign status |
| **Coverage** | Residual-risk matrix; re-queue shallow/aborted/none cells |
| **Explorer** | Browse target, select code, enqueue hunts |
| **Report** | Structured findings table + exports; detail links to Evidence |
| **Evidence** | On-disk evidence packs (browse / open from Report) |
| **Tasks** | Task queue / transcripts, event timeline (mode id `audit`) |
| **AI** | Campaign co-pilot: start/query hunts, status, findings, runner control (confirm mutators) |
| **Harness** | Live agent graph (loop profiles are dev/API only — not operator UI) |

**Home** (`/`): all runs + **AI Chat** (`/chat`, fleet co-pilot) + **Tool gaps** (`/tool-gaps`) + **Dev dashboard** (`/dev`, hunt skills).

### Operator AI chat

- **Home** (`/chat`): query results across all runs, list/start/query hunts on a named run, init audits, start/pause Ralph. Mutating tools need UI **Confirm**.
- **Run tab AI**: bound to the current run (enqueue/requeue hunts, inspect tasks, coverage, findings).
- Implementation: `vulnforge/operator_chat/` (control-plane tools only — not the code_static hunt agent loop). Sessions: `config/operator_chat/home/` or `{run_dir}/operator_chat/`.
- Chat **enqueues** work; Ralph **executes** hunts.

### Steer a live campaign

1. Start Ralph from the mission bar.
2. **Explorer**: open a file, optionally select lines, pick a hunt class, add notes, **Enqueue hunt**.
3. **Coverage**: click residual cells (shallow/aborted/none) → re-queue with notes.
4. **Report**: open a finding → **Open Evidence**; **Develop POC** opens a **workshop modal** (not a mode tab) — hub is `evidence/<pack>/poc_develop.md`; optional Ralph `develop_poc` writes **runnable** PoC code (not a narrative rewrite); **Accept / Reject / Needs review** with optional notes. None of these auto-prove exploitability.

Keyboard: `e` focuses Explorer.

## Package layout (maintainers)

```
vulnforge/
  operator_chat/ # Home + run AI co-pilot (tools, confirm, sessions)
  control/       # exit codes, ops (coverage/selection hunt)
  findings/      # stable_key + near-dup merge (not a stage)
  hunt_profiles/ # operator hunt skills collection (seed + CRUD + import/export)
  stages/        # recon, hunt, validate_mech, render, …
  tools/         # FS jail, file_inventory, grep, codemap, evidence
  llm/           # (or llm.py) client + FakeLLM
  ui/            # FastAPI + research cockpit
  cli.py         # thin argparse → control plane
  db.py          # SQLite + RunLock (architecture_json + codemap_json)
```

Mechanical codemap is path-backed structure stored in `runs.codemap_json` (built at recon); it is not the architecture map.

## Extending

### New hunt class / skill

Hunt skills live in the **operator collection** (`config/hunt_profiles/`), not hardcoded defaults.

1. Dashboard: **Home → Open Dev** (`/dev`)
2. **+ New profile** (id slug + markdown body), or **Import** a collection JSON
3. Toggle **Active** for bulk enqueue (recon `active_fallback`, Coverage “all”, `file_by_file`)
4. **Export** to share a collection; **Reseed from package** restores seed library from `prompts/v1/hunt_classes/`

Package markdown under `prompts/v1/hunt_classes/` is a **seed library** only (first open / reseed). Runtime authority is the collection.

### New mech gate

Add check in `stages/validate_mech.py` `CHECKS` list; unit test in `tests/test_validate_mech_gates.py`.

### New agent tool

**Preferred path (one file):** add `vulnforge/tools/agent/<name>.py` with `SPEC = ToolSpec(...)` and `run(ctx, **args)`. Registry auto-discovers name, schema, stages, aliases, and `critical_for`. See [`docs/LAYOUT.md`](docs/LAYOUT.md).

**Full offline / AI generate guide:** [`toolgen.md`](toolgen.md). Dev dashboard: Home → **Open Dev** → **Tools** (drafts → validate → integrate). Validation: `python scripts/validate_tool.py config/tool_drafts/<id>`.

**When to open it**

- Tool-gap report suggests a missing capability (`vf tool-gaps`, dashboard **Tool gaps**)
- Extending `grep` / `file_inventory` / etc. with new args
- Adding a brand-new `code_static` tool name

Integrate **apply** mutates package source — dry-run first. Prefer writing a SPEC module under `tools/agent/`; `extra_registry` remains a compatibility path for older integrates.

**Rules** (same as honesty + `toolgen.md`): target tree read-only; evidence only via `write_evidence`; soft path jail for path tools; no unrestricted shell on default `code_static`. Prefer extending an existing tool when the model only needs filters/args.

**Verify**

```powershell
python -m pytest tests/test_tools.py tests/test_tool_gaps.py tests/test_phase1_scope.py tests/test_toolgen_validate.py tests/test_toolgen_generate.py -q
# Live Ornith (optional): $env:VF_LIVE=1; pytest tests/test_live_toolgen.py -v -s
```


## Tool-gap analysis

After (or during) a campaign, mine transcripts for tools the model wanted but does not have:

```powershell
vf tool-gaps --run-dir runs\<target_id>\run-001
# all runs:
vf tool-gaps --runs-root runs --all
```

Writes `project/TOOL_GAPS.md` and `project/tool_gaps.json`. Dashboard: **Home → Open tool gaps** (`/tool-gaps`, AI hybrid analysis).

Gaps are **ideas, not mandates** — evaluate safety/cost, then implement via **`toolgen.md`**.

Ralph can pick up a no-LLM task if enqueued:

```text
# e.g. from a small script / future UI: db.enqueue_task("tool_gaps", {}, priority=90)
```

Optional: set `run.auto_tool_gaps: true` in config so idle `run-once` writes gaps after render (default false).

## Scope

VulnForge is **source-code analysis only** (`code_static`). PE / binary reverse-engineering (Ghidra, `binary_re`) has been removed.

## Honesty rules

- Target tree is **read-only** for agents.
- Evidence only under `evidence/`.
- `project/*` is projection, not authority.
- Do not treat same-model `validate_llm` as strong proof.
- Automation never sets `confirmed`; only human review does.
