# AGENTS.md — using and extending VulnForge

**Where is X?** See [`docs/LAYOUT.md`](docs/LAYOUT.md) for the developer directory map (agent tools, seeds vs runtime, config precedence).

## What this system is

**VulnForge** runs a durable security-audit loop against a **read-only target tree**:

1. **init** — snapshot inventory, create `harness.db`, enqueue `recon`
2. **recon** (LLM) — mechanical skeleton first (no LLM), then map agents label it with trust zones and cited relations, then a **flow-tracer** fan-out records data flows (entrypoint → sink, cited `path:line`); then enqueue **hunt** tasks. Flows steer hunts; they are never findings. When a map already exists, each recon **merges** into it instead of blank-overwriting: structure merges deterministically with citation checks, and only the summary paragraph goes through the LLM. Atlas **History** can view/restore prior revisions. Spec: [`docs/harness/recon/FLOWS.md`](docs/harness/recon/FLOWS.md). Mechanical **codemap** (`runs.codemap_json`) is structure-only (modules/entrypoints), separate from architecture.
3. **hunt** (LLM) — one area × weakness class; candidate or `submit_none`
4. **validate_mech** (no LLM) — mechanical gates → `needs_human` or `rejected_mech`
5. **validate_llm** (default on) — dual adversarial disprove; both reject → `rejected_llm`, else stay `needs_human`. Never auto-confirms. Set `stages.validate_llm: false` to skip for speed/debug.
6. **human review** (Review tab; its badge counts `needs_human`) — accept → `confirmed`, reject → `rejected_human`. Durable `vulnforge/hitl-report@1` packet and responses; the harness re-reads them and never invents an approval. Optional notes.
7. **develop_poc / validate_poc** (operator) — write runnable PoC under `evidence/`; optional controlled harness run → `poc_run.json` (never auto-`confirmed`)
8. **project projection** — regenerates `project/*` on idle `run-once` / `vf project`

**`needs_human` = mech gates passed (and disprove did not kill, if enabled). `confirmed` = human accepted.** Neither is exploit proof.

**Evidence tier.** Every finding also carries a derived `evidence_tier`, weakest first: `ungated` (gates not passed), `gated` (gates passed; disprove off, pending, split or not run), `stood` (every disprove slot returned `stand`; same-model stand is weaker still) and `reproduced` (the latest finished sandbox PoC run returned `signal_observed`). One pure function, `vulnforge/evidence_tier.py`, computes it from `validation_mech`, `validation_llm` and `poc_validation_latest`; the snapshot, HITL packet, exports and the `human_review` entry (tier at verdict time) all read it. The Review queue sorts by tier, then severity. It is a label: it never changes state, never raises severity and never confirms. A failed or inconclusive PoC run does not raise the tier but is shown next to it.

## Quick start

```bash
cd VulnForge
python3 -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

vf init --target /path/to/codebase
python scripts/ralph.py --run-dir runs/<target_id>/run-001 --task-timeout 900 --max-tasks 50
# or: vf dashboard → http://127.0.0.1:8787
```

## Research cockpit (UI)

The dashboard is the main operator surface:

Run pages are tabs under one header (run switcher, tabs, pipeline totals, Ralph status, Start/Pause, ⌘K, ⋯ menu). Mode ids are kept as URL hashes; `#mission` opens Campaign. Spec: [`docs/ui/REDESIGN.md`](docs/ui/REDESIGN.md).

| Tab (mode id) | Job |
|------|-----|
| **Review** (`report`) | Human gate: queue → finding (data flow, cited code) → verdict rail (mech gates, disprove judges as a weak signal, PoC, notes, **Accept / Reject**); exports. Badge counts `needs_human` only |
| **Campaign** (`hunts`, default) | Pipeline (recon → hunt → gates → disprove → review → PoC) with an advisory yield sparkline (gated findings per token, last 20 hunts, beside the open-cell count), hunt-coverage matrix (area × skill, re-queue open cells), cell inspector, now running / up next / activity, **Plan hunts** drawer |
| **Atlas** (`explorer`) | Architecture map in trust-zone bands with data-flow arrows (flows / links / imports), Files and Flows tabs, area or flow inspector, **Hunt this area / flow**, Code view (select lines → enqueue hunt), recon brief, History, Codemap |
| **Evidence** | On-disk evidence packs (browse / open from Review) |
| **Tasks** (`audit`) | Task queue / transcripts, event timeline |
| **AI** (`ai`, ⌘K) | Campaign co-pilot sheet: start/query hunts, status, findings, runner control (confirm mutators) |

Coverage cell states use one vocabulary everywhere: Finding filed, Nothing found, Too shallow, Aborted, Queued, Hunting now, Not hunted. Everything except Finding filed and Hunting now is **open**; "Nothing found" is still open (a miss is not proof of safety).

**Home** (`/`): all runs + **AI Chat** (`/chat`, fleet co-pilot) + **Tool gaps** (`/tool-gaps`) + **Dev dashboard** (`/dev`, hunt skills) + **Benchmarks** (`/benchmarks`, `vf bench`: suite runs vs a pinned baseline, with gated recall, unmatched findings per target and tokens per hit; L0 fixture checks are not model quality; see [`benchmarks/README.md`](benchmarks/README.md)) + **Settings** (`/settings` — hosts, verified model catalog, role pickers, per-model context and max tokens, hunt MoA perspectives). A pair with no override uses the global context and max tokens as the seed. Max context fraction stays global.

### Operator AI chat

- **Home** (`/chat`): query results across all runs, list/start/query hunts on a named run, init audits, start/pause Ralph. Mutating tools need UI **Confirm**.
- **Run tab AI**: bound to the current run (enqueue/requeue hunts, inspect tasks, coverage, findings).
- Implementation: `vulnforge/operator_chat/` (control-plane tools only — not the code_static hunt agent loop). Sessions: `config/operator_chat/home/` or `{run_dir}/operator_chat/`.
- Chat **enqueues** work; Ralph **executes** hunts.

### Campaign control grammar

Seven verbs — `start`, `stop`, `pause`, `resume`, `status`, `findings`, `gate` — on `/api/runs/{target_id}/{run_id}/campaign/{verb}`. They call the existing Ralph runner and `harness.db` (dashboard lifecycle and operator chat use the same functions). `gate` reads the HITL inbox and never sets `confirmed`. Contract: [`docs/harness/CAMPAIGN.md`](docs/harness/CAMPAIGN.md) and `GET /api/campaign/grammar`.

### Steer a live campaign

1. Start Ralph from the run header.
2. **Atlas**: pick an area or a traced flow → **Hunt this area / flow**; or switch to Code, select lines, pick a hunt class, add notes, **Enqueue hunt**.
3. **Campaign**: **Plan hunts** for area × skill batches, or click open cells (not hunted / too shallow / aborted / nothing found) → re-queue with notes.
4. **Review**: open a finding → **Open Evidence**; **Develop POC** opens a **workshop modal** (not a mode tab) — hub is `evidence/<pack>/poc_develop.md`; optional Ralph `develop_poc` writes **runnable** PoC code (not a narrative rewrite); **Run in harness** queues a sandbox one-shot `validate_poc` (microVM or gVisor only; writes `poc_run.json`; does not confirm); **Iterate in sandbox** keeps that guest for rewrite/re-run cycles (default 5, 15-minute TTL, both in Settings) and writes `poc_session.json` without confirming; **Export validation job** builds a handoff zip; **Accept / Reject / Needs review** with optional notes. None of these auto-prove exploitability. New audit can opt in to the same one-shot as a validation-phase step (**Sandbox PoC one-shot**).

CLI handoff / harness:

```bash
vf export-validation-job --run-dir runs/<target_id>/run-001 --finding-id 3
vf validate-poc --run-dir runs/<target_id>/run-001 --finding-id 3 --execute
```

Keyboard: ⌘/Ctrl+K opens AI; `e` opens Atlas (outside Review); on Review `J`/`K` move, `A` accept, `R` reject, `E` open evidence.

## Package layout (maintainers)

```
vulnforge/
  operator_chat/ # Home + run AI co-pilot (tools, confirm, sessions)
  agent_runtime/ # Strands tool-loop (hunt, recon, develop_poc, operator chat)
  control/       # exit codes, ops (Hunts requeue / selection hunt)
  findings/      # stable_key + near-dup merge (not a stage)
  hunt_profiles/ # operator hunt skills collection (seed + CRUD + import/export)
  stages/        # recon, hunt, validate_mech, render, …
  tools/         # FS jail, file_inventory, grep, codemap, evidence
  llm.py         # HTTP clients + FakeLLM (production tool loop is agent_runtime/)
  ui/            # FastAPI + research cockpit
  cli.py         # thin argparse → control plane
  db.py          # SQLite + RunLock (architecture_json + codemap_json + HITL tables)
  hitl.py        # report↔responses contract (needs_human inbox)
```

Mechanical codemap is path-backed structure stored in `runs.codemap_json` (built at recon; v2 includes files + function/class symbols). Full map is stored; hunt packets get an **area slice** only. Optional `pip install 'vulnforge[codemap]'` enables tree-sitter; heuristic extraction works without it. It is not the architecture map.

## Extending

### Stage docs (recon / hunt / validate)

Maintainer guides (behavior + “what/where to modify”):

- [`docs/harness/`](docs/harness/) — pipeline overview and per-stage folders
- [`docs/system/`](docs/system/) — every `seeds/system/*` prompt: purpose and impact of edits

### New hunt class / skill

Hunt skills live in the **operator collection** (`config/hunt_profiles/`), not hardcoded defaults.

1. Dashboard: **Home → Open Dev** (`/dev`)
2. **+ New profile** (id slug + markdown body), or **Import** a collection JSON
3. Toggle **Active** for bulk enqueue (recon `active_fallback`, Hunts “all”, `file_by_file`)
4. **Export** to share a collection; **Reseed from package** restores seed library from `seeds/hunt_classes/`

Package markdown under `seeds/hunt_classes/` is a **seed library** only (first open / reseed). Runtime authority is the collection. See [`seeds/README.md`](seeds/README.md).

### New mech gate

Add check in `stages/validate_mech.py` `CHECKS` list; unit test in `tests/test_validate_mech_gates.py`.

### New agent tool

**Preferred path (one file):** add `vulnforge/tools/agent/<name>.py` with `SPEC = ToolSpec(...)` and `run(ctx, **args)`. Registry auto-discovers name, schema, stages, aliases, and `critical_for`. See [`docs/LAYOUT.md`](docs/LAYOUT.md).

**Full offline / AI generate guide:** [`toolgen.md`](toolgen.md). Dev dashboard: Home → **Open Dev** → **Tool lab** (brief → spec → impl → validate → integrate). **Tools** is read/configure only (catalog + per-stage defaults). Validation: `python scripts/validate_tool.py config/tool_drafts/<id>`.

**When to open it**

- Tool-gap report suggests a missing capability (`vf tool-gaps`, dashboard **Tool gaps**)
- Extending `grep` / `file_inventory` / etc. with new args
- Adding a brand-new `code_static` tool name

Integrate **apply** mutates package source. The server refuses apply without the `plan_hash` from a fresh dry-run (409), and refuses to overwrite an existing file unless `allow_overwrite` is sent. Prefer writing a SPEC module under `tools/agent/`; `extra_registry` remains a compatibility path for older integrates.

**Rules** (same as honesty + `toolgen.md`): target tree read-only; evidence only via `write_evidence`; soft path jail for path tools; no unrestricted shell on default `code_static`. Prefer extending an existing tool when the model only needs filters/args.

**Verify**

```bash
python -m pytest tests/test_tools.py tests/test_tool_gaps.py tests/test_phase1_scope.py tests/test_toolgen_validate.py tests/test_toolgen_generate.py -q
# Live Ornith (optional): VF_LIVE=1 pytest tests/test_live_toolgen.py -v -s
```


## Tool-gap analysis

After (or during) a campaign, mine transcripts for tools the model wanted but does not have:

```bash
vf tool-gaps --run-dir runs/<target_id>/run-001
# all runs:
vf tool-gaps --runs-root runs --all
```

Writes `project/TOOL_GAPS.md` and `project/tool_gaps.json`. Dashboard: **Home → Open tool gaps** (`/tool-gaps`, AI hybrid analysis).

Gaps are **ideas, not mandates** — evaluate safety/cost, then implement via **`toolgen.md`**.

**Swallowed errors.** Best-effort handlers that keep the loop alive call `vulnforge.errors.note_swallowed(exc, context=...)` instead of a bare `pass`. It logs with context, counts per run, and appends to `{run_dir}/swallowed_errors.jsonl`. The **Tool gaps → Per run** table shows the count (hover for top contexts). A non-zero count is a bug lead, not a finding.

Ralph can pick up a no-LLM task if enqueued:

```text
# e.g. from a small script / future UI: db.enqueue_task("tool_gaps", {}, priority=90)
```

Optional: set `run.auto_tool_gaps: true` in config so idle `run-once` writes gaps after render (default false).

## Agent loop runtime (Strands)

VulnForge uses **[Strands Agents](https://strandsagents.com/)** for all production LLM↔tools work (hunt, recon, develop_poc, operator chat). Implementation: `vulnforge/agent_runtime/`. Core dependency: `strands-agents[openai]`.

Operator chat **mutations still require UI Confirm**. Offline tests use `FakeLLMClient` (scripted; no network).

**Multi-agent recon** (`llm.recon_orchestrator` / `VF_RECON_ORCHESTRATOR`):

| Mode | Behavior |
|------|----------|
| `ralph` (default) | One durable Ralph task per recon agent (fan-out) |
| `inprocess` | All agents sequential in one task |
| `graph` | Sequential Strands Graph pipeline in one task |

Never auto-`confirmed`; human review unchanged.

## Scope

VulnForge is **source-code analysis only** (`code_static`). PE / binary reverse-engineering (Ghidra, `binary_re`) has been removed.

## Honesty rules

- Target tree is **read-only** for agents.
- Evidence only under `evidence/`.
- `project/*` is projection, not authority.
- Do not treat same-model `validate_llm` as strong proof (default on; demote-only).
- Automation never sets `confirmed`; only human review does.
- HITL responses are durable and re-readable. A missing answer is unanswered. See [`docs/harness/validate/HITL.md`](docs/harness/validate/HITL.md).
