# AGENTS.md — using and extending VulnForge

**Where is X?** See [`docs/LAYOUT.md`](docs/LAYOUT.md) for the developer directory map (agent tools, seeds vs runtime, config precedence).

## What this system is

**VulnForge** runs a durable security-audit loop against a **read-only target tree**:

1. **init** — snapshot inventory, create `harness.db`, enqueue `recon`
2. **recon** (LLM) — map architecture; enqueue **hunt** tasks. When a map already exists, each recon **merges** (LLM merge with mechanical fallback) instead of blank-overwriting; Mission **History** can view/restore prior revisions. Mechanical **codemap** (`runs.codemap_json`) is structure-only (modules/entrypoints), separate from architecture.
3. **hunt** (LLM) — one area × weakness class; candidate or `submit_none`
4. **validate_mech** (no LLM) — mechanical gates → `needs_human` or `rejected_mech`
5. **validate_llm** (default on) — dual adversarial disprove; both reject → `rejected_llm`, else stay `needs_human`. Never auto-confirms. Set `stages.validate_llm: false` to skip for speed/debug.
6. **human review** (Mission needs-review indicator + Report) — accept → `confirmed`, reject → `rejected_human`. Durable `vulnforge/hitl-report@1` packet and responses; the harness re-reads them and never invents an approval. Optional notes.
7. **develop_poc / validate_poc** (operator) — write runnable PoC under `evidence/`; optional controlled harness run → `poc_run.json` (never auto-`confirmed`)
7b. **develop_fix / verify_fix** (operator) — propose a patch as `evidence/<pack>/fix.patch` (never applied to the target); independently re-check a patched tree, git rev, or the fix patch → `verify_fix.json` with `fixed` / `still_vulnerable` / `inconclusive` (re-runs the PoC in the sandbox against the patched tree when one exists). Never changes finding state. See [`docs/system/FIX.md`](docs/system/FIX.md).
8. **project projection** — regenerates `project/*` on idle `run-once` / `vf project`

**`needs_human` = mech gates passed (and disprove did not kill, if enabled). `confirmed` = human accepted.** Neither is exploit proof.

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

**Diff-scoped audit** (PR / commit / branch): `vf init --target <repo> --diff base..head` hunts only the
files changed between the two commit trees plus their codemap callers/callees. See
[`docs/harness/DIFF_SCOPE.md`](docs/harness/DIFF_SCOPE.md).

## Research cockpit (UI)

The dashboard is the main operator surface:

| Mode | Job |
|------|-----|
| **Mission** | Architecture map of the target; campaign health; light needs-review indicator |
| **Hunts** | Plan hunts (areas × skills) + residual-risk matrix; re-queue shallow/aborted/none cells |
| **Explorer** | Browse target, select code, enqueue hunts |
| **Report** | Structured findings table, Needs review filter, human accept/reject, exports (incl. SARIF 2.1.0, [`docs/harness/SARIF.md`](docs/harness/SARIF.md)), **Track** in GitHub Issues (preview → Publish); detail links to Evidence |
| **Evidence** | On-disk evidence packs (browse / open from Report) |
| **Tasks** | Task queue / transcripts, event timeline (mode id `audit`) |
| **AI** | Campaign co-pilot: start/query hunts, status, findings, runner control (confirm mutators) |

**Home** (`/`): all runs + **AI Chat** (`/chat`, fleet co-pilot) + **Tool gaps** (`/tool-gaps`) + **Dev dashboard** (`/dev`, hunt skills) + **Settings** (`/settings` — hosts, verified model catalog, role pickers, per-model context and max tokens, hunt MoA perspectives). A pair with no override uses the global context and max tokens as the seed. Max context fraction stays global.

### Operator AI chat

- **Home** (`/chat`): query results across all runs, list/start/query hunts on a named run, init audits, start/pause Ralph. Mutating tools need UI **Confirm**.
- **Run tab AI**: bound to the current run (enqueue/requeue hunts, inspect tasks, coverage, findings).
- Implementation: `vulnforge/operator_chat/` (control-plane tools only — not the code_static hunt agent loop). Sessions: `config/operator_chat/home/` or `{run_dir}/operator_chat/`.
- Chat **enqueues** work; Ralph **executes** hunts.

### Campaign control grammar

Seven verbs — `start`, `stop`, `pause`, `resume`, `status`, `findings`, `gate` — on `/api/runs/{target_id}/{run_id}/campaign/{verb}`. They call the existing Ralph runner and `harness.db` (dashboard lifecycle and operator chat use the same functions). `gate` reads the HITL inbox and never sets `confirmed`. Contract: [`docs/harness/CAMPAIGN.md`](docs/harness/CAMPAIGN.md) and `GET /api/campaign/grammar`.

### Headless CI

`vf ci --target PATH` runs init → Ralph → render unattended and exits with an **outcome** code (0 pass, 1 threshold met, 2 infra/integrity), separate from the Ralph protocol codes. `--max-cost-usd` / `--max-time` are advisory (stop leasing; in-flight tasks may overrun). `--fail-on-state needs_human` fails the job for **review**, not proof; CI never sets `confirmed`. PR mode: `--diff merge-base..head`. SARIF (confirmed + needs_human) goes to `--output-dir`. Contract and example GitHub workflow: [`docs/harness/CI.md`](docs/harness/CI.md).

### Steer a live campaign

1. Start Ralph from the mission bar.
2. **Explorer**: open a file, optionally select lines, pick a hunt class, add notes, **Enqueue hunt**.
3. **Hunts**: plan area×skill batches, or click residual cells (shallow/aborted/none) → re-queue with notes.
4. **Report**: open a finding → **Open Evidence**; **Develop POC** opens a **workshop modal** (not a mode tab) — hub is `evidence/<pack>/poc_develop.md`; optional Ralph `develop_poc` writes **runnable** PoC code (not a narrative rewrite); **Run in harness** queues a sandbox one-shot `validate_poc` (microVM or gVisor only; writes `poc_run.json`; does not confirm); **Iterate in sandbox** keeps that guest for rewrite/re-run cycles (default 5, 15-minute TTL, both in Settings) and writes `poc_session.json` without confirming; **Export validation job** builds a handoff zip; **Accept / Reject / Needs review** with optional notes. None of these auto-prove exploitability. Opt-in **Suggested owners** (blame on cited lines, file/module authors, CODEOWNERS; read-only git) show in finding detail and exports, pseudonymised in exports by default — [`docs/harness/OWNERS.md`](docs/harness/OWNERS.md). New audit can opt in to the same one-shot as a validation-phase step (**Sandbox PoC one-shot**).

CLI handoff / harness:

```bash
vf export --run-dir runs/<target_id>/run-001 --format sarif --include-needs-human --out findings.sarif
vf export-validation-job --run-dir runs/<target_id>/run-001 --finding-id 3
vf validate-poc --run-dir runs/<target_id>/run-001 --finding-id 3 --execute
```

Keyboard: `e` focuses Explorer.

## Package layout (maintainers)

```
vulnforge/
  operator_chat/ # Home + run AI co-pilot (tools, confirm, sessions)
  agent_runtime/ # Strands tool-loop (hunt, recon, develop_poc, operator chat)
  control/       # exit codes, ops (Hunts requeue / selection hunt)
  ci/            # vf ci headless mode: outcome codes, budgets, thresholds
  findings/      # stable_key + near-dup merge + suggested owners (not a stage)
  tracking/      # external issue sinks (GitHub; Jira/Linear later) — confirm-gated
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

**Import review.** Imported profiles get mechanical checks (`hunt_profiles/review.py`) and, if you opt in, an LLM review. Verdicts are PASS, REVIEW, BLOCK or INCOMPLETE, and the LLM can only make a verdict stricter. Imported profiles start inactive. Activating a REVIEW profile needs confirmation. BLOCK and INCOMPLETE need an override with a reason, logged to `config/hunt_profiles/review_log.jsonl`. A profile that has not cleared review never reaches a prompt. Editing its content re-runs the review. See [`docs/system/PROFILE_REVIEW.md`](docs/system/PROFILE_REVIEW.md).

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
- **Track** (GitHub Issues, `vulnforge/tracking/`) is outward-facing: dashboard preview → explicit Publish, or chat Confirm. `confirmed` only unless opted in per publish. Ralph never publishes. See [`docs/harness/TRACKING.md`](docs/harness/TRACKING.md).
- HITL responses are durable and re-readable. A missing answer is unanswered. See [`docs/harness/validate/HITL.md`](docs/harness/validate/HITL.md).
- The operator **security policy** (Mission → Policy, `vf policy`) only narrows scope and demotes: exclusions → `rejected_mech` with the rule cited and shown in the Report, rubric caps `severity_claim`. It never promotes or confirms. Report → Reject → **Promote to policy** drafts an exclusion / out-of-scope rule from the reject; it is stored only on an explicit Save, with provenance (finding id + HITL response) the harness stamps and a manual edit cannot forge. See [`docs/harness/validate/POLICY.md`](docs/harness/validate/POLICY.md).
