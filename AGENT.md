# AGENT.md — using and extending VulnForge

## What this system is

**VulnForge** runs a durable security-audit loop against a **read-only target tree**:

1. **init** — snapshot inventory, create `harness.db`, enqueue `recon`
2. **recon** (LLM) — map architecture; enqueue **hunt** tasks. When a map already exists, each recon **merges** (LLM merge with mechanical fallback) instead of blank-overwriting; Mission **History** can view/restore prior revisions.
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

**Home** (`/`): all runs + **Tool gaps** (`/tool-gaps`) + **Dev dashboard** (`/dev`, hunt skills).

### Steer a live campaign

1. Start Ralph from the mission bar.
2. **Explorer**: open a file, optionally select lines, pick a hunt class, add notes, **Enqueue hunt**.
3. **Coverage**: click residual cells (shallow/aborted/none) → re-queue with notes.
4. **Report**: open a finding → **Open Evidence**; **Develop POC** opens a **workshop modal** (not a mode tab) — hub is `evidence/<pack>/poc_develop.md`; optional Ralph `develop_poc` writes **runnable** PoC code (not a narrative rewrite); **Accept / Reject / Needs review** with optional notes. None of these auto-prove exploitability.

Keyboard: `e` focuses Explorer.

## Package layout (maintainers)

```
vulnforge/
  control/       # exit codes, ops (coverage/selection hunt)
  findings/      # stable_key + near-dup merge (not a stage)
  hunt_profiles/ # operator hunt skills collection (seed + CRUD + import/export)
  stages/        # recon, hunt, validate_mech, render, …
  tools/         # FS jail, file_inventory, grep, evidence
  llm/           # (or llm.py) client + FakeLLM
  ui/            # FastAPI + research cockpit
  cli.py         # thin argparse → control plane
  db.py          # SQLite + RunLock
```

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

**Full offline guide:** [`toolgen.md`](toolgen.md) — use when adding or extending agent tools with a local/offline model (or any agent). It is the checklist of record for wire-up, safety, tests, and a pasteable prompt.

**Dev dashboard:** Home → **Open Dev** → **Tools** tab lists integrated tools (description + parameters), manages AI **drafts**, and walks gap → prompts → generate → `validate_tool` → integrate. Hunt skills can set an optional **Approved tools** allowlist. Validation: `python scripts/validate_tool.py config/tool_drafts/<id>`.

**When to open it**

- Tool-gap report suggests a missing capability (`vf tool-gaps`, dashboard **Tool gaps**)
- Extending `grep` / `file_inventory` / etc. with new args
- Adding a brand-new `code_static` tool name

**Ornith + AI generate (not FakeLLM)**

1. LM Studio (or compatible) with Ornith loaded; Settings → **Optimize AI** → Save (`ornith-1.0-35b@4bit` style id, high `max_tokens`).
2. Dev → **Tools** → **Generate tool…** (or `python scripts/live_toolgen_smoke.py`).
3. Offline tests use FakeLLM / hand-seeded drafts; live path:

```bash
VF_LIVE=1 pytest tests/test_live_ornith.py tests/test_live_toolgen.py -v -s
```

Integrate **apply** mutates package source — dry-run first. Toolgen JSON success ≠ recon tool-call readiness.

**Wire-up order** (details + skeleton in `toolgen.md`)

| Step | Where |
|------|--------|
| Implement | `vulnforge/tools/<module>.py` → `{"ok": True/False, ...}` |
| Dispatch | `vulnforge/tools/__init__.py` → `build_tool_handler` (+ optional aliases) |
| Allowlist | `vulnforge/profiles/code_static.py` → `allowed_tools()` |
| LLM schema | `vulnforge/packet.py` → `tool_schemas_for` |
| Caps (optional) | `config/default.yaml` → `tools.*` |
| Docs | `PROTOCOL.md` tool list |
| Tests | `tests/test_tools.py`, known-tools in `tests/test_tool_gaps.py` |

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

## Honesty rules

- Target tree is **read-only** for agents.
- Evidence only under `evidence/`.
- `project/*` is projection, not authority.
- Do not treat same-model `validate_llm` as strong proof.
- Automation never sets `confirmed`; only human review does.
