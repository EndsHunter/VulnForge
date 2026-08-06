# VulnForge Protocol

Single control plane. CLI (`vf`), skill, Ralph, and the dashboard are clients of this contract.

## Run identity

- `target_id` — stable slug from target path
- `run_id` — unique id (e.g. `run-001`)
- Run directory: `runs/<target_id>/<run_id>/`

## Source of truth

| Path | Authority |
|------|-----------|
| `harness.db` | Tasks, findings, leases, coverage, prompt_pin |
| `evidence/<id>/` | PoC / artifacts |
| `target_manifest.json` | File hashes at init |
| `events.jsonl` | Append-only infra log |
| `project/*` | **Generated only** — never authoritative |
| `inbox/*.json` | Skill submissions pending apply |
| `run.lock` | Single writer |

## CLI surface

```
vf init --target PATH [--profile code_static] [--config PATH]
# source tree or single source file only (no PE / reverse engineering)
vf run-once [--run-dir PATH]
vf status [--run-dir PATH]
vf project [--run-dir PATH]
vf apply-candidate --file inbox/x.json [--run-dir PATH]
vf tool-gaps [--run-dir PATH | --runs-root PATH --all]
vf dashboard [--host HOST] [--port PORT]
vf delete-run --run-dir PATH --yes
```

Outer loop: `python scripts/ralph.py` — thin client of `run-once` (not a `vf` subcommand).

## `run-once` exit codes

| Code | Meaning | Ralph |
|------|---------|-------|
| 0 | Progress (task completed this turn) | continue; counts toward `--max-tasks` |
| 10 | Idle / complete | stop OK |
| 11 | Busy (lease cap / peer working; no task this turn) | continue; **does not** count toward `--max-tasks` |
| 20 | Infra failure (retryable) | backoff retry |
| 30 | Config / hard error | halt |

Ralph process codes: `0` clean STOP, `10` idle, `20` infra give-up, `30` config, `40` budget, `130` interrupt.

Multi-worker note: Settings **max concurrent agents** spawns N Ralph processes and sets
`run.max_leases_parallel=N`. Workers that cannot lease (cap full or only leased peers)
must return **11 (busy)**, not 0 — otherwise a waiting worker burns its progress budget
and exits while the other is mid-task. Ralph treats **11** as free for both
`--max-tasks` and `--max-iterations` so a second agent can wait through a long
recon without exiting mid-campaign.

## Task states

```
queued → leased → succeeded | failed_task | blocked | deadletter
queued | leased → paused → queued (resume) | leased (auto when last left)
queued | paused | leased → cancelled (operator remove / halt)
```

**Operator pause / halt (per task, not whole runner):**

| Action | From | Effect |
|--------|------|--------|
| **Pause** | `queued` or `leased` | Park as `paused`. If leased, free the lease slot and stop that run-once worker so the next queued task can start. Paused tasks are not leased while any `queued` work remains; when only paused work is left, `lease_next_task` picks them up. |
| **Resume** | `paused` | Back to `queued` (default priority: run next). |
| **Halt** | `queued`, `paused`, or `leased` | Terminal `cancelled`. If leased, stop the worker so the next queued can start. |

Thrash / empty / max_tool_rounds → `failed_task` (not infra).
Transport / model-list under `max_task_attempts` → requeue + exit 20; at cap → `deadletter` + exit 0.

## Concurrent agents

`run.max_leases_parallel` (Settings: **Max concurrent agents**) caps how many
tasks may be `leased` at once. Dashboard Start spawns that many Ralph workers.

- **N = 1** (default): exclusive `run.lock` for the whole `run-once` (single writer).
- **N > 1**: exclusive lock skipped; SQLite `BEGIN IMMEDIATE` + lease cap coordinates
  multi-process agents. Evidence packs are per-task; events.jsonl is best-effort concurrent append.

LM Studio / the local server must accept concurrent chat completions for N>1 to help.

## Finding states

```
candidate → rejected_mech | needs_human
needs_human → [validate_llm (default on): rejected_llm | needs_human]
needs_human | rejected_* | confirmed  ↔  human review (confirm | reject | reopen)
confirmed | rejected_human | rejected_mech | rejected_llm | superseded
```

**`needs_human`** = mechanical gates passed (schema, citations, evidence or justified
`no_poc`, non-vacuous threat model, cited files vs manifest), and dual disprove did
not kill the claim when `stages.validate_llm` is on (default). Not exploit proof.

**`confirmed`** = a human accepted the finding after review (optional notes/docs).
Automation never auto-confirms.

## Pipeline

```
init → recon → hunt × N → validate_mech → validate_llm (default on; set false to skip)
     → idle project projection
     → [optional tool_gaps on idle if run.auto_tool_gaps]
```

**Operator-only task kinds** (not the default auto loop):

- **`develop_poc`** — human-queued from Report → Develop POC; writes runnable PoC scripts under `evidence/<pack>/` plus hub `poc_develop.md`. Never sets `confirmed`.
- **`tool_gaps`** — mine transcripts for missing tool signals; also via `vf tool-gaps`.

## Tools (`code_static`)

Schemas live in `vulnforge/packet.py` → `tool_schemas_for` (OpenAI function tools; Dev dashboard **Tools** tab mirrors them).

| Tool | Stages | Role |
|------|--------|------|
| `list_dir` | recon, hunt, develop_poc | One directory level (not recursive) |
| `file_inventory` | recon, hunt, develop_poc | Recursive tree/list; prefer over many `list_dir` |
| `read_file` | recon, hunt, develop_poc | File or 1-based line range; target is read-only |
| `grep` | recon, hunt, develop_poc | Content regex; `extension`/`glob`/`files_only`/`match_path` |
| `note` | recon, hunt, develop_poc | wishlist / sibling_seed / codemap (does not finish task). Mechanical codemap is built at recon (`runs.codemap_json`); `note(kind=codemap)` only annotates high-value paths |
| `submit_architecture` | recon only | Finish recon architecture map (not findings; separate from mechanical codemap) |
| `submit_candidate` / `submit_none` | hunt only | Finish hunt (candidate is not confirmed) |
| `write_evidence` | hunt, develop_poc | Write under `evidence/` only |
| `list_hunt_profiles` / `request_hunt` | hunt | Spawn another profile hunt (does not finish this task) |

- **Paths** are always relative to the audit target root (or evidence pack for `write_evidence`). No shell, no target writes on `code_static`.
- **grep** — empty pattern + `extension`/`glob` lists files by path; prefer `file_inventory` for trees. On 0 hits, follow the response hint — do not repeat the same empty query.
- **develop_poc** — read tools + `write_evidence` only (no `submit_*`).
- **Scope:** source-code analysis only. PE / reverse-engineering profiles and `ghidra_*` tools are not part of the product.

## Operator guidance

Dashboard Explorer and Hunts modes (plus Mission operator brief) can enqueue focused hunts and requeue coverage cells without editing the DB by hand. Selection hunts use `POST .../hunts/from-selection`. Report **Develop POC** opens a workshop modal (not a mode tab) and may enqueue `develop_poc`.
