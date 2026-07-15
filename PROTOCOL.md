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
```

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
needs_human → [optional validate_llm: rejected_llm | needs_human]
needs_human | rejected_* | confirmed  ↔  human review (confirm | reject | reopen)
confirmed | rejected_human | rejected_mech | rejected_llm | superseded
```

**`needs_human`** = mechanical gates passed (schema, citations, evidence or justified
`no_poc`, non-vacuous threat model, cited files vs manifest). Not exploit proof.

**`confirmed`** = a human accepted the finding after review (optional notes/docs).
Automation never auto-confirms.

## Pipeline

```
init → recon → hunt × N → validate_mech → [optional validate_llm]
     → idle project projection
     → [optional tool_gaps on idle if run.auto_tool_gaps]
```

**Operator-only task kinds** (not the default auto loop):

- **`develop_poc`** — human-queued from Report → Develop POC; writes runnable PoC scripts under `evidence/<pack>/` plus hub `poc_develop.md`. Never sets `confirmed`.
- **`tool_gaps`** — mine transcripts for missing tool signals; also via `vf tool-gaps`.

## Tools (`code_static`)

`list_dir` | `file_inventory` | `read_file` | `grep` | `write_evidence` | `submit_candidate` | `submit_none` | `note` | `submit_architecture` (recon)

- **file_inventory** — recursive tree / file list (optional `extension` / `glob`); prefer over many `list_dir` rounds.
- **grep** — content regex; `extension`/`glob` file-type filter; `files_only` (paths only); `match_path` (filename search); empty pattern + extension lists files of that type.
- **develop_poc** stage uses read tools + `write_evidence` only (no `submit_*`).

No unrestricted shell on the default profile.

## Operator guidance

Dashboard Explorer and Coverage modes (plus Mission operator brief) can enqueue focused hunts and requeue coverage cells without editing the DB by hand. Selection hunts use `POST .../hunts/from-selection`. Report **Develop POC** opens a workshop modal (not a mode tab) and may enqueue `develop_poc`.
