# Campaign control grammar

Operators drive one campaign with seven verbs. Each verb is a client of the existing Ralph runner (`scripts/ralph.py` → `vf run-once`) or of durable harness state (`harness.db`, HITL inbox). Dashboard Start / Pause / Resume / Stop and operator chat call the same functions.

Schema: `vulnforge.campaign@1`. Engine: `ralph`.

| Call | Returns |
|------|---------|
| `GET /api/campaign/grammar` | Static map (no run directory) |
| `GET /api/runs/{target_id}/{run_id}/campaign` | That map plus a live `status` read |

Verb routes live under `/api/runs/{target_id}/{run_id}/campaign/{verb}`.

## Verbs

| Verb | HTTP | Wires | Legacy route | Chat tool |
|------|------|-------|--------------|-----------|
| `start` | POST `.../campaign/start` | `start_run` | POST `.../start` | `start_run` |
| `stop` | POST `.../campaign/stop` | `stop_run_hard` | POST `.../stop` | `hard_stop_run` |
| `pause` | POST `.../campaign/pause` | `pause_run` | POST `.../pause` | `pause_run` |
| `resume` | POST `.../campaign/resume` | `resume_run` | POST `.../resume` | `resume_run` |
| `status` | GET `.../campaign/status` | `get_status_impl` | GET `.../runner` | `get_status` |
| `findings` | GET `.../campaign/findings` | `list_findings_impl` | operator chat `list_findings` | `list_findings` |
| `gate` | GET `.../campaign/gate` | `list_inbox` | GET `.../hitl/inbox` | — |

POST is accepted for `status`, `findings`, and `gate` (still a read). GET on `start`, `stop`, `pause`, or `resume` returns 405.

Module: `vulnforge/control/campaign.py`.

## Semantics

### `start`

Body matches dashboard `ControlBody`: `max_tasks` (null = run until idle / STOP), `workers` (capped by Settings **max concurrent agents**), `task_timeout`, `max_iterations`, `max_wall_seconds`, optional `loop_profile_id` (dev / smoke profiles only).

Clears `STOP` and spawns Ralph. Settings `max_tasks` stays the hunt-enqueue planning cap and is not copied onto Ralph. Already running → 409.

### `stop`

Writes `STOP`, kills Ralph workers, reclaims leased tasks to `queued`, and records `runner_stop_hard`. The run directory and findings stay. Resume clears `STOP` and starts Ralph again.

### `pause`

Same worker stop and lease reclaim as stop, recorded as `runner_pause`. Queued tasks stay queued. With `STOP` present and no live Ralph pid, runner state is `paused`.

### `resume`

Deletes `STOP`, reclaims stale leases only, and calls `start_run` when Ralph is not already alive. Body knobs match `start`.

### `status`

Read. Returns the operator-chat `get_status` payload (`card`, `runner`, `codemap`) plus `harness`: task counts, finding counts, `has_work`, and `leased` from `harness.db`. Does not take a lease.

### `findings`

Read. Query or JSON: `state`, `class`, `q`, `limit` (default 40, chat cap 80). Rows match chat `list_findings` (id, state, title, class, evidence, severity). Does not change finding state.

### `gate`

Read of the human gate. `needs_human` is the count of findings that passed mechanical gates. `inbox` is the awaiting-review HITL list (`vulnforge/hitl-report@1`), including explicit gate packets. `open` is true when that inbox is non-empty or `needs_human` > 0. `confirms` is always false.

Accept and reject stay on Report review or `vf hitl respond`. A gate read refreshes the HITL projection the same way `GET .../hitl/inbox` does, and it does not set `confirmed`.

## Honesty

`needs_human` means mechanical gates passed. `confirmed` is human-only. Neither is exploit proof. This grammar does not set `confirmed`.
