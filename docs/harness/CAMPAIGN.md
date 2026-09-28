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

Hard stop. Writes `STOP`, kills the Ralph process tree, reclaims every leased task to `queued`, and records `runner_stop_hard`. The kill is tree-wide: Windows `taskkill /T`, and on Linux the Ralph process group created by `start_new_session` plus any descendant and the `run.lock` holder. That stops in-flight `vf run-once` instead of leaving it reparented under the user service manager. Mid-task progress may be lost; the next lease increments `attempt`. The run directory and findings stay. Resume clears `STOP` and starts Ralph again.

The return includes `lock_cleared` (`run.lock` is absent). `ok` is false when a live PID still holds `run.lock` after the kill.

### `pause`

Drain. Writes `STOP` and returns immediately. Ralph (`scripts/ralph.py`) checks `STOP` between iterations and exits after the current `vf run-once` finishes. Pause does not kill workers and does not call `reclaim_all_leased_tasks`, so a lease held by the live task is kept. Recorded as `runner_pause`. `killed` is false and `reclaimed_leases` is 0. Queued tasks stay queued.

While a Ralph pid is alive and `STOP` is present, `runner_status` is `pausing` (`draining: true`). After that pid exits, state is `paused`. Pause does not wait out the task timeout; the dashboard polls. With no live Ralph pid, writing `STOP` is enough for `paused`. The Mission card `status` is `paused` while `STOP` is present (the `runs.status` row stays the durable value).

### `resume`

Deletes `STOP`, reclaims stale leases only, and calls `start_run` when Ralph is not already alive. Body knobs match `start`.

If no Ralph worker is alive and a live PID still holds `run.lock`, resume kills that holder (same tree kill as hard stop). When the holder survives, resume returns not ok, leaves `STOP` in place, and does not spawn Ralph — so the new loop does not exit `EXIT_INFRA` 20 (`run locked`). A Ralph worker that is still alive is not killed; resume only clears `STOP`.

### `status`

Read. Returns the operator-chat `get_status` payload (`card`, `runner`, `codemap`) plus `harness`: task counts, finding counts, `has_work`, and `leased` from `harness.db`. Does not take a lease.

### `findings`

Read. Query or JSON: `state`, `class`, `q`, `limit` (default 40, chat cap 80). Rows match chat `list_findings` (id, state, title, class, evidence, severity). Does not change finding state.

### `gate`

Read of the human gate. `needs_human` is the count of findings that passed mechanical gates. `inbox` is the awaiting-review HITL list (`vulnforge/hitl-report@1`), including explicit gate packets. `open` is true when that inbox is non-empty or `needs_human` > 0. `confirms` is always false.

Accept and reject stay on Report review or `vf hitl respond`. A gate read refreshes the HITL projection the same way `GET .../hitl/inbox` does, and it does not set `confirmed`.

## Honesty

`needs_human` means mechanical gates passed. `confirmed` is human-only. Neither is exploit proof. This grammar does not set `confirmed`.
