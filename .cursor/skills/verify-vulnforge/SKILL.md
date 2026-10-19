---
name: verify-vulnforge
description: Drive VulnForge through the vf CLI, the dashboard HTTP API, and the PoC harness. Use for /verify-vulnforge, "verify the gate", or proof of mechanical validation, disprove, Accept, validate_poc, canary evidence, or the source-to-sink path contract.
---

# Verify VulnForge

Drive `vf`, the dashboard HTTP API, and the PoC harness. Do not drive the GUI. Do not treat Ralph or a live model call as the target.

Read [features/README.md](features/README.md), then the matching feature file. Prove one mapped feature end to end. `GET /api/health` is a doctor check. It is not the proof.

## Launch

Work from the repo root. Create `.venv` if `.venv/bin/vf` is missing.

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -e ".[dev]"
```

Start an isolated dashboard so the HTTP API has a disposable runs root. Never use the operator `runs/` tree. Never attach to a dashboard you did not start.

```bash
.cursor/skills/verify-vulnforge/scripts/vf-verify launch
```

Ready when stdout prints `url=` and `pid=`, the log contains `vulnforge dashboard -> http://127.0.0.1:<port>`, and `GET /api/health` returns JSON with `"ok": true` plus `runs_root` and `project_root`. Default product port is 8787. This helper picks a free high port starting at 18787.

Equivalent raw command if you record pid, port, and runs-root yourself:

```bash
.venv/bin/vf dashboard --host 127.0.0.1 --port <port> --runs-root /tmp/vf-verify-$RUN_ID/runs
```

Instance state lives under `/tmp/vf-verify-$RUN_ID/`. That directory holds the pid, the log, and the disposable runs tree. Export the values:

```bash
eval "$(.cursor/skills/verify-vulnforge/scripts/vf-verify env)"
```

## Doctor

Run this first whenever anything looks off.

```bash
.cursor/skills/verify-vulnforge/scripts/vf-verify doctor --write
```

Pass only if `doctor --write` prints `"ok": true`. The helper requires all of these:

- Recorded pid is alive and its cmdline contains `dashboard`.
- `GET $VF_VERIFY_URL/api/health` is `ok: true` and `runs_root` matches the recorded directory.
- `project_root` matches this repo.
- `GET $VF_VERIFY_URL/api/runs` returns HTTP 200 and JSON with a `runs` array and a numeric `count`.

Refuse to drive on failure. Do not fall back to port 8787 or `pgrep`. Do not open a browser to decide health.

## Drive

Use the feature map. Stable HTTP paths and `vf` flags beat the GUI.

| Handle | Where |
| --- | --- |
| `GET /api/health` | Ready check |
| `GET /api/runs` | Fleet list for this runs root |
| `GET /api/runs/{target_id}/{run_id}` | Run snapshot, tasks, finding bodies |
| `GET /api/runs/{target_id}/{run_id}/hitl/inbox` | Awaiting-review packets, including `pending_llm` |
| `POST /api/runs/{target_id}/{run_id}/findings/{id}/review` | Accept (`confirm`) or Reject (`reject`) |
| `POST /api/runs/{target_id}/{run_id}/findings/{id}/validate-poc` | Enqueue harness one-shot |
| `vf init`, `vf status`, `vf apply-candidate`, `vf run-once` | CLI run and mechanical gate |
| `vf hitl inbox`, `vf hitl show`, `vf hitl respond` | Durable review inbox |
| `vf validate-poc` | Enqueue or `--execute` the harness |

CLI shape:

```bash
.venv/bin/vf init --target fixtures/toy_sqli --runs-root "$VF_VERIFY_RUNS_ROOT" --strategy file_by_file --no-enqueue-hunts
.venv/bin/vf status --run-dir "$VF_VERIFY_RUNS_ROOT"/<target_id>/<run_id>
.venv/bin/vf apply-candidate --run-dir <run-dir> --file <candidate.json>
.venv/bin/vf run-once --run-dir <run-dir>
.venv/bin/vf hitl inbox --run-dir <run-dir>
.venv/bin/vf validate-poc --run-dir <run-dir> --finding-id <id>
```

`vf init` prints the run directory and exits 0. It does not start Ralph. `--strategy file_by_file --no-enqueue-hunts` creates the run with an empty queue so the next `run-once` is the task you just enqueued.

Do not run a second `run-once` after mechanical validation while a `validate_llm` task is queued. That task calls a model. Do not pass `--referee` on `validate-poc`. Do not set `stages.validate_llm` false to make Accept succeed. Do not click through the dashboard.

## Evidence

Write proof under `.cursor/skills/verify-vulnforge/artifacts/$VF_VERIFY_RUN_ID/`. Cleanup must not delete that directory.

Capture the action and the resulting state.

| Kind | Capture |
| --- | --- |
| Launch or doctor | helper stdout, `health.json`, `doctor.json` from `doctor --write` |
| CLI | command, stdout, stderr, exit code, and a second read via `vf status` or `GET /api/runs/{target_id}/{run_id}` |
| API | method, path, request JSON, status code, response body |
| Harness | `evidence/<pack>/poc_run.json` when a PoC run wrote one, plus the finding `state` after the run |
| Gate | finding `state`, `validation_mech.pending_llm`, and the review response |

Proof standards:

- Exercise the operator path. `vf init`, `vf apply-candidate`, `vf run-once`, `vf hitl`, and the review API are real paths. A direct row insert is not.
- Side effects live on disk under `$VF_VERIFY_RUNS_ROOT/<target_id>/<run_id>/`. Read `harness.db` through `vf status` or the run API, and read `evidence/` files before cleanup.
- Record the feature id and entry point on the artifact. Use the filename or a one-line `meta.txt`.
- A feature that states a fixed contract fails when the observed body does not meet that contract. Do not rewrite the feature to match a weaker result.

## Cleanup

Stop only the instance you started.

```bash
.cursor/skills/verify-vulnforge/scripts/vf-verify stop
```

The helper SIGTERMs the recorded process group, then SIGKILLs if needed, then deletes `/tmp/vf-verify-$RUN_ID/`. It does not delete artifacts. It does not kill by process name. It does not touch port 8787 unless `instance.json` says this run owns that port.

After stop, confirm `GET $VF_VERIFY_URL/api/health` fails and the artifacts directory still exists.

Leave `.venv` in place. It is gitignored.

## Helpers

Executable: `.cursor/skills/verify-vulnforge/scripts/vf-verify`

```bash
.cursor/skills/verify-vulnforge/scripts/vf-verify launch
.cursor/skills/verify-vulnforge/scripts/vf-verify doctor --write
.cursor/skills/verify-vulnforge/scripts/vf-verify env
.cursor/skills/verify-vulnforge/scripts/vf-verify instance
.cursor/skills/verify-vulnforge/scripts/vf-verify stop
```

`launch` records pid, port, url, and runs-root under `/tmp/vf-verify-$RUN_ID/instance.json` and points `/tmp/vf-verify-latest` at that id. `doctor` and `stop` read that record, or `VF_VERIFY_RUN_ID` when set. `env` prints `export VF_VERIFY_*` lines.

Keep the map honest with `/maintain-verification-skill` when the gate chain, `validate_poc`, canary evidence, or the path contract change.
