---
name: verify-vulnforge
description: Drive VulnForge on the FastAPI research-cockpit dashboard and the vf CLI the way an operator does. Use for /verify-vulnforge, "verify in the app", "drive the cockpit", or UI/CLI proof of Home, the run workspace, Settings, Dev, or vf init and status.
---

# Verify VulnForge

Drive the operator cockpit and `vf`. Do not treat Ralph or live LLM hunts as the target.

Read [features/README.md](features/README.md), then the matching feature file. Prove one mapped feature end to end. HTTP GET of HTML is a doctor or ready check and a secondary assertion. A mapped UI feature still needs a browser drive when a browser exists.

## Launch

Work from the repo root. Create `.venv` if `.venv/bin/vf` is missing.

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -e ".[dev]"
```

Start an isolated dashboard. Never use the operator `runs/` tree. Never attach to a dashboard you did not start.

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
- `GET $VF_VERIFY_URL/` contains `data-page="home"`.
- `GET $VF_VERIFY_URL/settings` contains `data-page="settings"`.
- `GET $VF_VERIFY_URL/dev` contains `data-page="dev"`.

Refuse to drive on failure. Do not fall back to port 8787 or `pgrep`.

## Drive

Use the feature map. Stable handles beat CSS position.

| Handle | Where |
| --- | --- |
| `body[data-page="home"]` | Home |
| `#btn-new-run`, `#home-search`, `#run-list`, `a.run-row` | Home actions and run rows |
| `#btn-settings` `/settings`, `#btn-open-dev` `/dev`, `#btn-open-tool-gaps` `/tool-gaps` | Home dock icons |
| `#ai-fab`, `#ai-sheet`, `#operator-chat-root` | Ask bubble on Home and run |
| `body[data-page="run"]`, `[data-run-rail]`, `[data-nav-id]`, `[data-mode-panel]`, `#run-switch` | Run workspace |
| `body[data-page="settings"]`, `#settings-form`, `#settings-save` | Settings page |
| `body[data-page="dev"]`, `[data-dev-tab]`, `#dev-profiles-body` | Dev dashboard |

In a browser with browser-use or CDP, first navigation is `new_tab($VF_VERIFY_URL + path)`. Keep one tab. Click ids and `data-nav-id` values. Press `e` on a run page only when focus is not in an input.

CLI:

```bash
.venv/bin/vf init --target fixtures/toy_sqli --runs-root "$VF_VERIFY_RUNS_ROOT" --no-enqueue-hunts
.venv/bin/vf status --run-dir "$VF_VERIFY_RUNS_ROOT"/<target_id>/<run_id>
.venv/bin/vf --help
```

`vf init` prints the run directory and exits 0. It does not start Ralph. Use `--no-enqueue-hunts` when you only need a listed run.

Do not click **Start**, **Resume**, **Hard stop**, or **Delete run**. Do not submit **New audit** with **Start Ralph after create** checked. Do not click **Save settings**. Do not **Reseed**, **Import setup**, or toggle Active on Dev. Those writes leave this repo's `config/` and the operator collection.

## Evidence

Write proof under `.cursor/skills/verify-vulnforge/artifacts/$VF_VERIFY_RUN_ID/`. Cleanup must not delete that directory.

Capture the action and the resulting state.

| Kind | Capture |
| --- | --- |
| Launch or doctor | helper stdout, `health.json`, `doctor.json` from `doctor --write` |
| CLI | command, stdout, stderr, exit code, and a second read via `vf status` or `GET /api/runs` |
| UI | screenshot plus a DOM or ARIA snapshot that shows the id you clicked and the heading or run row that changed |
| Home list | `GET /api/runs` body and the visible `a.run-row` for that `target_id` |

Proof standards:

- Exercise the operator path. CLI init plus Home listing is a real path. Internal DB inserts are not.
- Side effects live on disk under `$VF_VERIFY_RUNS_ROOT/<target_id>/<run_id>/`. Read `harness.db` and `target_manifest.json`.
- Record the feature id and entry point on the artifact. Use the filename or a one-line `meta.txt`.

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

Keep the map honest with `/maintain-verification-skill` when Home, the run rail, Settings, Dev, or `vf init`/`status` change.
