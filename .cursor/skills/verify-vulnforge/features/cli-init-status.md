# CLI init and status

`vf` creates an audit run against a read-only target tree, prints the run directory, and later summarizes that run. The dashboard lists whatever exists under the same `--runs-root`.

## Sub-features

- `cli-help` prints the `vf` command list.
- `cli-init` writes `runs/<target_id>/run-00N/` with `harness.db` and `target_manifest.json`.
- `cli-init-isolated` honors `--runs-root` so the verification dashboard can see the run.
- `cli-status` prints `run_dir`, `target`, `profile`, `tasks`, `findings`, and `has_work`.
- `cli-init-missing` exits non-zero when `--target` does not exist.

## How to get to it (user POV)

- Run `vf --help` in a terminal from the repo (venv `vf` on PATH).
- Run `vf init --target <path> --runs-root <dir>`.
- Run `vf status --run-dir <run-dir>`.
- Optional. Add `--no-enqueue-hunts` when you only need a listed run and will not start Ralph.

## Driving it with vf-verify

Preconditions:

- `.venv/bin/vf` exists (or `vf-verify launch` already created it).
- Target `fixtures/toy_sqli` exists.
- `--runs-root` is `$VF_VERIFY_RUNS_ROOT` when a dashboard is up. For CLI-only, pass a fresh directory under `/tmp/vf-verify-$RUN_ID/runs`.
- Do not run `vf run-once`, `scripts/ralph.py`, or `vf dashboard` without the helper.

- **Help.** Run `$VF_VERIFY_VF --help`. Exit code `0`. Stdout includes `init`, `status`, and `dashboard`.
- **Init.** Run `$VF_VERIFY_VF init --target fixtures/toy_sqli --runs-root "$VF_VERIFY_RUNS_ROOT" --no-enqueue-hunts`. Exit code `0`. The last stdout line is an absolute path `$VF_VERIFY_RUNS_ROOT/<target_id>/run-001`.
- **Files.** That directory contains `harness.db`, `target_manifest.json`, `evidence/`, `inbox/`, and `project/`. `target_id` starts with `toy_sqli-`.
- **Status.** Run `$VF_VERIFY_VF status --run-dir <that path>`. Exit code `0`. Stdout includes `run_dir:`, `target:` pointing at `fixtures/toy_sqli`, `profile: code_static`, and a `tasks:` line.
- **Dashboard sees it.** If the isolated dashboard is up, `GET $VF_VERIFY_URL/api/runs` lists the same `target_id` and `run_id`. Home shows `a.run-row` for it (see [Home fleet](./home-fleet.md)).
- **Missing target.** Run `$VF_VERIFY_VF init --target /tmp/vf-verify-does-not-exist --runs-root "$VF_VERIFY_RUNS_ROOT"`. Exit code is `30`. Stderr contains `target not found`.
- **Proof.** Save `init.stdout.txt`, `status.stdout.txt`, `help.stdout.txt`, and a listing of the run directory. Keep the run until Home proof is done, then leave it for `vf-verify stop` to delete with the instance dir.

## Gotchas

- `vf init` and `vf status` exit `0` on success (`EXIT_PROGRESS`). Treat that as success, not "still running".
- `vf status` may print a `validate_llm` note on stderr. Assert the stdout fields. Do not treat that stderr line as failure.
- A missing target exits `30` (`EXIT_CONFIG`). The stderr line starts with `target not found`.
- Omit `--runs-root` and `vf` writes `runs/` in the repo. The isolated dashboard will not list it. `stop` will not delete it.
- First run under a target is `run-001`. A second init becomes `run-002`.
- `target_id` is `{directory-name}-{8 hex chars}` of the resolved target path. Do not hard-code the hex. Read it from init stdout.
- `--no-enqueue-hunts` still creates the run and, for discovery, a recon task. It does not start Ralph. Default init also does not start Ralph. Only the dashboard **Start** button and New audit's **Start Ralph after create** do.
- Do not pass `--execute` to `validate-poc` in this map.
