# VulnForge verification map

This directory is the maintained source for verifying VulnForge through the `vf` CLI, the dashboard HTTP API, and the PoC harness. Read this index before driving, then use the matching feature file as the recipe.

## Baseline preconditions

- Launch with `.cursor/skills/verify-vulnforge/scripts/vf-verify launch`.
- Put the disposable runs tree at `/tmp/vf-verify-$RUN_ID/runs`. Never point `--runs-root` at the operator `runs/` directory.
- `eval "$(.cursor/skills/verify-vulnforge/scripts/vf-verify env)"` and keep `$VF_VERIFY_URL` as the only API origin.
- Run `vf-verify doctor --write` and require `ok: true`, matching `runs_root`, and `GET /api/runs` JSON.
- Seed runs with `vf init` against `fixtures/toy_sqli` and that same `--runs-root`.
- Never drive an instance that this verification run did not start.
- Do not start Ralph. Do not call a live model. Do not open the GUI.

## Driving conventions

- Start every recipe from the baseline state unless its preconditions say otherwise.
- Prefer `vf` subcommands and `/api/...` paths over the browser.
- Treat every command as literal. Keep quoted names and flags unchanged.
- Run terminal actions with `$VF_VERIFY_VF` and `--runs-root "$VF_VERIFY_RUNS_ROOT"` or `--run-dir` on the run this recipe created.
- Send API calls to `$VF_VERIFY_URL` only.
- Restore nothing on disk except by `vf-verify stop`. Do not remove proof artifacts during cleanup.
- A fixed contract in a feature is the pass bar. A weaker result the process prints today is a failed drive.

## Proof and skip reporting

- Capture the operator action and the resulting state, not only the final status line.
- CLI proof includes the command, stdout, stderr, and exit code.
- API proof includes the method, path, status code, and response body.
- Mutation proof includes a read-only second view (`vf status`, `vf hitl show`, or `GET /api/runs/{target_id}/{run_id}`) plus the files under the run directory.
- Record the feature ID and entry point used with every artifact.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.
- HTTP GET of HTML is not a drive.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the operator-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every operator entry point.
3. `Driving it with vf-verify` starts with `Preconditions:` and uses labeled bullets that pair each operator action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only operator paths, stable handles, required state, commands, and observable proof.

## Features

- [Gate chain](./gate-chain.md) covers mechanical validation, the disprove inconclusive rule, and Accept blocked while `pending_llm` is set.
- [Validate PoC](./validate-poc.md) covers `vf validate-poc` and the validate-poc API. The harness writes `poc_run.json` and does not confirm.
- [Canary evidence](./canary-evidence.md) covers the fixed canary contract for a harness signal.
- [Path contract](./path-contract.md) covers ordered source-to-sink nodes, `query_flows` agreement, and disprove pruning.
