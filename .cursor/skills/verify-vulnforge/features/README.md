# VulnForge verification map

This directory is the maintained source for verifying operator-facing VulnForge behavior. Read this index before driving the app, then use the matching feature file as the recipe.

## Baseline preconditions

- Launch with `.cursor/skills/verify-vulnforge/scripts/vf-verify launch`.
- Put the disposable runs tree at `/tmp/vf-verify-$RUN_ID/runs`. Never point `--runs-root` at the operator `runs/` directory.
- `eval "$(.cursor/skills/verify-vulnforge/scripts/vf-verify env)"` and keep `$VF_VERIFY_URL` as the only dashboard you open.
- Run `vf-verify doctor --write` and require `ok: true`, matching `runs_root`, and `data-page="home"`.
- Seed runs only with `vf init` against `fixtures/toy_sqli` (or another fixture) and that same `--runs-root`.
- Never drive an instance that this verification run did not start.
- Do not start Ralph. Do not call a live LLM.

## Driving conventions

- Start every recipe from the baseline state unless its preconditions say otherwise.
- Prefer ids, `data-page`, `data-nav-id`, `data-mode-panel`, and `data-dev-tab` over CSS position.
- Treat every command as literal. Keep quoted names and flags unchanged.
- Run browser actions against `$VF_VERIFY_URL`. First navigation is `new_tab(url)` unless a tab is already on that host and port. Keep one tab. Do not open a second tab on the same URL.
- Run terminal actions with `$VF_VERIFY_VF` (the venv `vf`) and `--runs-root "$VF_VERIFY_RUNS_ROOT"`.
- Restore nothing on disk except by `vf-verify stop`. Do not remove proof artifacts during cleanup.

## Proof and skip reporting

- Capture the user action and the resulting state, not only the final screen.
- UI proof includes a screenshot and a DOM or ARIA snapshot with VulnForge identity visible (`data-page`, heading, run id).
- CLI proof includes the command, stdout, stderr, and exit code.
- Mutation proof includes a read-only second view (`vf status` or `GET /api/runs`) plus the files under the new run directory.
- Record the feature ID and entry point used with every artifact.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.
- HTTP GET of HTML may back a doctor check. It does not replace a browser drive when a browser exists.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with vf-verify` starts with `Preconditions:` and uses labeled bullets that pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only user paths, stable handles, required state, commands, and observable proof.

## Features

- [Home fleet](./home-fleet.md) covers the run list, search, New audit, dock icons, and the Ask bubble.
- [Run workspace](./run-workspace.md) covers the icon rail, mode panels, Explorer shortcut, run switch, and footer Settings/Dev/Tool gaps links.
- [CLI init and status](./cli-init-status.md) covers `vf init`, `vf status`, and `vf --help`.
- [Settings](./settings.md) covers the Settings page fields and read-only API check.
- [Dev dashboard](./dev-dashboard.md) covers hunt skills, collection tabs, and the read-only skill list.
