# Run workspace

The run workspace is the research cockpit for one `target_id/run_id`. The left rail switches Mission, Hunts, Explorer, Report, Evidence, Tasks, and AI. Footer links leave the run for Dev and Settings. Develop POC is a Report modal, not a rail item.

## Sub-features

- `rail-primary` shows Mission, Hunts, Explorer, Report, Evidence, Tasks, AI as `[data-nav-id]` tabs.
- `rail-mode` swaps `[data-mode-panel]` and writes `#<mode>/<tab>` (Mission default `#mission/overview`).
- `rail-explorer-key` focuses Explorer when the operator presses `e` outside an input.
- `rail-footer` links Dev (`/dev`) and Settings (`/settings`).
- `rail-hash` honors `#hunts/hunts`, `#explorer/explorer`, `#report/report`, `#evidence/evidence`, `#audit/tasks`, `#ai/ai`.
- `rail-poc-modal` is out of scope unless a finding exists. Develop POC is not a mode tab.

## How to get to it (user POV)

- Choose a run row on Home.
- Open `$VF_VERIFY_URL/runs/{target_id}/{run_id}` directly.
- Choose a primary rail button (`[data-nav-id="mission"]` and siblings).
- Press `e` to jump to Explorer.
- Open a hash URL such as `/runs/{target_id}/{run_id}#explorer/explorer`.
- Choose footer **Dev** or **Settings**.

## Driving it with vf-verify

Preconditions:

- A run exists under `$VF_VERIFY_RUNS_ROOT` (see [CLI init and status](./cli-init-status.md) or [Home fleet](./home-fleet.md)).
- `vf-verify doctor` is `ok: true`.
- You will not click **Start**, **Resume**, **Hard stop**, or **Delete run**.

- **Open workspace.** Go to `$VF_VERIFY_URL/runs/<target_id>/<run_id>`. `body` has `data-page="run"`. `#run-title` contains `<target_id> / <run_id>`. `[data-run-rail]` is present.
- **Default mode.** With no hash, `[data-nav-id="mission"]` has `aria-selected="true"` and `[data-mode-panel="mission"]` has class `active`. Hash is `#mission/overview`.
- **Rail labels.** Query `[data-run-rail] [data-nav-id]`. Primary buttons are Mission, Hunts, Explorer, Report, Evidence, Tasks, AI. Footer anchors are Dev (`href="/dev"`) and Settings (`href="/settings"`). There is no Develop POC rail item.
- **Switch Hunts.** Click `[data-nav-id="hunts"]`. `[data-mode-panel="hunts"]` is `active`. Hash is `#hunts/hunts`. Heading text includes `Hunts`.
- **Switch Explorer.** Click `[data-nav-id="explorer"]` or press `e` while focus is not in an input. `[data-mode-panel="explorer"]` is `active`. Hash is `#explorer/explorer`.
- **Hash entry.** Open `/runs/<target_id>/<run_id>#report/report`. `[data-mode-panel="report"]` is `active` and `[data-nav-id="report"]` is selected.
- **Tasks alias.** Open `#audit/tasks` (or `#tasks/tasks`). The Tasks panel is active. The rail id is `audit` and the label is Tasks.
- **Footer Dev.** Click `[data-nav-id="dev"]`. The page is `/dev` with `data-page="dev"`. Use the browser back button or Home to return.
- **Proof.** Screenshot the rail with Mission selected (`rail-mission.png`) and Explorer selected (`rail-explorer.png`). Save a DOM dump of `[data-run-rail]`.

## Gotchas

- Tasks uses mode id `audit`. Assert `[data-nav-id="audit"]` and `[data-mode-panel="audit"]`, not `tasks`.
- `#coverage` still maps to Hunts. `#harness` maps to Mission. `#poc/<id>` opens Report plus the Develop POC modal. Do not treat those aliases as extra rail buttons.
- `e` types a character when an input or textarea is focused.
- **Start** on the mission bar launches Ralph. Leave it alone.
- HTML GET of `run.html` includes every `data-mode-panel` in the document. Only the `active` panel is the current mode. Prove that in a browser.
