# Run workspace

The run workspace is the research cockpit for one `target_id/run_id`. A 48px icon rail leads with Home, then Mission, Hunts, Explorer, and Report. Footer links leave the run for Settings, Dev, and Tool gaps. Ask is the `#ai-fab` bubble. Evidence is a Report row action. Tasks stay as a hash panel. Develop POC is a Report modal, not a rail item.

## Sub-features

- `rail-primary` shows Mission, Hunts, Explorer, Report as `[data-nav-id]` tabs. Home is a rail href.
- `rail-mode` swaps `[data-mode-panel]` and writes `#<mode>/<tab>` (Mission default `#mission/overview`).
- `rail-explorer-key` focuses Explorer when the operator presses `e` outside an input.
- `rail-footer` links Settings (`/settings`), Dev (`/dev`), and Tool gaps (`/tool-gaps`).
- `rail-hash` honors `#hunts/hunts`, `#explorer/explorer`, `#report/report`. `#evidence/evidence` lands on Report. `#audit/tasks` still shows the audit panel. `#ai/ai` opens the Ask sheet without hiding the exclusive panel.
- `rail-strip` hops runs via `#run-switch` without going Home. Start/Pause stay on the strip. Refresh and Delete live in `···`.
- `rail-poc-modal` is out of scope unless a finding exists. Develop POC is not a mode tab.

## How to get to it (user POV)

- Choose a run row on Home.
- Open `$VF_VERIFY_URL/runs/{target_id}/{run_id}` directly.
- Choose a primary rail button (`[data-nav-id="mission"]` and siblings).
- Choose the rail Home link to return to `/`.
- Press `e` to jump to Explorer.
- Open a hash URL such as `/runs/{target_id}/{run_id}#explorer/explorer`.
- Choose footer **Settings**, **Dev**, or **Tool gaps**.
- Choose **Ask** (`#ai-fab`) or follow `#ai/ai`.
- Choose **Open Evidence** on a Report finding row.

## Driving it with vf-verify

Preconditions:

- A run exists under `$VF_VERIFY_RUNS_ROOT` (see [CLI init and status](./cli-init-status.md) or [Home fleet](./home-fleet.md)).
- `vf-verify doctor` is `ok: true`.
- You will not click **Start**, **Resume**, **Hard stop**, or **Delete run**.

- **Open workspace.** Go to `$VF_VERIFY_URL/runs/<target_id>/<run_id>`. `body` has `data-page="run"`. `#run-switch` contains `<target_id> / <run_id>`. `[data-run-rail]` is present. There is no second Home button in the header and no `#trust-line`.
- **Default mode.** With no hash, `[data-nav-id="mission"]` has `aria-selected="true"` and `[data-mode-panel="mission"]` has class `active`. Hash is `#mission/overview`.
- **Rail labels.** Query `[data-run-rail] [data-nav-id]`. Primary buttons are Mission, Hunts, Explorer, Report. Home is `href="/"`. Footer anchors are Settings (`href="/settings"`), Dev (`href="/dev"`), and Tool gaps (`href="/tool-gaps"`). There is no Evidence, Tasks, AI, or Develop POC rail item.
- **Switch Hunts.** Click `[data-nav-id="hunts"]`. `[data-mode-panel="hunts"]` is `active`. Hash is `#hunts/hunts`. Heading text includes `Hunts`.
- **Switch Explorer.** Click `[data-nav-id="explorer"]` or press `e` while focus is not in an input. `[data-mode-panel="explorer"]` is `active`. Hash is `#explorer/explorer`.
- **Hash entry.** Open `/runs/<target_id>/<run_id>#report/report`. `[data-mode-panel="report"]` is `active` and `[data-nav-id="report"]` is selected.
- **Evidence hash.** Open `#evidence/evidence`. The first paint is Report (`[data-mode-panel="report"]` is `active`). Evidence packs stay available from a Report row action. Do not expect `[data-nav-id="evidence"]` on the rail.
- **Tasks hash.** Open `#audit/tasks` (or `#tasks/tasks`). The Tasks panel is active (`[data-mode-panel="audit"]`). The rail does not select a Tasks item.
- **Ask overlay.** Open `#ai/ai` or click `#ai-fab`. `#ai-sheet` is visible. `#ai-title` is `<target_id> / <run_id>`. Mission or Report stays the exclusive panel (`[data-mode-panel="mission"]` or the prior mode still `active`). Rail `aria-selected` does not move to AI.
- **Footer Dev.** Click `[data-nav-id="dev"]`. The page is `/dev` with `data-page="dev"`. Use the browser back button or Home to return.
- **Proof.** Screenshot the rail with Mission selected (`rail-mission.png`) and Explorer selected (`rail-explorer.png`). Save a DOM dump of `[data-run-rail]`.

## Gotchas

- Tasks uses mode id `audit`. Assert `[data-mode-panel="audit"]`, not `tasks`. Do not look for `[data-nav-id="audit"]` on the rail.
- `#coverage` still maps to Hunts. `#harness` maps to Mission. `#poc/<id>` opens Report plus the Develop POC modal. Do not treat those aliases as extra rail buttons.
- `#evidence/evidence` is a Report landing, not Evidence mode. `goEvidence` from a Report row can still show the evidence panel. That panel stays in the DOM.
- `e` types a character when an input or textarea is focused.
- **Start** on the strip launches Ralph. Leave it alone.
- HTML GET of `run.html` includes every `data-mode-panel` in the document. Only the `active` panel is the current exclusive mode. Ask overlay does not toggle those classes.
- `/chat` remains a deep link. The operator path is the Ask bubble.
