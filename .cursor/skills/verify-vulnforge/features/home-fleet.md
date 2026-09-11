# Home fleet

Home is the run list. Search and New live in the list column. Settings, Dev, and Tool gaps are dock icons. Ask is the `#ai-fab` bubble, not a card.

## Sub-features

- `home-empty` shows the empty fleet copy when no runs exist yet.
- `home-list` renders a run row after `vf init` (or New audit) writes a run under the disposable root.
- `home-search` filters rows by target id, run id, or path. A miss is `No runs match.` plus Clear when a query is set.
- `home-open` follows a run row into `/runs/{target_id}/{run_id}`.
- `home-new-audit` opens the New audit dialog. Do not submit it with Start Ralph checked.
- `home-dock` reaches Settings, Dev, and Tool gaps from the list-column icons.
- `home-ask` opens the fleet Ask sheet from `#ai-fab`.

## How to get to it (user POV)

- Open `$VF_VERIFY_URL/`.
- Choose the rail Home link from a run workspace.
- Choose **New** (`#btn-new-run`).
- Type in **Search runs** (`#home-search`).
- Choose a run row (`a.run-row`) to open that workspace.
- Choose **Settings**, **Dev**, or **Tool gaps** in the dock.
- Choose **Ask** (`#ai-fab`).

## Driving it with vf-verify

Preconditions:

- `vf-verify doctor` reports `ok: true` for this instance.
- `$VF_VERIFY_RUNS_ROOT` is empty or contains only runs this recipe created.
- Browser, if present, is on `$VF_VERIFY_URL`, not port 8787.

- **Empty fleet.** Open Home before any init. Run `new_tab("$VF_VERIFY_URL/")`. `body` has `data-page="home"`. `#run-list` contains `No runs yet`. There is no `#btn-open-ai-chat` and no `.home-cta-row`. Ask is `#ai-fab`. Save `GET /api/runs` as `api-runs-empty.json` with `count` 0. The HTML shell from `GET /` does not include run cards. Those are filled by JS.
- **CLI seed.** Create a run the operator way. Run `$VF_VERIFY_VF init --target fixtures/toy_sqli --runs-root "$VF_VERIFY_RUNS_ROOT" --no-enqueue-hunts`. Exit code `0`. Stdout is the new run directory `.../<target_id>/run-001`.
- **API list.** Confirm the fleet JSON. Run `GET $VF_VERIFY_URL/api/runs`. `count` is at least `1`. A `runs[]` object has that `target_id`, `run_id`, and `target_path` ending in `fixtures/toy_sqli`. Save the body as `api-runs.json`.
- **Listed row.** Reload Home. Run `new_tab` only if no Home tab exists, otherwise reload the same tab. `#run-list a.run-row` href is `/runs/<target_id>/<run_id>` and the title is `<target_id> / <run_id>`. Screenshot `home-list.png`.
- **Search.** Type the target id into `#home-search`. The matching `a.run-row` stays. A nonsense query shows `No runs match.` and a **Clear** button. Clear restores the row.
- **Open run.** Choose the matching `a.run-row`. The URL is `/runs/<target_id>/<run_id>` and `body` has `data-page="run"` and `data-run-key="<target_id>/<run_id>"`.
- **New audit (open only).** From Home, choose `#btn-new-run`. `#init-modal` has class `open` and heading `New audit`. Choose `#init-cancel`. Do not submit.
- **Dock icons.** `#btn-settings` goes to `/settings`. `#btn-open-dev` goes to `/dev`. `#btn-open-tool-gaps` goes to `/tool-gaps`. Return to `/` after each hop.
- **Ask.** Choose `#ai-fab`. `#ai-sheet` is visible. `#ai-title` is `Across runs`. `#operator-chat-root` is inside `#ai-sheet`. Close with `#ai-close`. `/chat` still loads as a deep link (`GET /chat` is 200).
- **Proof.** Keep `init` stdout, `api-runs.json`, `home-list.png`, and a DOM snippet of `a.run-row`. The disk path `$VF_VERIFY_RUNS_ROOT/<target_id>/run-001/harness.db` exists.

## Gotchas

- Home cards load from `GET /api/runs` after paint. Wait for `a.run-row` or the empty copy. Do not assert on the `Loading...` placeholder.
- `vf init` without `--runs-root "$VF_VERIFY_RUNS_ROOT"` writes into the repo `runs/` tree. That run will not appear on this dashboard.
- Submitting New audit with **Start Ralph after create** starts the task loop. Cancel the dialog. Seed with `vf init` instead.
- `#btn-settings` is an `href="/settings"` link. The leftover settings modal on Home is not the operator path.
- Search matches `target_id`, `run_id`, `target_path`, `profile`, and `key` only.
- `target_id` is a slug of the target path. Another dashboard can list the same id. Prove the page URL host and port match `$VF_VERIFY_URL`. Do not open `127.0.0.1:8787` unless `instance.json` says this run owns that port.
- Ask is not a Home card. Do not look for **Open AI Chat**.
