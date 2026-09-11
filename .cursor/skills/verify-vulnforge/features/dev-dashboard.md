# Dev dashboard

Dev is the operator collection editor for hunt skills, the skill generator, recon agents, and tool drafts. Home **Open Dev** and the run rail footer **Dev** both go to `/dev`.

## Sub-features

- `dev-open` opens `/dev` with `data-page="dev"` and heading `Dev`.
- `dev-tabs` switches Hunt skills, Skill generator, Recon agents, and Tools.
- `dev-hunt-list` lists library hunt skills in `#dev-profiles-body` after `GET /api/hunt-profiles`.
- `dev-hunt-select` opens a library row in the editor (`#dev-id`, `#dev-title`) without saving.
- `dev-mutate` is **not** driven. New skill, Generate, Reseed, Import setup, and Active checkboxes write the operator collection.

## How to get to it (user POV)

- Choose **Open Dev** (`#btn-open-dev`) on Home.
- Open `$VF_VERIFY_URL/dev`.
- Choose **Dev** in the run rail footer (`[data-nav-id="dev"]`).

## Driving it with vf-verify

Preconditions:

- `vf-verify doctor` is `ok: true`.
- You will not click **+ New skill**, **Generate from description**, **Reseed from package**, **Export setup**, **Import setup…**, or any `data-active-toggle` checkbox.

- **Open page.** Go to `$VF_VERIFY_URL/dev`. `body` has `data-page="dev"`. Heading is `Dev`. Default tab `[data-dev-tab="hunt"]` is selected.
- **Hunt list.** Wait until `#dev-profiles-body tr.dev-row` exists. A library row has `data-id="injection"` (or another seed id). `#dev-meta` matches `N skills · M active`. `GET $VF_VERIFY_URL/api/hunt-profiles` returns `ok: true` and a `profiles` array. Save it as `hunt-profiles.json`.
- **Select skill.** Click `tr.dev-row[data-id="injection"]`. `#dev-editor-form` becomes visible. `#dev-id` is `injection`. Do not edit or save.
- **Other tabs.** Click `[data-dev-tab="recon"]`. `[data-dev-panel="recon"]` is active. Click `[data-dev-tab="tools"]`. Tools panel is active. Click `[data-dev-tab="hunt"]` to return.
- **Proof.** Screenshot `dev-hunt.png` showing the collection table and the injection editor. Keep `hunt-profiles.json`. Collection files under `config/hunt_profiles/` must not change.

## Gotchas

- Hunt skills on `/dev` are the operator collection, not a disposable copy. Reseed and Active toggles persist for later real campaigns.
- Library vs **Custom & generated** (`[data-hunt-explorer]`) filters the table. Seed ids such as `injection` live under Library.
- `GET /dev` HTML still says `Loading…` in the table body. Wait for `tr.dev-row`.
- Export setup downloads a pack. That is read-ish but skip it unless the feature under test is the download itself.
