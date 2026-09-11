# Settings

Settings is the dedicated page for the model endpoint, per-stage model ids, multi-model validation, and agent budgets. Values load from `GET /api/settings` and, if saved, write `config/ui_settings.json` in this repo.

## Sub-features

- `settings-open` opens `/settings` from Home or the run rail footer.
- `settings-fields` shows Endpoint, Stage models, Multi-model validation, and Agent budget.
- `settings-load` fills `#set-host`, `#set-port`, `#set-model`, and related controls from the API.
- `settings-save` is **not** driven in verification. Save writes the repo config file.

## How to get to it (user POV)

- Choose **⚙ Settings** (`#btn-settings`) on Home.
- Open `$VF_VERIFY_URL/settings`.
- Choose **Settings** in the run rail footer (`[data-nav-id="settings"]`).

## Driving it with vf-verify

Preconditions:

- `vf-verify doctor` is `ok: true`.
- You will not click **Save settings** or **Optimize AI settings**.

- **Open page.** Go to `$VF_VERIFY_URL/settings` (or click `#btn-settings` from Home). `body` has `data-page="settings"`. Heading is `Settings`. `#settings-form` is present.
- **Sections.** The page shows headings `Endpoint`, `Stage models`, `Multi-model validation`, and `Agent budget`. Controls include `#set-host`, `#set-port`, `#set-model`, `#set-api-mode`, `#set-model-recon`, `#set-model-hunt`, `#set-model-develop-poc`, `#set-validate-models`, `#set-workers`. Submit control is `#settings-save` labeled `Save settings`.
- **Loaded values.** Wait until `#set-model` is non-empty (filled from `GET /api/settings`). `GET $VF_VERIFY_URL/api/settings` returns `settings` and `effective` with `model` and `base_url`. Save the JSON as `settings-api.json`.
- **Identity.** The header hint shows the dashboard `runs_root` (the disposable `/tmp/vf-verify-.../runs` path). Screenshot `settings.png` with that hint visible.
- **Proof.** `settings.png` plus `settings-api.json`. `config/ui_settings.json` mtime must not change during this recipe.

## Gotchas

- `--runs-root` does not isolate settings. Save and Optimize write this checkout's `config/ui_settings.json`. Stay read-only.
- Home still contains a settings modal markup. The operator path is the `/settings` page. `settings.js` boots only when `data-page="settings"`.
- Optimize probes the configured LLM. Skip it. A live endpoint is not required for this proof.
- A missing `config/ui_settings.json` is fine. The form still fills from defaults merged into `effective`.
