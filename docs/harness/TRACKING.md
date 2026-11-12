# Track findings in external issues (#189)

**Track** publishes findings to an external tracker. GitHub Issues is the only
sink today. `jira` and `linear` are reserved names in
`vulnforge/tracking/base.py` `SINKS`.

This is **outward-facing**. Every publish needs explicit human confirmation:

| Surface | Confirmation |
|---------|--------------|
| Report → finding detail **Track…** / toolbar **Track visible…** | **Preview** (no network) shows the exact issue title and body and mints a one-shot token (10 min, bound to run, sink, repo, `include_needs_human`, finding ids and a hash of each body). Only **Publish** sends it. |
| Run AI chat `track_findings` | In `MUTATE_TOOLS` → UI **Confirm** card. Home chat has no tracking tool. |

Ralph, the stages, and `run-once` never import `vulnforge.tracking`
(`tests/test_tracking.py` greps for it).

## Rules

- **Eligibility:** `confirmed` only by default. `needs_human` needs a per-publish
  opt-in (dialog checkbox / `include_needs_human`). No config key turns it on.
  Eligibility is re-checked at publish time. A finding whose state or body changed
  after preview is skipped.
- **Never changes finding state.** Max 25 findings per publish.
- **Body:** state line, a standing *not exploit proof* line (also for
  `confirmed`, also with a PoC run), severity claim, class, summary, threat model,
  locations, evidence pack id + excerpt, and a visible marker line
  `vulnforge-stable-key: <key>`. `@mentions` are neutralized. Excerpt reads only
  `notes.md`, `evidence.md`, `summary.md` or `README.md` inside
  `evidence/<pack>/` (resolved, symlink-jailed). PoC code is never excerpted.
- **Storage:** table `finding_tracking` (`stable_key`, sink, destination → issue
  number + URL). It is the authority, and the snapshot shows it as
  `finding.tracking[]`.
- **Dedupe by `stable_key`:** a linked row → `PATCH` (replaces title + body; does
  not reopen/close or change labels). No row → claim a `pending` row (primary key
  blocks a second creator), scan open+closed issues labelled `vulnforge` for the
  exact marker line, then `PATCH` or `POST`. Every `PATCH` first fetches the issue
  and refuses one without the marker. The search API is not used (index lag).

## Config

```yaml
tracking:
  sink: github
  github:
    repo: "owner/name"   # Track dialog / chat may pass another
    labels: [security]   # `vulnforge` is always added
    transport: auto      # auto | gh | token
```

Transports: `gh api` (gh keeps its own credentials) or a token from
`VF_GITHUB_TOKEN` / `GITHUB_TOKEN` (urllib, pinned to `https://api.github.com`).
Tokens never go in config, argv, events, errors or chat results.

## Tests

`tests/test_tracking.py` uses an in-memory fake GitHub. `tests/conftest.py`
`_no_real_issue_tracker` blocks `gh` and network for every test.
