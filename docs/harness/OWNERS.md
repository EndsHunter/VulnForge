# Suggested finding owners (issue #190)

Opt-in. For each finding, VulnForge suggests who probably owns the cited code:

| Signal | Source | Weight |
|--------|--------|--------|
| Blame | `git blame` on the cited line ranges at `HEAD` | 0.60 |
| File | recent non-merge commits to the primary cited file | 0.25 |
| Module | recent commits to the codemap module (else the file's directory) | 0.15 |
| CODEOWNERS | first of `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS` at `HEAD` | reported separately |

Weights are normalised over the signals that have data. `[bot]` identities are dropped.
CODEOWNERS uses GitHub rules: the last matching rule wins, a rule with no owners clears
ownership, a `/` in the middle anchors the pattern at the repo root, `docs/*` and `/*` own only
direct entries, and `\ ` escapes a space. Matching is linear in pattern × path length (no
regex), so a hostile CODEOWNERS cannot stall the dashboard. These are suggestions, not assignments. Renames are not followed.

Code: `vulnforge/findings/owners.py`. Nothing is written to the finding, `harness.db`, or the target.

## Turning it on

`config/default.yaml`:

```yaml
owners:
  enabled: false            # opt-in
  redact_in_exports: true   # pseudonyms in exports
  allow_parent_repo: false  # true: target may be a monorepo subdirectory
  max_commits: 50
  max_suggestions: 5
  timeout_seconds: 10
  export_budget_seconds: 60
```

Or **Settings → Report and exports** (`finding_owners`, `finding_owners_redact_exports` in
`ui_settings.json`). An unset UI toggle leaves YAML in charge.

## Where owners show up

- **Report → finding detail**: "Suggested owners" block (`GET /api/runs/{t}/{r}/findings/{id}/owners`).
  Always real identities; this is the local operator view.
- **Exports** (`/export`): JSON `findings[].owners` + `rows[].suggested_owners`; a
  `suggested_owners` column in CSV/XLSX (only when on); a bullet in MD/HTML/DOCX.
  `include_owners=false` omits them. No query flag lifts redaction.
- **Tracker issues** (#189, `vulnforge/tracking/`): a "Suggested owners" section in the issue
  body, built by `owners_markdown()`. Every identity sits in a code span, so GitHub never sends
  a mention. Issues leave the machine like exports, so they follow `redact_in_exports`.
  Preview and publish render the same text, so the preview token hash still matches.
- Other sinks (SARIF, …): `owners_markdown()` or `owners_flat()`.

Redaction replaces author names, emails, and every CODEOWNERS token (users and teams) with
`owner-<16 hex>` (SHA-256 salted with the run id). It is stable within a run and differs
across runs. It is a pseudonym, not anonymisation: anyone with a candidate identity and the
run id can check it.

## Read-only git against an untrusted tree

The target is code under audit, so its `.git/config` and tracked files are hostile input.

- Commands: `rev-parse`, `cat-file -s|blob HEAD:<path>`, `blame --line-porcelain HEAD`,
  `log HEAD --format=…`. Everything reads objects at `HEAD`; nothing reads or refreshes the
  index or the working tree.
- Env: every `GIT_*` variable is removed. Then `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_OPTIONAL_LOCKS=0`, `GIT_LITERAL_PATHSPECS=1`
  (`:(top)` is a literal path), `GIT_NO_LAZY_FETCH=1`, and `GIT_CEILING_DIRECTORIES` (the
  target's parent unless `allow_parent_repo`) are set.
- `-c` pins (they beat `.git/config` per key): `core.fsmonitor`, `core.pager`, `core.hooksPath`,
  `core.attributesFile`, `core.sshCommand`, `core.gitProxy`, `core.askPass`, `credential.helper`,
  `diff.external`, `log.showSignature=false`, `mailmap.file`/`mailmap.blob`, `trace2.*Target=0`,
  `protocol.allow=never`, `gc.auto=0`. Flags: `--no-pager`, `--no-textconv`, `--no-ext-diff`,
  `--no-ignore-revs-file` (`blame.ignoreRevsFile` is multi-valued, so a `-c` value cannot reset it).
- The toplevel must equal the target (no climbing into a parent repo, no `.git` file pointing
  at a work tree elsewhere) → otherwise `unsafe_repository`. `safe.directory` is never overridden.
- Citation paths: no absolute paths, `..`, or control characters. Always passed after `--`.
- Each call has a timeout and runs in its own process group, which is killed on expiry.
  stdout is streamed with a 16 MiB cap (killed on overflow). A cited blob over 8 MiB is not
  blamed (`skipped: too_large`); file and module history still apply.
- Author strings lose control characters; log records use NUL/RS separators.
  CSV/XLSX owner cells that start with `= + - @` or a tab get a leading `'`.
- The in-repo `.mailmap` is honoured (blame cannot turn it off). It is target data, with the
  same trust as commit authors.

## Unavailable reasons

`disabled`, `git_missing`, `not_a_git_repo`, `unsafe_repository`, `no_head`, `untracked`,
`no_citations`, `target_missing`, `timeout`, `too_large`, `budget_exhausted`, `git_error`.

Tests: `tests/test_finding_owners.py` (temp git repos built in the test).
