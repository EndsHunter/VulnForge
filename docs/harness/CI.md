# Headless CI mode (`vf ci`)

`vf ci` runs one campaign unattended: **init → Ralph → render**, then exits with an
**outcome** code a CI job can gate on. It is a client of the existing loop: Ralph
(`scripts/ralph.py`) runs in-process with one worker and no sleep, and still spawns one
`vf run-once` subprocess per task. Code: `vulnforge/ci/`.

```bash
# new run (accepts every `vf init` flag)
vf --config ci.yaml ci --target . --max-time 2h \
   --max-cost-usd 20 --price-input-per-mtok 3 --price-output-per-mtok 15 \
   --fail-on-state needs_human --fail-on-severity high \
   --output-dir vulnforge-out

# PR mode: diff-scoped audit (every `vf init --diff` rule applies)
vf ci --target . --diff "$(git merge-base origin/main HEAD)..HEAD" \
   --fail-on-state needs_human --output-dir vulnforge-out

# resume an existing run (no init)
vf ci --run-dir runs/<target_id>/run-001 --fail-on-state needs_human
```

## Outcome exit codes

These are **not** the `run-once` protocol codes (0/10/11/20/30) or Ralph's process
codes (0/10/20/30/40/130). `vulnforge/ci/exit_codes.py`:

| Code | Outcome | When |
|------|---------|------|
| 0 | `pass` | Ralph went idle, or stopped early on `--max-time` / `--max-cost-usd` / `--max-iterations` / a `STOP` file, and no finding meets `--fail-on-*`. |
| 1 | `threshold` | At least one finding meets `--fail-on-*`. |
| 2 | `error` | Infra or integrity failure (below). Takes precedence over 1; matched findings are still listed. |

**Coverage gaps alone do not fail.** A budget stop leaves queued hunts, and failed or
deadlettered tasks are gaps too. They are reported in `coverage_gaps`. On GitHub they
also show as a `::warning::` annotation, so a green job does not hide unaudited code.

### Exit 2: integrity and infra

- bad flags, or `--max-cost-usd` with no prices
- `--diff` refused: bad spec, unknown revision, target not a git work tree, or the checkout is not at head (see [DIFF_SCOPE.md](DIFF_SCOPE.md))
- `vf init` failed, or `--run-dir` has no `harness.db`
- a `STOP` file is already in the run dir before the loop starts (Ralph is skipped,
  stop reason `not_run`; findings, thresholds and SARIF are still reported)
- Ralph gave up on infra (5 consecutive failures, task timeouts included), halted on config, or was interrupted
- the cost cap can't be enforced: spend on a model with no price (`cost_unpriced`), or calls recorded without token counts for any model / an unreadable `llm_usage_summary.json` (`cost_unmeasured`). Checked before each lease and again after the loop, so a wall-clock, STOP or iteration stop cannot hide it
- render failed, or `project/REPORT.md` or `project/findings.json` is missing
- the SARIF file could not be written
- a finding became `confirmed` during the loop without a human review record (`human_review_latest.to_state == "confirmed"`, written only by Report review / `vf hitl respond`)
- the queue drained with **zero** `succeeded` tasks and some `deadletter` / `failed_task` / `blocked` (for example a dead LLM endpoint: infra failures requeue, then deadletter, and Ralph would otherwise end "idle")

## Thresholds

| Flags | A finding fails the job when… |
|-------|-------------------------------|
| `--fail-on-state S` (repeatable or comma list; `needs_human`, `confirmed`) | its state is in S |
| `--fail-on-severity L` | it is `needs_human` or `confirmed` and `severity_claim` ≥ L (`critical` > `high` > `medium` > `low` > `informational`) |
| both | both hold (AND) |
| neither | never (exit 0 unless error) |

`rejected_*`, `superseded` and `candidate` never count. A finding with no
`severity_claim` **meets** a severity threshold (fail closed): the harness cannot show it
is lower. It is listed with `severity: null` and reason `severity_unrated`.

## Honesty

- CI never sets `confirmed`. Only human review does.
- A failure on `needs_human` means **needs review**: mechanical gates passed (and the
  dual disprove did not kill it, when on). It is not a proven vulnerability.
- `--fail-on-state confirmed` fails on findings a human already accepted. That is still
  not exploit proof.
- `validate_llm` stays demote-only. Same-model disprove is weak signal.

## Budgets (advisory)

Both caps are checked **before each lease**. A task already running is never killed by
them (only by `--task-timeout`, default 900 s), so a run can overrun by one task.

- `--max-time`: seconds, or `90s`, `45m`, `2h`, `1h30m`. Passed to Ralph as `max_wall_seconds`.
- `--max-cost-usd`: spend **since this `vf ci` started** (a resumed run's earlier spend
  does not count). VulnForge records tokens, not dollars, so the cap needs prices:
  - `ci.pricing` in config, per model id: `{input_per_mtok, output_per_mtok}`. A `default` key covers other models.
  - `--price-input-per-mtok` / `--price-output-per-mtok`: default for any model without a `ci.pricing` entry (wins over `ci.pricing.default`).
  - Use `0` for a local model.

  The estimate is conservative: input = `prompt + cache_read + cache_creation` tokens at
  the input price (cache discounts ignored; OpenAI cached tokens are counted twice). It
  may stop leasing early, never late.

```yaml
ci:
  pricing:
    claude-sonnet-5-5: {input_per_mtok: 3, output_per_mtok: 15}
    default: {input_per_mtok: 0, output_per_mtok: 0}
```

## PR mode (`--diff`)

`--diff BASE..HEAD` (and `--diff-depth`) are `vf init` flags, so `vf ci` takes them
for a new run and passes them through: recon and hunts are limited to the changed
files plus their codemap callers/callees. The compare is two-tree, not merge-base,
so for a PR pass the **merge-base** as BASE, or commits merged into the base branch
after the PR branched are in scope too. The checkout must be at HEAD, with both
commits fetched (`fetch-depth: 0`).

- A diff with **no hunt-able code changes** (docs only, all excluded, or BASE and
  HEAD the same commit, as when a PR head is already in its base) is not an error: `vf ci` exits 0 with stop reason `no_changes`, a warning that nothing was
  audited, no run, and an empty SARIF file. `vf init --diff` alone refuses it.
- `ci_result.json` `diff_scope` holds the counts (`changed`, `expanded`,
  `scope_files`, `excluded_by_reason`, `untouched_modules`, `drift`). Code outside
  the scope was not audited; the summary says so.
- `--diff` with `--run-dir` exits 2: a run's scope is fixed at init.

## SARIF

The SARIF 2.1.0 file comes from the findings exporter ([SARIF.md](SARIF.md)) and is
written to `--sarif PATH`, or `DIR/vulnforge.sarif` with `--output-dir DIR`. Unlike
`vf export`, it includes **`needs_human` as well as `confirmed`**, because a CI gate
is about review items. Code scanning titles those alerts
`needs_human: <title>. Mechanical gates passed; not a confirmed vulnerability.`
`--sarif-confirmed-only` leaves them out. It is written on exit 1 and 2 too (when a
run exists), so partial results still reach code scanning. URIs are relative to the
audited target, so upload with `checkout_path` set to the target directory.

## Outputs

- `{run_dir}/ci_result.json` (`vulnforge/ci-result@1`): `outcome`, `exit_code`, `errors`,
  `warnings`, `ralph.stop_reason`, `completed`, `budget`, `cost`, `threshold`,
  `matched_findings`, `findings` and `tasks` by state, `coverage_gaps`, `report`,
  `diff_scope`, `sarif`, `honesty`.
- `--output-dir DIR`: `DIR/ci_result.json`, `DIR/vulnforge.sarif` and `DIR/report/`
  (a copy of `project/`).
- stdout and `$GITHUB_STEP_SUMMARY`: a Markdown summary with the matched findings.
- `::error::` / `::warning::` annotations when `GITHUB_ACTIONS=true`.

## GitHub Actions example

[`examples/github/vulnforge-ci.yml`](../../examples/github/vulnforge-ci.yml) is a template
for a **target** repo. It is not wired into this repo's CI: it needs an LLM endpoint and
secrets. It has two jobs:

- **weekly** (`schedule` / `workflow_dispatch`): full audit of the default branch.
- **pull_request**: `--diff merge-base..head` of the PR. It checks out the PR head
  (not the default merge commit) with full history, and skips fork PRs, which get no
  secrets.

VulnForge is checked out beside the target (`pip install -e`, since `vf ci` loads
`scripts/ralph.py` from the checkout) and the config is generated from its
`default.yaml` plus secrets, because `--config` replaces the defaults rather than
merging. Both jobs upload SARIF to code scanning (`github/codeql-action/upload-sarif`,
category `vulnforge-full` / `vulnforge-pr`) and the output directory as an artifact,
each with `if: always()`, so a failing gate still publishes the evidence. Do not set
`continue-on-error` on the `vf ci` step: exit 1 is the gate. `tests/test_ci_mode.py`
parses the template's `vf ci` lines with the real CLI parser, offline.
