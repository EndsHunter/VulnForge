# Durable HITL inbox

Human review is a versioned **report ↔ responses** contract. Automation publishes packets. Only an explicit human action writes an answer. Reading the store never invents an approval and never sets `confirmed`.

Schema id: `vulnforge/hitl-report@1`. Responses schema: `vulnforge/hitl-responses@1`.

This follows the harness-deck report + `responses.json` shape (status, stable block ids, answers keyed by block id with `value`, `note`, `at`). It does not port that project's TUI or dashboard chrome. Ralph loop state (`run.lock`, Ralph pid) stays separate from the inbox.

## Status

`draft | awaiting-review | answered | done`

| Finding state | Report status | In the inbox |
|---------------|---------------|--------------|
| `needs_human` | `awaiting-review` | yes |
| `confirmed` | `done` | no |
| `rejected_human` | `done` | no |
| `rejected_llm` | `done` (no human answer invented) | no |

Explicit gate packets use the same statuses. They move to `answered` when every interactive block has a stored response. They never change finding state.

## Blocks

Interactive prompts are keyed by a stable `id`:

| type | records |
|------|---------|
| `approval` | `approved` or `changes-requested` |
| `decision` | the chosen side `tag` |
| `ask` | `choice` option, `yes`/`no`, or text |

Finding packets use ids `finding-{n}`, `finding-{n}-review` (approval), and `finding-{n}-notes` (ask/text). A note alone does not accept the finding. `approved` on a finding approval block is the explicit review that sets `confirmed` (`review_finding`). `changes-requested` sets `rejected_human`.

## Where it lives

| Store | Role |
|-------|------|
| `harness.db` tables `hitl_reports`, `hitl_responses` | Authority |
| `hitl/responses.json` | Projection the harness can re-read |
| `hitl/reports/<id>.json` | Projection of each packet |

The next read rewrites the projections from the database. A missing response key means unanswered.

## Surfaces

- Mission: light **needs review** indicator (jumps to Report with the Needs review filter).
- Report: **Needs review** filter plus finding-row Accept / Reject. That is the human review UI; there is no second inbox section on Report.
- Report Accept / Reject still calls human review and records the same response.
- `vf hitl inbox|show|responses|respond|emit`

Module: `vulnforge/hitl.py`.
