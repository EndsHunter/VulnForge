# Hunt profile import review prompt

## `profile_review.md`

| | |
|--|--|
| **What** | System prompt for the optional LLM review of imported hunt profiles (issue #191). Returns `{"verdict": "PASS\|REVIEW\|BLOCK", "reasons": [...]}`. |
| **Loaded by** | `vulnforge/hunt_profiles/review.py` `llm_review` via `load_prompt_slice` (so `config/prompts/overrides/profile_review.md` works). |
| **Runs when** | Dev **Import** with "Also run LLM review" checked, `import_collection(..., llm_review=True)`, or **Run LLM review** in the Dev editor (`POST /api/hunt-profiles/{id}/review`). |
| **Impact** | Can only make a verdict stricter. The harness keeps the more severe of the mechanical and model verdicts, so a prompt-injected `PASS` never clears a mechanical REVIEW or BLOCK. A transport error or unparsable reply is `INCOMPLETE`. |

## How the review gates activation

1. `import_collection` runs `mechanical_review` on every imported profile (body, title, description,
   tools). Imported profiles start **inactive** with `source=import`. Any `review` key in the file is
   discarded. A row is kept as-is only when its body, title, description and tools match the local
   row exactly.
2. Verdicts: `PASS` activates freely. `REVIEW` needs an explicit confirmation. `BLOCK` and `INCOMPLETE`
   need an override with a reason. Confirmations and overrides are appended to
   `config/hunt_profiles/review_log.jsonl`. Overrides also log a warning.
3. An acknowledgement binds to a hash of body, title, description and tools. Editing any of them
   re-runs the mechanical review and drops the acknowledgement. If the profile had an LLM verdict,
   it becomes stale, and the profile stays `INCOMPLETE` until the LLM review runs again.
4. A profile that has not cleared review never reaches a prompt. It is left out of active sets and
   empty-active fallbacks, run skill resolution, recon's class registry, `list_hunt_profiles`,
   `request_hunt`, and coverage select. `_load_hunt_class_body` falls back to `wildcard` or a stub.

Mechanical rules live in `review.py` `_RULES`. `tests/test_hunt_profile_review.py` checks that every
package seed in `seeds/hunt_classes/` stays `PASS`.
