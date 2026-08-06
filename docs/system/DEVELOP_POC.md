# Develop PoC system prompt

## `develop_poc.md`

| | |
|--|--|
| **What** | Stage instructions for **runnable** PoC development (not a narrative rewrite of the finding). |
| **Loaded by** | `packet.py` develop_poc packing + `stages/develop_poc.py` path. |
| **Impact** | Quality/style of code written under the evidence pack / workshop hub. Does not change finding state or auto-confirm. |
| **Override** | `config/prompts/overrides/develop_poc.md` |
| **UI** | Report → Develop POC workshop modal; optional Ralph `develop_poc` task. |

## Hub frontmatter (harness)

Optional YAML frontmatter on `poc_develop.md` drives `validate_poc` / export:

```yaml
---
run: python poc.py --url http://127.0.0.1:8000
entry: poc.py
success_regex: ASSERT_OK
timeout_s: 60
network: none
---
```

Hub default is ``network: none`` (matches harness safe default). Set
``network: allow`` only when the PoC must reach a local/lab service.

Soft readiness (`harness_ready`) requires runnable code + success criteria
(`success_regex` and/or non-placeholder **Expected signal**). Not a mech gate.

## Related

| | |
|--|--|
| **validate_poc** | Controlled execution → `evidence/<pack>/poc_run.json` |
| **export-validation-job** | CLI / Report: handoff zip (`HANDOFF.md`, finding.json, pack) |
| **referee_poc.md** | Optional LLM referee after run (`stages.validate_poc_referee`) |

## Honesty

PoC code is **not** exploit proof of production impact. Human review still owns `confirmed`.
`validate_poc` results are evidence only — automation never sets `confirmed`.
