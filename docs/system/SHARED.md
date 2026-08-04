# Shared system prompts

## `preamble.md`

| | |
|--|--|
| **What** | Short shared prefix: authorized defensive review, read-only target, use only provided tools, prefer real paths/symbols. |
| **Loaded by** | `packet.py` when packing recon agents, hunt (via pack helpers), disprove, develop_poc. |
| **Impact of changing package seed** | Affects **all** LLM stages that include the preamble: stricter/looser ground rules, tool discipline language. Changes prompt pin on new inits. |
| **Override** | `config/prompts/overrides/preamble.md` |
| **Do not break** | Read-only target; no inventing paths; no unrestricted shell language that contradicts jail. |

## `PRINCIPLES.md`

| | |
|--|--|
| **What** | Core security-audit doctrine: report exploitable impact (attacker does X → gets Z), threat model before claim, exclusion gates, severity table (CRITICAL…INFORMATIONAL). |
| **Loaded by** | `packet.py` hunt packing (`load_prompt_slice(..., "PRINCIPLES.md")`). |
| **Impact** | Dominant effect on **candidate volume and quality**: tighter exclusions → fewer FPs; looser → more noise. Severity/impact wording shapes what hunts submit; mech `check_non_vacuous` is a separate floor. Does not change human confirm rules. |
| **Override** | `config/prompts/overrides/PRINCIPLES.md` |
| **Do not break** | Honesty: theoretical-only risk should stay non-findings; do not instruct models to auto-confirm or write outside evidence. |

## See also

- [docs/harness/hunt/](../harness/hunt/)
- Root honesty rules in `AGENTS.md`
