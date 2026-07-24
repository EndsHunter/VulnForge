# Validate (disprove) system prompts

Used only when **`stages.validate_llm`** is enabled and a `validate_llm` task runs after mech pass.

## `disprove.md`

| | |
|--|--|
| **What** | Shared adversarial contract: try to kill the finding; verdict discipline. |
| **Loaded by** | `packet.pack_disprove`. |
| **Impact** | How aggressive LLM rejection is. Can only demote/reject → more rejects or more stands; **never** auto-confirm or raise severity (enforced in stage code). |
| **Override** | `config/prompts/overrides/disprove.md` |

## `disprove_threat.md`

| | |
|--|--|
| **What** | Threat-model verifier perspective appended after shared disprove. |
| **Loaded by** | Default verifier list in `stages/validate_llm.py` (`threat_model` → this file). |
| **Impact** | Perspective-specific demotions (attacker/boundary realism). |
| **Override** | `config/prompts/overrides/disprove_threat.md` |

## `disprove_code.md`

| | |
|--|--|
| **What** | Code/mitigation verifier perspective. |
| **Loaded by** | Default verifier `code_mitigation`. |
| **Impact** | Focus on mitigations, sinks, dataflow realism. |
| **Override** | `config/prompts/overrides/disprove_code.md` |

## Config

Verifier list can be customized via `llm.disprove_verifiers` (id + prompt basename). Missing perspective files degrade to shared contract only.

## See also

- [docs/harness/validate/](../harness/validate/)
