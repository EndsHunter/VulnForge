# Validate (disprove) system prompts

Runs after mech pass when **`stages.validate_llm`** is true (**default on** in `config/default.yaml`). Set false to opt out.

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

Defaults live in `config/default.yaml`. The current shipped values:

```yaml
stages:
  validate_llm: true
  validate_poc_referee: true
poc_harness:
  enabled: true
  runner: docker          # or local_subprocess if Docker is unavailable
  timeout_s: 60
  network: none
```

`llm.disprove_verifiers` can list `{id, prompt}` pairs. Missing perspective files fall back to the shared `disprove.md` contract only.

**When to disable validate_llm:** campaign speed, debugging hunt output without LLM filter, or same-model disprove is pure noise. Still never auto-confirms when on.

**Mech floor (always on):** `validate_mech.check_non_vacuous` rejects stub threat models and HIGH/CRITICAL without concrete impact hints — independent of this flag.

## `referee_poc.md`

| | |
|--|--|
| **What** | Optional PoC **run** referee after `validate_poc` mechanical execution. |
| **Loaded by** | `packet.pack_poc_referee` when `stages.validate_poc_referee` or task `referee: true`. |
| **Impact** | Annotates `poc_run.json` / body `poc_validation_latest` only. **Never** sets `confirmed`. |
| **Override** | `config/prompts/overrides/referee_poc.md` |

## See also

- [docs/harness/validate/](../harness/validate/)
- [docs/system/DEVELOP_POC.md](DEVELOP_POC.md) — hub frontmatter + export
- [docs/system/SHARED.md](SHARED.md) — `PRINCIPLES.md` impact/severity pin for hunts
