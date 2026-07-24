# Validate — what and where to change

## Common changes

| Want to… | Edit |
|----------|------|
| Add a mechanical gate | Append to `CHECKS` in `vulnforge/stages/validate_mech.py`; unit test in `tests/test_validate_mech_gates.py` |
| Change severity handling | `vulnforge/findings/severity.py` + mech check |
| Toggle LLM disprove | Config `stages.validate_llm` / UI settings |
| Change disprove contract | `seeds/system/disprove.md` (+ overrides) |
| Change threat/code perspectives | `disprove_threat.md`, `disprove_code.md` |
| Change disprove packing | `vulnforge/packet.py` → `pack_disprove` |
| Change dual-verifier list | `stages/validate_llm.py` / config `llm.disprove_verifiers` |
| Change human review API | `control/ops.py` human review helpers + `ui/app.py` Report routes |
| Change Report UI | `vulnforge/ui/static/report.js` |

## Key files

```text
vulnforge/stages/validate_mech.py   # CHECKS list
vulnforge/stages/validate_llm.py    # optional disprove
vulnforge/packet.py                 # pack_disprove
vulnforge/findings/                 # severity, stable_key, …
seeds/system/disprove.md
seeds/system/disprove_threat.md
seeds/system/disprove_code.md
tests/test_validate_mech_gates.py
tests/test_validate_llm_safety.py
```

## Tests

```powershell
python -m pytest tests/test_validate_mech_gates.py tests/test_validate_llm_safety.py tests/test_human_review.py -q
```

## Rules to preserve

- Mech pass ≠ exploit proof.
- Automation must never set `confirmed`.
- Disprove must not invent findings or raise severity.

## See also

- [README.md](README.md)
- [docs/system/VALIDATE.md](../../system/VALIDATE.md)
