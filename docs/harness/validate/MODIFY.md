# Validate — what and where to change

## Common changes

| Want to… | Edit |
|----------|------|
| Add a mechanical gate | Append to `CHECKS` in `vulnforge/stages/validate_mech.py`; unit test in `tests/test_validate_mech_gates.py` |
| Tighten citation content overlap | `check_citation_content` / `citation_claim_tokens` in `validate_mech.py`; optional `stages.strict_citation_content` |
| Tighten vacuous impact / severity floor | `check_non_vacuous` (+ `_VACUOUS_*` helpers) in `validate_mech.py` |
| Change severity handling | `vulnforge/findings/severity.py` + mech check |
| Improve hunter impact wording | `seeds/system/PRINCIPLES.md` and `submit_candidate` tool schema |
| Toggle LLM disprove | Config `stages.validate_llm` / UI settings (default on; set false for speed/debug) |
| Change disprove contract | `seeds/system/disprove.md` (+ overrides) |
| Change threat/code perspectives | `disprove_threat.md`, `disprove_code.md` |
| Change disprove packing | `vulnforge/packet.py` → `pack_disprove` |
| Change dual-verifier list | `stages/validate_llm.py` / config `llm.disprove_verifiers` |
| Change human review API | `control/ops.py` human review helpers + `ui/app.py` Report routes |
| Change Report UI | `vulnforge/ui/static/report.js` |
| PoC harness runner / timeouts / network | `config/default.yaml` → `poc_harness` (default `docker` + `network: none`); `vulnforge/poc_runner.py` `harness_config` |
| validate_poc stage | `vulnforge/stages/validate_poc.py` |
| Handoff export / readiness | `vulnforge/poc_handoff.py` |
| PoC referee prompt | `seeds/system/referee_poc.md` + `packet.pack_poc_referee` |

## Key files

```text
vulnforge/stages/validate_mech.py   # CHECKS list
vulnforge/stages/validate_llm.py    # optional disprove
vulnforge/stages/validate_poc.py    # PoC harness execution
vulnforge/poc_handoff.py            # frontmatter, readiness, export job
vulnforge/poc_runner.py             # local / docker runner
vulnforge/packet.py                 # pack_disprove, pack_poc_referee
vulnforge/findings/                 # severity, stable_key, …
seeds/system/disprove.md
seeds/system/disprove_threat.md
seeds/system/disprove_code.md
seeds/system/referee_poc.md
tests/test_validate_mech_gates.py
tests/test_validate_llm_safety.py
tests/test_poc_handoff.py
```

## Tests

```powershell
python -m pytest tests/test_validate_mech_gates.py tests/test_validate_llm_safety.py tests/test_human_review.py tests/test_poc_handoff.py -q
```

## Rules to preserve

- Mech pass ≠ exploit proof.
- Automation must never set `confirmed`.
- Disprove must not invent findings or raise severity.
- validate_poc results are evidence only (never auto-confirm).

## See also

- [README.md](README.md)
- [docs/system/VALIDATE.md](../../system/VALIDATE.md)
