# Validation stages

After a hunt submits a candidate, **mechanical gates** run (always). Optional **LLM disprove** may demote/reject. **Confirm** is human-only.

## Pipeline

```text
submit_candidate
  → validate_mech  (no LLM)
       fail → rejected_mech
       pass → needs_human  (+ optional enqueue validate_llm)
  → validate_llm   (optional, config stages.validate_llm)
       both reject → rejected_llm
       otherwise   → needs_human (stand / hold)
  → Report human review
       accept → confirmed
       reject → rejected_human
```

## validate_mech

Pure-code checks in `stages/validate_mech.py` `CHECKS`:

- Schema / required fields
- Citations resolve in target
- Evidence pack exists
- Target unmodified vs manifest fingerprint
- Non-vacuous body
- Severity claim allowed (or soft-dropped earlier)

Pass → `needs_human`. **Never** `confirmed`.

## validate_llm (optional)

Dual adversarial disprove (`pack_disprove` + `disprove.md` + perspective files). Can only demote/reject. Never create findings, never raise severity, never auto-confirm.

## Operator surfaces

| Surface | Action |
|---------|--------|
| Report | Accept / Reject / Needs review; notes; Open Evidence; Ask AI on near-dups |
| Evidence | Browse packs |

## Prompts

See [docs/system/VALIDATE.md](../../system/VALIDATE.md) for `disprove*.md`.
