# Validation stages

After a hunt submits a candidate, **mechanical gates** run (always). Optional **LLM disprove** may demote/reject. **Confirm** is human-only.

## Pipeline

```text
submit_candidate
  → validate_mech  (no LLM)
       fail → rejected_mech
       pass → needs_human  (+ optional enqueue validate_llm)
  → validate_llm   (default on; stages.validate_llm)
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
- Non-vacuous body (title/summary length; threat_model tokens; impact hedges; HIGH/CRITICAL needs concrete impact hints)
- Severity claim allowed (or soft-dropped earlier)

Pass → `needs_human`. **Never** `confirmed`.

There is **no numeric score**. Report severity comes from optional `severity_claim`; impact quality lives in `threat_model.impact`.

## validate_llm (default on)

Dual adversarial disprove (`pack_disprove` + `disprove.md` + perspective files). Can only demote/reject. Never create findings, never raise severity, never auto-confirm.

Default: `stages.validate_llm: true`. Set **false** to skip for speed, debug, or when same-model disprove adds noise (mech pass → human directly). Same-model dual stand is still weak signal — never treat as proof.

## Quality recipe (better severity / impact results)

| Lever | What to do |
|-------|------------|
| **Hunt upstream** | `seeds/system/PRINCIPLES.md` forces attacker→effect Z; cap HIGH/CRITICAL |
| **Tool schema** | `submit_candidate` descriptions steer concrete threat_model + enum severity |
| **Mech floor** | `check_non_vacuous` rejects stubs, hedges, vacuous privilege restatement |
| **LLM disprove** | Default on; set `stages.validate_llm: false` to opt out; tighten `disprove*.md` / overrides |
| **Human** | Report Accept/Reject is the real confirm and severity authority |

## validate_poc (operator / CLI)

Controlled **execution** of pack PoCs (separate from static disprove):

```text
enqueue validate_poc (finding_id)
  → read evidence pack + hub frontmatter
  → run under poc_harness (local_subprocess | docker)
  → write evidence/<pack>/poc_run.json
  → optional LLM referee (stages.validate_poc_referee)
  → update body.poc_validation_latest  (state unchanged)
```

Verdicts: `signal_observed` | `signal_absent` | `poc_broken` | `inconclusive` | `unsafe_skipped`.
**Never** sets `confirmed`.

Config: `poc_harness.*` and `stages.validate_poc_referee` in `config/default.yaml`.

CLI:

```powershell
vf export-validation-job --run-dir runs\<t>\run-001 --finding-id 3
vf validate-poc --run-dir runs\<t>\run-001 --finding-id 3          # enqueue
vf validate-poc --run-dir runs\<t>\run-001 --finding-id 3 --execute # in-process
```

Report → Develop POC: **Run in harness** / **Export validation job**.

## Operator surfaces

| Surface | Action |
|---------|--------|
| Report | Accept / Reject / Needs review; notes; Open Evidence; Ask AI on near-dups |
| Report → Develop POC | Hub + develop_poc; harness run; export validation job |
| Evidence | Browse packs (`poc_run.json` after validate_poc) |

## Prompts

See [docs/system/VALIDATE.md](../../system/VALIDATE.md) for `disprove*.md` and `referee_poc.md`.
