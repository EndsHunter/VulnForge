# Dual LLM Disprove Verify — Design

**Date:** 2026-07-18  
**Status:** Approved for implementation  
**Scope:** VulnForge `validate_llm` stage + Report tab

## Problem

Today a finding that passes mechanical gates gets at most **one** adversarial LLM disprove pass (`prompts/v1/disprove.md`). Operators lack a simple multi-perspective signal that both tries harder to kill weak claims and is visible on the Report tab.

## Goals

1. For each finding that runs `validate_llm`, execute **two** independent LLM verifiers.
2. Each verifier’s **sole job** is to **disprove** the finding (never invent bugs, never raise severity, never auto-confirm).
3. The two verifiers use **different perspectives**, each backed by its own `.md` prompt.
4. Report tab shows **`N/2 llm verified`** where **verified = verdict `stand`** (survived disprove / could not kill).
5. Config shape supports **future per-slot model choice** without a second UI/API redesign.

## Non-goals

- Per-verifier model picker in the operator UI (config hook only for now).
- Parallel workers / two task kinds / join across leases.
- Auto-confirm at `2/2`.
- Changing mechanical gates or human review actions.

## Decisions (operator-approved)

| Topic | Decision |
|-------|----------|
| “Verified” meaning | Survived disprove: `stand` counts as verified |
| Badge | `{stood}/2 llm verified` (e.g. `0/2`, `1/2`, `2/2`) |
| Auto-reject rule | **`rejected_llm` only if both verifiers return `reject`** |
| Other outcomes | Any `stand`, `needs_human`, parse fail, or infra partial failure that yields non-reject → **`needs_human`** (never auto-confirm) |
| Perspectives | A: threat-model skeptic · B: code/mitigation skeptic |
| Scheduling | **One** `validate_llm` task; **sequential** dual chat |

## Architecture

```
validate_mech (pass) → enqueue validate_llm(finding_id)
                              │
                              ▼
                    load citations + finding body
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
     pack_disprove(threat.md)        pack_disprove(code.md)
     chat (verifier A)               chat (verifier B)
              │                               │
              └───────────────┬───────────────┘
                              ▼
                   aggregate + write body.validation_llm
                   update finding state
```

No new task kind. Existing flag `stages.validate_llm` remains the on/off switch. Flag-off / terminal / missing-finding safety paths stay as today.

## Prompt layout

| File | Role |
|------|------|
| `prompts/v1/disprove.md` | Shared demote-only contract: process order, kill criteria catalog, alternative explanation, reachability labels, confidence discipline, **strict `VERDICT=` output** |
| `prompts/v1/disprove_threat.md` | Threat-model lens: prioritize attacker / boundary / impact honesty, scope, vacuous threat models |
| `prompts/v1/disprove_code.md` | Code/mitigation lens: prioritize citations match, source→sink, mitigations elsewhere, wrong layer / broken proof |

Each slot packet = system (preamble + stage header + principles without hunt tools) + **shared** `disprove.md` + **perspective** file + Finding JSON + cited slices.

Packet API change: `pack_disprove(..., perspective: str | Path | None = None)` or `verifier_prompt: str` so callers load the perspective relative to `prompts/v1/`.

## Config

Default under `llm` (and/or documented in `config/default.yaml`):

```yaml
llm:
  temperature_disprove: 0.1
  disprove_verifiers:
    - id: threat_model
      prompt: disprove_threat.md
      # model: null   # future: per-slot override; omit = inherit llm.model
    - id: code_mitigation
      prompt: disprove_code.md
      # model: null
```

- Exactly two slots in v1 (hard-coded expected `total=2` for badge copy; length of list drives loop).
- If config omits `disprove_verifiers`, use the two defaults above.
- Per-slot `model` is read and recorded when present; if unset, use existing client/model (no multi-client yet unless already trivial).

## Finding body shape

```json
"validation_llm": {
  "status": "completed",
  "stood": 1,
  "total": 2,
  "label": "1/2",
  "aggregate": "needs_human",
  "verdict": "needs_human",
  "verifiers": [
    {
      "id": "threat_model",
      "prompt": "disprove_threat.md",
      "verdict": "reject",
      "parse_reason": "tag",
      "model_id": "…",
      "reasoning": "…",
      "at": "…"
    },
    {
      "id": "code_mitigation",
      "prompt": "disprove_code.md",
      "verdict": "stand",
      "parse_reason": "tag",
      "model_id": "…",
      "reasoning": "…",
      "at": "…"
    }
  ],
  "parse_reason": "aggregate",
  "model_id": null,
  "residual_risk": "Same-model dual disprove is still weak signal; human is the confirm gate.",
  "at": "…"
}
```

### Compatibility

- Keep top-level `verdict` / `status` / `reasoning` (optional: join of both reasonings or first) so older readers do not break.
- Prefer `verifiers[]` for all new UI.
- Legacy single-verdict bodies (no `verifiers`): Report treats as unknown / `—` or maps single verdict to `0/1` only if we must — prefer show `—` until re-run.

### Aggregation rules

| Verifier A | Verifier B | stood | state |
|------------|------------|-------|-------|
| reject | reject | 0 | `rejected_llm` |
| reject | stand | 1 | `needs_human` |
| stand | stand | 2 | `needs_human` |
| reject | needs_human | 0 | `needs_human` |
| needs_human | needs_human | 0 | `needs_human` |
| stand | needs_human | 1 | `needs_human` |

`stood` = count of verdicts equal to `stand` only.

Parse failure / empty content → that slot’s verdict = `needs_human` (same as today).

### Partial / infra failure

- If verifier A fails with **infra** (retryable): fail the task as `failed_infra` **before** mutating to terminal reject (preserve retry semantics). Do not write half-reject as final `rejected_llm`.
- If A succeeds and B fails infra: `failed_infra`; optional body stamp `validation_llm.status=partial` with A’s result for operator visibility, but **finding state not** set to `rejected_llm` on partial.
- Model thrash / empty on a slot: slot = `needs_human`, continue to next slot when possible; aggregate as above.

## Stage implementation notes

File: `vulnforge/stages/validate_llm.py`

1. Resolve verifier list from config (default two).
2. Load citation slices once; reuse for both packets.
3. For each verifier: pack → chat → transcript (`kind=validate_llm`, meta includes `verifier_id`) → parse.
4. Aggregate; write `body.validation_llm`; set state; emit `validate_llm_done` with `stood`, `total`, `label`, per-slot verdicts.

`validation_reasons` notes:

- both reject → `validate_llm:rejected` (or `validate_llm:rejected:0/2`)
- else → `validate_llm:stand_awaiting_human` / `validate_llm:needs_human:…` including `stood/total`

## Report UI

File: `vulnforge/ui/static/report.js` (+ light CSS if needed)

### Table row

- Badge: `N/2 llm verified` when `validation_llm.verifiers` present (or `label` + total).
- If LLM not run / disabled skip / missing: omit badge or show muted `—`.
- Colors: `0/2` bad, `1/2` warn, `2/2` info (still not confirmed).

### Detail panel

Section **LLM verify**:

- Summary line: `1/2 llm verified`
- Per verifier: id, verdict, model_id, truncated reasoning (expandable)

No new API: findings already return `body` in snapshot.

## Events / usage

- One usage row per chat (`kind=validate_llm`, meta/verifier id in transcript meta).
- Event `validate_llm_done` gains: `stood`, `total`, `label`, `verdicts: [{id, verdict}, …]`.

## Tests

Extend `tests/test_validate_llm_safety.py` (FakeLLM multi-response already matches sequential chats):

1. Both reject → `rejected_llm`, `stood=0`, label `0/2`.
2. One stand one reject → `needs_human`, `stood=1`.
3. Both stand → `needs_human`, `stood=2`.
4. Parse fail on one slot → that slot needs_human; never confirm.
5. Flag-off / terminal skip paths unchanged.
6. Optional: packet includes both perspective prompts (string contains lens-specific heading).

UI: manual check or minimal static test if the project has none for report.js (no new harness required).

## Acceptance criteria

- [ ] With `validate_llm` on, each open finding task runs **two** disprove chats with different `.md` perspectives.
- [ ] Finding body stores `verifiers[]`, `stood`, `total`, `label`.
- [ ] Report table shows **`N/2 llm verified`**.
- [ ] Detail shows both reasonings.
- [ ] State = `rejected_llm` **only** when both say `reject`.
- [ ] Never auto-`confirmed`.
- [ ] Existing safety tests pass; new dual cases pass.

## Implementation order

1. Split/add prompt files + `pack_disprove` perspective arg.
2. Dual loop + aggregate in `validate_llm.py` + default config.
3. Report badge + detail.
4. Tests + fix regressions.

## Open follow-ups (explicitly later)

- Operator UI to choose model per verifier slot.
- Optional third verifier or configurable N.
- Parallel dual chat for wall-clock latency.
