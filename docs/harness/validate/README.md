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

Mech-pass also publishes a durable HITL packet (`vulnforge/hitl-report@1`, status `awaiting-review`). Human answers live in `hitl_responses` / `hitl/responses.json`. The harness re-reads that store. It does not invent approvals. See [HITL.md](HITL.md).

## validate_mech

Pure-code checks in `stages/validate_mech.py` `CHECKS`:

- Schema / required fields
- Citations resolve in target (path exists, line in bounds)
- **Citation content** — at least one `start_line`; cited slice non-empty; when claim tokens (sink symbol / title) exist, at least one must appear in the slice (±2 lines). Optional `stages.strict_citation_content: true` requires `start_line` on every path citation
- Evidence pack exists
- Target unmodified vs manifest fingerprint
- Non-vacuous body (title/summary length; threat_model tokens; impact hedges; HIGH/CRITICAL needs concrete impact hints)
- Severity claim allowed (or soft-dropped earlier)

Pass → `needs_human` and an awaiting-review HITL packet. **Never** `confirmed`.

There is **no numeric score**. Report severity comes from optional `severity_claim`; impact quality lives in `threat_model.impact`.

## validate_llm (default on)

Dual adversarial disprove (`pack_disprove` + `disprove.md` + perspective files). Can only demote/reject. Never create findings, never raise severity, never auto-confirm.

Default: `stages.validate_llm: true`. Set **false** to skip for speed, debug, or when same-model disprove adds noise (mech pass → human directly). Same-model dual stand is still weak signal — never treat as proof.

**Recommended multi-model:** assign 2+ verified `(host, model)` pairs in Settings → Roles (validation). Empty list falls back to the default role only. Rejection still requires **all** slots (model × perspective) to return `reject`. A pair that is not Available fails that slot; VulnForge does not substitute the same model id from another host.

## Quality recipe (better severity / impact results)

| Lever | What to do |
|-------|------------|
| **Hunt upstream** | `seeds/system/PRINCIPLES.md` forces attacker→effect Z; cap HIGH/CRITICAL |
| **Tool schema** | `submit_candidate` descriptions steer concrete threat_model + enum severity |
| **Mech floor** | `check_non_vacuous` + `check_citation_content` reject stubs and off-target citations |
| **LLM disprove** | Default on; prefer 2+ `validate_models`; set `stages.validate_llm: false` to opt out |
| **Human** | Report Accept/Reject is the real confirm and severity authority |

## validate_poc (operator / CLI)

Controlled **execution** of pack PoCs (separate from static disprove):

```text
enqueue validate_poc (finding_id)
  → read evidence pack + hub frontmatter
  → microVM (Kata / patched Firecracker) else gVisor runsc else refuse
  → write evidence/<pack>/poc_run.json
  → optional LLM referee (stages.validate_poc_referee)
  → update body.poc_validation_latest  (state unchanged, HITL unchanged)
```

Verdicts: `signal_observed` | `signal_absent` | `poc_broken` | `inconclusive` | `build_failed` | `sandbox_unavailable` | `unsafe_skipped`.
**Never** sets `confirmed`. UI copy is “sandbox reproduced” / “signal observed”.

Config: `poc_harness.*` and `stages.validate_poc_referee` in `config/default.yaml`.

**Sandbox (v1):**

| Key | Default | Notes |
|-----|---------|--------|
| `poc_harness.runner` | `sandbox` | microVM → gVisor `runsc` → refuse. `local_subprocess` and plain runc hard-fail |
| `poc_harness.network` | `none` | Deny egress. `allow` is an isolated bridge. Never host net |
| `allow_write_target` | `false` | Not honored. Optional `mount_target_ro` is read-only |
| `docker_image` | `python:3.12.8-slim-bookworm` | Pin. Linux host required |
| `iterate_max_cycles` | `5` | Rewrite/re-run cycles per sandbox session. Settings overrides |
| `iterate_wall_ttl_min` | `15` | Wall TTL minutes per session. Settings overrides |

Missing Kata/Firecracker/runsc returns `sandbox_unavailable` with an operator hint. It does **not** fall back to the host.

Run-start opt-in: New audit **Sandbox PoC one-shot**, or `vf init --sandbox-poc`. When on, idle Ralph queues one sandbox `validate_poc` per harness-ready `needs_human` finding. A missing sandbox does not block the rest of the run and does not clear HITL.

Firecracker/jailer, if used, must be patched for CVE-2026-5747 and CVE-2026-1386 (1.14.4–1.14.x or >= 1.15.1) and boot with `pci=off`. See [firecracker-guest-init.sh](firecracker-guest-init.sh).

CLI:

```powershell
vf export-validation-job --run-dir runs\<t>\run-001 --finding-id 3
vf validate-poc --run-dir runs\<t>\run-001 --finding-id 3          # enqueue
vf validate-poc --run-dir runs\<t>\run-001 --finding-id 3 --execute # in-process
```

Report → Develop POC: **Run in harness** (one-shot) / **Iterate in sandbox** (same guest, caps) / **Export validation job**. Steer and Stop join that session. Workshop shows isolation · network and a **Sandbox unavailable** badge when Kata and gVisor are both missing. Caps and fail-closed results do not confirm.

## Operator surfaces

| Surface | Action |
|---------|--------|
| Report | Accept / Reject / Needs review; notes; Open Evidence |
| Report → Develop POC | Hub + develop_poc; harness run; export validation job |
| Evidence | Browse packs (`poc_run.json` after validate_poc) |

## Prompts

See [docs/system/VALIDATE.md](../../system/VALIDATE.md) for `disprove*.md` and `referee_poc.md`.
